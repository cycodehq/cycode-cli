"""The contract every binary extractor implements.

Shaped to mirror ``BaseRestoreDependencies`` so the two read as siblings to anyone already familiar with the SCA
collector: a predicate that claims a file, a step that reads it, and a step that turns what was read into something
the BOM builder can use.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

LOGICAL_PATH_SEPARATOR = ' > '

# which tier produced a component, recorded on it so an analyst can weigh the match
EVIDENCE_POM_PROPERTIES = 'pom.properties'
EVIDENCE_DIGEST = 'digest'
EVIDENCE_MANIFEST = 'manifest.mf'
EVIDENCE_POM_XML = 'pom.xml'  # declared by an embedded pom, not found as bytes; only with --include-declared

# whether the component's bytes are in the artifact, or an embedded pom merely says a consumer will need it
PRESENCE_SHIPPED = 'shipped'
PRESENCE_DECLARED = 'declared'

CONFIDENCE_EXACT = 'exact'
CONFIDENCE_AMBIGUOUS = 'ambiguous'


def join_logical_path(parent: Optional[str], name: str) -> str:
    """Build the containment chain shown to users, e.g. ``app.ear > web.war > WEB-INF/lib/guava.jar``."""
    if not parent:
        return name

    return f'{parent}{LOGICAL_PATH_SEPARATOR}{name}'


@dataclass(frozen=True)
class ArchiveEntry:
    """One file recovered from an archive, with its containment chain."""

    logical_path: str  # 'app.ear > web.war > WEB-INF/lib/guava.jar'
    name: str  # 'guava-31.1-jre.jar'
    size: int  # uncompressed bytes
    sha1: str
    depth: int  # how many archives had to be opened to reach it; the scanned artifact itself is 0
    parent: Optional[str]  # logical_path of the containing archive
    payload: Optional[bytes] = None  # populated only for entries we must parse
    sha256: Optional[str] = None
    is_archive: bool = False
    was_opened: bool = False  # an archive we declined to open still gets reported, just not walked


@dataclass(frozen=True)
class IdentifiedComponent:
    group: str
    artifact: str
    version: str
    sha1: Optional[str]  # None only for a declared component: there are no bytes to digest
    logical_path: str  # for a declared component, the pom that declares it
    parent: Optional[str]
    evidence: str  # one of the EVIDENCE_* constants
    confidence: str  # one of the CONFIDENCE_* constants
    sha256: Optional[str] = None
    declared_scope: Optional[str] = None  # the Maven scope a declared component was declared with; None if shipped
    declared_via: Optional[str] = None  # 'group:artifact' that pulled a transitive in; None for a direct declaration

    @property
    def is_declared(self) -> bool:
        return self.declared_scope is not None

    @property
    def is_transitive(self) -> bool:
        return self.declared_via is not None

    @property
    def presence(self) -> str:
        return PRESENCE_DECLARED if self.is_declared else PRESENCE_SHIPPED

    @property
    def purl(self) -> str:
        # tier 3 recovers a name and a version but rarely a groupId; a purl may legitimately have no namespace,
        # and inventing one would be worse than omitting it
        if not self.group:
            return f'pkg:maven/{self.artifact}@{self.version}'

        return f'pkg:maven/{self.group}/{self.artifact}@{self.version}'


@dataclass(frozen=True)
class UnidentifiedArtifact:
    logical_path: str
    sha1: str
    size: int


@dataclass(frozen=True)
class UnresolvedDeclaration:
    """A declared dependency whose version could not be established. Listed, never guessed."""

    group: str
    artifact: str
    version_expression: Optional[str]
    declared_by: str  # logical path of the pom
    reason: str

    @property
    def coordinate_key(self) -> str:
        return f'{self.group}:{self.artifact}'


@dataclass
class ExtractionResult:
    components: list[IdentifiedComponent] = field(default_factory=list)
    unidentified: list[UnidentifiedArtifact] = field(default_factory=list)
    archives_opened: int = 0
    max_depth_reached: int = 0
    resolver_available: bool = True
    resolver_unavailability_reason: Optional[str] = None
    # bom-ref -> the refs it depends on, containment overlaid with real edges recovered from embedded poms
    dependency_edges: dict[str, list[str]] = field(default_factory=dict)
    has_real_edges: bool = False
    # --include-declared only: declared dependencies whose version could not be established
    declared_unresolved: list[UnresolvedDeclaration] = field(default_factory=list)

    @property
    def declared_components(self) -> list[IdentifiedComponent]:
        return [component for component in self.components if component.is_declared]

    @property
    def transitive_components(self) -> list[IdentifiedComponent]:
        return [component for component in self.components if component.is_transitive]

    @property
    def shipped_components(self) -> list[IdentifiedComponent]:
        return [component for component in self.components if not component.is_declared]


class BinaryExtractor(ABC):
    @abstractmethod
    def handles(self, path: str) -> bool: ...

    @abstractmethod
    def extract(self, path: str, max_depth: int) -> list[ArchiveEntry]: ...

    @abstractmethod
    def identify(self, entries: list[ArchiveEntry]) -> ExtractionResult: ...
