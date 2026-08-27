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
    sha1: str
    logical_path: str
    parent: Optional[str]
    evidence: str  # one of the EVIDENCE_* constants
    confidence: str  # one of the CONFIDENCE_* constants
    sha256: Optional[str] = None

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


class BinaryExtractor(ABC):
    @abstractmethod
    def handles(self, path: str) -> bool: ...

    @abstractmethod
    def extract(self, path: str, max_depth: int) -> list[ArchiveEntry]: ...

    @abstractmethod
    def identify(self, entries: list[ArchiveEntry]) -> ExtractionResult: ...
