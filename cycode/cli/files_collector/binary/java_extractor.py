"""Extraction of Java deployables: JAR, WAR, EAR and Spring Boot fat JARs, including nested archives.

Everything here is a pure function over bytes. No network, no auth, no Cycode API, no temp files.
"""

import hashlib
import logging
import os
from collections import defaultdict
from typing import Optional

from cycode.cli import consts
from cycode.cli.exceptions.custom_exceptions import BinaryExtractionError
from cycode.cli.files_collector.binary.base_extractor import (
    CONFIDENCE_AMBIGUOUS,
    CONFIDENCE_EXACT,
    EVIDENCE_DIGEST,
    EVIDENCE_MANIFEST,
    EVIDENCE_POM_PROPERTIES,
    EVIDENCE_POM_XML,
    ArchiveEntry,
    BinaryExtractor,
    ExtractionResult,
    IdentifiedComponent,
    UnidentifiedArtifact,
    UnresolvedDeclaration,
    join_logical_path,
)
from cycode.cli.files_collector.binary.declared import DeclaredDependencyResolver
from cycode.cli.files_collector.binary.identifiers import manifest_mf, pom_properties, pom_xml
from cycode.cli.files_collector.binary.identifiers.pom_properties import MavenCoordinates
from cycode.cli.files_collector.binary.resolver import DigestResolver, NullDigestResolver
from cycode.cli.files_collector.binary.safe_zip import ArchiveBudget, ArchiveLimits, SafeZip, SafeZipEntry

logger = logging.getLogger(__name__)

JAVA_ARCHIVE_EXTENSIONS = ('.jar', '.war', '.ear')

# where a Java deployable keeps the libraries it ships with
LIBRARY_DIRECTORIES = (
    'WEB-INF/lib/',  # WAR
    'BOOT-INF/lib/',  # Spring Boot fat JAR
    'APP-INF/lib/',  # legacy WebLogic-style EAR module
    'lib/',  # plain JAR and EAR conventions
)

MANIFEST_ENTRY_NAME = 'META-INF/MANIFEST.MF'
MANIFEST_FILE_NAME = 'MANIFEST.MF'
POM_PROPERTIES_FILE_NAME = 'pom.properties'
POM_XML_FILE_NAME = 'pom.xml'
_MAVEN_METADATA_FILE_NAMES = (POM_PROPERTIES_FILE_NAME, POM_XML_FILE_NAME)
_MAVEN_METADATA_PATH_DEPTH = 5  # META-INF/maven/<groupId>/<artifactId>/<file>

_READ_CHUNK_SIZE_IN_BYTES = 64 * 1024
_MAVEN_PURL_PREFIX = 'pkg:maven/'


def is_java_archive_name(name: str) -> bool:
    return name.lower().endswith(JAVA_ARCHIVE_EXTENSIONS)


def is_library_entry(name: str, container_extension: str) -> bool:
    """True when an entry is a shipped library rather than an incidental file that happens to be a zip."""
    if not is_java_archive_name(name):
        return False

    if name.startswith(LIBRARY_DIRECTORIES):
        return True

    # EAR modules are not confined to a lib directory; a WAR or JAR sits wherever application.xml points
    return container_extension == '.ear'


def is_metadata_entry(name: str) -> bool:
    """True for the embedded files identification reads in phase 2. Everything else is skipped unread."""
    if name.upper() == MANIFEST_ENTRY_NAME:
        return True

    parts = name.split('/')
    return (
        len(parts) == _MAVEN_METADATA_PATH_DEPTH
        and parts[0] == 'META-INF'
        and parts[1] == 'maven'
        and parts[4] in _MAVEN_METADATA_FILE_NAMES
    )


def compute_file_digest(path: str) -> str:
    """SHA-1 of a file on disk, streamed. Used to seed the cycle guard with the artifact we were pointed at."""
    # SHA-1 is identification, not security: it is the digest Maven Central and every artifact index key on, so
    # it is the only algorithm a coordinate lookup can use. usedforsecurity=False declares that intent to the
    # runtime and to ruff's S324. SHA-256 is emitted alongside it in the BOM for anyone who wants a strong digest.
    digest = hashlib.sha1(usedforsecurity=False)
    with open(path, 'rb') as handle:
        while True:
            chunk = handle.read(_READ_CHUNK_SIZE_IN_BYTES)
            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


class JavaArchiveExtractor(BinaryExtractor):
    """Reads a Java archive and everything shipped inside it, down to a bounded depth."""

    def __init__(
        self,
        limits: Optional[ArchiveLimits] = None,
        resolver: Optional[DigestResolver] = None,
        declared_resolver: Optional[DeclaredDependencyResolver] = None,
    ) -> None:
        self._limits = limits or ArchiveLimits()
        self._resolver = resolver or NullDigestResolver()
        # None means --include-declared was not given: embedded poms then contribute edges only, never components
        self._declared_resolver = declared_resolver

    def handles(self, path: str) -> bool:
        return is_java_archive_name(path)

    def extract(self, path: str, max_depth: int = consts.BINARY_MAX_DEPTH) -> list[ArchiveEntry]:
        """Walk the artifact, returning the archives it ships and the metadata needed to identify them.

        Class files and resources are never returned: they are not components, and carrying them would mean holding
        an entire deployable in memory to no purpose.
        """
        if not os.path.isfile(path):
            raise BinaryExtractionError(f'{path!r} is not a file.')

        root_name = os.path.basename(path)
        root_sha1 = compute_file_digest(path)
        root_entry = ArchiveEntry(
            logical_path=root_name,
            name=root_name,
            size=os.path.getsize(path),
            sha1=root_sha1,
            depth=0,
            parent=None,
            is_archive=True,
            was_opened=True,
        )

        entries = [root_entry]
        budget = ArchiveBudget(self._limits)
        visited_digests = {root_sha1}

        with SafeZip.open(path, budget=budget, source_name=root_name) as archive:
            self._walk(
                archive=archive,
                container_logical_path=root_name,
                container_extension=_extension_of(root_name),
                depth=1,
                max_depth=max_depth,
                budget=budget,
                visited_digests=visited_digests,
                entries=entries,
            )

        return entries

    def identify(self, entries: list[ArchiveEntry]) -> ExtractionResult:
        """Run the identification ladder over what extraction found.

        Tier 1 reads embedded Maven metadata, tier 2 resolves the digests tier 1 could not place, tier 3 falls back
        to manifest attributes, and whatever survives all three is reported as unidentified rather than guessed at.
        The first tier to produce coordinates wins and records itself in ``evidence``.
        """
        metadata_by_container = defaultdict(list)
        for entry in entries:
            if not entry.is_archive and entry.parent is not None:
                metadata_by_container[entry.parent].append(entry)

        archives = [entry for entry in entries if entry.is_archive]
        if not archives:
            return ExtractionResult(resolver_available=self._resolver.available)

        root = archives[0]
        shipped = [entry for entry in archives if entry.depth > 0]

        # a deployable is described by the BOM's metadata component and is never one of its own components. A jar
        # that ships nothing is a library, and a library is precisely the thing being assessed: it is a candidate
        # like any shipped jar, and failing to name it is a coverage gap that must be reported, not dropped. A
        # scan that cannot name the one archive it was pointed at and still claims full coverage is lying.
        candidates = shipped or ([root] if _is_library_root(root) else [])

        components, unidentified = self._run_identification_ladder(candidates, metadata_by_container)

        declared_unresolved: list[UnresolvedDeclaration] = []
        declared_keys_by_path: dict[str, set[str]] = {}
        transitive_edges: dict[str, set[str]] = {}
        if self._declared_resolver is not None:
            declared, declared_unresolved, declared_keys_by_path, transitive_edges = self._expand_declared(
                archives, components, metadata_by_container
            )
            components.extend(declared)

        edges, has_real_edges = self._build_dependency_graph(
            root, candidates, components, metadata_by_container, declared_keys_by_path, transitive_edges
        )

        return ExtractionResult(
            components=components,
            unidentified=unidentified,
            declared_unresolved=declared_unresolved,
            archives_opened=sum(1 for entry in entries if entry.was_opened),
            # expressed as a count of archives on the deepest chain, so it compares directly against --max-depth
            max_depth_reached=max((entry.depth for entry in entries if entry.is_archive), default=-1) + 1,
            resolver_available=self._resolver.available,
            resolver_unavailability_reason=None if self._resolver.available else self._resolver.unavailability_reason,
            dependency_edges=edges,
            has_real_edges=has_real_edges,
        )

    def _run_identification_ladder(
        self,
        candidates: list[ArchiveEntry],
        metadata_by_container: dict[str, list[ArchiveEntry]],
    ) -> tuple[list[IdentifiedComponent], list[UnidentifiedArtifact]]:
        components: list[IdentifiedComponent] = []

        # tier 1
        needs_resolution: list[ArchiveEntry] = []
        for archive in candidates:
            tier_one = self._identify_from_pom_properties(archive, metadata_by_container)
            if tier_one:
                components.extend(tier_one)
            else:
                needs_resolution.append(archive)

        # tier 2, as a single batch: every digest tier 1 could not place. The resolver is always asked; whether it
        # can still attempt a lookup after an earlier failure is its own state to keep, and gating on
        # ``available`` here would silently skip every artifact after the first one that hit trouble
        resolved: dict[str, str] = {}
        if needs_resolution:
            resolved = self._resolver.resolve([archive.sha1 for archive in needs_resolution])

        needs_manifest: list[ArchiveEntry] = []
        for archive in needs_resolution:
            coordinates = parse_maven_purl(resolved.get(archive.sha1))
            if coordinates:
                components.append(_component(archive, coordinates, EVIDENCE_DIGEST, CONFIDENCE_EXACT))
            else:
                needs_manifest.append(archive)

        # tier 3, then tier 4
        unidentified: list[UnidentifiedArtifact] = []
        for archive in needs_manifest:
            tier_three = self._identify_from_manifest(archive, metadata_by_container)
            if tier_three:
                components.append(tier_three)
            else:
                unidentified.append(
                    UnidentifiedArtifact(logical_path=archive.logical_path, sha1=archive.sha1, size=archive.size)
                )

        return components, unidentified

    def _identify_from_pom_properties(
        self,
        archive: ArchiveEntry,
        metadata_by_container: dict[str, list[ArchiveEntry]],
    ) -> list[IdentifiedComponent]:
        """Tier 1. A shaded jar aggregates several projects and carries a pom.properties for each, so all are kept."""
        components = []
        for entry in metadata_by_container.get(archive.logical_path, []):
            if entry.name != POM_PROPERTIES_FILE_NAME or entry.payload is None:
                continue

            coordinates = pom_properties.identify(entry.payload)
            if coordinates:
                components.append(_component(archive, coordinates, EVIDENCE_POM_PROPERTIES, CONFIDENCE_EXACT))

        return components

    def _identify_from_manifest(
        self,
        archive: ArchiveEntry,
        metadata_by_container: dict[str, list[ArchiveEntry]],
    ) -> Optional[IdentifiedComponent]:
        """Tier 3. Always ambiguous: a manifest names the jar but rarely its groupId."""
        for entry in metadata_by_container.get(archive.logical_path, []):
            if entry.name.upper() != MANIFEST_FILE_NAME or entry.payload is None:
                continue

            identity = manifest_mf.identify(entry.payload)
            if identity:
                return _component(archive, identity.coordinates, EVIDENCE_MANIFEST, CONFIDENCE_AMBIGUOUS)

        return None

    def _expand_declared(
        self,
        archives: list[ArchiveEntry],
        shipped: list[IdentifiedComponent],
        metadata_by_container: dict[str, list[ArchiveEntry]],
    ) -> tuple[list[IdentifiedComponent], list[UnresolvedDeclaration], dict[str, set[str]], dict[str, set[str]]]:
        """``--include-declared``: what every embedded pom says its component needs and did not ship.

        Every archive with a pom contributes, the deployable itself included: a war's pom that declares something
        absent from WEB-INF/lib is exactly the case a reader of this list wants to know about. A declared
        coordinate that is also physically present is not repeated -- the shipped component is the truth about
        it, whatever version the pom asked for -- so this only ever adds what a consumer would pull in unseen.

        The third result is every directly resolved coordinate key per archive, shipped or not, so the dependency
        graph can draw an edge for a dependency a parent pom declared on the jar's behalf: the jar's own pom never
        mentions it, but the jar depends on it all the same. The fourth is the edges among declared components
        themselves, requester key to transitive key, when transitives were expanded.
        """
        shipped_keys = {f'{component.group}:{component.artifact}' for component in shipped}
        declared: list[IdentifiedComponent] = []
        unresolved: list[UnresolvedDeclaration] = []
        keys_by_path: dict[str, set[str]] = defaultdict(set)
        transitive_edges: dict[str, set[str]] = defaultdict(set)

        for archive in archives:
            for entry in metadata_by_container.get(archive.logical_path, []):
                if entry.name != POM_XML_FILE_NAME or entry.payload is None:
                    continue

                resolution = self._declared_resolver.resolve(entry.payload)
                for dependency in resolution.dependencies:
                    if dependency.via is None:
                        keys_by_path[archive.logical_path].add(dependency.coordinate_key)
                    else:
                        transitive_edges[dependency.via].add(dependency.coordinate_key)

                    if dependency.coordinate_key in shipped_keys:
                        continue

                    declared.append(
                        IdentifiedComponent(
                            group=dependency.group,
                            artifact=dependency.artifact,
                            version=dependency.version,
                            sha1=None,
                            logical_path=entry.logical_path,
                            parent=archive.logical_path,
                            evidence=EVIDENCE_POM_XML,
                            confidence=CONFIDENCE_EXACT,
                            declared_scope=dependency.scope,
                            declared_via=dependency.via,
                        )
                    )

                unresolved.extend(
                    UnresolvedDeclaration(
                        group=item.group,
                        artifact=item.artifact,
                        version_expression=item.version_expression,
                        declared_by=entry.logical_path,
                        reason=item.reason,
                    )
                    for item in resolution.unresolved
                    if item.coordinate_key not in shipped_keys
                )

        return declared, unresolved, dict(keys_by_path), dict(transitive_edges)

    def _build_dependency_graph(
        self,
        root: ArchiveEntry,
        candidates: list[ArchiveEntry],
        components: list[IdentifiedComponent],
        metadata_by_container: dict[str, list[ArchiveEntry]],
        declared_keys_by_path: Optional[dict[str, set[str]]] = None,
        transitive_edges: Optional[dict[str, set[str]]] = None,
    ) -> tuple[dict[str, list[str]], bool]:
        """Containment as the base tree, with real edges from embedded poms overlaid on top.

        Where the two disagree the real edge wins and the containment edge is dropped, because a jar that is
        genuinely a transitive dependency of another is not a direct child of the application.
        """
        declared_keys_by_path = declared_keys_by_path or {}
        transitive_edges = transitive_edges or {}
        refs_by_path: dict[str, list[str]] = defaultdict(list)
        for component in components:
            refs_by_path[component.logical_path].append(component.purl)

        archive_by_path = {archive.logical_path: archive for archive in candidates}
        ref_by_coordinate = {f'{component.group}:{component.artifact}': component.purl for component in components}
        root_ref = root.name

        containment: dict[str, set] = defaultdict(set)
        for component in components:
            container = self._container_ref(component.parent, root, refs_by_path, archive_by_path, root_ref)
            if container != component.purl:
                containment[container].add(component.purl)

        # what each archive's pom (and, with --include-declared, its parents) says it depends on
        keys_by_source_ref: dict[str, set[str]] = defaultdict(set)
        for archive in candidates:
            source_refs = refs_by_path.get(archive.logical_path)
            if not source_refs:
                continue

            keys = {d.coordinate_key for d in self._declared_dependencies(archive, metadata_by_container)}
            keys |= declared_keys_by_path.get(archive.logical_path, set())
            keys_by_source_ref[source_refs[0]] |= keys

        # a transitive hangs off whichever component asked for it, shipped or declared
        for source_key, target_keys in transitive_edges.items():
            source_ref = ref_by_coordinate.get(source_key)
            if source_ref:
                keys_by_source_ref[source_ref] |= target_keys

        real = _resolve_edges(keys_by_source_ref, ref_by_coordinate)
        claimed = {target for targets in real.values() for target in targets}
        for targets in containment.values():
            targets -= claimed

        merged: dict[str, list[str]] = {}
        for ref in set(containment) | set(real):
            merged[ref] = sorted(containment.get(ref, set()) | real.get(ref, set()))

        return merged, bool(claimed)

    def _declared_dependencies(
        self,
        archive: ArchiveEntry,
        metadata_by_container: dict[str, list[ArchiveEntry]],
    ) -> list[pom_xml.MavenDependency]:
        dependencies = []
        for entry in metadata_by_container.get(archive.logical_path, []):
            if entry.name == POM_XML_FILE_NAME and entry.payload is not None:
                dependencies.extend(pom_xml.parse_dependencies(entry.payload))

        return dependencies

    def _container_ref(
        self,
        parent_path: Optional[str],
        root: ArchiveEntry,
        refs_by_path: dict[str, list[str]],
        archive_by_path: dict[str, ArchiveEntry],
        root_ref: str,
    ) -> str:
        """The nearest identified ancestor, falling back to the artifact itself.

        An unidentified intermediate jar must not break the chain: its children still shipped inside the artifact,
        so they attach to the nearest thing we can name.
        """
        current = parent_path
        while current and current != root.logical_path:
            refs = refs_by_path.get(current)
            if refs:
                return refs[0]

            ancestor = archive_by_path.get(current)
            current = ancestor.parent if ancestor else None

        return root_ref

    def _walk(
        self,
        archive: SafeZip,
        container_logical_path: str,
        container_extension: str,
        depth: int,
        max_depth: int,
        budget: ArchiveBudget,
        visited_digests: set[str],
        entries: list[ArchiveEntry],
    ) -> None:
        for entry in archive.entries():
            if is_library_entry(entry.name, container_extension):
                self._handle_nested_archive(
                    archive=archive,
                    entry=entry,
                    container_logical_path=container_logical_path,
                    depth=depth,
                    max_depth=max_depth,
                    budget=budget,
                    visited_digests=visited_digests,
                    entries=entries,
                )
            elif is_metadata_entry(entry.name):
                content = archive.read(entry)
                entries.append(
                    ArchiveEntry(
                        logical_path=join_logical_path(container_logical_path, entry.name),
                        name=os.path.basename(entry.name),
                        size=content.size,
                        sha1=content.sha1,
                        sha256=content.sha256,
                        depth=depth,
                        parent=container_logical_path,
                        payload=content.data,
                    )
                )

    def _handle_nested_archive(
        self,
        archive: SafeZip,
        entry: SafeZipEntry,
        container_logical_path: str,
        depth: int,
        max_depth: int,
        budget: ArchiveBudget,
        visited_digests: set[str],
        entries: list[ArchiveEntry],
    ) -> None:
        content = archive.read(entry)
        logical_path = join_logical_path(container_logical_path, entry.name)

        if depth >= max_depth:
            logger.debug('Not opening %s: depth limit of %s reached', logical_path, max_depth)
            should_open = False
        elif content.sha1 in visited_digests:
            logger.debug('Not opening %s: an archive with the same digest was already opened', logical_path)
            should_open = False
        else:
            should_open = True

        # the bytes are dropped once we have recursed: a component is identified by its digest and its metadata,
        # never by keeping the whole jar around
        entries.append(
            ArchiveEntry(
                logical_path=logical_path,
                name=os.path.basename(entry.name),
                size=content.size,
                sha1=content.sha1,
                sha256=content.sha256,
                depth=depth,
                parent=container_logical_path,
                is_archive=True,
                was_opened=should_open,
            )
        )

        if not should_open:
            return

        visited_digests.add(content.sha1)

        with SafeZip.open(content.data, budget=budget, source_name=entry.name) as nested:
            self._walk(
                archive=nested,
                container_logical_path=logical_path,
                container_extension=_extension_of(entry.name),
                depth=depth + 1,
                max_depth=max_depth,
                budget=budget,
                visited_digests=visited_digests,
                entries=entries,
            )


def _resolve_edges(keys_by_source_ref: dict[str, set[str]], ref_by_coordinate: dict[str, str]) -> dict[str, set]:
    """Coordinate keys to bom-refs, dropping anything that is not a known component or points at itself."""
    real: dict[str, set] = defaultdict(set)
    for source_ref, keys in keys_by_source_ref.items():
        for key in sorted(keys):
            target_ref = ref_by_coordinate.get(key)
            if target_ref and target_ref != source_ref:
                real[source_ref].add(target_ref)

    return real


def _is_library_root(root: ArchiveEntry) -> bool:
    """A ``.jar`` that ships no libraries is a library. A WAR or EAR is an application, whatever it contains."""
    return _extension_of(root.name) == '.jar'


def parse_maven_purl(purl: Optional[str]) -> Optional[MavenCoordinates]:
    """Read back a ``pkg:maven`` purl, as tier 2 returns them. The namespace is optional."""
    if not purl or not purl.startswith(_MAVEN_PURL_PREFIX):
        return None

    remainder = purl[len(_MAVEN_PURL_PREFIX) :].split('?')[0].split('#')[0]
    coordinates, separator, version = remainder.rpartition('@')
    if not separator or not version or not coordinates:
        return None

    group, _, artifact = coordinates.rpartition('/')
    if not artifact:
        return None

    return MavenCoordinates(group=group, artifact=artifact, version=version)


def _component(
    archive: ArchiveEntry,
    coordinates: MavenCoordinates,
    evidence: str,
    confidence: str,
) -> IdentifiedComponent:
    return IdentifiedComponent(
        group=coordinates.group,
        artifact=coordinates.artifact,
        version=coordinates.version,
        sha1=archive.sha1,
        sha256=archive.sha256,
        logical_path=archive.logical_path,
        parent=archive.parent,
        evidence=evidence,
        confidence=confidence,
    )


def _extension_of(name: str) -> str:
    return os.path.splitext(name)[1].lower()
