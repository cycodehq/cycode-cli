"""``--include-declared``: what an embedded pom says its component needs, resolved the way Maven would read it.

A binary scan reports what is physically packaged. That is the right default, but it is not the only question a
reader asks of a vendor jar: a consumer who builds against it inherits its compile- and runtime-scope dependencies
whether or not the vendor shipped them, and a vulnerability in one of those is real in the consumer's build.
This module answers that second question from the same embedded metadata, and it is honest about the limits.

Versions in a real pom are rarely literal. They come from ``<properties>``, from ``${project.version}``, from a
parent's ``<dependencyManagement>`` several levels up, or from an imported BOM. Resolving them means walking the
parent chain, which lives on Maven Central and not inside the jar, so the walk is behind a ``PomSource`` seam: a
no-op source resolves whatever the pom itself can answer and reports the rest as unresolved with the reason, and
the Maven Central source fetches the chain. Nothing here guesses: a dependency whose version cannot be established
is listed, not invented, and a dependency Maven would not hand to a consumer -- test, provided, optional -- is left
out, because the point is what will actually be in the consumer's build.

Transitive dependencies of the declared ones are expanded only when asked (``--include-transitive``), and only
with a real pom source: every hop is another pom fetched from Maven Central. The walk follows Maven's rules where
they are mechanical -- nearest declaration wins, exclusions apply down the branch, optional dependencies stop, scope
is mapped the way Maven maps it for a transitive -- and refuses to guess where they are not: a version range, or a
version that only a repository's metadata could pin, is listed as unresolved rather than picked.
"""

import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from cycode.cli import consts
from cycode.cli.files_collector.binary.identifiers import pom_xml
from cycode.cli.files_collector.binary.identifiers.pom_xml import ParentReference, PomDependency, PomModel

logger = logging.getLogger(__name__)

# the scopes Maven propagates to a consumer's build; everything else stays with the producer
PROPAGATED_SCOPES = frozenset({pom_xml.SCOPE_COMPILE, pom_xml.SCOPE_RUNTIME})
# every scope a dependency can be declared with; --include-test-scope reports all of them, as some SCA tools do
ALL_SCOPES = PROPAGATED_SCOPES | frozenset({'test', 'provided', 'system'})

_PROPERTY_PATTERN = re.compile(r'\$\{([^}]+)\}')
_MAX_INTERPOLATION_DEPTH = 10

# a group, artifact or version that will be put into a URL must be a plain Maven coordinate segment
COORDINATE_SEGMENT = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*$')

REASON_NO_VERSION = 'no version declared or managed'

# how a transitive's own scope combines with the scope it was reached through (the Maven scope table). Absent
# combinations are dropped: a provided or test dependency is never handed further down the tree
_TRANSITIVE_SCOPE = {
    (pom_xml.SCOPE_COMPILE, pom_xml.SCOPE_COMPILE): pom_xml.SCOPE_COMPILE,
    (pom_xml.SCOPE_COMPILE, pom_xml.SCOPE_RUNTIME): pom_xml.SCOPE_RUNTIME,
    (pom_xml.SCOPE_RUNTIME, pom_xml.SCOPE_COMPILE): pom_xml.SCOPE_RUNTIME,
    (pom_xml.SCOPE_RUNTIME, pom_xml.SCOPE_RUNTIME): pom_xml.SCOPE_RUNTIME,
    ('provided', pom_xml.SCOPE_COMPILE): 'provided',
    ('provided', pom_xml.SCOPE_RUNTIME): 'provided',
    ('test', pom_xml.SCOPE_COMPILE): 'test',
    ('test', pom_xml.SCOPE_RUNTIME): 'test',
}
REASON_VERSION_RANGE = 'version is a range; only a repository lookup can pin it'
REASON_PARENT_COORDINATES = 'parent coordinates could not be resolved'


@dataclass(frozen=True)
class DeclaredDependency:
    group: str
    artifact: str
    version: str
    scope: str
    via: Optional[str] = None  # the 'group:artifact' that pulled this in; None for a direct declaration
    depth: int = 1  # 1 = declared directly by the pom, 2 = needed by one of those, and so on

    @property
    def coordinate_key(self) -> str:
        return f'{self.group}:{self.artifact}'

    @property
    def is_transitive(self) -> bool:
        return self.via is not None


@dataclass(frozen=True)
class UnresolvedDependency:
    group: str
    artifact: str
    version_expression: Optional[str]  # what the pom wrote, e.g. '${jetty.version}', or None
    reason: str
    via: Optional[str] = None

    @property
    def coordinate_key(self) -> str:
        return f'{self.group}:{self.artifact}'


@dataclass
class DeclaredResolution:
    dependencies: list[DeclaredDependency] = field(default_factory=list)
    unresolved: list[UnresolvedDependency] = field(default_factory=list)


@dataclass(frozen=True)
class PomFetch:
    """What a source has to say about one coordinate: the bytes, or one sentence on why there are none."""

    payload: Optional[bytes] = None
    failure: Optional[str] = None


class PomSource(ABC):
    @abstractmethod
    def fetch(self, group: str, artifact: str, version: str) -> PomFetch:
        """Never raises. A miss and a transport failure are both a ``failure`` with a reason."""


class NullPomSource(PomSource):
    """The default: nothing about the artifact leaves the machine, and parents are simply not consulted."""

    def fetch(self, group: str, artifact: str, version: str) -> PomFetch:
        return PomFetch(failure=f'{group}:{artifact}:{version} not consulted without --maven-central')


def is_safe_coordinate(group: str, artifact: str, version: str) -> bool:
    """A coordinate read out of an untrusted pom must not be able to shape a URL path."""
    return all(COORDINATE_SEGMENT.match(part) and '..' not in part for part in (group, artifact, version))


@dataclass
class _Managed:
    version: Optional[str]
    scope: Optional[str]


@dataclass
class _EffectiveModel:
    """The pom with its parent chain folded in: merged properties and dependency management, and the inherited
    coordinates. ``incomplete`` names the first pom in the chain that could not be read, if any."""

    properties: dict[str, str]
    managed: dict[str, _Managed]
    dependencies: list[PomDependency]
    incomplete: Optional[str] = None


class DeclaredDependencyResolver:
    """Resolves one embedded pom's direct dependencies to exact coordinates.

    One resolver serves a whole run. Parent poms are cached by coordinate, so a deployable whose forty jars all
    descend from ``org.apache:apache`` fetches that pom once, and the fetch budget is per embedded pom rather than
    per run so one pathological chain cannot starve the rest.
    """

    def __init__(
        self,
        source: Optional[PomSource] = None,
        fetch_budget: int = consts.BINARY_POM_FETCH_BUDGET,
        max_parent_depth: int = consts.BINARY_POM_PARENT_MAX_DEPTH,
        scopes: frozenset = PROPAGATED_SCOPES,
        transitive: bool = False,
        max_transitive_depth: int = consts.BINARY_TRANSITIVE_MAX_DEPTH,
    ) -> None:
        self._source = source or NullPomSource()
        self._fetch_budget = fetch_budget
        self._max_parent_depth = max_parent_depth
        self._scopes = scopes
        self._transitive = transitive
        self._max_transitive_depth = max_transitive_depth
        self._cache: dict[str, tuple[Optional[PomModel], Optional[str]]] = {}

    def resolve(self, payload: bytes) -> DeclaredResolution:
        model = pom_xml.parse_model(payload)
        if model is None:
            return DeclaredResolution()

        budget = _Budget(self._fetch_budget)
        effective = self._effective_model(model, budget, visited=set())

        resolution = DeclaredResolution()
        chosen: dict[str, DeclaredDependency] = {}
        frontier: list[tuple[DeclaredDependency, frozenset]] = []
        for dependency in effective.dependencies:
            resolved = self._resolve_one(dependency, effective, resolution, chosen, via=None, depth=1)
            if resolved is not None and resolved.scope in self._scopes:
                frontier.append((resolved, dependency.exclusions))

        if self._transitive:
            self._expand(frontier, effective, budget, resolution, chosen)

        # a transitive reached through a scope the caller did not ask for is dropped here, after mediation, so
        # that a test-scope declaration still claims its coordinate the way it would in Maven
        resolution.dependencies = [d for d in resolution.dependencies if d.scope in self._scopes]
        return resolution

    def _resolve_one(
        self,
        dependency: PomDependency,
        effective: _EffectiveModel,
        resolution: DeclaredResolution,
        chosen: dict[str, DeclaredDependency],
        via: Optional[str],
        depth: int,
        root: Optional[_EffectiveModel] = None,
        reached_through: Optional[str] = None,
    ) -> Optional[DeclaredDependency]:
        """One dependency element to one coordinate, or None when Maven would not hand it on.

        ``root`` is the embedded pom's own effective model, whose dependency management overrides the version of
        anything reached transitively, exactly as it does in a Maven build. ``reached_through`` is the scope the
        requester was itself reached with, which decides what scope this one ends up in.
        """
        group = self._interpolate(dependency.group, effective.properties)
        artifact = self._interpolate(dependency.artifact, effective.properties)
        key = f'{group}:{artifact}'
        if key in chosen or dependency.optional or dependency.type == pom_xml.TYPE_POM:
            return None

        managed = effective.managed.get(key)
        root_managed = root.managed.get(key) if root is not None else None

        scope = dependency.scope or (managed.scope if managed else None) or pom_xml.SCOPE_COMPILE
        if reached_through is not None:
            scope = _TRANSITIVE_SCOPE.get((reached_through, scope))
            if scope is None:
                return None

        # the root pom's management wins over anything a transitive pom says about itself
        expression = (
            (root_managed.version if root_managed else None)
            or dependency.version
            or (managed.version if managed else None)
        )
        if expression is None:
            reason = REASON_NO_VERSION
            if effective.incomplete:
                reason = f'{reason}; {effective.incomplete}'

            resolution.unresolved.append(UnresolvedDependency(group, artifact, None, reason, via))
            return None

        properties = root.properties if root_managed else effective.properties
        version = self._interpolate(expression, properties)
        if _PROPERTY_PATTERN.search(version):
            reason = f'property {version} is not defined'
            if effective.incomplete:
                reason = f'{reason}; {effective.incomplete}'

            resolution.unresolved.append(UnresolvedDependency(group, artifact, expression, reason, via))
            return None

        if version[0] in '[(':
            resolution.unresolved.append(UnresolvedDependency(group, artifact, expression, REASON_VERSION_RANGE, via))
            return None

        resolved = DeclaredDependency(group, artifact, version, scope, via=via, depth=depth)
        chosen[key] = resolved
        resolution.dependencies.append(resolved)
        return resolved

    def _expand(
        self,
        frontier: list[tuple[DeclaredDependency, frozenset]],
        root: _EffectiveModel,
        budget: '_Budget',
        resolution: DeclaredResolution,
        chosen: dict[str, DeclaredDependency],
    ) -> None:
        """Breadth-first over the declared dependencies' own poms, so the nearest declaration of a coordinate is
        the one that wins, as in Maven. Exclusions accumulate down a branch and never apply across branches."""
        queue = list(frontier)
        while queue:
            requester, exclusions = queue.pop(0)
            if requester.depth >= self._max_transitive_depth:
                continue

            reference = ParentReference(requester.group, requester.artifact, requester.version)
            model, failure = self._fetch_model(reference, budget)
            if model is None:
                resolution.unresolved.append(
                    UnresolvedDependency(
                        requester.group,
                        requester.artifact,
                        requester.version,
                        f'its own dependencies are unknown: {failure}',
                        via=requester.via,
                    )
                )
                continue

            effective = self._effective_model(model, budget, visited={reference.coordinate})
            for dependency in effective.dependencies:
                if _is_excluded(dependency, exclusions):
                    continue

                resolved = self._resolve_one(
                    dependency,
                    effective,
                    resolution,
                    chosen,
                    via=requester.coordinate_key,
                    depth=requester.depth + 1,
                    root=root,
                    reached_through=requester.scope,
                )
                if resolved is not None:
                    queue.append((resolved, exclusions | dependency.exclusions))

    def _effective_model(self, model: PomModel, budget: '_Budget', visited: set[str]) -> _EffectiveModel:
        chain, incomplete = self._parent_chain(model, budget, visited)

        # properties: the child overrides the parent, so fold the chain in from the top down
        properties: dict[str, str] = {}
        for pom in reversed(chain):
            properties.update(pom.properties)

        properties.update(self._project_properties(chain))

        # dependency management: an explicit entry anywhere in the chain beats an imported one, and nearer wins
        managed: dict[str, _Managed] = {}
        imports: list[tuple[PomDependency, dict[str, str]]] = []
        for pom in chain:
            for entry in pom.dependency_management:
                if entry.scope == pom_xml.SCOPE_IMPORT and entry.type == pom_xml.TYPE_POM:
                    imports.append((entry, properties))
                else:
                    managed.setdefault(entry.coordinate_key, _Managed(entry.version, entry.scope))

        for entry, scope_properties in imports:
            imported, failure = self._imported_management(entry, scope_properties, budget, visited)
            incomplete = incomplete or failure
            for key, value in imported.items():
                managed.setdefault(key, value)

        # a parent's <dependencies> are inherited by every child; the child's own declaration wins on a clash
        dependencies: list[PomDependency] = []
        seen: set[str] = set()
        for pom in chain:
            for dependency in pom.dependencies:
                if dependency.coordinate_key not in seen:
                    seen.add(dependency.coordinate_key)
                    dependencies.append(dependency)

        return _EffectiveModel(properties, managed, dependencies, incomplete)

    def _parent_chain(
        self, model: PomModel, budget: '_Budget', visited: set[str]
    ) -> tuple[list[PomModel], Optional[str]]:
        chain = [model]
        current = model
        for _ in range(self._max_parent_depth):
            if current.parent is None:
                return chain, None

            # a parent version is occasionally a property of the child, as in the CI-friendly ${revision} idiom
            reference = self._interpolated_parent(current)
            if reference is None:
                return chain, f'{REASON_PARENT_COORDINATES}: {current.parent.coordinate}'

            if reference.coordinate in visited:
                return chain, f'parent chain loops at {reference.coordinate}'

            visited.add(reference.coordinate)
            parent, failure = self._fetch_model(reference, budget)
            if parent is None:
                return chain, failure

            chain.append(parent)
            current = parent

        return chain, f'parent chain is deeper than {self._max_parent_depth}'

    def _imported_management(
        self,
        entry: PomDependency,
        properties: dict[str, str],
        budget: '_Budget',
        visited: set[str],
    ) -> tuple[dict[str, _Managed], Optional[str]]:
        group = self._interpolate(entry.group, properties)
        artifact = self._interpolate(entry.artifact, properties)
        version = self._interpolate(entry.version or '', properties)
        if not version or _PROPERTY_PATTERN.search(version):
            return {}, f'imported BOM {group}:{artifact} has no resolvable version'

        reference = ParentReference(group, artifact, version)
        if reference.coordinate in visited:
            return {}, None

        visited.add(reference.coordinate)
        bom, failure = self._fetch_model(reference, budget)
        if bom is None:
            return {}, failure

        # a BOM is a pom like any other: its own parents and imports contribute to what it manages
        effective = self._effective_model(bom, budget, visited)
        managed = {
            key: _Managed(self._interpolate(value.version or '', effective.properties) or None, value.scope)
            for key, value in effective.managed.items()
        }
        return managed, effective.incomplete

    def _fetch_model(self, reference: ParentReference, budget: '_Budget') -> tuple[Optional[PomModel], Optional[str]]:
        if reference.coordinate in self._cache:
            return self._cache[reference.coordinate]

        if not is_safe_coordinate(reference.group, reference.artifact, reference.version):
            outcome = (None, f'{reference.coordinate} is not a valid Maven coordinate')
        elif not budget.take():
            # not cached: another pom's budget may still afford it
            return None, f'parent chain needs more than {self._fetch_budget} poms'
        else:
            fetched = self._source.fetch(reference.group, reference.artifact, reference.version)
            if fetched.payload is None:
                outcome = (None, fetched.failure or f'{reference.coordinate} could not be fetched')
            else:
                model = pom_xml.parse_model(fetched.payload)
                outcome = (model, None if model else f'{reference.coordinate} is not a readable pom')

        self._cache[reference.coordinate] = outcome
        return outcome

    def _interpolated_parent(self, model: PomModel) -> Optional[ParentReference]:
        if model.parent is None:
            return None

        properties = dict(model.properties)
        properties.update(self._project_properties([model]))

        parts = [
            self._interpolate(value, properties)
            for value in (model.parent.group, model.parent.artifact, model.parent.version)
        ]
        if any(_PROPERTY_PATTERN.search(part) for part in parts):
            return None

        return ParentReference(*parts)

    @staticmethod
    def _project_properties(chain: list[PomModel]) -> dict[str, str]:
        """``${project.version}`` and friends, with coordinates inherited from the parent where the pom omits them."""
        model = chain[0]
        parent = model.parent

        group = model.group or (parent.group if parent else None)
        version = model.version or (parent.version if parent else None)

        properties: dict[str, str] = {}
        for prefix in ('project.', 'pom.', ''):
            if group:
                properties[f'{prefix}groupId'] = group
            if model.artifact:
                properties[f'{prefix}artifactId'] = model.artifact
            if version:
                properties[f'{prefix}version'] = version

        if parent:
            for prefix in ('project.parent.', 'parent.'):
                properties[f'{prefix}groupId'] = parent.group
                properties[f'{prefix}artifactId'] = parent.artifact
                properties[f'{prefix}version'] = parent.version

        return properties

    @staticmethod
    def _interpolate(value: str, properties: dict[str, str]) -> str:
        """Expand ``${name}`` references, recursively and boundedly. An unknown reference is left as written."""
        for _ in range(_MAX_INTERPOLATION_DEPTH):
            expanded = _PROPERTY_PATTERN.sub(lambda match: properties.get(match.group(1), match.group(0)), value)
            if expanded == value:
                break

            value = expanded

        return value.strip()


def _is_excluded(dependency: PomDependency, exclusions: frozenset) -> bool:
    return bool(exclusions) and any(
        pattern in exclusions
        for pattern in (
            f'{dependency.group}:{dependency.artifact}',
            f'{dependency.group}:*',
            f'*:{dependency.artifact}',
            '*:*',
        )
    )


class _Budget:
    def __init__(self, limit: int) -> None:
        self._remaining = limit

    def take(self) -> bool:
        if self._remaining <= 0:
            return False

        self._remaining -= 1
        return True
