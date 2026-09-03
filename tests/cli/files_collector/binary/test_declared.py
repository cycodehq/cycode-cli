"""``DeclaredDependencyResolver``: an embedded pom's direct dependencies, resolved the way Maven would read them.

The pom source is an in-memory dictionary. Nothing here touches the network; the Maven Central source has its own
tests against a mocked repository.
"""

from typing import Optional

import pytest

from cycode.cli.files_collector.binary.declared import (
    ALL_SCOPES,
    REASON_NO_VERSION,
    REASON_VERSION_RANGE,
    DeclaredDependency,
    DeclaredDependencyResolver,
    NullPomSource,
    PomFetch,
    PomSource,
    is_safe_coordinate,
)

_NS = 'http://maven.apache.org/POM/4.0.0'


def _pom(
    coordinates: Optional[tuple[str, str, str]] = ('com.acme', 'widget', '1.0'),
    parent: Optional[tuple[str, str, str]] = None,
    properties: Optional[dict[str, str]] = None,
    managed: str = '',
    dependencies: str = '',
) -> bytes:
    """A pom from its parts. ``managed`` and ``dependencies`` are raw ``<dependency>`` elements."""
    parts = [f'<?xml version="1.0"?><project xmlns="{_NS}"><modelVersion>4.0.0</modelVersion>']
    if parent:
        parts.append(
            f'<parent><groupId>{parent[0]}</groupId><artifactId>{parent[1]}</artifactId>'
            f'<version>{parent[2]}</version></parent>'
        )
    if coordinates:
        group, artifact, version = coordinates
        if group:
            parts.append(f'<groupId>{group}</groupId>')
        parts.append(f'<artifactId>{artifact}</artifactId>')
        if version:
            parts.append(f'<version>{version}</version>')
    if properties:
        parts.append('<properties>' + ''.join(f'<{k}>{v}</{k}>' for k, v in properties.items()) + '</properties>')
    if managed:
        parts.append(f'<dependencyManagement><dependencies>{managed}</dependencies></dependencyManagement>')
    if dependencies:
        parts.append(f'<dependencies>{dependencies}</dependencies>')
    parts.append('</project>')
    return ''.join(parts).encode()


def _dep(
    group: str,
    artifact: str,
    version: Optional[str] = None,
    scope: Optional[str] = None,
    optional: bool = False,
    type_: Optional[str] = None,
) -> str:
    body = f'<groupId>{group}</groupId><artifactId>{artifact}</artifactId>'
    if version:
        body += f'<version>{version}</version>'
    if scope:
        body += f'<scope>{scope}</scope>'
    if optional:
        body += '<optional>true</optional>'
    if type_:
        body += f'<type>{type_}</type>'
    return f'<dependency>{body}</dependency>'


class _DictSource(PomSource):
    def __init__(self, poms: Optional[dict[str, bytes]] = None) -> None:
        self.poms = poms or {}
        self.fetched: list[str] = []

    def fetch(self, group: str, artifact: str, version: str) -> PomFetch:
        coordinate = f'{group}:{artifact}:{version}'
        self.fetched.append(coordinate)
        payload = self.poms.get(coordinate)
        if payload is None:
            return PomFetch(failure=f'{coordinate} is not on the test repository')

        return PomFetch(payload=payload)


def _resolve(payload: bytes, source: Optional[PomSource] = None, **kwargs: int) -> tuple[list, list]:
    resolution = DeclaredDependencyResolver(source or NullPomSource(), **kwargs).resolve(payload)
    return resolution.dependencies, resolution.unresolved


def _coordinates(dependencies: list[DeclaredDependency]) -> list[str]:
    return [f'{d.group}:{d.artifact}:{d.version}' for d in dependencies]


class TestWithoutAParentSource:
    def test_a_literal_version_resolves(self) -> None:
        dependencies, unresolved = _resolve(_pom(dependencies=_dep('org.slf4j', 'slf4j-api', '1.7.36')))

        assert _coordinates(dependencies) == ['org.slf4j:slf4j-api:1.7.36']
        assert dependencies[0].scope == 'compile'
        assert unresolved == []

    def test_a_property_defined_by_the_pom_resolves(self) -> None:
        payload = _pom(
            properties={'slf4j.version': '1.7.36'},
            dependencies=_dep('org.slf4j', 'slf4j-api', '${slf4j.version}'),
        )

        dependencies, unresolved = _resolve(payload)

        assert _coordinates(dependencies) == ['org.slf4j:slf4j-api:1.7.36']
        assert unresolved == []

    def test_properties_chain(self) -> None:
        payload = _pom(
            properties={'base': '2.18', 'jackson.version': '${base}.3'},
            dependencies=_dep('com.fasterxml.jackson.core', 'jackson-core', '${jackson.version}'),
        )

        dependencies, _ = _resolve(payload)

        assert _coordinates(dependencies) == ['com.fasterxml.jackson.core:jackson-core:2.18.3']

    @pytest.mark.parametrize('expression', ['${project.version}', '${pom.version}', '${version}'])
    def test_the_project_version_is_a_property(self, expression: str) -> None:
        payload = _pom(
            coordinates=('com.acme', 'widget', '3.1'),
            dependencies=_dep('com.acme', 'widget-core', expression),
        )

        dependencies, _ = _resolve(payload)

        assert _coordinates(dependencies) == ['com.acme:widget-core:3.1']

    def test_the_project_version_is_inherited_from_the_parent_reference(self) -> None:
        # a module pom that omits its own version takes the parent's, and the reference is right there in the pom
        payload = _pom(
            coordinates=('', 'widget', ''),
            parent=('com.acme', 'widget-parent', '3.1'),
            dependencies=_dep('${project.groupId}', 'widget-core', '${project.version}'),
        )

        dependencies, _ = _resolve(payload)

        assert _coordinates(dependencies) == ['com.acme:widget-core:3.1']

    def test_a_version_managed_by_the_pom_itself_resolves(self) -> None:
        payload = _pom(
            managed=_dep('org.slf4j', 'slf4j-api', '1.7.36'),
            dependencies=_dep('org.slf4j', 'slf4j-api'),
        )

        dependencies, _ = _resolve(payload)

        assert _coordinates(dependencies) == ['org.slf4j:slf4j-api:1.7.36']

    def test_a_parent_managed_version_is_unresolved_and_says_why(self) -> None:
        payload = _pom(
            parent=('org.apache', 'apache', '30'),
            dependencies=_dep('commons-codec', 'commons-codec'),
        )

        dependencies, unresolved = _resolve(payload)

        assert dependencies == []
        assert len(unresolved) == 1
        assert unresolved[0].coordinate_key == 'commons-codec:commons-codec'
        assert unresolved[0].version_expression is None
        assert unresolved[0].reason.startswith(REASON_NO_VERSION)
        assert 'org.apache:apache:30 not consulted without --maven-central' in unresolved[0].reason

    def test_an_undefined_property_is_unresolved_with_the_expression(self) -> None:
        payload = _pom(dependencies=_dep('org.eclipse.jetty', 'jetty-server', '${jetty.version}'))

        dependencies, unresolved = _resolve(payload)

        assert dependencies == []
        assert unresolved[0].version_expression == '${jetty.version}'
        assert 'property ${jetty.version} is not defined' in unresolved[0].reason

    @pytest.mark.parametrize('expression', ['[1.0,2.0)', '(,1.0]', '[1.5]'])
    def test_a_version_range_is_not_guessed_at(self, expression: str) -> None:
        payload = _pom(dependencies=_dep('a', 'b', expression))

        dependencies, unresolved = _resolve(payload)

        assert dependencies == []
        assert unresolved[0].reason == REASON_VERSION_RANGE


class TestWhatMavenHandsToAConsumer:
    @pytest.mark.parametrize('scope', ['test', 'provided', 'system', 'import'])
    def test_scopes_that_do_not_propagate_are_left_out(self, scope: str) -> None:
        payload = _pom(dependencies=_dep('junit', 'junit', '4.12', scope=scope))

        dependencies, unresolved = _resolve(payload)

        assert dependencies == []
        # not a failure to resolve; the consumer simply never sees it, so it is not listed anywhere
        assert unresolved == []

    @pytest.mark.parametrize('scope', ['test', 'provided', 'system'])
    def test_every_scope_is_reported_when_asked_and_the_scope_is_kept(self, scope: str) -> None:
        payload = _pom(dependencies=_dep('junit', 'junit', '4.12', scope=scope))

        resolution = DeclaredDependencyResolver(NullPomSource(), scopes=ALL_SCOPES).resolve(payload)

        assert _coordinates(resolution.dependencies) == ['junit:junit:4.12']
        assert resolution.dependencies[0].scope == scope

    def test_import_scope_is_never_a_library_even_with_every_scope(self) -> None:
        payload = _pom(dependencies=_dep('g', 'bom', '1', scope='import', type_='pom'))

        resolution = DeclaredDependencyResolver(NullPomSource(), scopes=ALL_SCOPES).resolve(payload)

        assert resolution.dependencies == []

    def test_optional_stays_excluded_with_every_scope(self) -> None:
        payload = _pom(dependencies=_dep('a', 'b', '1', optional=True))

        resolution = DeclaredDependencyResolver(NullPomSource(), scopes=ALL_SCOPES).resolve(payload)

        assert resolution.dependencies == []

    def test_runtime_scope_propagates_and_is_recorded(self) -> None:
        payload = _pom(dependencies=_dep('com.fasterxml.woodstox', 'woodstox-core', '6.5.1', scope='runtime'))

        dependencies, _ = _resolve(payload)

        assert dependencies[0].scope == 'runtime'

    def test_scope_is_case_insensitive(self) -> None:
        payload = _pom(dependencies=_dep('junit', 'junit', '4.12', scope='TEST'))

        assert _resolve(payload) == ([], [])

    def test_an_optional_dependency_is_left_out(self) -> None:
        payload = _pom(dependencies=_dep('com.google.guava', 'guava', '31.1-jre', optional=True))

        assert _resolve(payload) == ([], [])

    def test_a_pom_typed_dependency_is_not_a_library(self) -> None:
        payload = _pom(dependencies=_dep('org.springframework.boot', 'spring-boot-dependencies', '2.5.0', type_='pom'))

        assert _resolve(payload) == ([], [])

    def test_a_managed_scope_applies_to_a_dependency_that_declares_none(self) -> None:
        payload = _pom(
            managed=_dep('junit', 'junit', '4.12', scope='test'),
            dependencies=_dep('junit', 'junit'),
        )

        assert _resolve(payload) == ([], [])

    def test_a_repeated_coordinate_is_reported_once(self) -> None:
        payload = _pom(dependencies=_dep('a', 'b', '1') + _dep('a', 'b', '2'))

        dependencies, _ = _resolve(payload)

        assert _coordinates(dependencies) == ['a:b:1']

    def test_an_unreadable_pom_declares_nothing(self) -> None:
        assert _resolve(b'<!DOCTYPE x><project/>') == ([], [])
        assert _resolve(b'<project><dependencies>') == ([], [])


class TestWithAParentSource:
    _APACHE = ('org.apache', 'apache', '30')
    _WODEN = ('org.apache.woden', 'woden', '1.0M10')

    def test_a_parent_managed_version_resolves(self) -> None:
        source = _DictSource(
            {
                'org.apache.woden:woden:1.0M10': _pom(
                    coordinates=self._WODEN,
                    managed=_dep('commons-logging', 'commons-logging', '1.1.1'),
                )
            }
        )
        payload = _pom(parent=self._WODEN, dependencies=_dep('commons-logging', 'commons-logging'))

        dependencies, unresolved = _resolve(payload, source)

        assert _coordinates(dependencies) == ['commons-logging:commons-logging:1.1.1']
        assert unresolved == []

    def test_a_property_defined_by_a_grandparent_resolves(self) -> None:
        source = _DictSource(
            {
                'org.apache:apache:30': _pom(coordinates=self._APACHE, properties={'codec.version': '1.15'}),
                'org.apache.woden:woden:1.0M10': _pom(coordinates=self._WODEN, parent=self._APACHE),
            }
        )
        payload = _pom(parent=self._WODEN, dependencies=_dep('commons-codec', 'commons-codec', '${codec.version}'))

        dependencies, _ = _resolve(payload, source)

        assert _coordinates(dependencies) == ['commons-codec:commons-codec:1.15']
        assert source.fetched == ['org.apache.woden:woden:1.0M10', 'org.apache:apache:30']

    def test_the_child_overrides_a_parent_property(self) -> None:
        source = _DictSource({'org.apache:apache:30': _pom(coordinates=self._APACHE, properties={'v': '1'})})
        payload = _pom(parent=self._APACHE, properties={'v': '2'}, dependencies=_dep('a', 'b', '${v}'))

        dependencies, _ = _resolve(payload, source)

        assert _coordinates(dependencies) == ['a:b:2']

    def test_the_nearest_managed_version_wins(self) -> None:
        source = _DictSource(
            {
                'org.apache:apache:30': _pom(coordinates=self._APACHE, managed=_dep('a', 'b', '1')),
                'org.apache.woden:woden:1.0M10': _pom(
                    coordinates=self._WODEN, parent=self._APACHE, managed=_dep('a', 'b', '2')
                ),
            }
        )
        payload = _pom(parent=self._WODEN, dependencies=_dep('a', 'b'))

        dependencies, _ = _resolve(payload, source)

        assert _coordinates(dependencies) == ['a:b:2']

    def test_a_parent_declares_dependencies_on_the_child_behalf(self) -> None:
        # jackson-dataformats-text declares jackson-core for every module; the module's own pom never mentions it
        source = _DictSource(
            {
                'com.fasterxml.jackson.dataformat:jackson-dataformats-text:2.18.3': _pom(
                    coordinates=('com.fasterxml.jackson.dataformat', 'jackson-dataformats-text', '2.18.3'),
                    properties={'jackson.version': '2.18.3'},
                    dependencies=_dep('com.fasterxml.jackson.core', 'jackson-core', '${jackson.version}'),
                )
            }
        )
        payload = _pom(
            parent=('com.fasterxml.jackson.dataformat', 'jackson-dataformats-text', '2.18.3'),
            dependencies=_dep('com.fasterxml.jackson.core', 'jackson-databind', '2.18.3'),
        )

        dependencies, _ = _resolve(payload, source)

        assert _coordinates(dependencies) == [
            'com.fasterxml.jackson.core:jackson-databind:2.18.3',
            'com.fasterxml.jackson.core:jackson-core:2.18.3',
        ]

    def test_an_imported_bom_manages_versions(self) -> None:
        source = _DictSource(
            {
                'com.fasterxml.jackson:jackson-bom:2.18.3': _pom(
                    coordinates=('com.fasterxml.jackson', 'jackson-bom', '2.18.3'),
                    managed=_dep('com.fasterxml.jackson.core', 'jackson-databind', '2.18.3'),
                )
            }
        )
        payload = _pom(
            managed=_dep('com.fasterxml.jackson', 'jackson-bom', '2.18.3', scope='import', type_='pom'),
            dependencies=_dep('com.fasterxml.jackson.core', 'jackson-databind'),
        )

        dependencies, _ = _resolve(payload, source)

        assert _coordinates(dependencies) == ['com.fasterxml.jackson.core:jackson-databind:2.18.3']

    def test_an_explicit_managed_entry_beats_an_imported_one(self) -> None:
        source = _DictSource(
            {'g:bom:1': _pom(coordinates=('g', 'bom', '1'), managed=_dep('a', 'b', 'from-bom'))},
        )
        payload = _pom(
            managed=_dep('g', 'bom', '1', scope='import', type_='pom') + _dep('a', 'b', 'explicit'),
            dependencies=_dep('a', 'b'),
        )

        dependencies, _ = _resolve(payload, source)

        assert _coordinates(dependencies) == ['a:b:explicit']

    def test_a_bom_version_interpolated_inside_the_bom_resolves(self) -> None:
        source = _DictSource(
            {
                'g:bom:1': _pom(
                    coordinates=('g', 'bom', '1'),
                    properties={'b.version': '7'},
                    managed=_dep('a', 'b', '${b.version}'),
                )
            },
        )
        payload = _pom(
            managed=_dep('g', 'bom', '1', scope='import', type_='pom'),
            dependencies=_dep('a', 'b'),
        )

        dependencies, _ = _resolve(payload, source)

        assert _coordinates(dependencies) == ['a:b:7']

    def test_a_parent_version_that_is_a_child_property_resolves(self) -> None:
        # the CI-friendly ${revision} idiom
        source = _DictSource({'g:parent:9': _pom(coordinates=('g', 'parent', '9'), managed=_dep('a', 'b', '1'))})
        payload = _pom(
            parent=('g', 'parent', '${revision}'),
            properties={'revision': '9'},
            dependencies=_dep('a', 'b'),
        )

        dependencies, _ = _resolve(payload, source)

        assert _coordinates(dependencies) == ['a:b:1']

    def test_a_missing_parent_is_reported_not_guessed(self) -> None:
        source = _DictSource()
        payload = _pom(parent=self._APACHE, dependencies=_dep('a', 'b'))

        dependencies, unresolved = _resolve(payload, source)

        assert dependencies == []
        assert 'org.apache:apache:30 is not on the test repository' in unresolved[0].reason

    def test_what_the_pom_itself_can_answer_survives_a_missing_parent(self) -> None:
        source = _DictSource()
        payload = _pom(parent=self._APACHE, dependencies=_dep('a', 'b', '1') + _dep('c', 'd'))

        dependencies, unresolved = _resolve(payload, source)

        assert _coordinates(dependencies) == ['a:b:1']
        assert [u.coordinate_key for u in unresolved] == ['c:d']

    def test_a_looping_parent_chain_terminates(self) -> None:
        source = _DictSource(
            {
                'g:a:1': _pom(coordinates=('g', 'a', '1'), parent=('g', 'b', '1')),
                'g:b:1': _pom(coordinates=('g', 'b', '1'), parent=('g', 'a', '1')),
            }
        )
        payload = _pom(parent=('g', 'a', '1'), dependencies=_dep('x', 'y'))

        _, unresolved = _resolve(payload, source)

        assert 'parent chain loops at g:a:1' in unresolved[0].reason

    def test_the_parent_chain_depth_is_bounded(self) -> None:
        poms = {f'g:p{i}:1': _pom(coordinates=('g', f'p{i}', '1'), parent=('g', f'p{i + 1}', '1')) for i in range(20)}
        source = _DictSource(poms)
        payload = _pom(parent=('g', 'p0', '1'), dependencies=_dep('x', 'y'))

        _, unresolved = _resolve(payload, source, max_parent_depth=3)

        assert 'parent chain is deeper than 3' in unresolved[0].reason
        assert len(source.fetched) == 3

    def test_the_fetch_budget_is_bounded_per_pom(self) -> None:
        poms = {f'g:p{i}:1': _pom(coordinates=('g', f'p{i}', '1'), parent=('g', f'p{i + 1}', '1')) for i in range(20)}
        source = _DictSource(poms)
        payload = _pom(parent=('g', 'p0', '1'), dependencies=_dep('x', 'y'))

        _, unresolved = _resolve(payload, source, fetch_budget=2, max_parent_depth=10)

        assert 'parent chain needs more than 2 poms' in unresolved[0].reason
        assert len(source.fetched) == 2

    def test_parents_are_fetched_once_per_run(self) -> None:
        source = _DictSource({'org.apache:apache:30': _pom(coordinates=self._APACHE, managed=_dep('a', 'b', '1'))})
        resolver = DeclaredDependencyResolver(source)

        resolver.resolve(_pom(parent=self._APACHE, dependencies=_dep('a', 'b')))
        resolver.resolve(_pom(coordinates=('x', 'y', '1'), parent=self._APACHE, dependencies=_dep('a', 'b')))

        assert source.fetched == ['org.apache:apache:30']

    def test_a_hostile_parent_coordinate_is_never_fetched(self) -> None:
        source = _DictSource()
        payload = _pom(parent=('../../etc', 'passwd', '1'), dependencies=_dep('a', 'b'))

        _, unresolved = _resolve(payload, source)

        assert source.fetched == []
        assert 'is not a valid Maven coordinate' in unresolved[0].reason


class TestCoordinateSafety:
    @pytest.mark.parametrize(
        'coordinate',
        [('org.apache', 'apache', '30'), ('com.acme-corp', 'my_lib', '1.0.0-SNAPSHOT'), ('g', 'a', '9.4.53.v20231009')],
    )
    def test_ordinary_coordinates_are_safe(self, coordinate: tuple[str, str, str]) -> None:
        assert is_safe_coordinate(*coordinate) is True

    @pytest.mark.parametrize(
        'coordinate',
        [
            ('../x', 'a', '1'),
            ('g', 'a/../../b', '1'),
            ('g', 'a', '1?x=y'),
            ('g', 'a', '1#frag'),
            ('g', 'a', ''),
            ('.hidden', 'a', '1'),
            ('g', 'a', '1 2'),
            ('g', 'a', '1..2'),
        ],
    )
    def test_anything_that_could_shape_a_url_path_is_refused(self, coordinate: tuple[str, str, str]) -> None:
        assert is_safe_coordinate(*coordinate) is False


class TestTransitives:
    """``--include-transitive``: each declared dependency's own pom, walked the way Maven walks it."""

    def _resolver(self, poms: dict[str, bytes], **kwargs: object) -> tuple[DeclaredDependencyResolver, _DictSource]:
        source = _DictSource(poms)
        return DeclaredDependencyResolver(source, transitive=True, **kwargs), source

    def test_off_by_default(self) -> None:
        source = _DictSource({'a:b:1': _pom(coordinates=('a', 'b', '1'), dependencies=_dep('c', 'd', '2'))})
        payload = _pom(dependencies=_dep('a', 'b', '1'))

        resolution = DeclaredDependencyResolver(source).resolve(payload)

        assert _coordinates(resolution.dependencies) == ['a:b:1']
        assert source.fetched == []

    def test_a_transitive_is_reported_with_who_asked_for_it(self) -> None:
        resolver, _ = self._resolver(
            {'a:b:1': _pom(coordinates=('a', 'b', '1'), dependencies=_dep('c', 'd', '2'))},
        )

        resolution = resolver.resolve(_pom(dependencies=_dep('a', 'b', '1')))

        assert _coordinates(resolution.dependencies) == ['a:b:1', 'c:d:2']
        direct, transitive = resolution.dependencies
        assert (direct.via, direct.depth, direct.is_transitive) == (None, 1, False)
        assert (transitive.via, transitive.depth, transitive.is_transitive) == ('a:b', 2, True)

    def test_the_walk_goes_deeper_than_one_hop(self) -> None:
        resolver, _ = self._resolver(
            {
                'a:b:1': _pom(coordinates=('a', 'b', '1'), dependencies=_dep('c', 'd', '2')),
                'c:d:2': _pom(coordinates=('c', 'd', '2'), dependencies=_dep('e', 'f', '3')),
            },
        )

        resolution = resolver.resolve(_pom(dependencies=_dep('a', 'b', '1')))

        assert _coordinates(resolution.dependencies) == ['a:b:1', 'c:d:2', 'e:f:3']
        assert resolution.dependencies[2].via == 'c:d'

    def test_the_nearest_declaration_wins(self) -> None:
        # the pom itself asks for e:f:9; a transitive asks for e:f:3. Maven keeps 9.
        resolver, _ = self._resolver(
            {'a:b:1': _pom(coordinates=('a', 'b', '1'), dependencies=_dep('e', 'f', '3'))},
        )

        resolution = resolver.resolve(_pom(dependencies=_dep('a', 'b', '1') + _dep('e', 'f', '9')))

        assert _coordinates(resolution.dependencies) == ['a:b:1', 'e:f:9']

    def test_the_first_declaration_at_a_depth_wins(self) -> None:
        resolver, _ = self._resolver(
            {
                'a:b:1': _pom(coordinates=('a', 'b', '1'), dependencies=_dep('e', 'f', '3')),
                'c:d:1': _pom(coordinates=('c', 'd', '1'), dependencies=_dep('e', 'f', '4')),
            },
        )

        resolution = resolver.resolve(_pom(dependencies=_dep('a', 'b', '1') + _dep('c', 'd', '1')))

        assert 'e:f:3' in _coordinates(resolution.dependencies)
        assert 'e:f:4' not in _coordinates(resolution.dependencies)

    def test_the_root_pom_management_overrides_a_transitive_version(self) -> None:
        resolver, _ = self._resolver(
            {'a:b:1': _pom(coordinates=('a', 'b', '1'), dependencies=_dep('e', 'f', '3'))},
        )
        payload = _pom(managed=_dep('e', 'f', '7'), dependencies=_dep('a', 'b', '1'))

        resolution = resolver.resolve(payload)

        assert _coordinates(resolution.dependencies) == ['a:b:1', 'e:f:7']

    def test_a_transitive_version_managed_by_its_own_parent_resolves(self) -> None:
        resolver, _ = self._resolver(
            {
                'a:b:1': _pom(coordinates=('a', 'b', '1'), parent=('a', 'parent', '1'), dependencies=_dep('e', 'f')),
                'a:parent:1': _pom(coordinates=('a', 'parent', '1'), managed=_dep('e', 'f', '5')),
            },
        )

        resolution = resolver.resolve(_pom(dependencies=_dep('a', 'b', '1')))

        assert _coordinates(resolution.dependencies) == ['a:b:1', 'e:f:5']

    @pytest.mark.parametrize(
        ('reached_through', 'own_scope', 'expected'),
        [
            ('compile', 'compile', 'compile'),
            ('compile', 'runtime', 'runtime'),
            ('runtime', 'compile', 'runtime'),
            ('test', 'compile', 'test'),
            ('test', 'runtime', 'test'),
            ('provided', 'compile', 'provided'),
        ],
    )
    def test_scope_is_combined_the_way_maven_combines_it(
        self, reached_through: str, own_scope: str, expected: str
    ) -> None:
        resolver, _ = self._resolver(
            {'a:b:1': _pom(coordinates=('a', 'b', '1'), dependencies=_dep('e', 'f', '3', scope=own_scope))},
            scopes=ALL_SCOPES,
        )

        resolution = resolver.resolve(_pom(dependencies=_dep('a', 'b', '1', scope=reached_through)))

        transitive = [d for d in resolution.dependencies if d.coordinate_key == 'e:f']
        assert [d.scope for d in transitive] == [expected]

    @pytest.mark.parametrize('own_scope', ['test', 'provided', 'system'])
    def test_a_transitive_own_test_or_provided_scope_is_never_handed_on(self, own_scope: str) -> None:
        resolver, _ = self._resolver(
            {'a:b:1': _pom(coordinates=('a', 'b', '1'), dependencies=_dep('e', 'f', '3', scope=own_scope))},
            scopes=ALL_SCOPES,
        )

        resolution = resolver.resolve(_pom(dependencies=_dep('a', 'b', '1')))

        assert _coordinates(resolution.dependencies) == ['a:b:1']

    def test_a_test_scope_tree_is_dropped_unless_test_scope_was_asked_for(self) -> None:
        resolver, source = self._resolver(
            {'a:b:1': _pom(coordinates=('a', 'b', '1'), dependencies=_dep('e', 'f', '3'))},
        )

        resolution = resolver.resolve(_pom(dependencies=_dep('a', 'b', '1', scope='test')))

        assert resolution.dependencies == []
        assert source.fetched == []

    def test_an_optional_transitive_is_not_followed(self) -> None:
        resolver, _ = self._resolver(
            {'a:b:1': _pom(coordinates=('a', 'b', '1'), dependencies=_dep('e', 'f', '3', optional=True))},
        )

        resolution = resolver.resolve(_pom(dependencies=_dep('a', 'b', '1')))

        assert _coordinates(resolution.dependencies) == ['a:b:1']

    def test_an_exclusion_applies_down_its_own_branch_only(self) -> None:
        excluded = (
            '<dependency><groupId>a</groupId><artifactId>b</artifactId><version>1</version>'
            '<exclusions><exclusion><groupId>e</groupId><artifactId>f</artifactId></exclusion></exclusions>'
            '</dependency>'
        )
        resolver, _ = self._resolver(
            {
                'a:b:1': _pom(coordinates=('a', 'b', '1'), dependencies=_dep('e', 'f', '3')),
                'c:d:1': _pom(coordinates=('c', 'd', '1'), dependencies=_dep('e', 'f', '3')),
            },
        )

        resolution = resolver.resolve(_pom(dependencies=excluded + _dep('c', 'd', '1')))

        by_key = {d.coordinate_key: d for d in resolution.dependencies}
        assert by_key['e:f'].via == 'c:d'

    def test_a_wildcard_exclusion_stops_the_branch(self) -> None:
        excluded = (
            '<dependency><groupId>a</groupId><artifactId>b</artifactId><version>1</version>'
            '<exclusions><exclusion><groupId>*</groupId><artifactId>*</artifactId></exclusion></exclusions>'
            '</dependency>'
        )
        resolver, _ = self._resolver(
            {'a:b:1': _pom(coordinates=('a', 'b', '1'), dependencies=_dep('e', 'f', '3') + _dep('g', 'h', '4'))},
        )

        resolution = resolver.resolve(_pom(dependencies=excluded))

        assert _coordinates(resolution.dependencies) == ['a:b:1']

    def test_an_exclusion_is_inherited_by_deeper_hops(self) -> None:
        excluded = (
            '<dependency><groupId>a</groupId><artifactId>b</artifactId><version>1</version>'
            '<exclusions><exclusion><groupId>g</groupId><artifactId>h</artifactId></exclusion></exclusions>'
            '</dependency>'
        )
        resolver, _ = self._resolver(
            {
                'a:b:1': _pom(coordinates=('a', 'b', '1'), dependencies=_dep('e', 'f', '3')),
                'e:f:3': _pom(coordinates=('e', 'f', '3'), dependencies=_dep('g', 'h', '4')),
            },
        )

        resolution = resolver.resolve(_pom(dependencies=excluded))

        assert _coordinates(resolution.dependencies) == ['a:b:1', 'e:f:3']

    def test_a_dependency_whose_pom_is_missing_is_reported_and_the_walk_continues(self) -> None:
        resolver, _ = self._resolver(
            {
                'c:d:1': _pom(coordinates=('c', 'd', '1'), dependencies=_dep('e', 'f', '3')),
                'e:f:3': _pom(coordinates=('e', 'f', '3')),
            },
        )

        resolution = resolver.resolve(_pom(dependencies=_dep('a', 'b', '1') + _dep('c', 'd', '1')))

        assert _coordinates(resolution.dependencies) == ['a:b:1', 'c:d:1', 'e:f:3']
        assert [(u.coordinate_key, u.version_expression) for u in resolution.unresolved] == [('a:b', '1')]
        assert 'its own dependencies are unknown' in resolution.unresolved[0].reason

    def test_a_transitive_version_range_is_unresolved_with_its_requester(self) -> None:
        resolver, _ = self._resolver(
            {'a:b:1': _pom(coordinates=('a', 'b', '1'), dependencies=_dep('e', 'f', '[3,4)'))},
        )

        resolution = resolver.resolve(_pom(dependencies=_dep('a', 'b', '1')))

        assert resolution.unresolved[0].coordinate_key == 'e:f'
        assert resolution.unresolved[0].via == 'a:b'
        assert resolution.unresolved[0].reason == REASON_VERSION_RANGE

    def test_the_depth_is_bounded(self) -> None:
        poms = {
            f'g:a{i}:1': _pom(coordinates=('g', f'a{i}', '1'), dependencies=_dep('g', f'a{i + 1}', '1'))
            for i in range(20)
        }
        resolver, _ = self._resolver(poms, max_transitive_depth=3)

        resolution = resolver.resolve(_pom(dependencies=_dep('g', 'a0', '1')))

        assert _coordinates(resolution.dependencies) == ['g:a0:1', 'g:a1:1', 'g:a2:1']

    def test_a_cycle_terminates(self) -> None:
        resolver, _ = self._resolver(
            {
                'a:b:1': _pom(coordinates=('a', 'b', '1'), dependencies=_dep('c', 'd', '1')),
                'c:d:1': _pom(coordinates=('c', 'd', '1'), dependencies=_dep('a', 'b', '1')),
            },
        )

        resolution = resolver.resolve(_pom(dependencies=_dep('a', 'b', '1')))

        assert _coordinates(resolution.dependencies) == ['a:b:1', 'c:d:1']
