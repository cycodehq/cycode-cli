import hashlib
from pathlib import Path

import pytest

from cycode.cli.exceptions.custom_exceptions import BinaryExtractionError, UnsafeArchiveEntryError
from cycode.cli.files_collector.binary.base_extractor import (
    CONFIDENCE_EXACT,
    EVIDENCE_POM_XML,
    ArchiveEntry,
    ExtractionResult,
)
from cycode.cli.files_collector.binary.declared import DeclaredDependencyResolver, PomFetch, PomSource
from cycode.cli.files_collector.binary.java_extractor import (
    JavaArchiveExtractor,
    is_library_entry,
    is_metadata_entry,
)
from tests.cli.files_collector.binary import fixtures

_GUAVA = ('com.google.guava', 'guava', '31.1-jre')
_LOG4J = ('org.apache.logging.log4j', 'log4j-core', '2.14.1')


@pytest.fixture
def extractor() -> JavaArchiveExtractor:
    return JavaArchiveExtractor()


def _write(tmp_path: Path, name: str, content: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(content)
    return str(path)


def _by_logical_path(entries: list[ArchiveEntry]) -> dict[str, ArchiveEntry]:
    return {entry.logical_path: entry for entry in entries}


class TestHandles:
    @pytest.mark.parametrize('name', ['app.jar', 'app.war', 'app.ear', 'DIST/App.WAR', '/abs/path/x.jar'])
    def test_java_archives_are_claimed(self, extractor: JavaArchiveExtractor, name: str) -> None:
        assert extractor.handles(name) is True

    @pytest.mark.parametrize('name', ['app.zip', 'pom.xml', 'app.tar.gz', 'jar', 'app.jarfile'])
    def test_everything_else_is_declined(self, extractor: JavaArchiveExtractor, name: str) -> None:
        assert extractor.handles(name) is False


class TestLayoutRecognition:
    @pytest.mark.parametrize(
        'name',
        [
            'WEB-INF/lib/guava.jar',
            'BOOT-INF/lib/guava.jar',
            'APP-INF/lib/guava.jar',
            'lib/guava.jar',
        ],
    )
    def test_library_directories(self, name: str) -> None:
        assert is_library_entry(name, '.war') is True

    def test_ear_modules_are_recognised_anywhere(self) -> None:
        assert is_library_entry('web.war', '.ear') is True
        assert is_library_entry('modules/ejb.jar', '.ear') is True

    def test_a_stray_jar_outside_a_library_directory_is_not_a_module(self) -> None:
        assert is_library_entry('docs/samples/example.jar', '.war') is False

    def test_non_archives_are_never_libraries(self) -> None:
        assert is_library_entry('WEB-INF/lib/readme.txt', '.war') is False

    @pytest.mark.parametrize(
        'name',
        [
            'META-INF/MANIFEST.MF',
            'META-INF/manifest.mf',
            'META-INF/maven/com.google.guava/guava/pom.properties',
            'META-INF/maven/com.google.guava/guava/pom.xml',
        ],
    )
    def test_metadata_entries(self, name: str) -> None:
        assert is_metadata_entry(name) is True

    @pytest.mark.parametrize(
        'name',
        [
            'com/google/common/Thing.class',
            'META-INF/maven/pom.properties',
            'META-INF/maven/g/a/extra/pom.xml',
            'META-INF/LICENSE',
        ],
    )
    def test_non_metadata_entries(self, name: str) -> None:
        assert is_metadata_entry(name) is False


class TestPlainJar:
    def test_root_entry_describes_the_artifact(self, extractor: JavaArchiveExtractor, tmp_path: Path) -> None:
        content = fixtures.library_jar(*_GUAVA)
        path = _write(tmp_path, 'guava.jar', content)

        entries = extractor.extract(path)
        root = entries[0]

        assert root.logical_path == 'guava.jar'
        assert root.depth == 0
        assert root.parent is None
        assert root.is_archive is True
        assert root.sha1 == hashlib.sha1(content, usedforsecurity=False).hexdigest()
        assert root.size == len(content)

    def test_metadata_is_carried_but_class_files_are_not(self, extractor: JavaArchiveExtractor, tmp_path: Path) -> None:
        path = _write(tmp_path, 'guava.jar', fixtures.library_jar(*_GUAVA))

        entries = extractor.extract(path)
        logical_paths = [entry.logical_path for entry in entries]

        assert 'guava.jar > META-INF/MANIFEST.MF' in logical_paths
        assert 'guava.jar > META-INF/maven/com.google.guava/guava/pom.properties' in logical_paths
        assert not any('.class' in path for path in logical_paths)

    def test_metadata_payload_is_readable(self, extractor: JavaArchiveExtractor, tmp_path: Path) -> None:
        path = _write(tmp_path, 'guava.jar', fixtures.library_jar(*_GUAVA))

        entries = _by_logical_path(extractor.extract(path))
        pom = entries['guava.jar > META-INF/maven/com.google.guava/guava/pom.properties']

        assert pom.payload is not None
        assert b'version=31.1-jre' in pom.payload
        assert pom.is_archive is False
        assert pom.parent == 'guava.jar'
        assert pom.depth == 1


class TestWar:
    def test_web_inf_lib_jars_are_found_and_opened(self, extractor: JavaArchiveExtractor, tmp_path: Path) -> None:
        guava = fixtures.library_jar(*_GUAVA)
        war = fixtures.war_bytes(libraries={'guava-31.1-jre.jar': guava})
        path = _write(tmp_path, 'payments.war', war)

        entries = _by_logical_path(extractor.extract(path))
        jar_path = 'payments.war > WEB-INF/lib/guava-31.1-jre.jar'

        assert jar_path in entries
        assert entries[jar_path].is_archive is True
        assert entries[jar_path].depth == 1
        assert entries[jar_path].parent == 'payments.war'
        assert entries[jar_path].sha1 == hashlib.sha1(guava, usedforsecurity=False).hexdigest()

        # opened, so its own metadata came back with it
        assert f'{jar_path} > META-INF/maven/com.google.guava/guava/pom.properties' in entries

    def test_nested_jar_bytes_are_not_retained(self, extractor: JavaArchiveExtractor, tmp_path: Path) -> None:
        war = fixtures.war_bytes(libraries={'guava.jar': fixtures.library_jar(*_GUAVA)})
        path = _write(tmp_path, 'payments.war', war)

        entries = _by_logical_path(extractor.extract(path))

        # holding every nested jar would mean holding the whole deployable in memory
        assert entries['payments.war > WEB-INF/lib/guava.jar'].payload is None

    def test_several_libraries(self, extractor: JavaArchiveExtractor, tmp_path: Path) -> None:
        war = fixtures.war_bytes(
            libraries={
                'guava.jar': fixtures.library_jar(*_GUAVA),
                'log4j-core.jar': fixtures.library_jar(*_LOG4J),
            }
        )
        path = _write(tmp_path, 'payments.war', war)

        entries = extractor.extract(path)
        archives = [entry.logical_path for entry in entries if entry.is_archive]

        assert archives == [
            'payments.war',
            'payments.war > WEB-INF/lib/guava.jar',
            'payments.war > WEB-INF/lib/log4j-core.jar',
        ]


class TestSpringBoot:
    def test_boot_inf_lib_is_recognised(self, extractor: JavaArchiveExtractor, tmp_path: Path) -> None:
        boot = fixtures.boot_jar_bytes(libraries={'log4j-core-2.14.1.jar': fixtures.library_jar(*_LOG4J)})
        path = _write(tmp_path, 'app.jar', boot)

        entries = _by_logical_path(extractor.extract(path))
        jar_path = 'app.jar > BOOT-INF/lib/log4j-core-2.14.1.jar'

        assert jar_path in entries
        assert f'{jar_path} > META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties' in entries


class TestEar:
    def test_modules_and_app_inf_lib(self, extractor: JavaArchiveExtractor, tmp_path: Path) -> None:
        war = fixtures.war_bytes(libraries={'log4j-core.jar': fixtures.library_jar(*_LOG4J)})
        ear = fixtures.ear_bytes(modules={'web.war': war}, libraries={'guava.jar': fixtures.library_jar(*_GUAVA)})
        path = _write(tmp_path, 'payments.ear', ear)

        entries = _by_logical_path(extractor.extract(path))

        assert 'payments.ear > web.war' in entries
        assert 'payments.ear > APP-INF/lib/guava.jar' in entries
        assert 'payments.ear > web.war > WEB-INF/lib/log4j-core.jar' in entries

    def test_three_level_containment_reports_a_readable_chain(
        self, extractor: JavaArchiveExtractor, tmp_path: Path
    ) -> None:
        war = fixtures.war_bytes(libraries={'log4j-core-2.14.1.jar': fixtures.library_jar(*_LOG4J)})
        ear = fixtures.ear_bytes(modules={'web.war': war})
        path = _write(tmp_path, 'payments.ear', ear)

        entries = _by_logical_path(extractor.extract(path))
        deep = entries['payments.ear > web.war > WEB-INF/lib/log4j-core-2.14.1.jar']

        assert deep.depth == 2
        assert deep.parent == 'payments.ear > web.war'
        assert deep.name == 'log4j-core-2.14.1.jar'


class TestRecursionSafety:
    def _four_level_nest(self) -> bytes:
        level4 = fixtures.library_jar('com.acme', 'deepest', '1.0')
        level3 = fixtures.archive_bytes(files={'lib/level4.jar': level4})
        level2 = fixtures.archive_bytes(files={'lib/level3.jar': level3})
        return fixtures.war_bytes(libraries={'level2.jar': level2})

    def test_depth_cap_stops_the_fourth_level_being_opened(
        self, extractor: JavaArchiveExtractor, tmp_path: Path
    ) -> None:
        path = _write(tmp_path, 'app.war', self._four_level_nest())

        entries = extractor.extract(path, max_depth=3)
        logical_paths = [entry.logical_path for entry in entries]
        deepest = 'app.war > WEB-INF/lib/level2.jar > lib/level3.jar > lib/level4.jar'

        # the fourth archive is reported, but never opened, so nothing from inside it comes back
        assert deepest in logical_paths
        assert max(entry.depth for entry in entries) == 3
        assert not any(path.startswith(f'{deepest} > ') for path in logical_paths)

    def test_a_lower_depth_cap_stops_sooner(self, extractor: JavaArchiveExtractor, tmp_path: Path) -> None:
        path = _write(tmp_path, 'app.war', self._four_level_nest())

        entries = extractor.extract(path, max_depth=1)

        assert max(entry.depth for entry in entries) == 1
        assert [entry.logical_path for entry in entries if entry.is_archive] == [
            'app.war',
            'app.war > WEB-INF/lib/level2.jar',
        ]

    def test_repeated_digest_is_opened_only_once(self, extractor: JavaArchiveExtractor, tmp_path: Path) -> None:
        guava = fixtures.library_jar(*_GUAVA)
        war = fixtures.war_bytes(libraries={'guava.jar': guava, 'guava-shadow.jar': guava})
        path = _write(tmp_path, 'app.war', war)

        entries = extractor.extract(path)
        logical_paths = [entry.logical_path for entry in entries]

        # both copies are reported as shipped components...
        assert 'app.war > WEB-INF/lib/guava.jar' in logical_paths
        assert 'app.war > WEB-INF/lib/guava-shadow.jar' in logical_paths
        # ...but identical bytes are only walked once, which is what makes a self-containing archive terminate
        assert sum(1 for path in logical_paths if path.endswith('pom.properties')) == 1

    def test_an_archive_containing_its_own_parent_terminates(
        self, extractor: JavaArchiveExtractor, tmp_path: Path
    ) -> None:
        inner = fixtures.library_jar('com.acme', 'inner', '1.0')
        outer = fixtures.war_bytes(libraries={'inner.jar': inner, 'inner-again.jar': inner})
        path = _write(tmp_path, 'app.war', outer)

        entries = extractor.extract(path, max_depth=10)

        assert len(entries) < 20


class TestFailureModes:
    def test_a_directory_is_refused(self, extractor: JavaArchiveExtractor, tmp_path: Path) -> None:
        with pytest.raises(BinaryExtractionError, match='is not a file'):
            extractor.extract(str(tmp_path))

    def test_a_missing_file_is_refused(self, extractor: JavaArchiveExtractor, tmp_path: Path) -> None:
        with pytest.raises(BinaryExtractionError, match='is not a file'):
            extractor.extract(str(tmp_path / 'absent.jar'))

    def test_non_zip_bytes_named_jar(self, extractor: JavaArchiveExtractor, tmp_path: Path) -> None:
        path = _write(tmp_path, 'app.jar', fixtures.not_a_zip_bytes())

        with pytest.raises(BinaryExtractionError, match='not a readable archive'):
            extractor.extract(path)

    def test_a_hostile_entry_inside_a_nested_jar_aborts_the_scan(
        self, extractor: JavaArchiveExtractor, tmp_path: Path
    ) -> None:
        hostile = fixtures.zip_slip_bytes()
        war = fixtures.war_bytes(libraries={'hostile.jar': hostile})
        path = _write(tmp_path, 'app.war', war)

        with pytest.raises(UnsafeArchiveEntryError):
            extractor.extract(path)


class TestIdentify:
    def test_shipped_libraries_are_identified_from_embedded_maven_metadata(
        self, extractor: JavaArchiveExtractor, tmp_path: Path
    ) -> None:
        war = fixtures.war_bytes(
            libraries={
                'guava.jar': fixtures.library_jar(*_GUAVA),
                'log4j-core.jar': fixtures.library_jar(*_LOG4J),
            }
        )
        path = _write(tmp_path, 'payments.war', war)

        result = extractor.identify(extractor.extract(path))

        assert [component.purl for component in result.components] == [
            'pkg:maven/com.google.guava/guava@31.1-jre',
            'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
        ]
        assert all(component.evidence == 'pom.properties' for component in result.components)
        assert all(component.confidence == 'exact' for component in result.components)
        assert result.unidentified == []
        # the artifact we were pointed at is not one of its own components
        assert all(component.logical_path != 'payments.war' for component in result.components)

    def test_a_library_without_metadata_is_reported_unidentified(
        self, extractor: JavaArchiveExtractor, tmp_path: Path
    ) -> None:
        anonymous = fixtures.archive_bytes(files={'com/acme/Shim.class': b'\xca\xfe\xba\xbe'})
        war = fixtures.war_bytes(libraries={'internal-shim.jar': anonymous})
        path = _write(tmp_path, 'payments.war', war)

        result = extractor.identify(extractor.extract(path))

        assert result.components == []
        assert [item.logical_path for item in result.unidentified] == ['payments.war > WEB-INF/lib/internal-shim.jar']
        # we do not guess a coordinate from the filename
        assert result.unidentified[0].sha1 == hashlib.sha1(anonymous, usedforsecurity=False).hexdigest()

    def test_a_standalone_library_jar_identifies_itself(self, extractor: JavaArchiveExtractor, tmp_path: Path) -> None:
        # the vendor-artifact case: a jar that ships nothing is itself the thing being assessed
        path = _write(tmp_path, 'guava.jar', fixtures.library_jar(*_GUAVA))

        result = extractor.identify(extractor.extract(path))

        assert [component.purl for component in result.components] == ['pkg:maven/com.google.guava/guava@31.1-jre']

    def test_a_standalone_jar_without_metadata_is_reported_unidentified(
        self, extractor: JavaArchiveExtractor, tmp_path: Path
    ) -> None:
        # the archive we were pointed at is the only thing under assessment; failing to name it is the whole
        # coverage gap, and dropping it would let the scan claim full coverage of nothing
        anonymous = fixtures.archive_bytes(files={'com/acme/Shim.class': b'\xca\xfe\xba\xbe'})
        path = _write(tmp_path, 'internal-shim.jar', anonymous)

        result = extractor.identify(extractor.extract(path))

        assert result.components == []
        assert [item.logical_path for item in result.unidentified] == ['internal-shim.jar']
        assert result.unidentified[0].sha1 == hashlib.sha1(anonymous, usedforsecurity=False).hexdigest()

    def test_a_deployable_without_libraries_is_not_its_own_component(
        self, extractor: JavaArchiveExtractor, tmp_path: Path
    ) -> None:
        # a war is an application, not a library, even when maven wrote its coordinates into it
        files = {
            'WEB-INF/web.xml': '<web-app/>',
            fixtures.pom_properties_entry_name('com.acme', 'payments'): fixtures.pom_properties(
                'com.acme', 'payments', '1.0'
            ),
        }
        path = _write(tmp_path, 'payments.war', fixtures.archive_bytes(files=files))

        result = extractor.identify(extractor.extract(path))

        assert result.components == []
        assert result.unidentified == []

    def test_counters_describe_the_walk(self, extractor: JavaArchiveExtractor, tmp_path: Path) -> None:
        war = fixtures.war_bytes(libraries={'log4j-core.jar': fixtures.library_jar(*_LOG4J)})
        ear = fixtures.ear_bytes(modules={'web.war': war})
        path = _write(tmp_path, 'payments.ear', ear)

        result = extractor.identify(extractor.extract(path))

        # the ear, the war and the jar were each opened
        assert result.archives_opened == 3
        assert result.max_depth_reached == 3
        assert result.resolver_available is False

    def test_an_artifact_with_no_libraries_yields_nothing_unidentified(
        self, extractor: JavaArchiveExtractor, tmp_path: Path
    ) -> None:
        path = _write(tmp_path, 'app.war', fixtures.war_bytes())

        result = extractor.identify(extractor.extract(path))

        assert result.unidentified == []
        assert result.components == []
        assert result.archives_opened == 1

    def test_an_archive_left_unopened_at_the_depth_cap_is_not_counted_as_opened(
        self, extractor: JavaArchiveExtractor, tmp_path: Path
    ) -> None:
        level3 = fixtures.library_jar('com.acme', 'deepest', '1.0')
        level2 = fixtures.archive_bytes(files={'lib/level3.jar': level3})
        path = _write(tmp_path, 'app.war', fixtures.war_bytes(libraries={'level2.jar': level2}))

        result = extractor.identify(extractor.extract(path, max_depth=2))

        # the war and level2 were walked; level3 was reported but never opened
        assert result.archives_opened == 2
        assert result.max_depth_reached == 3
        # level2 carries no metadata of its own; level3 was never opened so its metadata was never read
        assert len(result.components) == 0
        assert len(result.unidentified) == 2


class TestDeclaredExpansion:
    """``--include-declared``: embedded poms contribute components, not just edges."""

    _WODEN = ('org.apache.woden', 'woden-core', '1.0M10')
    _POM = b"""<?xml version="1.0"?>
    <project xmlns="http://maven.apache.org/POM/4.0.0">
      <groupId>org.apache.woden</groupId><artifactId>woden-core</artifactId><version>1.0M10</version>
      <properties><codec.version>1.15</codec.version></properties>
      <dependencies>
        <dependency>
          <groupId>commons-codec</groupId><artifactId>commons-codec</artifactId><version>${codec.version}</version>
        </dependency>
        <dependency>
          <groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>1.7.36</version>
        </dependency>
        <dependency>
          <groupId>log4j</groupId><artifactId>log4j</artifactId><version>1.2.15</version><scope>test</scope>
        </dependency>
        <dependency>
          <groupId>commons-logging</groupId><artifactId>commons-logging</artifactId>
        </dependency>
      </dependencies>
    </project>"""

    def _jar(self) -> bytes:
        return fixtures.archive_bytes(
            files={
                fixtures.pom_properties_entry_name(*self._WODEN[:2]): fixtures.pom_properties(*self._WODEN),
                f'META-INF/maven/{self._WODEN[0]}/{self._WODEN[1]}/pom.xml': self._POM,
            }
        )

    def _identify(self, tmp_path: Path, name: str, content: bytes, enabled: bool = True) -> ExtractionResult:
        path = tmp_path / name
        path.write_bytes(content)
        resolver = DeclaredDependencyResolver() if enabled else None
        extractor = JavaArchiveExtractor(declared_resolver=resolver)
        return extractor.identify(extractor.extract(str(path)))

    def test_off_by_default_poms_contribute_nothing_but_edges(self, tmp_path: Path) -> None:
        result = self._identify(tmp_path, 'woden-core.jar', self._jar(), enabled=False)

        assert [c.purl for c in result.components] == ['pkg:maven/org.apache.woden/woden-core@1.0M10']
        assert result.declared_unresolved == []

    def test_declared_dependencies_become_components_marked_as_such(self, tmp_path: Path) -> None:
        result = self._identify(tmp_path, 'woden-core.jar', self._jar())

        declared = {c.purl: c for c in result.declared_components}
        assert set(declared) == {
            'pkg:maven/commons-codec/commons-codec@1.15',
            'pkg:maven/org.slf4j/slf4j-api@1.7.36',
        }
        component = declared['pkg:maven/commons-codec/commons-codec@1.15']
        assert component.evidence == EVIDENCE_POM_XML
        assert component.confidence == CONFIDENCE_EXACT
        assert component.declared_scope == 'compile'
        assert component.sha1 is None
        assert component.sha256 is None
        # the declaring pom, so a finding says exactly which file made the claim
        assert component.logical_path == 'woden-core.jar > META-INF/maven/org.apache.woden/woden-core/pom.xml'
        assert component.parent == 'woden-core.jar'
        # the shipped jar itself is untouched and still counts as the only identified archive
        assert [c.purl for c in result.shipped_components] == ['pkg:maven/org.apache.woden/woden-core@1.0M10']

    def test_a_test_scoped_dependency_is_neither_a_component_nor_unresolved(self, tmp_path: Path) -> None:
        result = self._identify(tmp_path, 'woden-core.jar', self._jar())

        assert not any(c.artifact == 'log4j' for c in result.components)
        assert not any(u.artifact == 'log4j' for u in result.declared_unresolved)

    def test_an_unresolvable_version_is_listed_with_its_pom(self, tmp_path: Path) -> None:
        result = self._identify(tmp_path, 'woden-core.jar', self._jar())

        assert [(u.coordinate_key, u.version_expression) for u in result.declared_unresolved] == [
            ('commons-logging:commons-logging', None)
        ]
        assert result.declared_unresolved[0].declared_by.endswith('/woden-core/pom.xml')
        assert 'no version declared or managed' in result.declared_unresolved[0].reason

    def test_a_declared_dependency_that_shipped_is_not_repeated(self, tmp_path: Path) -> None:
        # the war ships slf4j 1.7.30; the pom asks for 1.7.36. What shipped is the truth about it.
        war = fixtures.war_bytes(
            libraries={
                'woden-core.jar': self._jar(),
                'slf4j-api.jar': fixtures.library_jar('org.slf4j', 'slf4j-api', '1.7.30'),
            }
        )

        result = self._identify(tmp_path, 'app.war', war)

        purls = [c.purl for c in result.components]
        assert 'pkg:maven/org.slf4j/slf4j-api@1.7.30' in purls
        assert 'pkg:maven/org.slf4j/slf4j-api@1.7.36' not in purls
        assert [c.artifact for c in result.declared_components] == ['commons-codec']

    def test_a_declared_component_hangs_off_the_jar_that_declared_it(self, tmp_path: Path) -> None:
        war = fixtures.war_bytes(libraries={'woden-core.jar': self._jar()})

        result = self._identify(tmp_path, 'app.war', war)

        woden = 'pkg:maven/org.apache.woden/woden-core@1.0M10'
        assert result.has_real_edges is True
        assert sorted(result.dependency_edges[woden]) == [
            'pkg:maven/commons-codec/commons-codec@1.15',
            'pkg:maven/org.slf4j/slf4j-api@1.7.36',
        ]
        assert result.dependency_edges['app.war'] == [woden]

    def test_the_deployable_own_pom_contributes_too(self, tmp_path: Path) -> None:
        # a war built by Maven carries its own pom; something it declares at compile scope but did not package is
        # exactly what this flag exists to surface
        war_pom = b"""<project>
          <groupId>com.acme</groupId><artifactId>app</artifactId><version>1</version>
          <dependencies>
            <dependency><groupId>javax.servlet</groupId><artifactId>servlet-api</artifactId>
              <version>2.5</version><scope>provided</scope></dependency>
            <dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId>
              <version>31.1-jre</version></dependency>
          </dependencies>
        </project>"""
        war = fixtures.archive_bytes(
            files={'WEB-INF/web.xml': '<web-app/>', 'META-INF/maven/com.acme/app/pom.xml': war_pom}
        )

        result = self._identify(tmp_path, 'app.war', war)

        assert [c.purl for c in result.declared_components] == ['pkg:maven/com.google.guava/guava@31.1-jre']
        assert result.dependency_edges['app.war'] == ['pkg:maven/com.google.guava/guava@31.1-jre']

    def test_a_dependency_inherited_from_a_parent_is_an_edge_of_the_jar(self, tmp_path: Path) -> None:
        # the jar's own pom never mentions jackson-core; its parent declares it on the jar's behalf. The edge must
        # still come from the jar, not fall back to containment on the application
        parent = b"""<project>
          <groupId>g</groupId><artifactId>parent</artifactId><version>1</version>
          <dependencies>
            <dependency><groupId>a</groupId><artifactId>inherited</artifactId><version>2</version></dependency>
          </dependencies>
        </project>"""
        child = b"""<project>
          <parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version></parent>
          <artifactId>child</artifactId>
        </project>"""

        class _Source(PomSource):
            def fetch(self, group: str, artifact: str, version: str) -> PomFetch:
                return PomFetch(payload=parent)

        jar = fixtures.archive_bytes(
            files={
                fixtures.pom_properties_entry_name('g', 'child'): fixtures.pom_properties('g', 'child', '1'),
                'META-INF/maven/g/child/pom.xml': child,
            }
        )
        war = fixtures.war_bytes(libraries={'child.jar': jar})
        path = tmp_path / 'app.war'
        path.write_bytes(war)

        extractor = JavaArchiveExtractor(declared_resolver=DeclaredDependencyResolver(_Source()))
        result = extractor.identify(extractor.extract(str(path)))

        assert result.dependency_edges['pkg:maven/g/child@1'] == ['pkg:maven/a/inherited@2']
        assert result.dependency_edges['app.war'] == ['pkg:maven/g/child@1']


class TestTransitiveExpansion:
    def test_a_transitive_hangs_off_the_declared_component_that_pulled_it_in(self, tmp_path: Path) -> None:
        jar_pom = b"""<project>
          <groupId>g</groupId><artifactId>lib</artifactId><version>1</version>
          <dependencies>
            <dependency><groupId>a</groupId><artifactId>b</artifactId><version>1</version></dependency>
          </dependencies>
        </project>"""
        poms = {
            'a:b:1': b'<project><groupId>a</groupId><artifactId>b</artifactId><version>1</version><dependencies>'
            b'<dependency><groupId>c</groupId><artifactId>d</artifactId><version>2</version></dependency>'
            b'</dependencies></project>',
        }

        class _Source(PomSource):
            def fetch(self, group: str, artifact: str, version: str) -> PomFetch:
                payload = poms.get(f'{group}:{artifact}:{version}')
                return PomFetch(payload=payload) if payload else PomFetch(failure='missing')

        jar = fixtures.archive_bytes(
            files={
                fixtures.pom_properties_entry_name('g', 'lib'): fixtures.pom_properties('g', 'lib', '1'),
                'META-INF/maven/g/lib/pom.xml': jar_pom,
            }
        )
        path = tmp_path / 'lib.jar'
        path.write_bytes(jar)

        resolver = DeclaredDependencyResolver(_Source(), transitive=True)
        extractor = JavaArchiveExtractor(declared_resolver=resolver)
        result = extractor.identify(extractor.extract(str(path)))

        transitive = [c for c in result.declared_components if c.is_transitive]
        assert [(c.purl, c.declared_via) for c in transitive] == [('pkg:maven/c/d@2', 'a:b')]
        assert result.dependency_edges['pkg:maven/g/lib@1'] == ['pkg:maven/a/b@1']
        assert result.dependency_edges['pkg:maven/a/b@1'] == ['pkg:maven/c/d@2']
        assert result.transitive_components == transitive
