import hashlib
from pathlib import Path

import pytest

from cycode.cli.exceptions.custom_exceptions import BinaryExtractionError, UnsafeArchiveEntryError
from cycode.cli.files_collector.binary.base_extractor import ArchiveEntry
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
