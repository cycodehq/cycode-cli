import json
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer

from cycode.cli.apps.scan.binary.identity import (
    IDENTITY_FROM_FILENAME,
    IDENTITY_FROM_GIT_REMOTE,
    IDENTITY_FROM_PROJECT_NAME,
    assert_monitor_has_an_explicit_identity,
    resolve_platform_identity,
)
from cycode.cli.exceptions.custom_exceptions import MalformedArchiveError
from cycode.cli.files_collector.binary.base_extractor import ExtractionResult
from cycode.cli.files_collector.binary.collector import (
    BinaryCollectionResult,
    build_document_path,
    build_manifest_path,
    build_synthetic_manifest,
    collect_binary_documents,
    find_supported_artifacts,
    get_resolver,
)
from cycode.cli.files_collector.binary.maven_central import MavenCentralDigestResolver
from cycode.cli.files_collector.binary.resolver import NullDigestResolver
from cycode.cli.utils.path_utils import get_path_by_os
from tests.cli.files_collector.binary import fixtures

_COLLECTOR_MODULE = 'cycode.cli.files_collector.binary.collector'
_IDENTITY_MODULE = 'cycode.cli.apps.scan.binary.identity'

_GUAVA = ('com.google.guava', 'guava', '31.1-jre')
_LOG4J = ('org.apache.logging.log4j', 'log4j-core', '2.14.1')


@pytest.fixture
def mock_ctx() -> typer.Context:
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = {'progress_bar': None, 'binary_max_depth': 3, 'keep_bom': False, 'monitor': False}
    return ctx


def _os_path(*parts: str) -> str:
    """Document paths use the platform separator, so expectations must too. CI runs Windows."""
    return get_path_by_os('/'.join(parts))


def _bom_document(collection: object) -> object:
    return next(document for document in collection.documents if document.path.endswith('bom.json'))


def _war(tmp_path: Path, name: str = 'payments.war') -> Path:
    path = tmp_path / name
    path.write_bytes(
        fixtures.war_bytes(
            libraries={
                'guava.jar': fixtures.library_jar(*_GUAVA),
                'log4j-core.jar': fixtures.library_jar(*_LOG4J),
            }
        )
    )
    return path


class TestFindSupportedArtifacts:
    def test_a_single_file(self, tmp_path: Path) -> None:
        path = _war(tmp_path)

        assert find_supported_artifacts((str(path),)) == [str(path)]

    def test_a_directory_is_walked(self, tmp_path: Path) -> None:
        _war(tmp_path, 'a.war')
        (tmp_path / 'nested').mkdir()
        _war(tmp_path / 'nested', 'b.jar')
        (tmp_path / 'README.md').write_text('not an artifact')

        found = [os.path.basename(path) for path in find_supported_artifacts((str(tmp_path),))]

        assert sorted(found) == ['a.war', 'b.jar']

    def test_unsupported_files_are_ignored(self, tmp_path: Path) -> None:
        (tmp_path / 'app.zip').write_bytes(fixtures.archive_bytes(files={'a.txt': 'a'}))
        (tmp_path / 'pom.xml').write_text('<project/>')

        assert find_supported_artifacts((str(tmp_path),)) == []


class TestDocumentPath:
    def test_a_relative_path_is_kept_for_provenance(self) -> None:
        artifact = os.path.join('dist', 'payments.war')

        # mirrors the cyclonedx-maven-plugin layout: <manifest_dir>/pom.xml and <manifest_dir>/target/bom.json
        assert build_document_path(artifact) == _os_path('dist', 'payments.war', 'target', 'bom.json')
        assert build_manifest_path(artifact) == _os_path('dist', 'payments.war', 'pom.xml')

    def test_an_absolute_path_under_the_working_directory_is_relativised(self, tmp_path: Path) -> None:
        artifact = tmp_path / 'dist' / 'payments.war'

        with patch(f'{_COLLECTOR_MODULE}.os.getcwd', return_value=str(tmp_path)):
            assert build_document_path(str(artifact)) == _os_path('dist', 'payments.war', 'target', 'bom.json')

    def test_a_path_outside_the_working_directory_falls_back_to_the_filename(self, tmp_path: Path) -> None:
        with patch(f'{_COLLECTOR_MODULE}.os.getcwd', return_value=str(tmp_path / 'somewhere' / 'else')):
            assert build_document_path(str(tmp_path / 'payments.war')) == _os_path('payments.war', 'target', 'bom.json')

    def test_it_always_ends_with_bom_json(self, tmp_path: Path) -> None:
        # the existing SCA routing recognises the document by this name
        assert os.path.basename(build_document_path(str(_war(tmp_path)))) == 'bom.json'


class TestSyntheticManifest:
    """Phase 0 established the engine will not route a lone bom.json. This manifest is what makes it route."""

    def test_it_is_well_formed_xml_declaring_no_dependencies(self) -> None:
        manifest = build_synthetic_manifest('payments.war')
        root = ET.fromstring(manifest)  # noqa: S314 - the document under test is one we generated

        assert root.tag.endswith('project')
        # every finding must still come from the BOM, so the manifest must never contribute dependencies of its own
        assert root.find('.//{*}dependencies') is None
        assert root.find('.//{*}dependency') is None

    def test_it_names_the_artifact(self) -> None:
        manifest = build_synthetic_manifest('payments.war')

        assert '<artifactId>payments.war</artifactId>' in manifest
        assert '<name>payments.war</name>' in manifest

    @pytest.mark.parametrize(
        ('artifact_name', 'expected_id'),
        [
            ('payments.war', 'payments.war'),
            ('my app (1).jar', 'my-app--1-.jar'),
            ('caf\u00e9.jar', 'caf-.jar'),
        ],
    )
    def test_unusual_filenames_produce_a_usable_artifact_id(self, artifact_name: str, expected_id: str) -> None:
        manifest = build_synthetic_manifest(artifact_name)

        assert f'<artifactId>{expected_id}</artifactId>' in manifest
        ET.fromstring(manifest)  # noqa: S314 - the document under test is one we generated

    def test_xml_metacharacters_in_a_filename_cannot_break_the_document(self) -> None:
        # a filename is attacker-influenced in a sweep over an artifact repository
        manifest = build_synthetic_manifest('evil</name><dependencies>&.jar')

        root = ET.fromstring(manifest)  # noqa: S314 - the document under test is one we generated
        assert root.find('.//{*}dependencies') is None
        assert root.find('{*}name').text == 'evil</name><dependencies>&.jar'


class TestCollectBinaryDocuments:
    def test_a_bom_and_a_manifest_per_artifact(self, mock_ctx: typer.Context, tmp_path: Path) -> None:
        _war(tmp_path, 'a.war')
        _war(tmp_path, 'b.war')

        collection = collect_binary_documents(mock_ctx, (str(tmp_path),))

        assert sorted(document.path for document in collection.documents) == sorted(
            [
                _os_path('a.war', 'pom.xml'),
                _os_path('a.war', 'target', 'bom.json'),
                _os_path('b.war', 'pom.xml'),
                _os_path('b.war', 'target', 'bom.json'),
            ]
        )

    def test_the_document_content_is_the_synthesised_bom(self, mock_ctx: typer.Context, tmp_path: Path) -> None:
        path = _war(tmp_path)

        collection = collect_binary_documents(mock_ctx, (str(path),))
        bom = json.loads(_bom_document(collection).content)

        assert bom['bomFormat'] == 'CycloneDX'
        assert bom['metadata']['component']['name'] == 'payments.war'
        assert {component['purl'] for component in bom['components']} == {
            'pkg:maven/com.google.guava/guava@31.1-jre',
            'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
        }

    def test_the_archive_itself_never_becomes_a_document(self, mock_ctx: typer.Context, tmp_path: Path) -> None:
        # this is what keeps the binary filter in file_excluder correct and untouched
        path = _war(tmp_path)

        collection = collect_binary_documents(mock_ctx, (str(path),))

        assert all(not document.path.endswith('.war') for document in collection.documents)
        assert {os.path.basename(document.path) for document in collection.documents} == {'bom.json', 'pom.xml'}

    def test_counters_are_aggregated_across_artifacts(self, mock_ctx: typer.Context, tmp_path: Path) -> None:
        _war(tmp_path, 'a.war')
        anonymous = fixtures.archive_bytes(files={'com/acme/Shim.class': b'\xca\xfe\xba\xbe'})
        (tmp_path / 'b.war').write_bytes(fixtures.war_bytes(libraries={'shim.jar': anonymous}))

        collection = collect_binary_documents(mock_ctx, (str(tmp_path),))

        assert collection.identified_count == 2
        assert collection.unidentified_count == 1
        assert collection.resolver_available is False

    def test_the_resolver_reason_is_the_last_snapshot(self) -> None:
        # one resolver serves every artifact and its failure count grows; the first artifact's snapshot is stale
        collection = BinaryCollectionResult()
        collection.results_by_artifact['a.jar'] = ExtractionResult(
            resolver_available=False, resolver_unavailability_reason='failed for 1 of 1 digests'
        )
        collection.results_by_artifact['b.jar'] = ExtractionResult(
            resolver_available=False, resolver_unavailability_reason='failed for 2 of 5 digests'
        )

        assert collection.resolver_unavailability_reason == 'failed for 2 of 5 digests'

    def test_the_resolver_is_opt_in(self, mock_ctx: typer.Context) -> None:
        assert isinstance(get_resolver(mock_ctx), NullDigestResolver)

        mock_ctx.obj['maven_central'] = True

        assert isinstance(get_resolver(mock_ctx), MavenCentralDigestResolver)

    def test_max_depth_is_taken_from_the_context(self, mock_ctx: typer.Context, tmp_path: Path) -> None:
        inner = fixtures.war_bytes(libraries={'guava.jar': fixtures.library_jar(*_GUAVA)})
        (tmp_path / 'app.ear').write_bytes(fixtures.ear_bytes(modules={'web.war': inner}))
        mock_ctx.obj['binary_max_depth'] = 1

        collection = collect_binary_documents(mock_ctx, (str(tmp_path),))
        bom = json.loads(_bom_document(collection).content)

        # the war was reported but never opened, so guava inside it was never seen
        assert bom['components'] == []

    def test_one_unreadable_artifact_does_not_stop_the_others(self, mock_ctx: typer.Context, tmp_path: Path) -> None:
        _war(tmp_path, 'good.war')
        (tmp_path / 'broken.jar').write_bytes(fixtures.not_a_zip_bytes())

        collection = collect_binary_documents(mock_ctx, (str(tmp_path),))

        assert sorted(document.path for document in collection.documents) == sorted(
            [_os_path('good.war', 'pom.xml'), _os_path('good.war', 'target', 'bom.json')]
        )
        assert list(collection.failures) == [str(tmp_path / 'broken.jar')]

    def test_stop_on_error_propagates(self, mock_ctx: typer.Context, tmp_path: Path) -> None:
        (tmp_path / 'broken.jar').write_bytes(fixtures.not_a_zip_bytes())

        with pytest.raises(MalformedArchiveError):
            collect_binary_documents(mock_ctx, (str(tmp_path),), stop_on_error=True)

    def test_nothing_to_scan_is_not_an_error(self, mock_ctx: typer.Context, tmp_path: Path) -> None:
        (tmp_path / 'README.md').write_text('no artifacts here')

        collection = collect_binary_documents(mock_ctx, (str(tmp_path),))

        assert collection.documents == []
        assert collection.failures == {}

    def test_keep_bom_writes_the_document_beside_the_artifact(self, mock_ctx: typer.Context, tmp_path: Path) -> None:
        path = _war(tmp_path)
        mock_ctx.obj['keep_bom'] = True

        collect_binary_documents(mock_ctx, (str(path),))

        written = tmp_path / 'payments.war.bom.json'
        assert written.exists()
        assert json.loads(written.read_text())['bomFormat'] == 'CycloneDX'

    def test_keep_bom_is_off_by_default(self, mock_ctx: typer.Context, tmp_path: Path) -> None:
        path = _war(tmp_path)

        collect_binary_documents(mock_ctx, (str(path),))

        assert not (tmp_path / 'payments.war.bom.json').exists()

    def test_the_progress_bar_reflects_the_archive_count(self, mock_ctx: typer.Context, tmp_path: Path) -> None:
        _war(tmp_path, 'a.war')
        _war(tmp_path, 'b.war')
        progress_bar = MagicMock()
        mock_ctx.obj['progress_bar'] = progress_bar

        collect_binary_documents(mock_ctx, (str(tmp_path),))

        assert progress_bar.set_section_length.call_args[0][1] == 2
        assert progress_bar.update.call_count == 2


class TestPlatformIdentity:
    def test_project_name_wins(self, mock_ctx: typer.Context, tmp_path: Path) -> None:
        mock_ctx.obj['project_name'] = 'payments-service'
        path = _war(tmp_path)

        with patch(f'{_IDENTITY_MODULE}.get_remote_url_scan_parameter', return_value='https://git/acme/repo.git'):
            identity = resolve_platform_identity(mock_ctx, (str(path),))

        assert identity.value == 'payments-service'
        assert identity.source == IDENTITY_FROM_PROJECT_NAME

    def test_a_git_remote_is_used_when_there_is_no_override(self, mock_ctx: typer.Context, tmp_path: Path) -> None:
        path = _war(tmp_path)

        with patch(f'{_IDENTITY_MODULE}.get_remote_url_scan_parameter', return_value='https://git/acme/repo.git'):
            identity = resolve_platform_identity(mock_ctx, (str(path),))

        assert identity.value == 'https://git/acme/repo.git'
        assert identity.source == IDENTITY_FROM_GIT_REMOTE

    def test_a_detached_artifact_falls_back_to_its_filename(self, mock_ctx: typer.Context, tmp_path: Path) -> None:
        path = _war(tmp_path)

        with patch(f'{_IDENTITY_MODULE}.get_remote_url_scan_parameter', return_value=None):
            identity = resolve_platform_identity(mock_ctx, (str(path),))

        assert identity.value == 'payments.war'
        assert identity.source == IDENTITY_FROM_FILENAME
        assert identity.is_explicit is False


class TestMonitorGuard:
    def test_a_filename_identity_is_refused(self, mock_ctx: typer.Context, tmp_path: Path) -> None:
        path = _war(tmp_path)

        with patch(f'{_IDENTITY_MODULE}.get_remote_url_scan_parameter', return_value=None):
            identity = resolve_platform_identity(mock_ctx, (str(path),))

        with pytest.raises(typer.BadParameter) as error:
            assert_monitor_has_an_explicit_identity(identity)

        # the message has to name the fix, not just the problem
        assert '--project-name' in str(error.value)
        assert 'payments.war' in str(error.value)

    @pytest.mark.parametrize('remote_url', ['https://git/acme/repo.git', None])
    def test_an_explicit_identity_is_permitted(self, mock_ctx: typer.Context, tmp_path: Path, remote_url: str) -> None:
        mock_ctx.obj['project_name'] = None if remote_url else 'payments-service'
        path = _war(tmp_path)

        with patch(f'{_IDENTITY_MODULE}.get_remote_url_scan_parameter', return_value=remote_url):
            identity = resolve_platform_identity(mock_ctx, (str(path),))

        assert_monitor_has_an_explicit_identity(identity)
