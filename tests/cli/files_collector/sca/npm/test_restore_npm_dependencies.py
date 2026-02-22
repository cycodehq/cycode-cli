from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer

from cycode.cli.files_collector.sca.npm.restore_npm_dependencies import (
    NPM_LOCK_FILE_NAME,
    RestoreNpmDependencies,
)
from cycode.cli.models import Document


@pytest.fixture
def mock_ctx(tmp_path: Path) -> typer.Context:
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = {'monitor': False}
    ctx.params = {'path': str(tmp_path)}
    return ctx


@pytest.fixture
def restore_npm(mock_ctx: typer.Context) -> RestoreNpmDependencies:
    return RestoreNpmDependencies(mock_ctx, is_git_diff=False, command_timeout=30)


class TestIsProject:
    def test_package_json_with_no_lockfile_matches(self, restore_npm: RestoreNpmDependencies, tmp_path: Path) -> None:
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))
        assert restore_npm.is_project(doc) is True

    def test_package_json_with_yarn_lock_does_not_match(
        self, restore_npm: RestoreNpmDependencies, tmp_path: Path
    ) -> None:
        """Yarn projects are handled by RestoreYarnDependencies — NPM should not claim them."""
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        (tmp_path / 'yarn.lock').write_text('# yarn lockfile v1\n')
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))
        assert restore_npm.is_project(doc) is False

    def test_package_json_with_pnpm_lock_does_not_match(
        self, restore_npm: RestoreNpmDependencies, tmp_path: Path
    ) -> None:
        """pnpm projects are handled by RestorePnpmDependencies — NPM should not claim them."""
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        (tmp_path / 'pnpm-lock.yaml').write_text('lockfileVersion: 5.4\n')
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))
        assert restore_npm.is_project(doc) is False

    def test_tsconfig_json_does_not_match(self, restore_npm: RestoreNpmDependencies) -> None:
        doc = Document('tsconfig.json', '{}')
        assert restore_npm.is_project(doc) is False

    def test_arbitrary_json_does_not_match(self, restore_npm: RestoreNpmDependencies) -> None:
        for filename in ('jest.config.json', '.eslintrc.json', 'settings.json', 'bom.json'):
            doc = Document(filename, '{}')
            assert restore_npm.is_project(doc) is False, f'Expected False for {filename}'

    def test_non_json_file_does_not_match(self, restore_npm: RestoreNpmDependencies) -> None:
        for filename in ('readme.txt', 'script.js', 'Makefile'):
            doc = Document(filename, '')
            assert restore_npm.is_project(doc) is False, f'Expected False for {filename}'


class TestTryRestoreDependencies:
    def test_no_lockfile_calls_base_class(self, restore_npm: RestoreNpmDependencies, tmp_path: Path) -> None:
        """When no lockfile exists, the base class (npm install) should be invoked."""
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))

        with patch.object(
            restore_npm.__class__.__bases__[0], 'try_restore_dependencies', return_value=None
        ) as mock_super:
            restore_npm.try_restore_dependencies(doc)
            mock_super.assert_called_once_with(doc)

    def test_lockfile_in_different_directory_still_calls_base_class(
        self, restore_npm: RestoreNpmDependencies, tmp_path: Path
    ) -> None:
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        other_dir = tmp_path / 'other'
        other_dir.mkdir()
        (other_dir / 'pnpm-lock.yaml').write_text('lockfileVersion: 5.4\n')
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))

        with patch.object(
            restore_npm.__class__.__bases__[0], 'try_restore_dependencies', return_value=None
        ) as mock_super:
            restore_npm.try_restore_dependencies(doc)
            mock_super.assert_called_once_with(doc)


class TestGetLockFileName:
    def test_get_lock_file_name(self, restore_npm: RestoreNpmDependencies) -> None:
        assert restore_npm.get_lock_file_name() == NPM_LOCK_FILE_NAME

    def test_get_lock_file_names_contains_only_npm_lock(self, restore_npm: RestoreNpmDependencies) -> None:
        assert restore_npm.get_lock_file_names() == [NPM_LOCK_FILE_NAME]


class TestPrepareManifestFilePath:
    def test_strips_package_json_filename(self, restore_npm: RestoreNpmDependencies) -> None:
        assert restore_npm.prepare_manifest_file_path_for_command('/path/to/package.json') == '/path/to'

    def test_package_json_in_cwd_returns_empty_string(self, restore_npm: RestoreNpmDependencies) -> None:
        assert restore_npm.prepare_manifest_file_path_for_command('package.json') == ''

    def test_non_package_json_path_returned_unchanged(self, restore_npm: RestoreNpmDependencies) -> None:
        assert restore_npm.prepare_manifest_file_path_for_command('/path/to/') == '/path/to/'
