from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
import typer

from cycode.cli.files_collector.sca.npm.restore_pnpm_dependencies import (
    PNPM_LOCK_FILE_NAME,
    RestorePnpmDependencies,
)
from cycode.cli.models import Document


@pytest.fixture
def mock_ctx(tmp_path: Path) -> typer.Context:
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = {'monitor': False}
    ctx.params = {'path': str(tmp_path)}
    return ctx


@pytest.fixture
def restore_pnpm(mock_ctx: typer.Context) -> RestorePnpmDependencies:
    return RestorePnpmDependencies(mock_ctx, is_git_diff=False, command_timeout=30)


class TestIsProject:
    def test_package_json_with_pnpm_lock_matches(self, restore_pnpm: RestorePnpmDependencies, tmp_path: Path) -> None:
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        (tmp_path / 'pnpm-lock.yaml').write_text('lockfileVersion: 5.4\n')
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))
        assert restore_pnpm.is_project(doc) is True

    def test_package_json_with_package_manager_pnpm_matches(self, restore_pnpm: RestorePnpmDependencies) -> None:
        content = '{"name": "test", "packageManager": "pnpm@8.6.2"}'
        doc = Document('package.json', content)
        assert restore_pnpm.is_project(doc) is True

    def test_package_json_with_engines_pnpm_matches(self, restore_pnpm: RestorePnpmDependencies) -> None:
        content = '{"name": "test", "engines": {"pnpm": ">=8"}}'
        doc = Document('package.json', content)
        assert restore_pnpm.is_project(doc) is True

    def test_package_json_with_no_pnpm_signal_does_not_match(
        self, restore_pnpm: RestorePnpmDependencies, tmp_path: Path
    ) -> None:
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))
        assert restore_pnpm.is_project(doc) is False

    def test_package_json_with_yarn_lock_does_not_match(
        self, restore_pnpm: RestorePnpmDependencies, tmp_path: Path
    ) -> None:
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        (tmp_path / 'yarn.lock').write_text('# yarn lockfile v1\n')
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))
        assert restore_pnpm.is_project(doc) is False

    def test_tsconfig_json_does_not_match(self, restore_pnpm: RestorePnpmDependencies) -> None:
        doc = Document('tsconfig.json', '{"compilerOptions": {}}')
        assert restore_pnpm.is_project(doc) is False

    def test_package_manager_yarn_does_not_match(self, restore_pnpm: RestorePnpmDependencies) -> None:
        content = '{"name": "test", "packageManager": "yarn@4.0.0"}'
        doc = Document('package.json', content)
        assert restore_pnpm.is_project(doc) is False

    def test_invalid_json_content_does_not_match(self, restore_pnpm: RestorePnpmDependencies) -> None:
        doc = Document('package.json', 'not valid json')
        assert restore_pnpm.is_project(doc) is False


class TestTryRestoreDependencies:
    def test_existing_pnpm_lock_returned_directly(self, restore_pnpm: RestorePnpmDependencies, tmp_path: Path) -> None:
        pnpm_lock_content = 'lockfileVersion: 5.4\n\npackages:\n  /package@1.0.0:\n    resolution: {}\n'
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        (tmp_path / 'pnpm-lock.yaml').write_text(pnpm_lock_content)

        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))
        result = restore_pnpm.try_restore_dependencies(doc)

        assert result is not None
        assert PNPM_LOCK_FILE_NAME in result.path
        assert result.content == pnpm_lock_content

    def test_get_lock_file_name(self, restore_pnpm: RestorePnpmDependencies) -> None:
        assert restore_pnpm.get_lock_file_name() == PNPM_LOCK_FILE_NAME

    def test_get_commands_returns_pnpm_install(self, restore_pnpm: RestorePnpmDependencies) -> None:
        commands = restore_pnpm.get_commands('/path/to/package.json')
        assert commands == [['pnpm', 'install', '--ignore-scripts']]


_BASE_MODULE = 'cycode.cli.files_collector.sca.base_restore_dependencies'


class TestCleanup:
    def test_generated_lockfile_is_deleted_after_restore(
        self, restore_pnpm: RestorePnpmDependencies, tmp_path: Path
    ) -> None:
        # pnpm: no pre-existing pnpm-lock.yaml but package.json indicates pnpm
        content = '{"name": "test", "packageManager": "pnpm@8.6.2"}'
        (tmp_path / 'package.json').write_text(content)
        doc = Document(str(tmp_path / 'package.json'), content, absolute_path=str(tmp_path / 'package.json'))
        lock_path = tmp_path / PNPM_LOCK_FILE_NAME

        def side_effect(
            commands: list, timeout: int, output_file_path: Optional[str] = None, working_directory: Optional[str] = None
        ) -> str:
            lock_path.write_text('lockfileVersion: 5.4\n')
            return 'output'

        with patch(f'{_BASE_MODULE}.execute_commands', side_effect=side_effect):
            result = restore_pnpm.try_restore_dependencies(doc)

        assert result is not None
        assert not lock_path.exists(), f'{PNPM_LOCK_FILE_NAME} must be deleted after restore'

    def test_preexisting_lockfile_is_not_deleted(
        self, restore_pnpm: RestorePnpmDependencies, tmp_path: Path
    ) -> None:
        lock_content = 'lockfileVersion: 5.4\n\npackages:\n  /pkg@1.0.0:\n    resolution: {}\n'
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        lock_path = tmp_path / PNPM_LOCK_FILE_NAME
        lock_path.write_text(lock_content)
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))

        result = restore_pnpm.try_restore_dependencies(doc)

        assert result is not None
        assert lock_path.exists(), f'Pre-existing {PNPM_LOCK_FILE_NAME} must not be deleted'
