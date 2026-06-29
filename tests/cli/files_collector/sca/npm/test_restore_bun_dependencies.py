from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
import typer

from cycode.cli.files_collector.sca.npm.restore_bun_dependencies import (
    BUN_LOCK_FILE_NAME,
    RestoreBunDependencies,
    _parse_bun_version,
)
from cycode.cli.models import Document

_BUN_MODULE = 'cycode.cli.files_collector.sca.npm.restore_bun_dependencies'


@pytest.fixture
def mock_ctx(tmp_path: Path) -> typer.Context:
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = {'monitor': False}
    ctx.params = {'path': str(tmp_path)}
    return ctx


@pytest.fixture
def restore_bun(mock_ctx: typer.Context) -> RestoreBunDependencies:
    return RestoreBunDependencies(mock_ctx, is_git_diff=False, command_timeout=30)


class TestIsProject:
    def test_package_json_with_bun_lock_matches(self, restore_bun: RestoreBunDependencies, tmp_path: Path) -> None:
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        (tmp_path / 'bun.lock').write_text('{"lockfileVersion": 1}\n')
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))
        assert restore_bun.is_project(doc) is True

    def test_package_json_with_package_manager_bun_matches(self, restore_bun: RestoreBunDependencies) -> None:
        content = '{"name": "test", "packageManager": "bun@1.1.0"}'
        doc = Document('package.json', content)
        assert restore_bun.is_project(doc) is True

    def test_package_json_with_engines_bun_matches(self, restore_bun: RestoreBunDependencies) -> None:
        content = '{"name": "test", "engines": {"bun": ">=1"}}'
        doc = Document('package.json', content)
        assert restore_bun.is_project(doc) is True

    def test_package_json_with_no_bun_signal_does_not_match(
        self, restore_bun: RestoreBunDependencies, tmp_path: Path
    ) -> None:
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))
        assert restore_bun.is_project(doc) is False

    def test_package_json_with_yarn_lock_does_not_match(
        self, restore_bun: RestoreBunDependencies, tmp_path: Path
    ) -> None:
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        (tmp_path / 'yarn.lock').write_text('# yarn lockfile v1\n')
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))
        assert restore_bun.is_project(doc) is False

    def test_tsconfig_json_does_not_match(self, restore_bun: RestoreBunDependencies) -> None:
        doc = Document('tsconfig.json', '{"compilerOptions": {}}')
        assert restore_bun.is_project(doc) is False

    def test_package_manager_yarn_does_not_match(self, restore_bun: RestoreBunDependencies) -> None:
        content = '{"name": "test", "packageManager": "yarn@4.0.0"}'
        doc = Document('package.json', content)
        assert restore_bun.is_project(doc) is False

    def test_invalid_json_content_does_not_match(self, restore_bun: RestoreBunDependencies) -> None:
        doc = Document('package.json', 'not valid json')
        assert restore_bun.is_project(doc) is False


class TestTryRestoreDependencies:
    def test_existing_bun_lock_returned_directly(self, restore_bun: RestoreBunDependencies, tmp_path: Path) -> None:
        bun_lock_content = '{"lockfileVersion": 1, "packages": {"package": ["package@1.0.0", "", {}, ""]}}\n'
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        (tmp_path / 'bun.lock').write_text(bun_lock_content)

        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))
        result = restore_bun.try_restore_dependencies(doc)

        assert result is not None
        assert BUN_LOCK_FILE_NAME in result.path
        assert result.content == bun_lock_content

    def test_get_lock_file_name(self, restore_bun: RestoreBunDependencies) -> None:
        assert restore_bun.get_lock_file_name() == BUN_LOCK_FILE_NAME

    def test_get_commands_returns_bun_install(self, restore_bun: RestoreBunDependencies) -> None:
        commands = restore_bun.get_commands('/path/to/package.json')
        assert commands == [['bun', 'install', '--ignore-scripts']]


_BASE_MODULE = 'cycode.cli.files_collector.sca.base_restore_dependencies'


class TestParseBunVersion:
    def test_parses_full_semver(self) -> None:
        assert _parse_bun_version('1.2.3') == (1, 2)

    def test_parses_with_surrounding_whitespace(self) -> None:
        assert _parse_bun_version(' 1.2.0\n') == (1, 2)

    def test_none_input_returns_none(self) -> None:
        assert _parse_bun_version(None) is None

    def test_non_version_string_returns_none(self) -> None:
        assert _parse_bun_version('not-a-version') is None


class TestBunVersionGate:
    def test_supported_version_proceeds_to_restore(self, restore_bun: RestoreBunDependencies, tmp_path: Path) -> None:
        content = '{"name": "test", "packageManager": "bun@1.2.0"}'
        (tmp_path / 'package.json').write_text(content)
        doc = Document(str(tmp_path / 'package.json'), content, absolute_path=str(tmp_path / 'package.json'))

        with (
            patch(f'{_BUN_MODULE}.shell', return_value='1.2.5'),
            patch.object(
                restore_bun.__class__.__bases__[0], 'try_restore_dependencies', return_value=None
            ) as mock_super,
        ):
            restore_bun.try_restore_dependencies(doc)
            mock_super.assert_called_once_with(doc)

    def test_old_version_skips_restore(self, restore_bun: RestoreBunDependencies, tmp_path: Path) -> None:
        content = '{"name": "test", "packageManager": "bun@1.1.0"}'
        (tmp_path / 'package.json').write_text(content)
        doc = Document(str(tmp_path / 'package.json'), content, absolute_path=str(tmp_path / 'package.json'))

        with (
            patch(f'{_BUN_MODULE}.shell', return_value='1.1.38'),
            patch.object(restore_bun.__class__.__bases__[0], 'try_restore_dependencies') as mock_super,
        ):
            result = restore_bun.try_restore_dependencies(doc)
            assert result is None
            mock_super.assert_not_called()

    def test_missing_bun_skips_restore(self, restore_bun: RestoreBunDependencies, tmp_path: Path) -> None:
        content = '{"name": "test", "packageManager": "bun@1.2.0"}'
        (tmp_path / 'package.json').write_text(content)
        doc = Document(str(tmp_path / 'package.json'), content, absolute_path=str(tmp_path / 'package.json'))

        with (
            patch(f'{_BUN_MODULE}.shell', return_value=None),
            patch.object(restore_bun.__class__.__bases__[0], 'try_restore_dependencies') as mock_super,
        ):
            result = restore_bun.try_restore_dependencies(doc)
            assert result is None
            mock_super.assert_not_called()

    def test_existing_lockfile_skips_version_check(self, restore_bun: RestoreBunDependencies, tmp_path: Path) -> None:
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        (tmp_path / 'bun.lock').write_text('{"lockfileVersion": 1}\n')
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))

        with patch(f'{_BUN_MODULE}.shell') as mock_shell:
            result = restore_bun.try_restore_dependencies(doc)
            assert result is not None
            mock_shell.assert_not_called()


class TestCleanup:
    def test_generated_lockfile_is_deleted_after_restore(
        self, restore_bun: RestoreBunDependencies, tmp_path: Path
    ) -> None:
        # bun: no pre-existing bun.lock but package.json indicates bun (supported version installed)
        content = '{"name": "test", "packageManager": "bun@1.2.0"}'
        (tmp_path / 'package.json').write_text(content)
        doc = Document(str(tmp_path / 'package.json'), content, absolute_path=str(tmp_path / 'package.json'))
        lock_path = tmp_path / BUN_LOCK_FILE_NAME

        def side_effect(
            commands: list,
            timeout: int,
            output_file_path: Optional[str] = None,
            working_directory: Optional[str] = None,
        ) -> str:
            lock_path.write_text('{"lockfileVersion": 1}\n')
            return 'output'

        with (
            patch(f'{_BUN_MODULE}.shell', return_value='1.2.5'),
            patch(f'{_BASE_MODULE}.execute_commands', side_effect=side_effect),
        ):
            result = restore_bun.try_restore_dependencies(doc)

        assert result is not None
        assert not lock_path.exists(), f'{BUN_LOCK_FILE_NAME} must be deleted after restore'

    def test_preexisting_lockfile_is_not_deleted(self, restore_bun: RestoreBunDependencies, tmp_path: Path) -> None:
        lock_content = '{"lockfileVersion": 1, "packages": {"pkg": ["pkg@1.0.0", "", {}, ""]}}\n'
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        lock_path = tmp_path / BUN_LOCK_FILE_NAME
        lock_path.write_text(lock_content)
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))

        result = restore_bun.try_restore_dependencies(doc)

        assert result is not None
        assert lock_path.exists(), f'Pre-existing {BUN_LOCK_FILE_NAME} must not be deleted'
