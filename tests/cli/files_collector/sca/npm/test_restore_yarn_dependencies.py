from pathlib import Path
from unittest.mock import MagicMock

import pytest
import typer

from cycode.cli.files_collector.sca.npm.restore_yarn_dependencies import (
    YARN_LOCK_FILE_NAME,
    RestoreYarnDependencies,
)
from cycode.cli.models import Document


@pytest.fixture
def mock_ctx(tmp_path: Path) -> typer.Context:
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = {'monitor': False}
    ctx.params = {'path': str(tmp_path)}
    return ctx


@pytest.fixture
def restore_yarn(mock_ctx: typer.Context) -> RestoreYarnDependencies:
    return RestoreYarnDependencies(mock_ctx, is_git_diff=False, command_timeout=30)


class TestIsProject:
    def test_package_json_with_yarn_lock_matches(self, restore_yarn: RestoreYarnDependencies, tmp_path: Path) -> None:
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        (tmp_path / 'yarn.lock').write_text('# yarn lockfile v1\n')
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))
        assert restore_yarn.is_project(doc) is True

    def test_package_json_with_package_manager_yarn_matches(self, restore_yarn: RestoreYarnDependencies) -> None:
        content = '{"name": "test", "packageManager": "yarn@4.0.2"}'
        doc = Document('package.json', content)
        assert restore_yarn.is_project(doc) is True

    def test_package_json_with_engines_yarn_matches(self, restore_yarn: RestoreYarnDependencies) -> None:
        content = '{"name": "test", "engines": {"yarn": ">=1.22"}}'
        doc = Document('package.json', content)
        assert restore_yarn.is_project(doc) is True

    def test_package_json_with_no_yarn_signal_does_not_match(
        self, restore_yarn: RestoreYarnDependencies, tmp_path: Path
    ) -> None:
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))
        assert restore_yarn.is_project(doc) is False

    def test_package_json_with_pnpm_lock_does_not_match(
        self, restore_yarn: RestoreYarnDependencies, tmp_path: Path
    ) -> None:
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        (tmp_path / 'pnpm-lock.yaml').write_text('lockfileVersion: 5.4\n')
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))
        assert restore_yarn.is_project(doc) is False

    def test_tsconfig_json_does_not_match(self, restore_yarn: RestoreYarnDependencies) -> None:
        doc = Document('tsconfig.json', '{"compilerOptions": {}}')
        assert restore_yarn.is_project(doc) is False

    def test_package_manager_npm_does_not_match(self, restore_yarn: RestoreYarnDependencies) -> None:
        content = '{"name": "test", "packageManager": "npm@9.0.0"}'
        doc = Document('package.json', content)
        assert restore_yarn.is_project(doc) is False

    def test_invalid_json_content_does_not_match(self, restore_yarn: RestoreYarnDependencies) -> None:
        doc = Document('package.json', 'not valid json')
        assert restore_yarn.is_project(doc) is False


class TestTryRestoreDependencies:
    def test_existing_yarn_lock_returned_directly(self, restore_yarn: RestoreYarnDependencies, tmp_path: Path) -> None:
        yarn_lock_content = '# yarn lockfile v1\n\npackage@1.0.0:\n  resolved "https://example.com"\n'
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        (tmp_path / 'yarn.lock').write_text(yarn_lock_content)

        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))
        result = restore_yarn.try_restore_dependencies(doc)

        assert result is not None
        assert YARN_LOCK_FILE_NAME in result.path
        assert result.content == yarn_lock_content

    def test_get_lock_file_name(self, restore_yarn: RestoreYarnDependencies) -> None:
        assert restore_yarn.get_lock_file_name() == YARN_LOCK_FILE_NAME

    def test_get_commands_returns_yarn_install(self, restore_yarn: RestoreYarnDependencies) -> None:
        commands = restore_yarn.get_commands('/path/to/package.json')
        assert commands == [['yarn', 'install', '--ignore-scripts']]
