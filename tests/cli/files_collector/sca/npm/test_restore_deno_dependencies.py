from pathlib import Path
from unittest.mock import MagicMock

import pytest
import typer

from cycode.cli.files_collector.sca.npm.restore_deno_dependencies import (
    DENO_LOCK_FILE_NAME,
    DENO_MANIFEST_FILE_NAMES,
    RestoreDenoDependencies,
)
from cycode.cli.models import Document


@pytest.fixture
def mock_ctx(tmp_path: Path) -> typer.Context:
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = {'monitor': False}
    ctx.params = {'path': str(tmp_path)}
    return ctx


@pytest.fixture
def restore_deno(mock_ctx: typer.Context) -> RestoreDenoDependencies:
    return RestoreDenoDependencies(mock_ctx, is_git_diff=False, command_timeout=30)


class TestIsProject:
    @pytest.mark.parametrize('filename', DENO_MANIFEST_FILE_NAMES)
    def test_deno_manifest_files_match(self, restore_deno: RestoreDenoDependencies, filename: str) -> None:
        doc = Document(filename, '{}')
        assert restore_deno.is_project(doc) is True

    @pytest.mark.parametrize('filename', ['package.json', 'tsconfig.json', 'deno.ts', 'main.ts', 'deno.lock'])
    def test_non_deno_manifest_files_do_not_match(self, restore_deno: RestoreDenoDependencies, filename: str) -> None:
        doc = Document(filename, '')
        assert restore_deno.is_project(doc) is False


class TestTryRestoreDependencies:
    def test_existing_deno_lock_returned(self, restore_deno: RestoreDenoDependencies, tmp_path: Path) -> None:
        deno_lock_content = '{"version": "3", "packages": {}}'
        (tmp_path / 'deno.json').write_text('{"imports": {}}')
        (tmp_path / 'deno.lock').write_text(deno_lock_content)

        doc = Document(str(tmp_path / 'deno.json'), '{"imports": {}}', absolute_path=str(tmp_path / 'deno.json'))
        result = restore_deno.try_restore_dependencies(doc)

        assert result is not None
        assert DENO_LOCK_FILE_NAME in result.path
        assert result.content == deno_lock_content

    def test_no_deno_lock_returns_none(self, restore_deno: RestoreDenoDependencies, tmp_path: Path) -> None:
        (tmp_path / 'deno.json').write_text('{"imports": {}}')

        doc = Document(str(tmp_path / 'deno.json'), '{"imports": {}}', absolute_path=str(tmp_path / 'deno.json'))
        result = restore_deno.try_restore_dependencies(doc)

        assert result is None

    def test_get_lock_file_name(self, restore_deno: RestoreDenoDependencies) -> None:
        assert restore_deno.get_lock_file_name() == DENO_LOCK_FILE_NAME

    def test_get_commands_returns_empty(self, restore_deno: RestoreDenoDependencies) -> None:
        assert restore_deno.get_commands('/path/to/deno.json') == []
