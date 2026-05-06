from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
import typer

from cycode.cli.files_collector.sca.python.restore_uv_dependencies import (
    UV_LOCK_FILE_NAME,
    RestoreUvDependencies,
)
from cycode.cli.models import Document


@pytest.fixture
def mock_ctx(tmp_path: Path) -> typer.Context:
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = {'monitor': False}
    ctx.params = {'path': str(tmp_path)}
    return ctx


@pytest.fixture
def restore_uv(mock_ctx: typer.Context) -> RestoreUvDependencies:
    return RestoreUvDependencies(mock_ctx, is_git_diff=False, command_timeout=30)


class TestIsProject:
    def test_pyproject_toml_with_uv_lock_matches(self, restore_uv: RestoreUvDependencies, tmp_path: Path) -> None:
        (tmp_path / 'pyproject.toml').write_text('[build-system]\nrequires = ["hatchling"]\n')
        (tmp_path / 'uv.lock').write_text('version = 1\n')
        doc = Document(
            str(tmp_path / 'pyproject.toml'),
            '[build-system]\nrequires = ["hatchling"]\n',
            absolute_path=str(tmp_path / 'pyproject.toml'),
        )
        assert restore_uv.is_project(doc) is True

    def test_pyproject_toml_with_tool_uv_section_matches(self, restore_uv: RestoreUvDependencies) -> None:
        content = '[tool.uv]\ndev-dependencies = ["pytest"]\n'
        doc = Document('pyproject.toml', content)
        assert restore_uv.is_project(doc) is True

    def test_pyproject_toml_without_uv_signals_does_not_match(
        self, restore_uv: RestoreUvDependencies, tmp_path: Path
    ) -> None:
        content = '[tool.poetry]\nname = "my-project"\n'
        (tmp_path / 'pyproject.toml').write_text(content)
        doc = Document(
            str(tmp_path / 'pyproject.toml'),
            content,
            absolute_path=str(tmp_path / 'pyproject.toml'),
        )
        assert restore_uv.is_project(doc) is False

    def test_requirements_txt_does_not_match(self, restore_uv: RestoreUvDependencies) -> None:
        doc = Document('requirements.txt', 'requests==2.31.0\n')
        assert restore_uv.is_project(doc) is False

    def test_empty_content_does_not_match(self, restore_uv: RestoreUvDependencies, tmp_path: Path) -> None:
        (tmp_path / 'pyproject.toml').write_text('')
        doc = Document(
            str(tmp_path / 'pyproject.toml'),
            '',
            absolute_path=str(tmp_path / 'pyproject.toml'),
        )
        assert restore_uv.is_project(doc) is False


class TestTryRestoreDependencies:
    def test_existing_uv_lock_returned_directly(self, restore_uv: RestoreUvDependencies, tmp_path: Path) -> None:
        lock_content = 'version = 1\n\n[[package]]\nname = "requests"\n'
        (tmp_path / 'pyproject.toml').write_text('[tool.uv]\n')
        (tmp_path / 'uv.lock').write_text(lock_content)

        doc = Document(
            str(tmp_path / 'pyproject.toml'),
            '[tool.uv]\n',
            absolute_path=str(tmp_path / 'pyproject.toml'),
        )
        result = restore_uv.try_restore_dependencies(doc)

        assert result is not None
        assert UV_LOCK_FILE_NAME in result.path
        assert result.content == lock_content

    def test_get_lock_file_name(self, restore_uv: RestoreUvDependencies) -> None:
        assert restore_uv.get_lock_file_name() == UV_LOCK_FILE_NAME

    def test_get_commands_returns_uv_lock(self, restore_uv: RestoreUvDependencies) -> None:
        commands = restore_uv.get_commands('/path/to/pyproject.toml')
        assert commands == [['uv', 'lock']]


_BASE_MODULE = 'cycode.cli.files_collector.sca.base_restore_dependencies'


class TestCleanup:
    def test_generated_lockfile_is_deleted_after_restore(
        self, restore_uv: RestoreUvDependencies, tmp_path: Path
    ) -> None:
        manifest_content = '[tool.uv]\ndev-dependencies = ["pytest"]\n'
        (tmp_path / 'pyproject.toml').write_text(manifest_content)
        doc = Document(
            str(tmp_path / 'pyproject.toml'), manifest_content, absolute_path=str(tmp_path / 'pyproject.toml')
        )
        lock_path = tmp_path / UV_LOCK_FILE_NAME

        def side_effect(
            commands: list,
            timeout: int,
            output_file_path: Optional[str] = None,
            working_directory: Optional[str] = None,
        ) -> str:
            lock_path.write_text('version = 1\n')
            return 'output'

        with patch(f'{_BASE_MODULE}.execute_commands', side_effect=side_effect):
            result = restore_uv.try_restore_dependencies(doc)

        assert result is not None
        assert not lock_path.exists(), f'{UV_LOCK_FILE_NAME} must be deleted after restore'

    def test_preexisting_lockfile_is_not_deleted(self, restore_uv: RestoreUvDependencies, tmp_path: Path) -> None:
        lock_content = 'version = 1\n\n[[package]]\nname = "requests"\n'
        (tmp_path / 'pyproject.toml').write_text('[tool.uv]\n')
        lock_path = tmp_path / UV_LOCK_FILE_NAME
        lock_path.write_text(lock_content)
        doc = Document(
            str(tmp_path / 'pyproject.toml'),
            '[tool.uv]\n',
            absolute_path=str(tmp_path / 'pyproject.toml'),
        )

        result = restore_uv.try_restore_dependencies(doc)

        assert result is not None
        assert lock_path.exists(), f'Pre-existing {UV_LOCK_FILE_NAME} must not be deleted'
