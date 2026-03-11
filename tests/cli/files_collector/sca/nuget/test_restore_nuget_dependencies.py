from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
import typer

from cycode.cli.files_collector.sca.nuget.restore_nuget_dependencies import (
    NUGET_LOCK_FILE_NAME,
    RestoreNugetDependencies,
)
from cycode.cli.models import Document

_BASE_MODULE = 'cycode.cli.files_collector.sca.base_restore_dependencies'


@pytest.fixture
def mock_ctx(tmp_path: Path) -> typer.Context:
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = {'monitor': False}
    ctx.params = {'path': str(tmp_path)}
    return ctx


@pytest.fixture
def restore_nuget(mock_ctx: typer.Context) -> RestoreNugetDependencies:
    return RestoreNugetDependencies(mock_ctx, is_git_diff=False, command_timeout=30)


class TestIsProject:
    def test_csproj_matches(self, restore_nuget: RestoreNugetDependencies) -> None:
        doc = Document('MyProject.csproj', '<Project Sdk="Microsoft.NET.Sdk"/>')
        assert restore_nuget.is_project(doc) is True

    def test_vbproj_matches(self, restore_nuget: RestoreNugetDependencies) -> None:
        doc = Document('MyProject.vbproj', '<Project Sdk="Microsoft.NET.Sdk"/>')
        assert restore_nuget.is_project(doc) is True

    def test_sln_does_not_match(self, restore_nuget: RestoreNugetDependencies) -> None:
        doc = Document('MySolution.sln', '')
        assert restore_nuget.is_project(doc) is False

    def test_packages_json_does_not_match(self, restore_nuget: RestoreNugetDependencies) -> None:
        doc = Document('packages.json', '{}')
        assert restore_nuget.is_project(doc) is False


class TestCleanup:
    def test_generated_lockfile_is_deleted_after_restore(
        self, restore_nuget: RestoreNugetDependencies, tmp_path: Path
    ) -> None:
        (tmp_path / 'MyProject.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"/>')
        doc = Document(
            str(tmp_path / 'MyProject.csproj'),
            '<Project Sdk="Microsoft.NET.Sdk"/>',
            absolute_path=str(tmp_path / 'MyProject.csproj'),
        )
        lock_path = tmp_path / NUGET_LOCK_FILE_NAME

        def side_effect(
            commands: list,
            timeout: int,
            output_file_path: Optional[str] = None,
            working_directory: Optional[str] = None,
        ) -> str:
            lock_path.write_text('{"version": 1, "dependencies": {}}')
            return 'output'

        with patch(f'{_BASE_MODULE}.execute_commands', side_effect=side_effect):
            result = restore_nuget.try_restore_dependencies(doc)

        assert result is not None
        assert not lock_path.exists(), f'{NUGET_LOCK_FILE_NAME} must be deleted after restore'

    def test_preexisting_lockfile_is_not_deleted(self, restore_nuget: RestoreNugetDependencies, tmp_path: Path) -> None:
        lock_content = '{"version": 1, "dependencies": {"net8.0": {}}}'
        (tmp_path / 'MyProject.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"/>')
        lock_path = tmp_path / NUGET_LOCK_FILE_NAME
        lock_path.write_text(lock_content)
        doc = Document(
            str(tmp_path / 'MyProject.csproj'),
            '<Project Sdk="Microsoft.NET.Sdk"/>',
            absolute_path=str(tmp_path / 'MyProject.csproj'),
        )

        result = restore_nuget.try_restore_dependencies(doc)

        assert result is not None
        assert lock_path.exists(), f'Pre-existing {NUGET_LOCK_FILE_NAME} must not be deleted'
