from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
import typer

from cycode.cli.files_collector.sca.go.restore_go_dependencies import (
    GO_RESTORE_FILE_NAME,
    RestoreGoDependencies,
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
def restore_go(mock_ctx: typer.Context) -> RestoreGoDependencies:
    return RestoreGoDependencies(mock_ctx, is_git_diff=False, command_timeout=30)


class TestIsProject:
    def test_go_mod_matches(self, restore_go: RestoreGoDependencies) -> None:
        doc = Document('go.mod', 'module example.com/mymod\ngo 1.21\n')
        assert restore_go.is_project(doc) is True

    def test_go_sum_matches(self, restore_go: RestoreGoDependencies) -> None:
        doc = Document('go.sum', 'github.com/pkg/errors v0.9.1 h1:...\n')
        assert restore_go.is_project(doc) is True

    def test_go_in_subdir_matches(self, restore_go: RestoreGoDependencies) -> None:
        doc = Document('myapp/go.mod', 'module example.com/mymod\n')
        assert restore_go.is_project(doc) is True

    def test_pom_xml_does_not_match(self, restore_go: RestoreGoDependencies) -> None:
        doc = Document('pom.xml', '<project/>')
        assert restore_go.is_project(doc) is False


class TestCleanup:
    def test_generated_output_file_is_deleted_after_restore(
        self, restore_go: RestoreGoDependencies, tmp_path: Path
    ) -> None:
        # Go handler requires both go.mod and go.sum to be present
        (tmp_path / 'go.mod').write_text('module example.com/test\ngo 1.21\n')
        (tmp_path / 'go.sum').write_text('github.com/pkg/errors v0.9.1 h1:abc\n')
        doc = Document(
            str(tmp_path / 'go.mod'),
            'module example.com/test\ngo 1.21\n',
            absolute_path=str(tmp_path / 'go.mod'),
        )
        output_path = tmp_path / GO_RESTORE_FILE_NAME

        def side_effect(
            commands: list,
            timeout: int,
            output_file_path: Optional[str] = None,
            working_directory: Optional[str] = None,
        ) -> str:
            # Go uses create_output_file_manually=True; output_file_path is provided
            target = output_file_path or str(output_path)
            Path(target).write_text('example.com/test github.com/pkg/errors@v0.9.1\n')
            return 'graph output'

        with patch(f'{_BASE_MODULE}.execute_commands', side_effect=side_effect):
            result = restore_go.try_restore_dependencies(doc)

        assert result is not None
        assert not output_path.exists(), f'{GO_RESTORE_FILE_NAME} must be deleted after restore'

    def test_missing_go_sum_returns_none(self, restore_go: RestoreGoDependencies, tmp_path: Path) -> None:
        (tmp_path / 'go.mod').write_text('module example.com/test\ngo 1.21\n')
        # go.sum intentionally absent
        doc = Document(
            str(tmp_path / 'go.mod'),
            'module example.com/test\ngo 1.21\n',
            absolute_path=str(tmp_path / 'go.mod'),
        )

        result = restore_go.try_restore_dependencies(doc)

        assert result is None
