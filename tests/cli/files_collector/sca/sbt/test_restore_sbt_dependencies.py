from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
import typer

from cycode.cli.files_collector.sca.sbt.restore_sbt_dependencies import (
    SBT_LOCK_FILE_NAME,
    RestoreSbtDependencies,
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
def restore_sbt(mock_ctx: typer.Context) -> RestoreSbtDependencies:
    return RestoreSbtDependencies(mock_ctx, is_git_diff=False, command_timeout=30)


class TestIsProject:
    def test_sbt_file_matches(self, restore_sbt: RestoreSbtDependencies) -> None:
        doc = Document('build.sbt', 'name := "my-project"\n')
        assert restore_sbt.is_project(doc) is True

    def test_sbt_in_subdir_matches(self, restore_sbt: RestoreSbtDependencies) -> None:
        doc = Document('myapp/build.sbt', 'name := "my-project"\n')
        assert restore_sbt.is_project(doc) is True

    def test_build_gradle_does_not_match(self, restore_sbt: RestoreSbtDependencies) -> None:
        doc = Document('build.gradle', '')
        assert restore_sbt.is_project(doc) is False

    def test_pom_xml_does_not_match(self, restore_sbt: RestoreSbtDependencies) -> None:
        doc = Document('pom.xml', '<project/>')
        assert restore_sbt.is_project(doc) is False


class TestCleanup:
    def test_generated_lockfile_is_deleted_after_restore(
        self, restore_sbt: RestoreSbtDependencies, tmp_path: Path
    ) -> None:
        (tmp_path / 'build.sbt').write_text('name := "test"\n')
        doc = Document(
            str(tmp_path / 'build.sbt'),
            'name := "test"\n',
            absolute_path=str(tmp_path / 'build.sbt'),
        )
        lock_path = tmp_path / SBT_LOCK_FILE_NAME

        def side_effect(
            commands: list,
            timeout: int,
            output_file_path: Optional[str] = None,
            working_directory: Optional[str] = None,
        ) -> str:
            lock_path.write_text('[{"org": "org.typelevel", "name": "cats-core", "version": "2.10.0"}]')
            return 'output'

        with patch(f'{_BASE_MODULE}.execute_commands', side_effect=side_effect):
            result = restore_sbt.try_restore_dependencies(doc)

        assert result is not None
        assert not lock_path.exists(), f'{SBT_LOCK_FILE_NAME} must be deleted after restore'

    def test_preexisting_lockfile_is_not_deleted(self, restore_sbt: RestoreSbtDependencies, tmp_path: Path) -> None:
        lock_content = '[{"org": "org.typelevel", "name": "cats-core", "version": "2.10.0"}]'
        (tmp_path / 'build.sbt').write_text('name := "test"\n')
        lock_path = tmp_path / SBT_LOCK_FILE_NAME
        lock_path.write_text(lock_content)
        doc = Document(
            str(tmp_path / 'build.sbt'),
            'name := "test"\n',
            absolute_path=str(tmp_path / 'build.sbt'),
        )

        result = restore_sbt.try_restore_dependencies(doc)

        assert result is not None
        assert lock_path.exists(), f'Pre-existing {SBT_LOCK_FILE_NAME} must not be deleted'
