from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
import typer

from cycode.cli.files_collector.sca.python.restore_pip_dependencies import (
    PIP_LOCK_FILE_NAME,
    RestorePipDependencies,
)
from cycode.cli.models import Document


@pytest.fixture
def mock_ctx(tmp_path: Path) -> typer.Context:
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = {'monitor': False}
    ctx.params = {'path': str(tmp_path)}
    return ctx


@pytest.fixture
def restore_pip(mock_ctx: typer.Context) -> RestorePipDependencies:
    return RestorePipDependencies(mock_ctx, is_git_diff=False, command_timeout=30)


class TestIsProject:
    def test_plain_pyproject_toml_matches(self, restore_pip: RestorePipDependencies) -> None:
        content = '[project]\nname = "my-project"\ndependencies = ["requests"]\n'
        doc = Document('pyproject.toml', content)
        assert restore_pip.is_project(doc) is True

    def test_pyproject_toml_with_poetry_section_does_not_match(self, restore_pip: RestorePipDependencies) -> None:
        content = '[tool.poetry]\nname = "my-project"\n'
        doc = Document('pyproject.toml', content)
        assert restore_pip.is_project(doc) is False

    def test_pyproject_toml_with_uv_section_does_not_match(self, restore_pip: RestorePipDependencies) -> None:
        content = '[tool.uv]\nindex-url = "https://example.com"\n'
        doc = Document('pyproject.toml', content)
        assert restore_pip.is_project(doc) is False

    def test_pyproject_toml_with_existing_pylock_matches(
        self, restore_pip: RestorePipDependencies, tmp_path: Path
    ) -> None:
        (tmp_path / 'pyproject.toml').write_text('[project]\nname = "test"\n')
        (tmp_path / PIP_LOCK_FILE_NAME).write_text('lock-version = "1.0"\n')
        doc = Document(
            str(tmp_path / 'pyproject.toml'),
            '[project]\nname = "test"\n',
            absolute_path=str(tmp_path / 'pyproject.toml'),
        )
        assert restore_pip.is_project(doc) is True

    def test_requirements_txt_matches(self, restore_pip: RestorePipDependencies) -> None:
        doc = Document('requirements.txt', 'requests==2.31.0\n')
        assert restore_pip.is_project(doc) is True

    def test_setup_py_does_not_match(self, restore_pip: RestorePipDependencies) -> None:
        doc = Document('setup.py', 'from setuptools import setup\nsetup()\n')
        assert restore_pip.is_project(doc) is False

    def test_empty_pyproject_toml_does_not_match(self, restore_pip: RestorePipDependencies) -> None:
        # Same conservative behavior as Poetry/Uv's own is_project: empty content can't be
        # confirmed as plain-pip, so don't claim it.
        doc = Document('pyproject.toml', '')
        assert restore_pip.is_project(doc) is False


class TestGetCommands:
    def test_get_commands_for_pyproject_toml(self, restore_pip: RestorePipDependencies) -> None:
        commands = restore_pip.get_commands('/path/to/pyproject.toml')
        assert commands == [['pip', 'lock', '.']]

    def test_get_commands_for_requirements_txt(self, restore_pip: RestorePipDependencies) -> None:
        commands = restore_pip.get_commands('/path/to/requirements.txt')
        assert commands == [['pip', 'lock', '-r', 'requirements.txt', '-o', PIP_LOCK_FILE_NAME]]

    def test_get_lock_file_name(self, restore_pip: RestorePipDependencies) -> None:
        assert restore_pip.get_lock_file_name() == PIP_LOCK_FILE_NAME


class TestTryRestoreDependencies:
    def test_existing_pylock_returned_directly_for_pyproject_toml(
        self, restore_pip: RestorePipDependencies, tmp_path: Path
    ) -> None:
        lock_content = 'lock-version = "1.0"\n\n[[packages]]\nname = "requests"\n'
        (tmp_path / 'pyproject.toml').write_text('[project]\nname = "test"\n')
        (tmp_path / PIP_LOCK_FILE_NAME).write_text(lock_content)

        doc = Document(
            str(tmp_path / 'pyproject.toml'),
            '[project]\nname = "test"\n',
            absolute_path=str(tmp_path / 'pyproject.toml'),
        )
        result = restore_pip.try_restore_dependencies(doc)

        assert result is not None
        assert PIP_LOCK_FILE_NAME in result.path
        assert result.content == lock_content

    def test_existing_pylock_returned_directly_for_requirements_txt(
        self, restore_pip: RestorePipDependencies, tmp_path: Path
    ) -> None:
        lock_content = 'lock-version = "1.0"\n\n[[packages]]\nname = "requests"\n'
        (tmp_path / 'requirements.txt').write_text('requests==2.31.0\n')
        (tmp_path / PIP_LOCK_FILE_NAME).write_text(lock_content)

        doc = Document(
            str(tmp_path / 'requirements.txt'),
            'requests==2.31.0\n',
            absolute_path=str(tmp_path / 'requirements.txt'),
        )
        result = restore_pip.try_restore_dependencies(doc)

        assert result is not None
        assert result.content == lock_content


_BASE_MODULE = 'cycode.cli.files_collector.sca.base_restore_dependencies'


class TestRestoreWithoutExistingLock:
    def test_pyproject_toml_runs_pip_lock_dot(self, restore_pip: RestorePipDependencies, tmp_path: Path) -> None:
        manifest_content = '[project]\nname = "test"\ndependencies = ["requests"]\n'
        (tmp_path / 'pyproject.toml').write_text(manifest_content)
        doc = Document(
            str(tmp_path / 'pyproject.toml'), manifest_content, absolute_path=str(tmp_path / 'pyproject.toml')
        )

        seen_commands = []

        def side_effect(
            commands: list,
            timeout: int,
            output_file_path: Optional[str] = None,
            working_directory: Optional[str] = None,
        ) -> str:
            seen_commands.extend(commands)
            (tmp_path / PIP_LOCK_FILE_NAME).write_text('lock-version = "1.0"\n')
            return 'output'

        with patch(f'{_BASE_MODULE}.execute_commands', side_effect=side_effect):
            result = restore_pip.try_restore_dependencies(doc)

        assert result is not None
        assert seen_commands == [['pip', 'lock', '.']]

    def test_requirements_txt_runs_pip_lock_dash_r(self, restore_pip: RestorePipDependencies, tmp_path: Path) -> None:
        (tmp_path / 'requirements.txt').write_text('requests==2.31.0\n')
        doc = Document(
            str(tmp_path / 'requirements.txt'),
            'requests==2.31.0\n',
            absolute_path=str(tmp_path / 'requirements.txt'),
        )

        seen_commands = []

        def side_effect(
            commands: list,
            timeout: int,
            output_file_path: Optional[str] = None,
            working_directory: Optional[str] = None,
        ) -> str:
            seen_commands.extend(commands)
            (tmp_path / PIP_LOCK_FILE_NAME).write_text('lock-version = "1.0"\n')
            return 'output'

        with patch(f'{_BASE_MODULE}.execute_commands', side_effect=side_effect):
            result = restore_pip.try_restore_dependencies(doc)

        assert result is not None
        assert seen_commands == [['pip', 'lock', '-r', 'requirements.txt', '-o', PIP_LOCK_FILE_NAME]]


class TestCleanup:
    def test_generated_lockfile_is_deleted_after_restore(
        self, restore_pip: RestorePipDependencies, tmp_path: Path
    ) -> None:
        manifest_content = '[project]\nname = "test"\ndependencies = ["requests"]\n'
        (tmp_path / 'pyproject.toml').write_text(manifest_content)
        doc = Document(
            str(tmp_path / 'pyproject.toml'), manifest_content, absolute_path=str(tmp_path / 'pyproject.toml')
        )
        lock_path = tmp_path / PIP_LOCK_FILE_NAME

        def side_effect(
            commands: list,
            timeout: int,
            output_file_path: Optional[str] = None,
            working_directory: Optional[str] = None,
        ) -> str:
            lock_path.write_text('lock-version = "1.0"\n')
            return 'output'

        with patch(f'{_BASE_MODULE}.execute_commands', side_effect=side_effect):
            result = restore_pip.try_restore_dependencies(doc)

        assert result is not None
        assert not lock_path.exists(), f'{PIP_LOCK_FILE_NAME} must be deleted after restore'

    def test_preexisting_lockfile_is_not_deleted(self, restore_pip: RestorePipDependencies, tmp_path: Path) -> None:
        lock_content = 'lock-version = "1.0"\n'
        (tmp_path / 'pyproject.toml').write_text('[project]\nname = "test"\n')
        lock_path = tmp_path / PIP_LOCK_FILE_NAME
        lock_path.write_text(lock_content)
        doc = Document(
            str(tmp_path / 'pyproject.toml'),
            '[project]\nname = "test"\n',
            absolute_path=str(tmp_path / 'pyproject.toml'),
        )

        result = restore_pip.try_restore_dependencies(doc)

        assert result is not None
        assert lock_path.exists(), f'Pre-existing {PIP_LOCK_FILE_NAME} must not be deleted'
