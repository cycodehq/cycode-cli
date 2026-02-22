from pathlib import Path
from unittest.mock import MagicMock

import pytest
import typer

from cycode.cli.files_collector.sca.python.restore_pipenv_dependencies import (
    PIPENV_LOCK_FILE_NAME,
    RestorePipenvDependencies,
)
from cycode.cli.models import Document


@pytest.fixture
def mock_ctx(tmp_path: Path) -> typer.Context:
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = {'monitor': False}
    ctx.params = {'path': str(tmp_path)}
    return ctx


@pytest.fixture
def restore_pipenv(mock_ctx: typer.Context) -> RestorePipenvDependencies:
    return RestorePipenvDependencies(mock_ctx, is_git_diff=False, command_timeout=30)


class TestIsProject:
    def test_pipfile_matches(self, restore_pipenv: RestorePipenvDependencies) -> None:
        doc = Document('Pipfile', '[[source]]\nname = "pypi"\n')
        assert restore_pipenv.is_project(doc) is True

    def test_pipfile_in_subdir_matches(self, restore_pipenv: RestorePipenvDependencies) -> None:
        doc = Document('myapp/Pipfile', '[[source]]\nname = "pypi"\n')
        assert restore_pipenv.is_project(doc) is True

    def test_pipfile_lock_does_not_match(self, restore_pipenv: RestorePipenvDependencies) -> None:
        doc = Document('Pipfile.lock', '{"default": {}}\n')
        assert restore_pipenv.is_project(doc) is False

    def test_requirements_txt_does_not_match(self, restore_pipenv: RestorePipenvDependencies) -> None:
        doc = Document('requirements.txt', 'requests==2.31.0\n')
        assert restore_pipenv.is_project(doc) is False

    def test_pyproject_toml_does_not_match(self, restore_pipenv: RestorePipenvDependencies) -> None:
        doc = Document('pyproject.toml', '[build-system]\nrequires = ["setuptools"]\n')
        assert restore_pipenv.is_project(doc) is False


class TestTryRestoreDependencies:
    def test_existing_pipfile_lock_returned_directly(
        self, restore_pipenv: RestorePipenvDependencies, tmp_path: Path
    ) -> None:
        lock_content = '{"_meta": {"hash": {"sha256": "abc"}}, "default": {}, "develop": {}}\n'
        (tmp_path / 'Pipfile').write_text('[[source]]\nname = "pypi"\n')
        (tmp_path / 'Pipfile.lock').write_text(lock_content)

        doc = Document(
            str(tmp_path / 'Pipfile'),
            '[[source]]\nname = "pypi"\n',
            absolute_path=str(tmp_path / 'Pipfile'),
        )
        result = restore_pipenv.try_restore_dependencies(doc)

        assert result is not None
        assert PIPENV_LOCK_FILE_NAME in result.path
        assert result.content == lock_content

    def test_get_lock_file_name(self, restore_pipenv: RestorePipenvDependencies) -> None:
        assert restore_pipenv.get_lock_file_name() == PIPENV_LOCK_FILE_NAME

    def test_get_commands_returns_pipenv_lock(self, restore_pipenv: RestorePipenvDependencies) -> None:
        commands = restore_pipenv.get_commands('/path/to/Pipfile')
        assert commands == [['pipenv', 'lock']]
