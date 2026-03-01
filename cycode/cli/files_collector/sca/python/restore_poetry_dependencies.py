from pathlib import Path
from typing import Optional

import typer

from cycode.cli.files_collector.sca.base_restore_dependencies import BaseRestoreDependencies, build_dep_tree_path
from cycode.cli.models import Document
from cycode.cli.utils.path_utils import get_file_content
from cycode.logger import get_logger

logger = get_logger('Poetry Restore Dependencies')

POETRY_MANIFEST_FILE_NAME = 'pyproject.toml'
POETRY_LOCK_FILE_NAME = 'poetry.lock'

# Section header that signals this pyproject.toml is managed by Poetry
_POETRY_TOOL_SECTION = '[tool.poetry]'


def _indicates_poetry(pyproject_content: Optional[str]) -> bool:
    """Return True if pyproject.toml content signals that this project uses Poetry."""
    if not pyproject_content:
        return False
    return _POETRY_TOOL_SECTION in pyproject_content


class RestorePoetryDependencies(BaseRestoreDependencies):
    def __init__(self, ctx: typer.Context, is_git_diff: bool, command_timeout: int) -> None:
        super().__init__(ctx, is_git_diff, command_timeout)

    def is_project(self, document: Document) -> bool:
        if Path(document.path).name != POETRY_MANIFEST_FILE_NAME:
            return False

        manifest_dir = self.get_manifest_dir(document)
        if manifest_dir and (Path(manifest_dir) / POETRY_LOCK_FILE_NAME).is_file():
            return True

        return _indicates_poetry(document.content)

    def try_restore_dependencies(self, document: Document) -> Optional[Document]:
        manifest_dir = self.get_manifest_dir(document)
        lockfile_path = Path(manifest_dir) / POETRY_LOCK_FILE_NAME if manifest_dir else None

        if lockfile_path and lockfile_path.is_file():
            # Lockfile already exists — read it directly without running poetry
            content = get_file_content(str(lockfile_path))
            relative_path = build_dep_tree_path(document.path, POETRY_LOCK_FILE_NAME)
            logger.debug('Using existing poetry.lock, %s', {'path': str(lockfile_path)})
            return Document(relative_path, content, self.is_git_diff)

        # Lockfile absent but Poetry is indicated in pyproject.toml — generate it
        return super().try_restore_dependencies(document)

    def get_commands(self, manifest_file_path: str) -> list[list[str]]:
        return [['poetry', 'lock']]

    def get_lock_file_name(self) -> str:
        return POETRY_LOCK_FILE_NAME

    def get_lock_file_names(self) -> list[str]:
        return [POETRY_LOCK_FILE_NAME]
