from pathlib import Path
from typing import Optional

import typer

from cycode.cli.files_collector.sca.base_restore_dependencies import BaseRestoreDependencies, build_dep_tree_path
from cycode.cli.models import Document
from cycode.cli.utils.path_utils import get_file_content
from cycode.logger import get_logger

logger = get_logger('Pip Restore Dependencies')

PIP_PYPROJECT_MANIFEST_FILE_NAME = 'pyproject.toml'
PIP_REQUIREMENTS_MANIFEST_FILE_NAME = 'requirements.txt'
PIP_LOCK_FILE_NAME = 'pylock.toml'

_POETRY_TOOL_SECTION = '[tool.poetry]'
_UV_TOOL_SECTION = '[tool.uv]'


def _indicates_plain_pip(pyproject_content: Optional[str]) -> bool:
    """Return True if pyproject.toml content signals a plain-pip project (no Poetry, no uv)."""
    if not pyproject_content:
        return False
    return _POETRY_TOOL_SECTION not in pyproject_content and _UV_TOOL_SECTION not in pyproject_content


class RestorePipDependencies(BaseRestoreDependencies):
    def __init__(self, ctx: typer.Context, is_git_diff: bool, command_timeout: int) -> None:
        super().__init__(ctx, is_git_diff, command_timeout)

    def is_project(self, document: Document) -> bool:
        manifest_name = Path(document.path).name

        if manifest_name == PIP_REQUIREMENTS_MANIFEST_FILE_NAME:
            return True

        if manifest_name != PIP_PYPROJECT_MANIFEST_FILE_NAME:
            return False

        manifest_dir = self.get_manifest_dir(document)
        if manifest_dir and (Path(manifest_dir) / PIP_LOCK_FILE_NAME).is_file():
            return True

        return _indicates_plain_pip(document.content)

    def try_restore_dependencies(self, document: Document) -> Optional[Document]:
        manifest_dir = self.get_manifest_dir(document)
        lockfile_path = Path(manifest_dir) / PIP_LOCK_FILE_NAME if manifest_dir else None

        if lockfile_path and lockfile_path.is_file():
            content = get_file_content(str(lockfile_path))
            relative_path = build_dep_tree_path(document.path, PIP_LOCK_FILE_NAME)
            logger.debug('Using existing pylock.toml, %s', {'path': str(lockfile_path)})
            return Document(relative_path, content, self.is_git_diff)

        return super().try_restore_dependencies(document)

    def get_commands(self, manifest_file_path: str) -> list[list[str]]:
        if Path(manifest_file_path).name == PIP_REQUIREMENTS_MANIFEST_FILE_NAME:
            return [['pip', 'lock', '-r', 'requirements.txt', '-o', PIP_LOCK_FILE_NAME]]

        return [['pip', 'lock', '.']]

    def get_lock_file_name(self) -> str:
        return PIP_LOCK_FILE_NAME

    def get_lock_file_names(self) -> list[str]:
        return [PIP_LOCK_FILE_NAME]
