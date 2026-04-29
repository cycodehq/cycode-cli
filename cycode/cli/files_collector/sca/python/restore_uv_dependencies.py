from pathlib import Path
from typing import Optional

import typer

from cycode.cli.files_collector.sca.base_restore_dependencies import BaseRestoreDependencies, build_dep_tree_path
from cycode.cli.models import Document
from cycode.cli.utils.path_utils import get_file_content
from cycode.logger import get_logger

logger = get_logger('UV Restore Dependencies')

UV_MANIFEST_FILE_NAME = 'pyproject.toml'
UV_LOCK_FILE_NAME = 'uv.lock'

_UV_TOOL_SECTION = '[tool.uv]'


def _indicates_uv(pyproject_content: Optional[str]) -> bool:
    """Return True if pyproject.toml content signals that this project uses UV."""
    if not pyproject_content:
        return False
    return _UV_TOOL_SECTION in pyproject_content


class RestoreUvDependencies(BaseRestoreDependencies):
    def __init__(self, ctx: typer.Context, is_git_diff: bool, command_timeout: int) -> None:
        super().__init__(ctx, is_git_diff, command_timeout)

    def is_project(self, document: Document) -> bool:
        if Path(document.path).name != UV_MANIFEST_FILE_NAME:
            return False

        manifest_dir = self.get_manifest_dir(document)
        if manifest_dir and (Path(manifest_dir) / UV_LOCK_FILE_NAME).is_file():
            return True

        return _indicates_uv(document.content)

    def try_restore_dependencies(self, document: Document) -> Optional[Document]:
        manifest_dir = self.get_manifest_dir(document)
        lockfile_path = Path(manifest_dir) / UV_LOCK_FILE_NAME if manifest_dir else None

        if lockfile_path and lockfile_path.is_file():
            content = get_file_content(str(lockfile_path))
            relative_path = build_dep_tree_path(document.path, UV_LOCK_FILE_NAME)
            logger.debug('Using existing uv.lock, %s', {'path': str(lockfile_path)})
            return Document(relative_path, content, self.is_git_diff)

        return super().try_restore_dependencies(document)

    def get_commands(self, manifest_file_path: str) -> list[list[str]]:
        return [['uv', 'lock']]

    def get_lock_file_name(self) -> str:
        return UV_LOCK_FILE_NAME

    def get_lock_file_names(self) -> list[str]:
        return [UV_LOCK_FILE_NAME]
