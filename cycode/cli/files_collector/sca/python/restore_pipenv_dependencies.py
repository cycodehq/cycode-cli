from pathlib import Path
from typing import Optional

import typer

from cycode.cli.files_collector.sca.base_restore_dependencies import BaseRestoreDependencies, build_dep_tree_path
from cycode.cli.models import Document
from cycode.cli.utils.path_utils import get_file_content
from cycode.logger import get_logger

logger = get_logger('Pipenv Restore Dependencies')

PIPENV_MANIFEST_FILE_NAME = 'Pipfile'
PIPENV_LOCK_FILE_NAME = 'Pipfile.lock'


class RestorePipenvDependencies(BaseRestoreDependencies):
    def __init__(self, ctx: typer.Context, is_git_diff: bool, command_timeout: int) -> None:
        super().__init__(ctx, is_git_diff, command_timeout)

    def is_project(self, document: Document) -> bool:
        return Path(document.path).name == PIPENV_MANIFEST_FILE_NAME

    def try_restore_dependencies(self, document: Document) -> Optional[Document]:
        manifest_dir = self.get_manifest_dir(document)
        lockfile_path = Path(manifest_dir) / PIPENV_LOCK_FILE_NAME if manifest_dir else None

        if lockfile_path and lockfile_path.is_file():
            # Lockfile already exists — read it directly without running pipenv
            content = get_file_content(str(lockfile_path))
            relative_path = build_dep_tree_path(document.path, PIPENV_LOCK_FILE_NAME)
            logger.debug('Using existing Pipfile.lock, %s', {'path': str(lockfile_path)})
            return Document(relative_path, content, self.is_git_diff)

        # Lockfile absent — generate it
        return super().try_restore_dependencies(document)

    def get_commands(self, manifest_file_path: str) -> list[list[str]]:
        return [['pipenv', 'lock']]

    def get_lock_file_name(self) -> str:
        return PIPENV_LOCK_FILE_NAME

    def get_lock_file_names(self) -> list[str]:
        return [PIPENV_LOCK_FILE_NAME]
