from pathlib import Path
from typing import Optional

import typer

from cycode.cli.files_collector.sca.base_restore_dependencies import BaseRestoreDependencies, build_dep_tree_path
from cycode.cli.models import Document
from cycode.cli.utils.path_utils import get_file_content
from cycode.logger import get_logger

logger = get_logger('Deno Restore Dependencies')

DENO_MANIFEST_FILE_NAMES = ('deno.json', 'deno.jsonc')
DENO_LOCK_FILE_NAME = 'deno.lock'


class RestoreDenoDependencies(BaseRestoreDependencies):
    def __init__(self, ctx: typer.Context, is_git_diff: bool, command_timeout: int) -> None:
        super().__init__(ctx, is_git_diff, command_timeout)

    def is_project(self, document: Document) -> bool:
        return Path(document.path).name in DENO_MANIFEST_FILE_NAMES

    def try_restore_dependencies(self, document: Document) -> Optional[Document]:
        manifest_dir = self.get_manifest_dir(document)
        if not manifest_dir:
            return None

        lockfile_path = Path(manifest_dir) / DENO_LOCK_FILE_NAME
        if not lockfile_path.is_file():
            logger.debug('No deno.lock found alongside deno.json, skipping deno restore, %s', {'path': document.path})
            return None

        content = get_file_content(str(lockfile_path))
        relative_path = build_dep_tree_path(document.path, DENO_LOCK_FILE_NAME)
        logger.debug('Using existing deno.lock, %s', {'path': str(lockfile_path)})
        return Document(relative_path, content, self.is_git_diff)

    def get_commands(self, manifest_file_path: str) -> list[list[str]]:
        return []

    def get_lock_file_name(self) -> str:
        return DENO_LOCK_FILE_NAME

    def get_lock_file_names(self) -> list[str]:
        return [DENO_LOCK_FILE_NAME]
