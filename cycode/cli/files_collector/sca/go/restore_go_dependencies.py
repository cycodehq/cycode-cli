import os
from typing import List

import click

from cycode.cli.files_collector.sca.base_restore_dependencies import BaseRestoreDependencies
from cycode.cli.models import Document

NPM_PROJECT_FILE_EXTENSIONS = ['.mod']

class RestoreGoDependencies(BaseRestoreDependencies):
    def __init__(self, context: click.Context, is_git_diff: bool, command_timeout: int) -> None:
        super().__init__(context, is_git_diff, command_timeout, True)

    def is_project(self, document: Document) -> bool:
        return any(document.path.endswith(ext) for ext in NPM_PROJECT_FILE_EXTENSIONS)

    def get_command(self, manifest_file_path: str) -> List[str]:
        return ['go', 'list', '-m', '-json', 'all']

    def get_lock_file_name(self) -> str:
        return None

    def verify_restore_file_already_exist(self, restore_file_path: str) -> bool:
        return os.path.isfile(restore_file_path)

