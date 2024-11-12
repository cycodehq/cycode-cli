import os
from typing import List, Optional

import click

from cycode.cli.files_collector.sca.base_restore_dependencies import BaseRestoreDependencies
from cycode.cli.models import Document

GO_PROJECT_FILE_EXTENSIONS = ['.mod']
GO_RESTORE_FILE_NAME = 'go.mod.graph'
BUILD_GO_FILE_NAME = 'go.mod'


class RestoreGoDependencies(BaseRestoreDependencies):
    def __init__(self, context: click.Context, is_git_diff: bool, command_timeout: int) -> None:
        super().__init__(context, is_git_diff, command_timeout, create_output_file_manually=True)

    def is_project(self, document: Document) -> bool:
        return any(document.path.endswith(ext) for ext in GO_PROJECT_FILE_EXTENSIONS)

    def get_commands(self, manifest_file_path: str) -> List[List[str]]:
        return [
            ['go', 'list', '-m', '-json', 'all'],
            ['echo', '------------------------------------------------------'],
            ['go', 'mod', 'graph'],
        ]

    def get_lock_file_name(self) -> str:
        return GO_RESTORE_FILE_NAME

    def verify_restore_file_already_exist(self, restore_file_path: str) -> bool:
        return os.path.isfile(restore_file_path)

    def get_working_directory(self, document: Document) -> Optional[str]:
        return os.path.dirname(document.absolute_path)
