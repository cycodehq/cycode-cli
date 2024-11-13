import logging
import os
from typing import List, Optional

import click

from cycode.cli.files_collector.sca.base_restore_dependencies import BaseRestoreDependencies
from cycode.cli.models import Document

GO_PROJECT_FILE_EXTENSIONS = ['.mod', '.sum']
GO_RESTORE_FILE_NAME = 'go.mod.graph'
BUILD_GO_FILE_NAME = 'go.mod'
BUILD_GO_LOCK_FILE_NAME = 'go.sum'


class RestoreGoDependencies(BaseRestoreDependencies):
    def __init__(self, context: click.Context, is_git_diff: bool, command_timeout: int) -> None:
        super().__init__(context, is_git_diff, command_timeout, create_output_file_manually=True)

    def try_restore_dependencies(self, document: Document) -> Optional[Document]:
        manifest_exists = os.path.isfile(self.get_working_directory(document) + os.sep + BUILD_GO_FILE_NAME)
        lock_exists = os.path.isfile(self.get_working_directory(document) + os.sep + BUILD_GO_LOCK_FILE_NAME)

        if not manifest_exists or not lock_exists:
            logging.info('No manifest go.mod file found' if not manifest_exists else 'No manifest go.sum file found')

        manifest_files_exists = manifest_exists & lock_exists

        if not manifest_files_exists:
            return None

        return super().try_restore_dependencies(document)

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
