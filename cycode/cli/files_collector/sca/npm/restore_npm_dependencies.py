import os
from typing import List

import click

from cycode.cli.files_collector.sca.base_restore_dependencies import BaseRestoreDependencies
from cycode.cli.models import Document

NPM_PROJECT_FILE_EXTENSIONS = ['.json']
NPM_LOCK_FILE_NAME = 'package-lock.json'
NPM_MANIFEST_FILE_NAME = 'package.json'


class RestoreNpmDependencies(BaseRestoreDependencies):
    def __init__(self, context: click.Context, is_git_diff: bool, command_timeout: int) -> None:
        super().__init__(context, is_git_diff, command_timeout)

    def is_project(self, document: Document) -> bool:
        return any(document.path.endswith(ext) for ext in NPM_PROJECT_FILE_EXTENSIONS)

    def get_commands(self, manifest_file_path: str) -> List[List[str]]:
        return [
            [
                'npm',
                'install',
                '--prefix',
                self.prepare_manifest_file_path_for_command(manifest_file_path),
                '--package-lock-only',
                '--ignore-scripts',
                '--no-audit',
            ]
        ]

    def get_lock_file_name(self) -> str:
        return NPM_LOCK_FILE_NAME

    def verify_restore_file_already_exist(self, restore_file_path: str) -> bool:
        return os.path.isfile(restore_file_path)

    def prepare_manifest_file_path_for_command(self, manifest_file_path: str) -> str:
        return manifest_file_path.replace(os.sep + NPM_MANIFEST_FILE_NAME, '')
