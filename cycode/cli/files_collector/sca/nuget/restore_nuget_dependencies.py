import os
from typing import List

import click

from cycode.cli.files_collector.sca.base_restore_dependencies import BaseRestoreDependencies
from cycode.cli.models import Document

NUGET_PROJECT_FILE_EXTENSIONS = ['.csproj', '.vbproj']
NUGET_LOCK_FILE_NAME = 'packages.lock.json'


class RestoreNugetDependencies(BaseRestoreDependencies):
    def __init__(self, context: click.Context, is_git_diff: bool, command_timeout: int) -> None:
        super().__init__(context, is_git_diff, command_timeout)

    def is_project(self, document: Document) -> bool:
        return any(document.path.endswith(ext) for ext in NUGET_PROJECT_FILE_EXTENSIONS)

    def get_command(self, manifest_file_path: str) -> List[str]:
        return ['dotnet', 'restore', manifest_file_path, '--use-lock-file', '--verbosity', 'quiet']

    def get_lock_file_name(self) -> str:
        return NUGET_LOCK_FILE_NAME

    def verify_restore_file_already_exist(self, restore_file_path: str) -> bool:
        return os.path.isfile(restore_file_path)
