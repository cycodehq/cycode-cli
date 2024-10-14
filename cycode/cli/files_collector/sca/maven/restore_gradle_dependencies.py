import os
from typing import List

import click

from cycode.cli.files_collector.sca.base_restore_dependencies import BaseRestoreDependencies
from cycode.cli.models import Document

BUILD_GRADLE_FILE_NAME = 'build.gradle'
BUILD_GRADLE_KTS_FILE_NAME = 'build.gradle.kts'
BUILD_GRADLE_DEP_TREE_FILE_NAME = 'gradle-dependencies-generated.txt'
OUTPUT_FILE_MANUALLY = True


class RestoreGradleDependencies(BaseRestoreDependencies):
    def __init__(self, context: click.Context, is_git_diff: bool, command_timeout: int) -> None:
        super().__init__(context, is_git_diff, command_timeout, OUTPUT_FILE_MANUALLY)

    def is_project(self, document: Document) -> bool:
        return document.path.endswith(BUILD_GRADLE_FILE_NAME) or document.path.endswith(BUILD_GRADLE_KTS_FILE_NAME)

    def get_command(self, manifest_file_path: str) -> List[str]:
        return ['gradle', 'dependencies', '-b', manifest_file_path, '-q', '--console', 'plain']

    def get_lock_file_name(self) -> str:
        return BUILD_GRADLE_DEP_TREE_FILE_NAME

    def verify_restore_file_already_exist(self, restore_file_path: str) -> bool:
        return os.path.isfile(restore_file_path)

    def prepare_tree_file_path_for_command(self, manifest_file_path: str) -> str:
        return '/' + manifest_file_path.strip('/' + BUILD_GRADLE_FILE_NAME) + '/' + BUILD_GRADLE_DEP_TREE_FILE_NAME
