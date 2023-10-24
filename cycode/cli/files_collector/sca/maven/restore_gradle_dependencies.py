from typing import List

import click

from cycode.cli.files_collector.sca.maven.base_restore_maven_dependencies import BaseRestoreMavenDependencies
from cycode.cli.models import Document

BUILD_GRADLE_FILE_NAME = 'build.gradle'
BUILD_GRADLE_KTS_FILE_NAME = 'build.gradle.kts'
BUILD_GRADLE_DEP_TREE_FILE_NAME = 'gradle-dependencies-generated.txt'


class RestoreGradleDependencies(BaseRestoreMavenDependencies):
    def __init__(self, context: click.Context, is_git_diff: bool, command_timeout: int) -> None:
        super().__init__(context, is_git_diff, command_timeout)

    def is_project(self, document: Document) -> bool:
        return document.path.endswith(BUILD_GRADLE_FILE_NAME) or document.path.endswith(BUILD_GRADLE_KTS_FILE_NAME)

    def get_command(self, manifest_file_path: str) -> List[str]:
        return ['gradle', 'dependencies', '-b', manifest_file_path, '-q', '--console', 'plain']

    def get_lock_file_name(self) -> str:
        return BUILD_GRADLE_DEP_TREE_FILE_NAME
