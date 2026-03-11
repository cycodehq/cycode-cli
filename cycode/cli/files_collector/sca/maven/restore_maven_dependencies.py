from os import path
from pathlib import Path
from typing import Optional

import typer

from cycode.cli.files_collector.sca.base_restore_dependencies import (
    BaseRestoreDependencies,
    build_dep_tree_path,
    execute_commands,
)
from cycode.cli.models import Document
from cycode.cli.utils.path_utils import get_file_content, join_paths
from cycode.logger import get_logger

logger = get_logger('Maven Restore Dependencies')

BUILD_MAVEN_FILE_NAME = 'pom.xml'
MAVEN_CYCLONE_DEP_TREE_FILE_NAME = 'bom.json'
MAVEN_DEP_TREE_FILE_NAME = 'bcde.mvndeps'


class RestoreMavenDependencies(BaseRestoreDependencies):
    def __init__(self, ctx: typer.Context, is_git_diff: bool, command_timeout: int) -> None:
        super().__init__(ctx, is_git_diff, command_timeout)

    def is_project(self, document: Document) -> bool:
        return path.basename(document.path).split('/')[-1] == BUILD_MAVEN_FILE_NAME

    def get_commands(self, manifest_file_path: str) -> list[list[str]]:
        command = ['mvn', 'org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeAggregateBom', '-f', manifest_file_path]

        maven_settings_file = self.ctx.obj.get('maven_settings_file')
        if maven_settings_file:
            command += ['-s', str(maven_settings_file)]
        return [command]

    def get_lock_file_name(self) -> str:
        return join_paths('target', MAVEN_CYCLONE_DEP_TREE_FILE_NAME)

    def get_lock_file_names(self) -> list[str]:
        return [self.get_lock_file_name()]

    def try_restore_dependencies(self, document: Document) -> Optional[Document]:
        manifest_file_path = self.get_manifest_file_path(document)
        if document.content is None:
            return self.restore_from_secondary_command(document, manifest_file_path)

        # super() reads the content and cleans up any generated file; no re-read needed
        return super().try_restore_dependencies(document)

    def restore_from_secondary_command(self, document: Document, manifest_file_path: str) -> Optional[Document]:
        restore_content = execute_commands(
            commands=self.create_secondary_restore_commands(manifest_file_path),
            timeout=self.command_timeout,
            working_directory=self.get_working_directory(document),
        )
        if restore_content is None:
            return None

        restore_file_path = build_dep_tree_path(document.absolute_path, MAVEN_DEP_TREE_FILE_NAME)
        content = get_file_content(restore_file_path)

        try:
            Path(restore_file_path).unlink(missing_ok=True)
        except Exception as e:
            logger.debug('Failed to clean up generated maven dep tree file', exc_info=e)

        return Document(
            path=build_dep_tree_path(document.path, MAVEN_DEP_TREE_FILE_NAME),
            content=content,
            is_git_diff_format=self.is_git_diff,
        )

    def create_secondary_restore_commands(self, manifest_file_path: str) -> list[list[str]]:
        command = [
            'mvn',
            'dependency:tree',
            '-B',
            '-DoutputType=text',
            '-f',
            manifest_file_path,
            f'-DoutputFile={MAVEN_DEP_TREE_FILE_NAME}',
        ]

        maven_settings_file = self.ctx.obj.get('maven_settings_file')
        if maven_settings_file:
            command += ['-s', str(maven_settings_file)]

        return [command]
