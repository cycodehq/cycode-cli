from os import path
from typing import Optional

import typer

from cycode.cli.files_collector.sca.base_restore_dependencies import (
    BaseRestoreDependencies,
    build_dep_tree_path,
    execute_commands,
)
from cycode.cli.models import Document
from cycode.cli.utils.path_utils import get_file_content, get_file_dir, join_paths

BUILD_MAVEN_FILE_NAME = 'pom.xml'
MAVEN_CYCLONE_DEP_TREE_FILE_NAME = 'bom.json'
MAVEN_DEP_TREE_FILE_NAME = 'bcde.mvndeps'


class RestoreMavenDependencies(BaseRestoreDependencies):
    def __init__(self, ctx: typer.Context, is_git_diff: bool, command_timeout: int) -> None:
        super().__init__(ctx, is_git_diff, command_timeout)

    def is_project(self, document: Document) -> bool:
        return path.basename(document.path).split('/')[-1] == BUILD_MAVEN_FILE_NAME

    def get_commands(self, manifest_file_path: str) -> list[list[str]]:
        command = ['mvn', 'org.cyclonedx:cyclonedx-maven-plugin:2.7.4:makeAggregateBom', '-f', manifest_file_path]

        maven_settings_file = self.ctx.obj.get('maven_settings_file')
        if maven_settings_file:
            command += ['-s', str(maven_settings_file)]
        return [command]

    def get_lock_file_name(self) -> str:
        return join_paths('target', MAVEN_CYCLONE_DEP_TREE_FILE_NAME)

    def try_restore_dependencies(self, document: Document) -> Optional[Document]:
        manifest_file_path = self.get_manifest_file_path(document)
        if document.content is None:
            return self.restore_from_secondary_command(document, manifest_file_path)

        restore_dependencies_document = super().try_restore_dependencies(document)
        if restore_dependencies_document is None:
            return None

        restore_dependencies_document.content = get_file_content(
            join_paths(get_file_dir(manifest_file_path), self.get_lock_file_name())
        )

        return restore_dependencies_document

    def restore_from_secondary_command(self, document: Document, manifest_file_path: str) -> Optional[Document]:
        restore_content = execute_commands(
            commands=self.create_secondary_restore_commands(manifest_file_path),
            timeout=self.command_timeout,
            working_directory=self.get_working_directory(document),
        )
        if restore_content is None:
            return None

        restore_file_path = build_dep_tree_path(document.absolute_path, MAVEN_DEP_TREE_FILE_NAME)
        return Document(
            path=build_dep_tree_path(document.path, MAVEN_DEP_TREE_FILE_NAME),
            content=get_file_content(restore_file_path),
            is_git_diff_format=self.is_git_diff,
            absolute_path=restore_file_path,
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
