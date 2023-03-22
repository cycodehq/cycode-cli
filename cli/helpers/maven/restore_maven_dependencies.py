from typing import List

import click

from cli.helpers.maven.base_restore_maven_dependencies import BaseRestoreMavenDependencies
from cli.models import Document
from cli.utils.path_utils import get_file_dir, get_file_content, join_paths

BUILD_MAVEN_FILE_NAME = 'pom.xml'
MAVEN_CYCLONE_DEP_TREE_FILE_NAME = 'bom.json'
MAVEN_DEP_TREE_FILE_NAME = 'bcde.mvndeps'


class RestoreMavenDependencies(BaseRestoreMavenDependencies):
    def __init__(self, context: click.Context, documents_to_add: List[Document], is_git_diff: bool,
                 command_timeout: int):
        super().__init__(context, documents_to_add, is_git_diff, command_timeout)

    def is_project(self, document: Document) -> bool:
        return document.path.endswith(BUILD_MAVEN_FILE_NAME)

    def get_command(self, manifest_file_path: str) -> List[str]:
        return ['mvn', 'org.cyclonedx:cyclonedx-maven-plugin:2.7.4:makeAggregateBom', '-f', manifest_file_path]

    def get_lock_file_name(self) -> str:
        return join_paths('target', MAVEN_CYCLONE_DEP_TREE_FILE_NAME)

    def try_restore_dependencies(self, document: Document) -> Document:
        restore_dependencies_document = super().try_restore_dependencies(document)
        manifest_file_path = self.get_manifest_file_path(document)
        if document.content is None:
            backup_restore_content = super()._execute_command(
                ['mvn', 'dependency:tree', '-B', '-DoutputType=text', '-f', manifest_file_path,
                 f'-DoutputFile={MAVEN_DEP_TREE_FILE_NAME}'],
                manifest_file_path)
            restore_dependencies_document = Document(self.build_dep_tree_path(document.path, MAVEN_DEP_TREE_FILE_NAME),
                                                     backup_restore_content,
                                                     self.is_git_diff)

            if restore_dependencies_document.content is not None:
                restore_dependencies_document.content = get_file_content(MAVEN_DEP_TREE_FILE_NAME)
        else:
            restore_dependencies_document.content = get_file_content(
                join_paths(get_file_dir(manifest_file_path), restore_dependencies_document.path))

        return restore_dependencies_document