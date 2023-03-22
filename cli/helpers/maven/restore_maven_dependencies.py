import click
from typing import List, Dict

from cli.helpers.maven.base_restore_maven_dependencies import BaseRestoreMavenDependencies
from cli.models import Document
from cli.utils.path_utils import get_file_dir, get_file_content

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
        return MAVEN_CYCLONE_DEP_TREE_FILE_NAME

    def try_restore_dependencies(self, manifest_file_path) -> Dict:
        restore_dependencies = super().try_restore_dependencies(manifest_file_path)
        if restore_dependencies.get('content') is None:
            return {
                'lock_file_name': MAVEN_DEP_TREE_FILE_NAME,
                'content': super()._execute_command(
                    ['mvn', 'dependency:tree', '-B', '-DoutputType=text', '-f', manifest_file_path,
                     '-DoutputFile=bcde.mvndeps'],
                    manifest_file_path)
            }
        else:
            restore_dependencies['content'] = get_file_content(
                get_file_dir(manifest_file_path) + "/" + MAVEN_CYCLONE_DEP_TREE_FILE_NAME)

        return restore_dependencies
