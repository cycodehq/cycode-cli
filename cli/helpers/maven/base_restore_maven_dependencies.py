from abc import ABC, abstractmethod

import click
from typing import List, Optional, Dict

from cli.models import Document
from cli.utils.path_utils import join_paths, get_file_dir
from cli.utils.shell_executor import shell
from cyclient import logger


class BaseRestoreMavenDependencies(ABC):
    context: click.Context
    documents_to_add: List[Document]
    is_git_diff: bool
    command_timeout: int

    def __init__(self, context: click.Context, documents_to_add: List[Document], is_git_diff: bool,
                 command_timeout: int):
        self.context = context
        self.documents_to_add = documents_to_add
        self.is_git_diff = is_git_diff
        self.command_timeout = command_timeout

    def restore(self, document: Document):
        if self.is_project(document):

            restore_dependencies_document = self.try_restore_dependencies(document)
            if restore_dependencies_document.content is None:
                logger.warning('Error occurred while trying to generate dependencies tree. %s',
                               {'filename': document.path})
                restore_dependencies_document.content = ''
                # logger.debug(
                #    f"Failed to generate dependencies tree on path: {manifest_file_path}")
            else:
                logger.debug(f"Succeeded to generate dependencies tree on path: {self.get_manifest_file_path(document)}")

            self.documents_to_add.append(restore_dependencies_document)

    def get_manifest_file_path(self, document: Document) -> str:
        return join_paths(self.context.params.get('path'), document.path) if self.context.obj.get('monitor') else document.path

    def build_dep_tree_path(self, path: str, generated_file_name: str) -> str:
        return join_paths(get_file_dir(path), generated_file_name)

    @abstractmethod
    def is_project(self, document: Document) -> bool:
        pass

    @abstractmethod
    def get_command(self, manifest_file_path: str) -> List[str]:
        pass

    @abstractmethod
    def get_lock_file_name(self) -> str:
        pass

    def try_restore_dependencies(self, document: Document) -> Document:
        manifest_file_path = self.get_manifest_file_path(document)
        return Document(self.build_dep_tree_path(document.path, self.get_lock_file_name()),
                        self._execute_command(self.get_command(manifest_file_path), manifest_file_path),
                        self.is_git_diff)

    def _execute_command(self, command: List, file_name: str) -> Optional[Dict]:
        # command = ['gradle', 'dependencies', '-b', filename, '-q', '--console', 'plain']
        try:
            dependencies = shell(command, self.command_timeout)
        except Exception as e:
            logger.debug('Failed to restore dependencies shell comment. %s',
                         {'filename': file_name, 'exception': str(e)})
            return None

        return dependencies
