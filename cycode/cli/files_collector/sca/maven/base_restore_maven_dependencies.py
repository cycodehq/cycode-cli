from abc import ABC, abstractmethod
from typing import List, Optional

import click

from cycode.cli.models import Document
from cycode.cli.utils.path_utils import get_file_dir, join_paths
from cycode.cli.utils.shell_executor import shell
from cycode.cyclient import logger


def build_dep_tree_path(path: str, generated_file_name: str) -> str:
    return join_paths(get_file_dir(path), generated_file_name)


def execute_command(command: List[str], file_name: str, command_timeout: int) -> Optional[str]:
    try:
        dependencies = shell(command, command_timeout)
    except Exception as e:
        logger.debug('Failed to restore dependencies shell comment. %s', {'filename': file_name, 'exception': str(e)})
        return None

    return dependencies


class BaseRestoreMavenDependencies(ABC):
    def __init__(self, context: click.Context, is_git_diff: bool, command_timeout: int) -> None:
        self.context = context
        self.is_git_diff = is_git_diff
        self.command_timeout = command_timeout

    def restore(self, document: Document) -> Optional[Document]:
        return self.try_restore_dependencies(document)

    def get_manifest_file_path(self, document: Document) -> str:
        return (
            join_paths(self.context.params.get('path'), document.path)
            if self.context.obj.get('monitor')
            else document.path
        )

    @abstractmethod
    def is_project(self, document: Document) -> bool:
        pass

    @abstractmethod
    def get_command(self, manifest_file_path: str) -> List[str]:
        pass

    @abstractmethod
    def get_lock_file_name(self) -> str:
        pass

    def try_restore_dependencies(self, document: Document) -> Optional[Document]:
        manifest_file_path = self.get_manifest_file_path(document)
        return Document(
            build_dep_tree_path(document.path, self.get_lock_file_name()),
            execute_command(self.get_command(manifest_file_path), manifest_file_path, self.command_timeout),
            self.is_git_diff,
        )
