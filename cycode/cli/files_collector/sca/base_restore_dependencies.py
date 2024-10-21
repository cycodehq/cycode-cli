from abc import ABC, abstractmethod
from typing import List, Optional

import click

from cycode.cli.models import Document
from cycode.cli.utils.path_utils import get_file_content, get_file_dir, get_path_from_context, join_paths
from cycode.cli.utils.shell_executor import shell
from cycode.cyclient import logger


def build_dep_tree_path(path: str, generated_file_name: str) -> str:
    return join_paths(get_file_dir(path), generated_file_name)


def execute_command(
    command: List[str], file_name: str, command_timeout: int, dependencies_file_name: Optional[str] = None
) -> Optional[str]:
    try:
        dependencies = shell(command=command, timeout=command_timeout)
        # Write stdout output to the file if output_file_path is provided
        if dependencies_file_name:
            with open(dependencies_file_name, 'w') as output_file:
                output_file.write(dependencies)
    except Exception as e:
        logger.debug('Failed to restore dependencies via shell command, %s', {'filename': file_name}, exc_info=e)
        return None

    return dependencies


class BaseRestoreDependencies(ABC):
    def __init__(
        self, context: click.Context, is_git_diff: bool, command_timeout: int, create_output_file_manually: bool = False
    ) -> None:
        self.context = context
        self.is_git_diff = is_git_diff
        self.command_timeout = command_timeout
        self.create_output_file_manually = create_output_file_manually

    def restore(self, document: Document) -> Optional[Document]:
        return self.try_restore_dependencies(document)

    def get_manifest_file_path(self, document: Document) -> str:
        return (
            join_paths(get_path_from_context(self.context), document.path)
            if self.context.obj.get('monitor')
            else document.path
        )

    def try_restore_dependencies(self, document: Document) -> Optional[Document]:
        manifest_file_path = self.get_manifest_file_path(document)
        restore_file_path = build_dep_tree_path(document.path, self.get_lock_file_name())

        if self.verify_restore_file_already_exist(restore_file_path):
            restore_file_content = get_file_content(restore_file_path)
        else:
            output_file_path = restore_file_path if self.create_output_file_manually else None
            execute_command(
                self.get_command(manifest_file_path), manifest_file_path, self.command_timeout, output_file_path
            )
            restore_file_content = get_file_content(restore_file_path)

        return Document(restore_file_path, restore_file_content, self.is_git_diff)

    @abstractmethod
    def verify_restore_file_already_exist(self, restore_file_path: str) -> bool:
        pass

    @abstractmethod
    def is_project(self, document: Document) -> bool:
        pass

    @abstractmethod
    def get_command(self, manifest_file_path: str) -> List[str]:
        pass

    @abstractmethod
    def get_lock_file_name(self) -> str:
        pass
