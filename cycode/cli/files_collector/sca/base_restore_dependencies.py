from abc import ABC, abstractmethod
from typing import List, Optional

import click

from cycode.cli.models import Document
from cycode.cli.utils.path_utils import get_file_content, get_file_dir, get_path_from_context, join_paths
from cycode.cli.utils.shell_executor import shell
from cycode.cyclient import logger


def build_dep_tree_path(path: str, generated_file_name: str) -> str:
    return join_paths(get_file_dir(path), generated_file_name)


def execute_commands(
    commands: List[List[str]],
    file_name: str,
    command_timeout: int,
    dependencies_file_name: Optional[str] = None,
    working_directory: Optional[str] = None,
) -> Optional[str]:
    try:
        all_dependencies = []

        # Run all commands and collect outputs
        for command in commands:
            dependencies = shell(command=command, timeout=command_timeout, working_directory=working_directory)
            all_dependencies.append(dependencies)  # Collect each command's output

        dependencies = '\n'.join(all_dependencies)

        # Write all collected outputs to the file if dependencies_file_name is provided
        if dependencies_file_name:
            with open(dependencies_file_name, 'w') as output_file:  # Open once in 'w' mode to start fresh
                output_file.writelines(dependencies)
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
        restore_file_path = build_dep_tree_path(document.absolute_path, self.get_lock_file_name())
        relative_restore_file_path = build_dep_tree_path(document.path, self.get_lock_file_name())
        working_directory_path = self.get_working_directory(document)

        if self.verify_restore_file_already_exist(restore_file_path):
            restore_file_content = get_file_content(restore_file_path)
        else:
            output_file_path = restore_file_path if self.create_output_file_manually else None
            execute_commands(
                self.get_commands(manifest_file_path),
                manifest_file_path,
                self.command_timeout,
                output_file_path,
                working_directory_path,
            )
            restore_file_content = get_file_content(restore_file_path)

        return Document(relative_restore_file_path, restore_file_content, self.is_git_diff)

    def get_working_directory(self, document: Document) -> Optional[str]:
        return None

    @abstractmethod
    def verify_restore_file_already_exist(self, restore_file_path: str) -> bool:
        pass

    @abstractmethod
    def is_project(self, document: Document) -> bool:
        pass

    @abstractmethod
    def get_commands(self, manifest_file_path: str) -> List[List[str]]:
        pass

    @abstractmethod
    def get_lock_file_name(self) -> str:
        pass
