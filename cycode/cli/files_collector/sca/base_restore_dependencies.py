import os
from abc import ABC, abstractmethod
from typing import Optional

import typer

from cycode.cli.models import Document
from cycode.cli.utils.path_utils import get_file_content, get_file_dir, get_path_from_context, join_paths
from cycode.cli.utils.shell_executor import shell


def build_dep_tree_path(path: str, generated_file_name: str) -> str:
    return join_paths(get_file_dir(path), generated_file_name)


def execute_commands(
    commands: list[list[str]],
    timeout: int,
    output_file_path: Optional[str] = None,
    working_directory: Optional[str] = None,
) -> Optional[str]:
    try:
        outputs = []

        for command in commands:
            command_output = shell(command=command, timeout=timeout, working_directory=working_directory)
            if command_output:
                outputs.append(command_output)

        joined_output = '\n'.join(outputs)

        if output_file_path:
            with open(output_file_path, 'w', encoding='UTF-8') as output_file:
                output_file.writelines(joined_output)
    except Exception:
        return None

    return joined_output


class BaseRestoreDependencies(ABC):
    def __init__(
        self, ctx: typer.Context, is_git_diff: bool, command_timeout: int, create_output_file_manually: bool = False
    ) -> None:
        self.ctx = ctx
        self.is_git_diff = is_git_diff
        self.command_timeout = command_timeout
        self.create_output_file_manually = create_output_file_manually

    def restore(self, document: Document) -> Optional[Document]:
        return self.try_restore_dependencies(document)

    def get_manifest_file_path(self, document: Document) -> str:
        return (
            join_paths(get_path_from_context(self.ctx), document.path) if self.ctx.obj.get('monitor') else document.path
        )

    def try_restore_dependencies(self, document: Document) -> Optional[Document]:
        manifest_file_path = self.get_manifest_file_path(document)
        restore_file_path = build_dep_tree_path(document.absolute_path, self.get_lock_file_name())
        relative_restore_file_path = build_dep_tree_path(document.path, self.get_lock_file_name())

        if not self.verify_restore_file_already_exist(restore_file_path):
            output = execute_commands(
                commands=self.get_commands(manifest_file_path),
                timeout=self.command_timeout,
                output_file_path=restore_file_path if self.create_output_file_manually else None,
                working_directory=self.get_working_directory(document),
            )
            if output is None:  # one of the commands failed
                return None

        restore_file_content = get_file_content(restore_file_path)
        return Document(relative_restore_file_path, restore_file_content, self.is_git_diff)

    def get_working_directory(self, document: Document) -> Optional[str]:
        return os.path.dirname(document.absolute_path)

    @staticmethod
    def verify_restore_file_already_exist(restore_file_path: str) -> bool:
        return os.path.isfile(restore_file_path)

    @abstractmethod
    def is_project(self, document: Document) -> bool:
        pass

    @abstractmethod
    def get_commands(self, manifest_file_path: str) -> list[list[str]]:
        pass

    @abstractmethod
    def get_lock_file_name(self) -> str:
        pass
