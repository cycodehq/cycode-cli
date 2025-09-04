import os
import re
from typing import Optional

import typer

from cycode.cli.files_collector.sca.base_restore_dependencies import BaseRestoreDependencies
from cycode.cli.models import Document
from cycode.cli.utils.path_utils import get_path_from_context
from cycode.cli.utils.shell_executor import shell

BUILD_GRADLE_FILE_NAME = 'build.gradle'
BUILD_GRADLE_KTS_FILE_NAME = 'build.gradle.kts'
BUILD_GRADLE_DEP_TREE_FILE_NAME = 'gradle-dependencies-generated.txt'
BUILD_GRADLE_ALL_PROJECTS_COMMAND = ['gradle', 'projects']
ALL_PROJECTS_REGEX = r"[+-]{3} Project '(.*?)'"


class RestoreGradleDependencies(BaseRestoreDependencies):
    def __init__(
        self, ctx: typer.Context, is_git_diff: bool, command_timeout: int, projects: Optional[set[str]] = None
    ) -> None:
        super().__init__(ctx, is_git_diff, command_timeout, create_output_file_manually=True)
        if projects is None:
            projects = set()
        self.projects = self.get_all_projects() if self.is_gradle_sub_projects() else projects

    def is_gradle_sub_projects(self) -> bool:
        return self.ctx.obj.get('gradle_all_sub_projects', False)

    def is_project(self, document: Document) -> bool:
        return document.path.endswith(BUILD_GRADLE_FILE_NAME) or document.path.endswith(BUILD_GRADLE_KTS_FILE_NAME)

    def get_commands(self, manifest_file_path: str) -> list[list[str]]:
        return (
            self.get_commands_for_sub_projects(manifest_file_path)
            if self.is_gradle_sub_projects()
            else [['gradle', 'dependencies', '-b', manifest_file_path, '-q', '--console', 'plain']]
        )

    def get_lock_file_name(self) -> str:
        return BUILD_GRADLE_DEP_TREE_FILE_NAME

    def get_working_directory(self, document: Document) -> Optional[str]:
        return get_path_from_context(self.ctx) if self.is_gradle_sub_projects() else None

    def get_all_projects(self) -> set[str]:
        output = shell(
            command=BUILD_GRADLE_ALL_PROJECTS_COMMAND,
            timeout=self.command_timeout,
            working_directory=get_path_from_context(self.ctx),
        )
        if not output:
            return set()

        return set(re.findall(ALL_PROJECTS_REGEX, output))

    def get_commands_for_sub_projects(self, manifest_file_path: str) -> list[list[str]]:
        project_name = os.path.basename(os.path.dirname(manifest_file_path))
        project_name = f':{project_name}'
        return (
            [['gradle', f'{project_name}:dependencies', '-q', '--console', 'plain']]
            if project_name in self.projects
            else []
        )
