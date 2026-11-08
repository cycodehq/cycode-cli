import os
import platform
import re
from pathlib import Path

import typer

from cycode.cli.files_collector.sca.base_restore_dependencies import BaseRestoreDependencies
from cycode.cli.models import Document
from cycode.cli.utils.path_utils import get_path_from_context
from cycode.cli.utils.shell_executor import shell
from cycode.logger import get_logger

logger = get_logger('Gradle Restore')

BUILD_GRADLE_FILE_NAME = 'build.gradle'
BUILD_GRADLE_KTS_FILE_NAME = 'build.gradle.kts'
BUILD_GRADLE_DEP_TREE_FILE_NAME = 'gradle-dependencies-generated.txt'
ALL_PROJECTS_REGEX = r"[+-]{3} Project '(.*?)'"
# A line of the "Project locations" section of `gradle projects` (Gradle 9.1+), relative to the root project:
# project ':a-b' - /x/y
PROJECT_LOCATION_REGEX = r"^project '(.+?)' - (.+?)\s*$"
# The header of `gradle projects` when it runs in a subproject directory (the root project prints "Root project")
CURRENT_PROJECT_REGEX = r"^Project '(.+?)'\s*$"
ROOT_PROJECT_PATH = ':'

GRADLE_EXECUTABLE = 'gradle'
GRADLEW_FILE_NAME = 'gradlew'
GRADLEW_BAT_FILE_NAME = 'gradlew.bat'


class RestoreGradleDependencies(BaseRestoreDependencies):
    def __init__(
        self, ctx: typer.Context, is_git_diff: bool, command_timeout: int, projects: set[str] | None = None
    ) -> None:
        super().__init__(ctx, is_git_diff, command_timeout, create_output_file_manually=True)
        self.gradle_executable = self._resolve_gradle_executable()
        if projects is None:
            projects = set()
        self.project_locations: dict[Path, str] = {}
        self.projects = self.get_all_projects() if self.is_gradle_sub_projects() else projects

    def _resolve_gradle_executable(self) -> str:
        scan_root = get_path_from_context(self.ctx)
        if scan_root:
            wrapper_name = GRADLEW_BAT_FILE_NAME if platform.system() == 'Windows' else GRADLEW_FILE_NAME
            wrapper_path = os.path.join(scan_root, wrapper_name)
            if os.path.isfile(wrapper_path):
                return wrapper_path
        return GRADLE_EXECUTABLE

    def is_gradle_sub_projects(self) -> bool:
        return self.ctx.obj.get('gradle_all_sub_projects', False)

    def is_project(self, document: Document) -> bool:
        return document.path.endswith(BUILD_GRADLE_FILE_NAME) or document.path.endswith(BUILD_GRADLE_KTS_FILE_NAME)

    def get_commands(self, manifest_file_path: str) -> list[list[str]]:
        if self.is_gradle_sub_projects():
            return self.get_commands_for_sub_projects(manifest_file_path)

        # Gradle 9 removed -b (--build-file). -p starts Gradle in the manifest directory: Gradle finds the root
        # settings file above it and selects the project whose projectDir is that directory.
        manifest_dir = str(Path(manifest_file_path).parent)
        return [[self.gradle_executable, '-p', manifest_dir, 'dependencies', '-q', '--console', 'plain']]

    def get_lock_file_name(self) -> str:
        return BUILD_GRADLE_DEP_TREE_FILE_NAME

    def get_lock_file_names(self) -> list[str]:
        return [self.get_lock_file_name()]

    def get_working_directory(self, document: Document) -> str | None:
        return get_path_from_context(self.ctx) if self.is_gradle_sub_projects() else None

    def get_all_projects(self) -> set[str]:
        scan_root = get_path_from_context(self.ctx)
        output = shell(
            command=[self.gradle_executable, 'projects'],
            timeout=self.command_timeout,
            working_directory=scan_root,
        )
        if not output:
            return set()

        if scan_root:
            self.project_locations = self._parse_project_locations(output, Path(scan_root))

        return set(re.findall(ALL_PROJECTS_REGEX, output))

    @staticmethod
    def _parse_project_locations(output: str, scan_root: Path) -> dict[Path, str]:
        """Map each project directory to its Gradle project path.

        Reads the "Project locations" section of `gradle projects`. The section includes projectDir overrides
        from the settings file, so remapped and nested projects get their real path. Gradle versions before 9.1
        do not print the section; the result is then empty.
        """
        # A location starts with a separator ("/x/y"). Strip it, or pathlib treats it as an absolute path.
        relative_dirs = {
            project_path: Path(relative_dir.lstrip('/\\'))
            for project_path, relative_dir in re.findall(PROJECT_LOCATION_REGEX, output, flags=re.MULTILINE)
        }
        if not relative_dirs:
            return {}

        # Locations are relative to the build root. When the scan root is a subproject directory, Gradle reports
        # that subproject as the current project; walk up from the scan root to the build root.
        build_root = scan_root.resolve()
        current_project = re.search(CURRENT_PROJECT_REGEX, output, flags=re.MULTILINE)
        if current_project and current_project.group(1) in relative_dirs:
            for _ in relative_dirs[current_project.group(1)].parts:
                build_root = build_root.parent

        locations = {(build_root / relative_dir).resolve(): path for path, relative_dir in relative_dirs.items()}
        locations[build_root] = ROOT_PROJECT_PATH
        return locations

    def _get_sub_project_path(self, manifest_file_path: str) -> str | None:
        manifest_dir = Path(manifest_file_path).parent
        if self.project_locations:
            return self.project_locations.get(manifest_dir.resolve())

        # Without project locations (Gradle < 9.1), guess the project path from the directory name.
        scan_root = get_path_from_context(self.ctx)
        if self.projects and scan_root and manifest_dir.resolve() == Path(scan_root).resolve():
            return ROOT_PROJECT_PATH

        project_path = f':{manifest_dir.name}'
        return project_path if project_path in self.projects else None

    def get_commands_for_sub_projects(self, manifest_file_path: str) -> list[list[str]]:
        project_path = self._get_sub_project_path(manifest_file_path)
        if project_path is None:
            logger.debug(
                'Manifest does not match a Gradle project, skipping restore, %s',
                {'manifest_file_path': manifest_file_path},
            )
            return []

        task = 'dependencies' if project_path == ROOT_PROJECT_PATH else f'{project_path}:dependencies'
        return [[self.gradle_executable, task, '-q', '--console', 'plain']]
