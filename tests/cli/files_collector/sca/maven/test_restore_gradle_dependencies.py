import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer

from cycode.cli.files_collector.sca.maven.restore_gradle_dependencies import (
    BUILD_GRADLE_DEP_TREE_FILE_NAME,
    BUILD_GRADLE_FILE_NAME,
    BUILD_GRADLE_KTS_FILE_NAME,
    GRADLE_EXECUTABLE,
    GRADLEW_BAT_FILE_NAME,
    GRADLEW_FILE_NAME,
    RestoreGradleDependencies,
)
from cycode.cli.models import Document

_BASE_MODULE = 'cycode.cli.files_collector.sca.base_restore_dependencies'
_GRADLE_MODULE = 'cycode.cli.files_collector.sca.maven.restore_gradle_dependencies'


@pytest.fixture
def mock_ctx(tmp_path: Path) -> typer.Context:
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = {'monitor': False, 'gradle_all_sub_projects': False}
    ctx.params = {'path': str(tmp_path)}
    return ctx


@pytest.fixture
def restore_gradle(mock_ctx: typer.Context) -> RestoreGradleDependencies:
    return RestoreGradleDependencies(mock_ctx, is_git_diff=False, command_timeout=30)


class TestIsProject:
    def test_build_gradle_matches(self, restore_gradle: RestoreGradleDependencies) -> None:
        doc = Document('build.gradle', 'apply plugin: "java"\n')
        assert restore_gradle.is_project(doc) is True

    def test_build_gradle_kts_matches(self, restore_gradle: RestoreGradleDependencies) -> None:
        doc = Document('build.gradle.kts', 'plugins { java }\n')
        assert restore_gradle.is_project(doc) is True

    def test_pom_xml_does_not_match(self, restore_gradle: RestoreGradleDependencies) -> None:
        doc = Document('pom.xml', '<project/>')
        assert restore_gradle.is_project(doc) is False

    def test_settings_gradle_does_not_match(self, restore_gradle: RestoreGradleDependencies) -> None:
        doc = Document('settings.gradle', 'rootProject.name = "test"')
        assert restore_gradle.is_project(doc) is False


class TestResolveGradleExecutable:
    def test_falls_back_to_gradle_when_no_wrapper(self, restore_gradle: RestoreGradleDependencies) -> None:
        assert restore_gradle.gradle_executable == GRADLE_EXECUTABLE

    def test_prefers_gradlew_wrapper_on_posix(self, mock_ctx: typer.Context, tmp_path: Path) -> None:
        wrapper = tmp_path / GRADLEW_FILE_NAME
        wrapper.write_text('#!/bin/sh\n')
        with patch(f'{_GRADLE_MODULE}.platform.system', return_value='Linux'):
            restore = RestoreGradleDependencies(mock_ctx, is_git_diff=False, command_timeout=30)
        assert restore.gradle_executable == str(wrapper)

    def test_prefers_gradlew_bat_on_windows(self, mock_ctx: typer.Context, tmp_path: Path) -> None:
        wrapper = tmp_path / GRADLEW_BAT_FILE_NAME
        wrapper.write_text('@echo off\n')
        with patch(f'{_GRADLE_MODULE}.platform.system', return_value='Windows'):
            restore = RestoreGradleDependencies(mock_ctx, is_git_diff=False, command_timeout=30)
        assert restore.gradle_executable == str(wrapper)

    def test_posix_ignores_bat_wrapper(self, mock_ctx: typer.Context, tmp_path: Path) -> None:
        (tmp_path / GRADLEW_BAT_FILE_NAME).write_text('@echo off\n')
        with patch(f'{_GRADLE_MODULE}.platform.system', return_value='Linux'):
            restore = RestoreGradleDependencies(mock_ctx, is_git_diff=False, command_timeout=30)
        assert restore.gradle_executable == GRADLE_EXECUTABLE

    def test_wrapper_is_threaded_into_get_commands(self, mock_ctx: typer.Context, tmp_path: Path) -> None:
        wrapper = tmp_path / GRADLEW_FILE_NAME
        wrapper.write_text('#!/bin/sh\n')
        with patch(f'{_GRADLE_MODULE}.platform.system', return_value='Linux'):
            restore = RestoreGradleDependencies(mock_ctx, is_git_diff=False, command_timeout=30)
        commands = restore.get_commands(str(tmp_path / BUILD_GRADLE_FILE_NAME))
        assert commands == [[str(wrapper), '-p', str(tmp_path), 'dependencies', '-q', '--console', 'plain']]

    def test_wrapper_is_threaded_into_sub_project_commands(self, tmp_path: Path) -> None:
        wrapper = tmp_path / GRADLEW_FILE_NAME
        wrapper.write_text('#!/bin/sh\n')
        ctx = MagicMock(spec=typer.Context)
        ctx.obj = {'monitor': False, 'gradle_all_sub_projects': True}
        ctx.params = {'path': str(tmp_path)}
        module_project = tmp_path / 'module-a'
        module_project.mkdir()
        manifest = module_project / BUILD_GRADLE_FILE_NAME

        with (
            patch(f'{_GRADLE_MODULE}.platform.system', return_value='Linux'),
            patch.object(RestoreGradleDependencies, 'get_all_projects', return_value={':module-a'}),
        ):
            restore = RestoreGradleDependencies(ctx, is_git_diff=False, command_timeout=30)

        commands = restore.get_commands_for_sub_projects(str(manifest))
        assert commands == [[str(wrapper), ':module-a:dependencies', '-q', '--console', 'plain']]


class TestDefaultCommand:
    def test_uses_project_dir_instead_of_build_file(
        self, restore_gradle: RestoreGradleDependencies, tmp_path: Path
    ) -> None:
        manifest = tmp_path / 'x' / 'y' / BUILD_GRADLE_KTS_FILE_NAME

        commands = restore_gradle.get_commands(str(manifest))

        assert commands == [
            [GRADLE_EXECUTABLE, '-p', str(tmp_path / 'x' / 'y'), 'dependencies', '-q', '--console', 'plain']
        ]
        assert '-b' not in commands[0]


# The settings file moves the projectDir of ':tenant-service-implementation' to
# components/services/tenant/implementation.
_PROJECTS_OUTPUT_WITH_LOCATIONS = """
Projects:

------------------------------------------------------------
Root project 'root'
------------------------------------------------------------

Location: /repo

Project hierarchy:

Root project 'root'
+--- Project ':a'
|    \\--- Project ':a:b'
\\--- Project ':tenant-service-implementation'

Project locations:

project ':a' - /a
project ':a:b' - /a/b
project ':tenant-service-implementation' - /components/services/tenant/implementation

To see a list of the tasks of a project, run gradle <project-path>:tasks
"""

_PROJECTS_OUTPUT_WITHOUT_LOCATIONS = """
Root project 'root'
+--- Project ':a'
|    \\--- Project ':a:b'
\\--- Project ':tenant-service-implementation'
"""


def _sub_projects_restore(tmp_path: Path, projects_output: str) -> RestoreGradleDependencies:
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = {'monitor': False, 'gradle_all_sub_projects': True}
    ctx.params = {'path': str(tmp_path)}
    with patch(f'{_GRADLE_MODULE}.shell', return_value=projects_output):
        return RestoreGradleDependencies(ctx, is_git_diff=False, command_timeout=30)


class TestSubProjectCommands:
    def test_remapped_project_dir_uses_real_project_path(self, tmp_path: Path) -> None:
        restore = _sub_projects_restore(tmp_path, _PROJECTS_OUTPUT_WITH_LOCATIONS)
        manifest = tmp_path / 'components' / 'services' / 'tenant' / 'implementation' / BUILD_GRADLE_FILE_NAME

        assert restore.get_commands(str(manifest)) == [
            [GRADLE_EXECUTABLE, ':tenant-service-implementation:dependencies', '-q', '--console', 'plain']
        ]

    def test_nested_project_uses_full_path(self, tmp_path: Path) -> None:
        restore = _sub_projects_restore(tmp_path, _PROJECTS_OUTPUT_WITH_LOCATIONS)
        manifest = tmp_path / 'a' / 'b' / BUILD_GRADLE_KTS_FILE_NAME

        assert restore.get_commands(str(manifest)) == [
            [GRADLE_EXECUTABLE, ':a:b:dependencies', '-q', '--console', 'plain']
        ]

    def test_root_manifest_runs_root_dependencies(self, tmp_path: Path) -> None:
        restore = _sub_projects_restore(tmp_path, _PROJECTS_OUTPUT_WITH_LOCATIONS)

        assert restore.get_commands(str(tmp_path / BUILD_GRADLE_FILE_NAME)) == [
            [GRADLE_EXECUTABLE, 'dependencies', '-q', '--console', 'plain']
        ]

    def test_manifest_outside_the_build_is_skipped(self, tmp_path: Path) -> None:
        restore = _sub_projects_restore(tmp_path, _PROJECTS_OUTPUT_WITH_LOCATIONS)

        assert restore.get_commands(str(tmp_path / 'implementation' / BUILD_GRADLE_FILE_NAME)) == []

    def test_relative_manifest_path_is_resolved(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        restore = _sub_projects_restore(tmp_path, _PROJECTS_OUTPUT_WITH_LOCATIONS)
        monkeypatch.chdir(tmp_path / '..')

        manifest = Path(tmp_path.name) / 'a' / BUILD_GRADLE_FILE_NAME
        assert restore.get_commands(str(manifest)) == [
            [GRADLE_EXECUTABLE, ':a:dependencies', '-q', '--console', 'plain']
        ]

    def test_parses_crlf_line_endings(self, tmp_path: Path) -> None:
        output = "Project locations:\r\n\r\nproject ':a:b' - /a/b\r\n"

        locations = RestoreGradleDependencies._parse_project_locations(output, tmp_path)

        assert locations == {tmp_path.resolve(): ':', (tmp_path / 'a' / 'b').resolve(): ':a:b'}

    def test_scan_root_in_subproject_maps_from_build_root(self, tmp_path: Path) -> None:
        output = (
            "Project ':a'\n\nProject hierarchy:\n\nProject ':a'\n\\--- Project ':a:b'\n\n"
            "Project locations:\n\nproject ':a' - /a\nproject ':a:b' - /a/b\n"
        )
        scan_root = tmp_path / 'a'

        locations = RestoreGradleDependencies._parse_project_locations(output, scan_root)

        assert locations == {
            tmp_path.resolve(): ':',
            scan_root.resolve(): ':a',
            (scan_root / 'b').resolve(): ':a:b',
        }

    @pytest.mark.skipif(sys.platform != 'win32', reason='backslash is a path separator only on Windows')
    def test_parses_windows_separators_case_insensitively(self, tmp_path: Path) -> None:
        output = "Project locations:\r\n\r\nproject ':a:b' - \\A\\B\r\n"
        restore = _sub_projects_restore(tmp_path, output)

        assert restore._get_sub_project_path(str(tmp_path / 'a' / 'b' / BUILD_GRADLE_FILE_NAME)) == ':a:b'

    def test_older_gradle_falls_back_to_directory_name(self, tmp_path: Path) -> None:
        restore = _sub_projects_restore(tmp_path, _PROJECTS_OUTPUT_WITHOUT_LOCATIONS)

        assert restore.project_locations == {}
        assert restore.get_commands(str(tmp_path / 'a' / BUILD_GRADLE_FILE_NAME)) == [
            [GRADLE_EXECUTABLE, ':a:dependencies', '-q', '--console', 'plain']
        ]
        assert restore.get_commands(str(tmp_path / BUILD_GRADLE_FILE_NAME)) == [
            [GRADLE_EXECUTABLE, 'dependencies', '-q', '--console', 'plain']
        ]
        remapped = tmp_path / 'components' / 'services' / 'tenant' / 'implementation' / BUILD_GRADLE_FILE_NAME
        assert restore.get_commands(str(remapped)) == []


class TestCleanup:
    def test_generated_dep_tree_file_is_deleted_after_restore(
        self, restore_gradle: RestoreGradleDependencies, tmp_path: Path
    ) -> None:
        (tmp_path / BUILD_GRADLE_FILE_NAME).write_text('apply plugin: "java"\n')
        doc = Document(
            str(tmp_path / BUILD_GRADLE_FILE_NAME),
            'apply plugin: "java"\n',
            absolute_path=str(tmp_path / BUILD_GRADLE_FILE_NAME),
        )
        output_path = tmp_path / BUILD_GRADLE_DEP_TREE_FILE_NAME

        def side_effect(
            commands: list,
            timeout: int,
            output_file_path: str | None = None,
            working_directory: str | None = None,
        ) -> str:
            # Gradle uses create_output_file_manually=True; output_file_path is provided
            target = output_file_path or str(output_path)
            Path(target).write_text('compileClasspath - Compile classpath:\n\\--- org.example:lib:1.0\n')
            return 'dep tree output'

        with patch(f'{_BASE_MODULE}.execute_commands', side_effect=side_effect):
            result = restore_gradle.try_restore_dependencies(doc)

        assert result is not None
        assert not output_path.exists(), f'{BUILD_GRADLE_DEP_TREE_FILE_NAME} must be deleted after restore'

    def test_preexisting_dep_tree_file_is_not_deleted(
        self, restore_gradle: RestoreGradleDependencies, tmp_path: Path
    ) -> None:
        dep_tree_content = 'compileClasspath - Compile classpath:\n\\--- org.example:lib:1.0\n'
        (tmp_path / BUILD_GRADLE_FILE_NAME).write_text('apply plugin: "java"\n')
        output_path = tmp_path / BUILD_GRADLE_DEP_TREE_FILE_NAME
        output_path.write_text(dep_tree_content)
        doc = Document(
            str(tmp_path / BUILD_GRADLE_FILE_NAME),
            'apply plugin: "java"\n',
            absolute_path=str(tmp_path / BUILD_GRADLE_FILE_NAME),
        )

        result = restore_gradle.try_restore_dependencies(doc)

        assert result is not None
        assert output_path.exists(), f'Pre-existing {BUILD_GRADLE_DEP_TREE_FILE_NAME} must not be deleted'

    def test_kts_build_file_also_cleaned_up(self, restore_gradle: RestoreGradleDependencies, tmp_path: Path) -> None:
        (tmp_path / BUILD_GRADLE_KTS_FILE_NAME).write_text('plugins { java }\n')
        doc = Document(
            str(tmp_path / BUILD_GRADLE_KTS_FILE_NAME),
            'plugins { java }\n',
            absolute_path=str(tmp_path / BUILD_GRADLE_KTS_FILE_NAME),
        )
        output_path = tmp_path / BUILD_GRADLE_DEP_TREE_FILE_NAME

        def side_effect(
            commands: list,
            timeout: int,
            output_file_path: str | None = None,
            working_directory: str | None = None,
        ) -> str:
            target = output_file_path or str(output_path)
            Path(target).write_text('compileClasspath\n')
            return 'output'

        with patch(f'{_BASE_MODULE}.execute_commands', side_effect=side_effect):
            result = restore_gradle.try_restore_dependencies(doc)

        assert result is not None
        assert not output_path.exists(), f'{BUILD_GRADLE_DEP_TREE_FILE_NAME} must be deleted after restore'
