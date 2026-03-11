from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
import typer

from cycode.cli.files_collector.sca.maven.restore_gradle_dependencies import (
    BUILD_GRADLE_DEP_TREE_FILE_NAME,
    BUILD_GRADLE_FILE_NAME,
    BUILD_GRADLE_KTS_FILE_NAME,
    RestoreGradleDependencies,
)
from cycode.cli.models import Document

_BASE_MODULE = 'cycode.cli.files_collector.sca.base_restore_dependencies'


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
            commands: list, timeout: int, output_file_path: Optional[str] = None, working_directory: Optional[str] = None
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

    def test_kts_build_file_also_cleaned_up(
        self, restore_gradle: RestoreGradleDependencies, tmp_path: Path
    ) -> None:
        (tmp_path / BUILD_GRADLE_KTS_FILE_NAME).write_text('plugins { java }\n')
        doc = Document(
            str(tmp_path / BUILD_GRADLE_KTS_FILE_NAME),
            'plugins { java }\n',
            absolute_path=str(tmp_path / BUILD_GRADLE_KTS_FILE_NAME),
        )
        output_path = tmp_path / BUILD_GRADLE_DEP_TREE_FILE_NAME

        def side_effect(
            commands: list, timeout: int, output_file_path: Optional[str] = None, working_directory: Optional[str] = None
        ) -> str:
            target = output_file_path or str(output_path)
            Path(target).write_text('compileClasspath\n')
            return 'output'

        with patch(f'{_BASE_MODULE}.execute_commands', side_effect=side_effect):
            result = restore_gradle.try_restore_dependencies(doc)

        assert result is not None
        assert not output_path.exists(), f'{BUILD_GRADLE_DEP_TREE_FILE_NAME} must be deleted after restore'
