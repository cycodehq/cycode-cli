from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
import typer

from cycode.cli.files_collector.sca.maven.restore_maven_dependencies import (
    BUILD_MAVEN_FILE_NAME,
    MAVEN_CYCLONE_DEP_TREE_FILE_NAME,
    MAVEN_DEP_TREE_FILE_NAME,
    RestoreMavenDependencies,
)
from cycode.cli.models import Document

_BASE_MODULE = 'cycode.cli.files_collector.sca.base_restore_dependencies'
_MAVEN_MODULE = 'cycode.cli.files_collector.sca.maven.restore_maven_dependencies'


@pytest.fixture
def mock_ctx(tmp_path: Path) -> typer.Context:
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = {'monitor': False, 'maven_settings_file': None}
    ctx.params = {'path': str(tmp_path)}
    return ctx


@pytest.fixture
def restore_maven(mock_ctx: typer.Context) -> RestoreMavenDependencies:
    return RestoreMavenDependencies(mock_ctx, is_git_diff=False, command_timeout=30)


class TestIsProject:
    def test_pom_xml_matches(self, restore_maven: RestoreMavenDependencies) -> None:
        doc = Document('pom.xml', '<project/>')
        assert restore_maven.is_project(doc) is True

    def test_pom_xml_in_subdir_matches(self, restore_maven: RestoreMavenDependencies) -> None:
        doc = Document('mymodule/pom.xml', '<project/>')
        assert restore_maven.is_project(doc) is True

    def test_build_gradle_does_not_match(self, restore_maven: RestoreMavenDependencies) -> None:
        doc = Document('build.gradle', '')
        assert restore_maven.is_project(doc) is False


class TestCleanup:
    def test_generated_bom_is_deleted_after_primary_restore(
        self, restore_maven: RestoreMavenDependencies, tmp_path: Path
    ) -> None:
        """Primary path: super().try_restore_dependencies() generates target/bom.json and cleans it up."""
        pom_content = '<project><modelVersion>4.0.0</modelVersion></project>'
        (tmp_path / BUILD_MAVEN_FILE_NAME).write_text(pom_content)
        target_dir = tmp_path / 'target'
        target_dir.mkdir()
        bom_path = target_dir / MAVEN_CYCLONE_DEP_TREE_FILE_NAME
        doc = Document(
            str(tmp_path / BUILD_MAVEN_FILE_NAME),
            pom_content,
            absolute_path=str(tmp_path / BUILD_MAVEN_FILE_NAME),
        )

        def side_effect(
            commands: list,
            timeout: int,
            output_file_path: Optional[str] = None,
            working_directory: Optional[str] = None,
        ) -> str:
            bom_path.write_text('{"bomFormat": "CycloneDX", "components": []}')
            return 'output'

        with patch(f'{_BASE_MODULE}.execute_commands', side_effect=side_effect):
            result = restore_maven.try_restore_dependencies(doc)

        assert result is not None
        assert result.content is not None, 'Document content must be populated even after file deletion'
        assert not bom_path.exists(), f'target/{MAVEN_CYCLONE_DEP_TREE_FILE_NAME} must be deleted after restore'

    def test_generated_dep_tree_is_deleted_after_secondary_restore(
        self, restore_maven: RestoreMavenDependencies, tmp_path: Path
    ) -> None:
        """Secondary path (content=None): mvn dependency:tree generates bcde.mvndeps and it must be cleaned up."""
        (tmp_path / BUILD_MAVEN_FILE_NAME).write_text('<project/>')
        dep_tree_path = tmp_path / MAVEN_DEP_TREE_FILE_NAME
        # content=None triggers the secondary command path
        doc = Document(
            str(tmp_path / BUILD_MAVEN_FILE_NAME),
            None,
            absolute_path=str(tmp_path / BUILD_MAVEN_FILE_NAME),
        )

        def side_effect(
            commands: list,
            timeout: int,
            output_file_path: Optional[str] = None,
            working_directory: Optional[str] = None,
        ) -> str:
            dep_tree_path.write_text('[INFO] com.example:my-app:jar:1.0.0\n')
            return '[INFO] BUILD SUCCESS'

        with patch(f'{_MAVEN_MODULE}.execute_commands', side_effect=side_effect):
            result = restore_maven.try_restore_dependencies(doc)

        assert result is not None
        assert result.content is not None
        assert not dep_tree_path.exists(), f'{MAVEN_DEP_TREE_FILE_NAME} must be deleted after restore'

    def test_preexisting_bom_is_not_deleted(self, restore_maven: RestoreMavenDependencies, tmp_path: Path) -> None:
        pom_content = '<project><modelVersion>4.0.0</modelVersion></project>'
        (tmp_path / BUILD_MAVEN_FILE_NAME).write_text(pom_content)
        target_dir = tmp_path / 'target'
        target_dir.mkdir()
        bom_path = target_dir / MAVEN_CYCLONE_DEP_TREE_FILE_NAME
        bom_path.write_text('{"bomFormat": "CycloneDX", "components": [{"name": "requests"}]}')
        doc = Document(
            str(tmp_path / BUILD_MAVEN_FILE_NAME),
            pom_content,
            absolute_path=str(tmp_path / BUILD_MAVEN_FILE_NAME),
        )

        result = restore_maven.try_restore_dependencies(doc)

        assert result is not None
        assert bom_path.exists(), f'Pre-existing target/{MAVEN_CYCLONE_DEP_TREE_FILE_NAME} must not be deleted'
