from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer

from cycode.cli.files_collector.sca.npm.restore_npm_dependencies import (
    ALTERNATIVE_LOCK_FILES,
    NPM_LOCK_FILE_NAME,
    RestoreNpmDependencies,
)
from cycode.cli.models import Document


@pytest.fixture
def mock_ctx(tmp_path: Path) -> typer.Context:
    """Create a mock typer context."""
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = {'monitor': False}
    ctx.params = {'path': str(tmp_path)}
    return ctx


@pytest.fixture
def restore_npm_dependencies(mock_ctx: typer.Context) -> RestoreNpmDependencies:
    """Create a RestoreNpmDependencies instance."""
    return RestoreNpmDependencies(mock_ctx, is_git_diff=False, command_timeout=30)


class TestRestoreNpmDependenciesAlternativeLockfiles:
    """Test that lockfiles prevent npm install from running."""

    @pytest.mark.parametrize(
        ('lockfile_name', 'lockfile_content', 'expected_content'),
        [
            ('pnpm-lock.yaml', 'lockfileVersion: 5.4\n', 'lockfileVersion: 5.4\n'),
            ('yarn.lock', '# yarn lockfile v1\n', '# yarn lockfile v1\n'),
            ('deno.lock', '{"version": 2}\n', '{"version": 2}\n'),
            ('package-lock.json', '{"lockfileVersion": 2}\n', '{"lockfileVersion": 2}\n'),
        ],
    )
    def test_lockfile_exists_should_skip_npm_install(
        self,
        restore_npm_dependencies: RestoreNpmDependencies,
        tmp_path: Path,
        lockfile_name: str,
        lockfile_content: str,
        expected_content: str,
    ) -> None:
        """Test that when any lockfile exists, npm install is skipped."""
        # Setup: Create package.json and lockfile
        package_json_path = tmp_path / 'package.json'
        lockfile_path = tmp_path / lockfile_name

        package_json_path.write_text('{"name": "test", "version": "1.0.0"}')
        lockfile_path.write_text(lockfile_content)

        document = Document(
            path=str(package_json_path),
            content=package_json_path.read_text(),
            absolute_path=str(package_json_path),
        )

        # Execute
        result = restore_npm_dependencies.try_restore_dependencies(document)

        # Verify: Should return lockfile content without running npm install
        assert result is not None
        assert lockfile_name in result.path
        assert result.content == expected_content

    def test_no_lockfile_exists_should_proceed_with_normal_flow(
        self, restore_npm_dependencies: RestoreNpmDependencies, tmp_path: Path
    ) -> None:
        """Test that when no lockfile exists, normal flow proceeds (will run npm install)."""
        # Setup: Create only package.json (no lockfile)
        package_json_path = tmp_path / 'package.json'
        package_json_path.write_text('{"name": "test", "version": "1.0.0"}')

        document = Document(
            path=str(package_json_path),
            content=package_json_path.read_text(),
            absolute_path=str(package_json_path),
        )

        # Mock the base class's try_restore_dependencies to verify it's called
        with patch.object(
            restore_npm_dependencies.__class__.__bases__[0],
            'try_restore_dependencies',
            return_value=None,
        ) as mock_super:
            # Execute
            restore_npm_dependencies.try_restore_dependencies(document)

            # Verify: Should call parent's try_restore_dependencies (which will run npm install)
            mock_super.assert_called_once_with(document)


class TestRestoreNpmDependenciesPathResolution:
    """Test path resolution scenarios."""

    @pytest.mark.parametrize(
        'has_absolute_path',
        [True, False],
    )
    def test_path_resolution_with_different_path_types(
        self,
        restore_npm_dependencies: RestoreNpmDependencies,
        tmp_path: Path,
        has_absolute_path: bool,
    ) -> None:
        """Test path resolution with absolute or relative paths."""
        package_json_path = tmp_path / 'package.json'
        pnpm_lock_path = tmp_path / 'pnpm-lock.yaml'

        package_json_path.write_text('{"name": "test"}')
        pnpm_lock_path.write_text('lockfileVersion: 5.4\n')

        document = Document(
            path=str(package_json_path),
            content='{"name": "test"}',
            absolute_path=str(package_json_path) if has_absolute_path else None,
        )

        result = restore_npm_dependencies.try_restore_dependencies(document)

        assert result is not None
        assert result.content == 'lockfileVersion: 5.4\n'

    def test_path_resolution_in_monitor_mode(self, tmp_path: Path) -> None:
        """Test path resolution in monitor mode."""
        # Setup monitor mode context
        ctx = MagicMock(spec=typer.Context)
        ctx.obj = {'monitor': True}
        ctx.params = {'path': str(tmp_path)}

        restore_npm = RestoreNpmDependencies(ctx, is_git_diff=False, command_timeout=30)

        # Create files in a subdirectory
        subdir = tmp_path / 'project'
        subdir.mkdir()
        package_json_path = subdir / 'package.json'
        pnpm_lock_path = subdir / 'pnpm-lock.yaml'

        package_json_path.write_text('{"name": "test"}')
        pnpm_lock_path.write_text('lockfileVersion: 5.4\n')

        # Document with a relative path
        document = Document(
            path='project/package.json',
            content='{"name": "test"}',
            absolute_path=str(package_json_path),
        )

        result = restore_npm.try_restore_dependencies(document)

        assert result is not None
        assert result.content == 'lockfileVersion: 5.4\n'

    def test_path_resolution_with_nested_directory(
        self, restore_npm_dependencies: RestoreNpmDependencies, tmp_path: Path
    ) -> None:
        """Test path resolution with a nested directory structure."""
        subdir = tmp_path / 'src' / 'app'
        subdir.mkdir(parents=True)

        package_json_path = subdir / 'package.json'
        pnpm_lock_path = subdir / 'pnpm-lock.yaml'

        package_json_path.write_text('{"name": "test"}')
        pnpm_lock_path.write_text('lockfileVersion: 5.4\n')

        document = Document(
            path=str(package_json_path),
            content='{"name": "test"}',
            absolute_path=str(package_json_path),
        )

        result = restore_npm_dependencies.try_restore_dependencies(document)

        assert result is not None
        assert result.content == 'lockfileVersion: 5.4\n'


class TestRestoreNpmDependenciesEdgeCases:
    """Test edge cases and error scenarios."""

    def test_empty_lockfile_should_still_be_used(
        self, restore_npm_dependencies: RestoreNpmDependencies, tmp_path: Path
    ) -> None:
        """Test that the empty lockfile is still used (prevents npm install)."""
        package_json_path = tmp_path / 'package.json'
        pnpm_lock_path = tmp_path / 'pnpm-lock.yaml'

        package_json_path.write_text('{"name": "test"}')
        pnpm_lock_path.write_text('')  # Empty file

        document = Document(
            path=str(package_json_path),
            content='{"name": "test"}',
            absolute_path=str(package_json_path),
        )

        result = restore_npm_dependencies.try_restore_dependencies(document)

        # Should still return the empty lockfile (prevents npm install)
        assert result is not None
        assert result.content == ''

    def test_multiple_lockfiles_should_use_first_found(
        self, restore_npm_dependencies: RestoreNpmDependencies, tmp_path: Path
    ) -> None:
        """Test that when multiple lockfiles exist, the first one found is used (package-lock.json has priority)."""
        package_json_path = tmp_path / 'package.json'
        package_lock_path = tmp_path / 'package-lock.json'
        yarn_lock_path = tmp_path / 'yarn.lock'
        pnpm_lock_path = tmp_path / 'pnpm-lock.yaml'

        package_json_path.write_text('{"name": "test"}')
        package_lock_path.write_text('{"lockfileVersion": 2}\n')
        yarn_lock_path.write_text('# yarn lockfile\n')
        pnpm_lock_path.write_text('lockfileVersion: 5.4\n')

        document = Document(
            path=str(package_json_path),
            content='{"name": "test"}',
            absolute_path=str(package_json_path),
        )

        result = restore_npm_dependencies.try_restore_dependencies(document)

        # Should use package-lock.json (first in the check order)
        assert result is not None
        assert 'package-lock.json' in result.path
        assert result.content == '{"lockfileVersion": 2}\n'

    def test_multiple_alternative_lockfiles_should_use_first_found(
        self, restore_npm_dependencies: RestoreNpmDependencies, tmp_path: Path
    ) -> None:
        """Test that when multiple alternative lockfiles exist (but no package-lock.json),
        the first one found is used."""
        package_json_path = tmp_path / 'package.json'
        yarn_lock_path = tmp_path / 'yarn.lock'
        pnpm_lock_path = tmp_path / 'pnpm-lock.yaml'

        package_json_path.write_text('{"name": "test"}')
        yarn_lock_path.write_text('# yarn lockfile\n')
        pnpm_lock_path.write_text('lockfileVersion: 5.4\n')

        document = Document(
            path=str(package_json_path),
            content='{"name": "test"}',
            absolute_path=str(package_json_path),
        )

        result = restore_npm_dependencies.try_restore_dependencies(document)

        # Should use yarn.lock (first in ALTERNATIVE_LOCK_FILES list)
        assert result is not None
        assert 'yarn.lock' in result.path
        assert result.content == '# yarn lockfile\n'

    def test_lockfile_in_different_directory_should_not_be_found(
        self, restore_npm_dependencies: RestoreNpmDependencies, tmp_path: Path
    ) -> None:
        """Test that lockfile in a different directory is not found."""
        package_json_path = tmp_path / 'package.json'
        other_dir = tmp_path / 'other'
        other_dir.mkdir()
        pnpm_lock_path = other_dir / 'pnpm-lock.yaml'

        package_json_path.write_text('{"name": "test"}')
        pnpm_lock_path.write_text('lockfileVersion: 5.4\n')

        document = Document(
            path=str(package_json_path),
            content='{"name": "test"}',
            absolute_path=str(package_json_path),
        )

        # Mock the base class to verify it's called (since lockfile not found)
        with patch.object(
            restore_npm_dependencies.__class__.__bases__[0],
            'try_restore_dependencies',
            return_value=None,
        ) as mock_super:
            restore_npm_dependencies.try_restore_dependencies(document)

            # Should proceed with normal flow since lockfile not in same directory
            mock_super.assert_called_once_with(document)

    def test_non_json_file_should_not_trigger_restore(
        self, restore_npm_dependencies: RestoreNpmDependencies, tmp_path: Path
    ) -> None:
        """Test that non-JSON files don't trigger restore."""
        text_file = tmp_path / 'readme.txt'
        text_file.write_text('Some text')

        document = Document(
            path=str(text_file),
            content='Some text',
            absolute_path=str(text_file),
        )

        # Should return None because is_project() returns False
        result = restore_npm_dependencies.try_restore_dependencies(document)

        assert result is None


class TestRestoreNpmDependenciesHelperMethods:
    """Test helper methods."""

    def test_is_project_with_json_file(self, restore_npm_dependencies: RestoreNpmDependencies) -> None:
        """Test is_project identifies JSON files correctly."""
        document = Document('package.json', '{}')
        assert restore_npm_dependencies.is_project(document) is True

        document = Document('tsconfig.json', '{}')
        assert restore_npm_dependencies.is_project(document) is True

    def test_is_project_with_non_json_file(self, restore_npm_dependencies: RestoreNpmDependencies) -> None:
        """Test is_project returns False for non-JSON files."""
        document = Document('readme.txt', 'text')
        assert restore_npm_dependencies.is_project(document) is False

        document = Document('script.js', 'code')
        assert restore_npm_dependencies.is_project(document) is False

    def test_get_lock_file_name(self, restore_npm_dependencies: RestoreNpmDependencies) -> None:
        """Test get_lock_file_name returns the correct name."""
        assert restore_npm_dependencies.get_lock_file_name() == NPM_LOCK_FILE_NAME

    def test_get_lock_file_names(self, restore_npm_dependencies: RestoreNpmDependencies) -> None:
        """Test get_lock_file_names returns all lockfile names."""
        lock_file_names = restore_npm_dependencies.get_lock_file_names()
        assert NPM_LOCK_FILE_NAME in lock_file_names
        for alt_lock in ALTERNATIVE_LOCK_FILES:
            assert alt_lock in lock_file_names

    def test_prepare_manifest_file_path_for_command(self, restore_npm_dependencies: RestoreNpmDependencies) -> None:
        """Test prepare_manifest_file_path_for_command removes package.json from the path."""
        result = restore_npm_dependencies.prepare_manifest_file_path_for_command('/path/to/package.json')
        assert result == '/path/to'

        result = restore_npm_dependencies.prepare_manifest_file_path_for_command('package.json')
        assert result == ''
