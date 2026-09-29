import json
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
import typer

from cycode.cli.files_collector.sca.npm.restore_npm_dependencies import (
    NPM_LOCK_FILE_NAME,
    NPM_SHRINKWRAP_FILE_NAME,
    RestoreNpmDependencies,
)
from cycode.cli.models import Document


@pytest.fixture
def mock_ctx(tmp_path: Path) -> typer.Context:
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = {'monitor': False}
    ctx.params = {'path': str(tmp_path)}
    return ctx


@pytest.fixture
def restore_npm(mock_ctx: typer.Context) -> RestoreNpmDependencies:
    return RestoreNpmDependencies(mock_ctx, is_git_diff=False, command_timeout=30)


class TestIsProject:
    def test_package_json_with_no_lockfile_matches(self, restore_npm: RestoreNpmDependencies, tmp_path: Path) -> None:
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))
        assert restore_npm.is_project(doc) is True

    def test_package_json_with_yarn_lock_does_not_match(
        self, restore_npm: RestoreNpmDependencies, tmp_path: Path
    ) -> None:
        """Yarn projects are handled by RestoreYarnDependencies — NPM should not claim them."""
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        (tmp_path / 'yarn.lock').write_text('# yarn lockfile v1\n')
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))
        assert restore_npm.is_project(doc) is False

    def test_package_json_with_pnpm_lock_does_not_match(
        self, restore_npm: RestoreNpmDependencies, tmp_path: Path
    ) -> None:
        """pnpm projects are handled by RestorePnpmDependencies — NPM should not claim them."""
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        (tmp_path / 'pnpm-lock.yaml').write_text('lockfileVersion: 5.4\n')
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))
        assert restore_npm.is_project(doc) is False

    def test_package_json_with_bun_lock_does_not_match(
        self, restore_npm: RestoreNpmDependencies, tmp_path: Path
    ) -> None:
        """Bun projects are handled by RestoreBunDependencies — NPM should not claim them."""
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        (tmp_path / 'bun.lock').write_text('{"lockfileVersion": 1}\n')
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))
        assert restore_npm.is_project(doc) is False

    def test_package_json_with_only_a_binary_bun_lock_still_matches(
        self, restore_npm: RestoreNpmDependencies, tmp_path: Path
    ) -> None:
        """Bun restores only from a text bun.lock, so npm must stay the fallback for a Bun <1.2 project.

        Excluding bun.lockb here would leave such a project with no handler at all and no collected
        dependencies, which is worse than an npm-resolved lockfile.
        """
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        (tmp_path / 'bun.lockb').write_bytes(b'\x00bun-binary-lockfile')
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))
        assert restore_npm.is_project(doc) is True

    def test_tsconfig_json_does_not_match(self, restore_npm: RestoreNpmDependencies) -> None:
        doc = Document('tsconfig.json', '{}')
        assert restore_npm.is_project(doc) is False

    def test_arbitrary_json_does_not_match(self, restore_npm: RestoreNpmDependencies) -> None:
        for filename in ('jest.config.json', '.eslintrc.json', 'settings.json', 'bom.json'):
            doc = Document(filename, '{}')
            assert restore_npm.is_project(doc) is False, f'Expected False for {filename}'

    def test_non_json_file_does_not_match(self, restore_npm: RestoreNpmDependencies) -> None:
        for filename in ('readme.txt', 'script.js', 'Makefile'):
            doc = Document(filename, '')
            assert restore_npm.is_project(doc) is False, f'Expected False for {filename}'


class TestTryRestoreDependencies:
    def test_no_lockfile_calls_base_class(self, restore_npm: RestoreNpmDependencies, tmp_path: Path) -> None:
        """When no lockfile exists, the base class (npm install) should be invoked."""
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))

        with patch.object(
            restore_npm.__class__.__bases__[0], 'try_restore_dependencies', return_value=None
        ) as mock_super:
            restore_npm.try_restore_dependencies(doc)
            mock_super.assert_called_once_with(doc)

    def test_lockfile_in_different_directory_still_calls_base_class(
        self, restore_npm: RestoreNpmDependencies, tmp_path: Path
    ) -> None:
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        other_dir = tmp_path / 'other'
        other_dir.mkdir()
        (other_dir / 'pnpm-lock.yaml').write_text('lockfileVersion: 5.4\n')
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))

        with patch.object(
            restore_npm.__class__.__bases__[0], 'try_restore_dependencies', return_value=None
        ) as mock_super:
            restore_npm.try_restore_dependencies(doc)
            mock_super.assert_called_once_with(doc)


class TestGetLockFileName:
    def test_get_lock_file_name(self, restore_npm: RestoreNpmDependencies) -> None:
        assert restore_npm.get_lock_file_name() == NPM_LOCK_FILE_NAME

    def test_get_lock_file_names_contains_both_npm_lockfile_spellings(
        self, restore_npm: RestoreNpmDependencies
    ) -> None:
        """A project may commit npm-shrinkwrap.json instead of package-lock.json; both must be honoured."""
        assert restore_npm.get_lock_file_names() == [NPM_LOCK_FILE_NAME, NPM_SHRINKWRAP_FILE_NAME]

    def test_restored_name_keeps_the_shrinkwrap_spelling(self, restore_npm: RestoreNpmDependencies) -> None:
        """The collected document must report the file we actually read, not a renamed copy."""
        path = str(Path('/repo/npm-shrinkwrap.json'))
        assert restore_npm.get_restored_lock_file_name(path) == NPM_SHRINKWRAP_FILE_NAME

    def test_restored_name_defaults_to_package_lock(self, restore_npm: RestoreNpmDependencies) -> None:
        path = str(Path('/repo/package-lock.json'))
        assert restore_npm.get_restored_lock_file_name(path) == NPM_LOCK_FILE_NAME


_BASE_MODULE = 'cycode.cli.files_collector.sca.base_restore_dependencies'


class TestCleanup:
    def test_generated_lockfile_is_deleted_after_restore(
        self, restore_npm: RestoreNpmDependencies, tmp_path: Path
    ) -> None:
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))
        lock_path = tmp_path / NPM_LOCK_FILE_NAME

        def side_effect(
            commands: list,
            timeout: int,
            output_file_path: Optional[str] = None,
            working_directory: Optional[str] = None,
        ) -> str:
            lock_path.write_text('{"lockfileVersion": 3}')
            return 'output'

        with patch(f'{_BASE_MODULE}.execute_commands', side_effect=side_effect):
            result = restore_npm.try_restore_dependencies(doc)

        assert result is not None
        assert not lock_path.exists(), f'{NPM_LOCK_FILE_NAME} must be deleted after restore'

    def test_committed_shrinkwrap_is_used_instead_of_regenerating(
        self, restore_npm: RestoreNpmDependencies, tmp_path: Path
    ) -> None:
        """A project may ship npm-shrinkwrap.json; regenerating would re-resolve it against the registry."""
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        shrinkwrap_path = tmp_path / NPM_SHRINKWRAP_FILE_NAME
        shrinkwrap_path.write_text('{"lockfileVersion": 3, "packages": {"": {}}}')
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))

        with patch(f'{_BASE_MODULE}.execute_commands') as mock_execute:
            result = restore_npm.try_restore_dependencies(doc)

        mock_execute.assert_not_called()
        assert result is not None
        assert result.content == shrinkwrap_path.read_text()
        assert Path(result.path).name == NPM_SHRINKWRAP_FILE_NAME
        assert shrinkwrap_path.exists(), 'A committed lockfile must not be deleted'

    def test_preexisting_lockfile_is_not_deleted(self, restore_npm: RestoreNpmDependencies, tmp_path: Path) -> None:
        (tmp_path / 'package.json').write_text('{"name": "test"}')
        lock_path = tmp_path / NPM_LOCK_FILE_NAME
        lock_path.write_text('{"lockfileVersion": 3, "packages": {}}')
        doc = Document(str(tmp_path / 'package.json'), '{"name": "test"}', absolute_path=str(tmp_path / 'package.json'))

        result = restore_npm.try_restore_dependencies(doc)

        assert result is not None
        assert lock_path.exists(), f'Pre-existing {NPM_LOCK_FILE_NAME} must not be deleted'


class TestPrepareManifestFilePath:
    def test_strips_package_json_filename(self, restore_npm: RestoreNpmDependencies) -> None:
        path = str(Path('/path/to/package.json'))
        expected = str(Path('/path/to'))
        assert restore_npm.prepare_manifest_file_path_for_command(path) == expected

    def test_package_json_in_cwd_returns_empty_string(self, restore_npm: RestoreNpmDependencies) -> None:
        assert restore_npm.prepare_manifest_file_path_for_command('package.json') == ''

    def test_non_package_json_path_returned_unchanged(self, restore_npm: RestoreNpmDependencies) -> None:
        path = str(Path('/path/to/'))
        assert restore_npm.prepare_manifest_file_path_for_command(path) == path


class TestIsProjectInNpmWorkspace:
    @staticmethod
    def _member_document(member_dir: Path) -> Document:
        manifest = member_dir / 'package.json'
        return Document(str(manifest), manifest.read_text(), absolute_path=str(manifest))

    @staticmethod
    def _write_workspace_root(root: Path, *, lockfile_members: Optional[list] = None) -> None:
        (root / 'package.json').write_text('{"name": "root", "workspaces": ["frontend"]}')
        if lockfile_members is None:
            return

        packages = {'': {}}
        for member in lockfile_members:
            packages[member] = {}
        (root / NPM_LOCK_FILE_NAME).write_text(json.dumps({'lockfileVersion': 3, 'packages': packages}))

    def test_workspace_member_covered_by_the_root_lockfile_does_not_match(
        self, restore_npm: RestoreNpmDependencies, tmp_path: Path
    ) -> None:
        """npm installs a workspace from the root lockfile, so a member lockfile is never used."""
        self._write_workspace_root(tmp_path, lockfile_members=['frontend'])
        member_dir = tmp_path / 'frontend'
        member_dir.mkdir()
        (member_dir / 'package.json').write_text('{"name": "frontend"}')

        assert restore_npm.is_project(self._member_document(member_dir)) is False

    def test_workspace_member_not_listed_in_the_root_lockfile_matches(
        self, restore_npm: RestoreNpmDependencies, tmp_path: Path
    ) -> None:
        """The root lockfile covers other members, so this one still needs its own."""
        self._write_workspace_root(tmp_path, lockfile_members=['other'])
        member_dir = tmp_path / 'frontend'
        member_dir.mkdir()
        (member_dir / 'package.json').write_text('{"name": "frontend"}')

        assert restore_npm.is_project(self._member_document(member_dir)) is True

    def test_workspace_root_without_a_lockfile_still_matches(
        self, restore_npm: RestoreNpmDependencies, tmp_path: Path
    ) -> None:
        """Nothing covers the member yet, so the restore must still run."""
        self._write_workspace_root(tmp_path)
        member_dir = tmp_path / 'frontend'
        member_dir.mkdir()
        (member_dir / 'package.json').write_text('{"name": "frontend"}')

        assert restore_npm.is_project(self._member_document(member_dir)) is True

    def test_nested_project_that_is_not_a_workspace_member_matches(
        self, restore_npm: RestoreNpmDependencies, tmp_path: Path
    ) -> None:
        """A monorepo of independent packages: each one needs its own lockfile."""
        (tmp_path / 'package.json').write_text('{"name": "outer"}')
        (tmp_path / NPM_LOCK_FILE_NAME).write_text(json.dumps({'lockfileVersion': 3, 'packages': {'': {}}}))
        member_dir = tmp_path / 'nested'
        member_dir.mkdir()
        (member_dir / 'package.json').write_text('{"name": "nested"}')

        assert restore_npm.is_project(self._member_document(member_dir)) is True

    def test_workspace_root_itself_still_matches(self, restore_npm: RestoreNpmDependencies, tmp_path: Path) -> None:
        """The root owns the lockfile; try_restore_dependencies reads it instead of regenerating."""
        self._write_workspace_root(tmp_path, lockfile_members=['frontend'])

        manifest = tmp_path / 'package.json'
        doc = Document(str(manifest), manifest.read_text(), absolute_path=str(manifest))

        assert restore_npm.is_project(doc) is True

    def test_root_lockfile_that_is_not_a_json_object_matches(
        self, restore_npm: RestoreNpmDependencies, tmp_path: Path
    ) -> None:
        """A lockfile whose JSON root is not an object must not abort the scan."""
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["frontend"]}')
        (tmp_path / NPM_LOCK_FILE_NAME).write_text('[1, 2, 3]')
        member_dir = tmp_path / 'frontend'
        member_dir.mkdir()
        (member_dir / 'package.json').write_text('{"name": "frontend"}')

        assert restore_npm.is_project(self._member_document(member_dir)) is True

    def test_malformed_root_lockfile_matches(self, restore_npm: RestoreNpmDependencies, tmp_path: Path) -> None:
        """Unparseable lockfile: fall back to generating rather than failing the scan."""
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["frontend"]}')
        (tmp_path / NPM_LOCK_FILE_NAME).write_text('this is not json')
        member_dir = tmp_path / 'frontend'
        member_dir.mkdir()
        (member_dir / 'package.json').write_text('{"name": "frontend"}')

        assert restore_npm.is_project(self._member_document(member_dir)) is True

    def test_workspace_member_covered_by_a_root_shrinkwrap_does_not_match(
        self, restore_npm: RestoreNpmDependencies, tmp_path: Path
    ) -> None:
        """npm shrinkwrap just renames the lockfile, so it resolves the workspace the same way."""
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["frontend"]}')
        (tmp_path / NPM_SHRINKWRAP_FILE_NAME).write_text(
            json.dumps({'lockfileVersion': 3, 'packages': {'': {}, 'frontend': {}}})
        )
        member_dir = tmp_path / 'frontend'
        member_dir.mkdir()
        (member_dir / 'package.json').write_text('{"name": "frontend"}')

        assert restore_npm.is_project(self._member_document(member_dir)) is False

    def test_workspace_member_covered_by_a_lockfile_version_2_root_does_not_match(
        self, restore_npm: RestoreNpmDependencies, tmp_path: Path
    ) -> None:
        """npm 7 writes lockfileVersion 2, which carries both "packages" and the legacy "dependencies"."""
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["frontend"]}')
        (tmp_path / NPM_LOCK_FILE_NAME).write_text(
            json.dumps({'lockfileVersion': 2, 'packages': {'': {}, 'frontend': {}}, 'dependencies': {}})
        )
        member_dir = tmp_path / 'frontend'
        member_dir.mkdir()
        (member_dir / 'package.json').write_text('{"name": "frontend"}')

        assert restore_npm.is_project(self._member_document(member_dir)) is False

    def test_lockfile_version_1_root_still_matches(self, restore_npm: RestoreNpmDependencies, tmp_path: Path) -> None:
        """Workspaces arrived in npm 7 with lockfileVersion 2, so a v1 lockfile never describes one."""
        (tmp_path / 'package.json').write_text('{"name": "root"}')
        (tmp_path / NPM_LOCK_FILE_NAME).write_text(
            json.dumps({'lockfileVersion': 1, 'dependencies': {'y18n': {'version': '5.0.0'}}})
        )
        member_dir = tmp_path / 'frontend'
        member_dir.mkdir()
        (member_dir / 'package.json').write_text('{"name": "frontend"}')

        assert restore_npm.is_project(self._member_document(member_dir)) is True

    def test_file_dependency_directory_still_matches(self, restore_npm: RestoreNpmDependencies, tmp_path: Path) -> None:
        """npm records a file: target exactly like a workspace member, but only members resolve
        through the root lockfile, so a file: target still needs its own."""
        (tmp_path / 'package.json').write_text('{"name": "root", "dependencies": {"local-lib": "file:local-lib"}}')
        (tmp_path / NPM_LOCK_FILE_NAME).write_text(
            json.dumps({'lockfileVersion': 3, 'packages': {'': {}, 'local-lib': {}}})
        )
        member_dir = tmp_path / 'local-lib'
        member_dir.mkdir()
        (member_dir / 'package.json').write_text('{"name": "local-lib"}')

        assert restore_npm.is_project(self._member_document(member_dir)) is True

    def test_workspace_glob_does_not_match_a_deeper_directory(
        self, restore_npm: RestoreNpmDependencies, tmp_path: Path
    ) -> None:
        """A single star stops at a path separator, so packages/* must not claim packages/a/b."""
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["packages/*"]}')
        (tmp_path / NPM_LOCK_FILE_NAME).write_text(
            json.dumps({'lockfileVersion': 3, 'packages': {'': {}, 'packages/a/b': {}}})
        )
        member_dir = tmp_path / 'packages' / 'a' / 'b'
        member_dir.mkdir(parents=True)
        (member_dir / 'package.json').write_text('{"name": "deep"}')

        assert restore_npm.is_project(self._member_document(member_dir)) is True

    def test_workspace_glob_star_matches_a_direct_child(
        self, restore_npm: RestoreNpmDependencies, tmp_path: Path
    ) -> None:
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["packages/*"]}')
        (tmp_path / NPM_LOCK_FILE_NAME).write_text(
            json.dumps({'lockfileVersion': 3, 'packages': {'': {}, 'packages/member': {}}})
        )
        member_dir = tmp_path / 'packages' / 'member'
        member_dir.mkdir(parents=True)
        (member_dir / 'package.json').write_text('{"name": "member"}')

        assert restore_npm.is_project(self._member_document(member_dir)) is False

    def test_workspaces_object_form_is_honoured(self, restore_npm: RestoreNpmDependencies, tmp_path: Path) -> None:
        """npm also accepts {"workspaces": {"packages": [...]}}."""
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": {"packages": ["packages/member"]}}')
        (tmp_path / NPM_LOCK_FILE_NAME).write_text(
            json.dumps({'lockfileVersion': 3, 'packages': {'': {}, 'packages/member': {}}})
        )
        member_dir = tmp_path / 'packages' / 'member'
        member_dir.mkdir(parents=True)
        (member_dir / 'package.json').write_text('{"name": "member"}')

        assert restore_npm.is_project(self._member_document(member_dir)) is False
