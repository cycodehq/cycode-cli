import json
import logging
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import typer

from cycode.cli.files_collector.sca.npm import workspace
from cycode.cli.files_collector.sca.npm.restore_bun_dependencies import RestoreBunDependencies
from cycode.cli.files_collector.sca.npm.restore_npm_dependencies import RestoreNpmDependencies
from cycode.cli.files_collector.sca.npm.restore_pnpm_dependencies import RestorePnpmDependencies
from cycode.cli.files_collector.sca.npm.restore_yarn_dependencies import RestoreYarnDependencies
from cycode.cli.files_collector.sca.npm.workspace import (
    clear_cache,
    find_covering_workspace,
    is_covered_workspace_member,
)
from cycode.cli.models import Document


@pytest.fixture(autouse=True)
def _clear_workspace_cache() -> None:
    """Every test must see the filesystem it just built, not a previous test's memo."""
    clear_cache()


_WORKSPACE_LOGGER_NAME = 'SCA NPM Workspace'


def _write_member(root: Path, relative_dir: str, name: str = 'member') -> Path:
    member_dir = root / relative_dir
    member_dir.mkdir(parents=True, exist_ok=True)
    (member_dir / 'package.json').write_text(json.dumps({'name': name}))
    return member_dir


def _write_npm_lockfile(root: Path, members: list, file_name: str = 'package-lock.json') -> None:
    packages = {'': {'name': 'root'}}
    for member in members:
        packages[member] = {'name': member}
    (root / file_name).write_text(json.dumps({'lockfileVersion': 3, 'packages': packages}))


class TestNpmWorkspaceCoverage:
    def test_member_covered_by_the_root_lockfile(self, tmp_path: Path) -> None:
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["packages/*"]}')
        _write_npm_lockfile(tmp_path, ['packages/app'])
        member_dir = _write_member(tmp_path, 'packages/app')

        coverage = find_covering_workspace(str(member_dir))

        assert coverage is not None
        assert coverage.package_manager == 'npm'
        assert coverage.lock_file == tmp_path / 'package-lock.json'

    def test_member_covered_by_a_root_shrinkwrap(self, tmp_path: Path) -> None:
        """npm shrinkwrap only renames the lockfile, so it resolves the workspace the same way."""
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["packages/*"]}')
        _write_npm_lockfile(tmp_path, ['packages/app'], file_name='npm-shrinkwrap.json')
        member_dir = _write_member(tmp_path, 'packages/app')

        coverage = find_covering_workspace(str(member_dir))

        assert coverage is not None
        assert coverage.lock_file.name == 'npm-shrinkwrap.json'

    def test_stale_root_lockfile_missing_the_member_is_not_coverage(self, tmp_path: Path) -> None:
        """A root lockfile written before the member existed cannot resolve it, so it must still restore."""
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["packages/*"]}')
        _write_npm_lockfile(tmp_path, ['packages/other'])
        member_dir = _write_member(tmp_path, 'packages/app')

        assert find_covering_workspace(str(member_dir)) is None

    def test_file_dependency_target_is_not_a_member(self, tmp_path: Path) -> None:
        """npm records a file: target exactly like a member, but it does not resolve through the root lockfile."""
        (tmp_path / 'package.json').write_text('{"name": "root", "dependencies": {"lib": "file:lib"}}')
        _write_npm_lockfile(tmp_path, ['lib'])
        member_dir = _write_member(tmp_path, 'lib')

        assert find_covering_workspace(str(member_dir)) is None

    def test_lockfile_version_1_root_is_not_coverage(self, tmp_path: Path) -> None:
        """Workspaces arrived in npm 7 with lockfileVersion 2, so a v1 lockfile never describes one."""
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["packages/*"]}')
        (tmp_path / 'package-lock.json').write_text(json.dumps({'lockfileVersion': 1, 'dependencies': {}}))
        member_dir = _write_member(tmp_path, 'packages/app')

        assert find_covering_workspace(str(member_dir)) is None

    def test_malformed_root_lockfile_is_not_coverage(self, tmp_path: Path) -> None:
        """An unparseable lockfile must fall back to restoring rather than failing the scan."""
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["packages/*"]}')
        (tmp_path / 'package-lock.json').write_text('this is not json')
        member_dir = _write_member(tmp_path, 'packages/app')

        assert find_covering_workspace(str(member_dir)) is None


class TestNonNpmWorkspaceCoverage:
    @pytest.mark.parametrize(
        ('lock_file_name', 'lock_file_content', 'expected_package_manager'),
        [
            ('yarn.lock', '# yarn lockfile v1\n', 'yarn'),
            ('bun.lock', '{"lockfileVersion": 1}', 'bun'),
            ('deno.lock', '{"version": "4"}', 'deno'),
        ],
    )
    def test_member_covered_by_a_root_lockfile_of_another_package_manager(
        self, tmp_path: Path, lock_file_name: str, lock_file_content: str, expected_package_manager: str
    ) -> None:
        """The member folder holds no lockfile, so without this npm would claim it and generate the wrong one."""
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["packages/*"]}')
        (tmp_path / lock_file_name).write_text(lock_file_content)
        member_dir = _write_member(tmp_path, 'packages/app')

        coverage = find_covering_workspace(str(member_dir))

        assert coverage is not None
        assert coverage.package_manager == expected_package_manager

    def test_member_covered_by_a_binary_bun_lockfile(self, tmp_path: Path) -> None:
        """Bun <1.2 writes a binary bun.lockb; it still proves Bun owns the workspace."""
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["packages/*"]}')
        (tmp_path / 'bun.lockb').write_bytes(b'\x00bun-binary-lockfile')
        member_dir = _write_member(tmp_path, 'packages/app')

        coverage = find_covering_workspace(str(member_dir))

        assert coverage is not None
        assert coverage.package_manager == 'bun'

    def test_pnpm_declares_its_workspace_outside_package_json(self, tmp_path: Path) -> None:
        """pnpm lists members in pnpm-workspace.yaml, so the package.json "workspaces" field is absent."""
        (tmp_path / 'package.json').write_text('{"name": "root", "private": true}')
        (tmp_path / 'pnpm-workspace.yaml').write_text('packages:\n  - "packages/*"\n')
        (tmp_path / 'pnpm-lock.yaml').write_text("lockfileVersion: '9.0'\n")
        member_dir = _write_member(tmp_path, 'packages/app')

        coverage = find_covering_workspace(str(member_dir))

        assert coverage is not None
        assert coverage.package_manager == 'pnpm'

    def test_malformed_pnpm_workspace_file_is_not_coverage(self, tmp_path: Path) -> None:
        (tmp_path / 'package.json').write_text('{"name": "root", "private": true}')
        (tmp_path / 'pnpm-workspace.yaml').write_text('packages: [unclosed\n  - "oops"\n')
        (tmp_path / 'pnpm-lock.yaml').write_text("lockfileVersion: '9.0'\n")
        member_dir = _write_member(tmp_path, 'packages/app')

        assert find_covering_workspace(str(member_dir)) is None

    def test_root_without_any_lockfile_is_not_coverage(self, tmp_path: Path) -> None:
        """Nothing resolves the member yet, so the restore must still run."""
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["packages/*"]}')
        member_dir = _write_member(tmp_path, 'packages/app')

        assert find_covering_workspace(str(member_dir)) is None


class TestWorkspacePatternMatching:
    def test_single_star_stops_at_a_path_separator(self, tmp_path: Path) -> None:
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["packages/*"]}')
        _write_npm_lockfile(tmp_path, ['packages/a/b'])
        member_dir = _write_member(tmp_path, 'packages/a/b')

        assert find_covering_workspace(str(member_dir)) is None

    def test_double_star_crosses_a_path_separator(self, tmp_path: Path) -> None:
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["packages/**"]}')
        _write_npm_lockfile(tmp_path, ['packages/a/b'])
        member_dir = _write_member(tmp_path, 'packages/a/b')

        assert find_covering_workspace(str(member_dir)) is not None

    def test_workspaces_object_form_is_honoured(self, tmp_path: Path) -> None:
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": {"packages": ["packages/*"]}}')
        _write_npm_lockfile(tmp_path, ['packages/app'])
        member_dir = _write_member(tmp_path, 'packages/app')

        assert find_covering_workspace(str(member_dir)) is not None

    def test_leading_dot_slash_and_trailing_slash_are_normalized(self, tmp_path: Path) -> None:
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["./packages/app/"]}')
        _write_npm_lockfile(tmp_path, ['packages/app'])
        member_dir = _write_member(tmp_path, 'packages/app')

        assert find_covering_workspace(str(member_dir)) is not None

    def test_negated_pattern_excludes_a_member(self, tmp_path: Path) -> None:
        """packages/* matches, but the exclusion wins — treating "!" as a literal would lose this project."""
        (tmp_path / 'package.json').write_text(
            '{"name": "root", "workspaces": ["packages/*", "!packages/legacy"]}',
        )
        _write_npm_lockfile(tmp_path, ['packages/legacy'])
        member_dir = _write_member(tmp_path, 'packages/legacy')

        assert find_covering_workspace(str(member_dir)) is None

    def test_negated_pattern_leaves_other_members_covered(self, tmp_path: Path) -> None:
        (tmp_path / 'package.json').write_text(
            '{"name": "root", "workspaces": ["packages/*", "!packages/legacy"]}',
        )
        _write_npm_lockfile(tmp_path, ['packages/app'])
        member_dir = _write_member(tmp_path, 'packages/app')

        assert find_covering_workspace(str(member_dir)) is not None

    def test_non_string_workspace_entries_are_ignored(self, tmp_path: Path) -> None:
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": [null, 7, "packages/*"]}')
        _write_npm_lockfile(tmp_path, ['packages/app'])
        member_dir = _write_member(tmp_path, 'packages/app')

        assert find_covering_workspace(str(member_dir)) is not None


class TestWorkspaceRootWalk:
    def test_a_workspace_nested_inside_another_workspace(self, tmp_path: Path) -> None:
        """The inner root owns the member; the walk must stop at the nearest declaring ancestor."""
        (tmp_path / 'package.json').write_text('{"name": "outer", "workspaces": ["apps/*"]}')
        (tmp_path / 'yarn.lock').write_text('# yarn lockfile v1\n')

        inner_root = tmp_path / 'apps' / 'inner'
        inner_root.mkdir(parents=True)
        (inner_root / 'package.json').write_text('{"name": "inner", "workspaces": ["packages/*"]}')
        _write_npm_lockfile(inner_root, ['packages/app'])
        member_dir = _write_member(inner_root, 'packages/app')

        coverage = find_covering_workspace(str(member_dir))

        assert coverage is not None
        assert coverage.package_manager == 'npm'
        assert coverage.lock_file == inner_root / 'package-lock.json'

    def test_outer_workspace_covers_a_member_the_inner_root_does_not_declare(self, tmp_path: Path) -> None:
        """The walk continues past an ancestor that declares no matching pattern."""
        (tmp_path / 'package.json').write_text('{"name": "outer", "workspaces": ["apps/**"]}')
        (tmp_path / 'yarn.lock').write_text('# yarn lockfile v1\n')

        inner_root = tmp_path / 'apps' / 'inner'
        inner_root.mkdir(parents=True)
        (inner_root / 'package.json').write_text('{"name": "inner"}')
        member_dir = _write_member(inner_root, 'packages/app')

        coverage = find_covering_workspace(str(member_dir))

        assert coverage is not None
        assert coverage.package_manager == 'yarn'

    def test_the_walk_stops_at_the_git_repository_root(self, tmp_path: Path) -> None:
        """A manifest above the repository must never suppress a project inside it."""
        repo_root = tmp_path / 'repo'
        repo_root.mkdir()
        (repo_root / '.git').mkdir()
        (repo_root / 'package.json').write_text('{"name": "repo"}')

        (tmp_path / 'package.json').write_text('{"name": "outside", "workspaces": ["repo/**"]}')
        _write_npm_lockfile(tmp_path, ['repo/packages/app'])

        member_dir = _write_member(repo_root, 'packages/app')

        assert find_covering_workspace(str(member_dir)) is None

    def test_a_git_file_also_marks_the_repository_root(self, tmp_path: Path) -> None:
        """Worktrees and submodules carry a .git file rather than a directory."""
        repo_root = tmp_path / 'repo'
        repo_root.mkdir()
        (repo_root / '.git').write_text('gitdir: ../.git/worktrees/repo\n')
        (repo_root / 'package.json').write_text('{"name": "repo"}')

        (tmp_path / 'package.json').write_text('{"name": "outside", "workspaces": ["repo/**"]}')
        _write_npm_lockfile(tmp_path, ['repo/packages/app'])

        member_dir = _write_member(repo_root, 'packages/app')

        assert find_covering_workspace(str(member_dir)) is None

    def test_no_manifest_dir_is_not_coverage(self) -> None:
        assert find_covering_workspace(None) is None
        assert find_covering_workspace('') is None


class TestIsCoveredWorkspaceMember:
    def test_warns_when_the_workspace_root_sits_outside_the_scanned_path(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Scanning only the member folder collects nothing for it, so the skip must be visible."""
        (tmp_path / '.git').mkdir()
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["packages/*"]}')
        _write_npm_lockfile(tmp_path, ['packages/app'])
        member_dir = _write_member(tmp_path, 'packages/app')

        with caplog.at_level(logging.WARNING, logger=_WORKSPACE_LOGGER_NAME):
            covered = is_covered_workspace_member(str(member_dir), 'packages/app/package.json', (str(member_dir),))

        assert covered is True
        assert 'outside the scanned path' in caplog.text

    def test_does_not_warn_when_the_workspace_root_is_scanned_too(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["packages/*"]}')
        _write_npm_lockfile(tmp_path, ['packages/app'])
        member_dir = _write_member(tmp_path, 'packages/app')

        with caplog.at_level(logging.WARNING, logger=_WORKSPACE_LOGGER_NAME):
            covered = is_covered_workspace_member(str(member_dir), 'packages/app/package.json', (str(tmp_path),))

        assert covered is True
        assert 'outside the scanned path' not in caplog.text

    def test_uncovered_member_is_not_reported(self, tmp_path: Path) -> None:
        member_dir = _write_member(tmp_path, 'packages/app')

        assert is_covered_workspace_member(str(member_dir), 'packages/app/package.json', (str(tmp_path),)) is False


class TestCaching:
    def test_the_root_lockfile_is_parsed_once_for_all_members(self, tmp_path: Path) -> None:
        """200 members must not mean 200 parses of the same multi-megabyte lockfile."""
        members = [f'packages/m{index}' for index in range(25)]
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["packages/*"]}')
        _write_npm_lockfile(tmp_path, members)
        member_dirs = [_write_member(tmp_path, member) for member in members]

        parsed_paths = []
        original_read_json_object = workspace._read_json_object

        def counting_read_json_object(path: Path) -> object:
            parsed_paths.append(str(path))
            return original_read_json_object(path)

        workspace._read_json_object = counting_read_json_object
        try:
            coverages = [find_covering_workspace(str(member_dir)) for member_dir in member_dirs]
        finally:
            workspace._read_json_object = original_read_json_object

        assert all(coverage is not None for coverage in coverages)
        assert parsed_paths.count(str(tmp_path / 'package-lock.json')) == 1
        assert parsed_paths.count(str(tmp_path / 'package.json')) == 1

    def test_clearing_the_cache_picks_up_an_edited_lockfile(self, tmp_path: Path) -> None:
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["packages/*"]}')
        _write_npm_lockfile(tmp_path, ['packages/other'])
        member_dir = _write_member(tmp_path, 'packages/app')

        assert find_covering_workspace(str(member_dir)) is None

        _write_npm_lockfile(tmp_path, ['packages/app'])
        clear_cache()

        assert find_covering_workspace(str(member_dir)) is not None


class TestNoHandlerClaimsACoveredMember:
    """The npm fallback only helps if every dedicated handler declines a member the root already resolves.

    Before this, a yarn/pnpm/bun workspace member was claimed by npm: the dedicated handler
    declined because the member folder holds no lockfile, and npm generated a package-lock.json
    for a project that does not install with npm.
    """

    @staticmethod
    def _handlers(tmp_path: Path) -> dict:
        ctx = MagicMock(spec=typer.Context)
        ctx.obj = {'monitor': False}
        ctx.params = {'path': str(tmp_path)}
        return {
            'yarn': RestoreYarnDependencies(ctx, is_git_diff=False, command_timeout=30),
            'pnpm': RestorePnpmDependencies(ctx, is_git_diff=False, command_timeout=30),
            'bun': RestoreBunDependencies(ctx, is_git_diff=False, command_timeout=30),
            'npm': RestoreNpmDependencies(ctx, is_git_diff=False, command_timeout=30),
        }

    def _claimants(self, tmp_path: Path, member_dir: Path) -> list:
        manifest = member_dir / 'package.json'
        document = Document(str(manifest), manifest.read_text(), absolute_path=str(manifest))
        return [name for name, handler in self._handlers(tmp_path).items() if handler.is_project(document)]

    @pytest.mark.parametrize(
        ('lock_file_name', 'lock_file_content'),
        [
            ('yarn.lock', '# yarn lockfile v1\n'),
            ('bun.lock', '{"lockfileVersion": 1}'),
            ('bun.lockb', '\x00binary'),
        ],
    )
    def test_no_handler_claims_a_member_of_a_non_npm_workspace(
        self, tmp_path: Path, lock_file_name: str, lock_file_content: str
    ) -> None:
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["packages/*"]}')
        (tmp_path / lock_file_name).write_text(lock_file_content)
        member_dir = _write_member(tmp_path, 'packages/app')

        assert self._claimants(tmp_path, member_dir) == []

    def test_no_handler_claims_a_member_of_a_pnpm_workspace_declared_in_yaml(self, tmp_path: Path) -> None:
        (tmp_path / 'package.json').write_text('{"name": "root", "private": true}')
        (tmp_path / 'pnpm-workspace.yaml').write_text('packages:\n  - "packages/*"\n')
        (tmp_path / 'pnpm-lock.yaml').write_text("lockfileVersion: '9.0'\n")
        member_dir = _write_member(tmp_path, 'packages/app')

        assert self._claimants(tmp_path, member_dir) == []

    def test_no_handler_claims_a_member_of_an_npm_workspace(self, tmp_path: Path) -> None:
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["packages/*"]}')
        _write_npm_lockfile(tmp_path, ['packages/app'])
        member_dir = _write_member(tmp_path, 'packages/app')

        assert self._claimants(tmp_path, member_dir) == []

    def test_a_member_declaring_yarn_is_still_skipped_when_the_root_covers_it(self, tmp_path: Path) -> None:
        """The packageManager signal must not resurrect a member the root lockfile already resolves."""
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["packages/*"]}')
        (tmp_path / 'yarn.lock').write_text('# yarn lockfile v1\n')
        member_dir = tmp_path / 'packages' / 'app'
        member_dir.mkdir(parents=True)
        (member_dir / 'package.json').write_text('{"name": "app", "packageManager": "yarn@4.0.2"}')

        assert self._claimants(tmp_path, member_dir) == []

    def test_a_member_with_its_own_lockfile_is_still_claimed(self, tmp_path: Path) -> None:
        """A lockfile inside the member is authoritative for that member, workspace or not."""
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["packages/*"]}')
        (tmp_path / 'yarn.lock').write_text('# yarn lockfile v1\n')
        member_dir = _write_member(tmp_path, 'packages/app')
        (member_dir / 'yarn.lock').write_text('# yarn lockfile v1\n')

        assert self._claimants(tmp_path, member_dir) == ['yarn']

    def test_an_independent_nested_package_is_still_claimed_by_npm(self, tmp_path: Path) -> None:
        """A monorepo of unrelated packages is not a workspace; each one still needs its own lockfile."""
        (tmp_path / 'package.json').write_text('{"name": "root"}')
        (tmp_path / 'yarn.lock').write_text('# yarn lockfile v1\n')
        member_dir = _write_member(tmp_path, 'nested')

        assert self._claimants(tmp_path, member_dir) == ['npm']

    def test_scanning_only_the_member_folder_still_declines(self, tmp_path: Path) -> None:
        """The workspace root is outside the scanned path, but generating a member lockfile is still wrong."""
        (tmp_path / '.git').mkdir()
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["packages/*"]}')
        (tmp_path / 'yarn.lock').write_text('# yarn lockfile v1\n')
        member_dir = _write_member(tmp_path, 'packages/app')

        manifest = member_dir / 'package.json'
        ctx = MagicMock(spec=typer.Context)
        ctx.obj = {'monitor': False}
        ctx.params = {'path': str(member_dir)}
        document = Document(str(manifest), manifest.read_text(), absolute_path=str(manifest))

        npm = RestoreNpmDependencies(ctx, is_git_diff=False, command_timeout=30)
        assert npm.is_project(document) is False


class TestDeclarationSourceIsNotShared:
    """pnpm reads only pnpm-workspace.yaml; npm/yarn/bun read only package.json "workspaces"."""

    def test_pnpm_lockfile_does_not_cover_a_member_declared_only_in_package_json(self, tmp_path: Path) -> None:
        """A repo migrated to pnpm may still carry a stale workspaces array; it does not make a pnpm member."""
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["packages/*"]}')
        (tmp_path / 'pnpm-lock.yaml').write_text("lockfileVersion: '9.0'\n")
        member_dir = _write_member(tmp_path, 'packages/app')

        assert find_covering_workspace(str(member_dir)) is None

    def test_pnpm_workspace_yaml_does_not_cover_a_yarn_member(self, tmp_path: Path) -> None:
        """yarn.lock coverage must come from package.json, not from a leftover pnpm-workspace.yaml."""
        (tmp_path / 'package.json').write_text('{"name": "root", "private": true}')
        (tmp_path / 'pnpm-workspace.yaml').write_text('packages:\n  - "packages/*"\n')
        (tmp_path / 'yarn.lock').write_text('# yarn lockfile v1\n')
        member_dir = _write_member(tmp_path, 'packages/app')

        assert find_covering_workspace(str(member_dir)) is None

    def test_a_pnpm_member_excluded_in_yaml_is_not_covered(self, tmp_path: Path) -> None:
        (tmp_path / 'package.json').write_text('{"name": "root", "private": true}')
        (tmp_path / 'pnpm-workspace.yaml').write_text('packages:\n  - "packages/*"\n  - "!packages/legacy"\n')
        (tmp_path / 'pnpm-lock.yaml').write_text("lockfileVersion: '9.0'\n")
        member_dir = _write_member(tmp_path, 'packages/legacy')

        assert find_covering_workspace(str(member_dir)) is None


class TestWalkBoundary:
    def test_without_a_git_root_the_walk_stops_at_the_scanned_path(self, tmp_path: Path) -> None:
        """An extracted tarball has no .git; a manifest above the scanned path must not suppress a project."""
        scanned = tmp_path / 'checkout'
        scanned.mkdir()
        (scanned / 'package.json').write_text('{"name": "checkout"}')

        (tmp_path / 'package.json').write_text('{"name": "stray", "workspaces": ["**"]}')
        _write_npm_lockfile(tmp_path, ['checkout/packages/app'])

        member_dir = _write_member(scanned, 'packages/app')

        assert find_covering_workspace(str(member_dir), (str(scanned),)) is None

    def test_without_a_git_root_the_walk_still_reaches_the_scanned_path(self, tmp_path: Path) -> None:
        """Stopping at the scanned path must not stop before it."""
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["packages/*"]}')
        _write_npm_lockfile(tmp_path, ['packages/app'])
        member_dir = _write_member(tmp_path, 'packages/app')

        assert find_covering_workspace(str(member_dir), (str(tmp_path),)) is not None

    def test_a_git_root_lets_the_walk_pass_above_the_scanned_path(self, tmp_path: Path) -> None:
        """Scanning one member of a real repository must still find the workspace root above it."""
        (tmp_path / '.git').mkdir()
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["packages/*"]}')
        _write_npm_lockfile(tmp_path, ['packages/app'])
        member_dir = _write_member(tmp_path, 'packages/app')

        assert find_covering_workspace(str(member_dir), (str(member_dir),)) is not None


class TestUnscannedRootWarning:
    def test_the_warning_is_emitted_once_even_though_four_handlers_ask(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """All four handlers consult the same check; the user must not see the same skip four times."""
        (tmp_path / '.git').mkdir()
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["packages/*"]}')
        _write_npm_lockfile(tmp_path, ['packages/app'])
        member_dir = _write_member(tmp_path, 'packages/app')

        with caplog.at_level(logging.WARNING, logger=_WORKSPACE_LOGGER_NAME):
            for _ in range(4):
                is_covered_workspace_member(str(member_dir), 'packages/app/package.json', (str(member_dir),))

        assert caplog.text.count('outside the scanned path') == 1

    def test_a_second_scan_root_containing_the_workspace_suppresses_the_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """cycode scan path ./frontend ./repo-root scans the root too, so there is nothing to warn about."""
        (tmp_path / '.git').mkdir()
        (tmp_path / 'package.json').write_text('{"name": "root", "workspaces": ["packages/*"]}')
        _write_npm_lockfile(tmp_path, ['packages/app'])
        member_dir = _write_member(tmp_path, 'packages/app')

        with caplog.at_level(logging.WARNING, logger=_WORKSPACE_LOGGER_NAME):
            covered = is_covered_workspace_member(
                str(member_dir), 'packages/app/package.json', (str(member_dir), str(tmp_path))
            )

        assert covered is True
        assert 'outside the scanned path' not in caplog.text


class TestLogNoise:
    def test_absent_ancestor_manifests_are_not_logged(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """The walk visits every ancestor; an expected absence must not look like a parse failure."""
        member_dir = _write_member(tmp_path, 'a/b/c')

        with caplog.at_level(logging.DEBUG, logger=_WORKSPACE_LOGGER_NAME):
            find_covering_workspace(str(member_dir), (str(tmp_path),))

        assert 'Could not read' not in caplog.text

    def test_a_genuine_parse_failure_is_still_logged(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """Silencing the expected absences must not also silence a real malformed file."""
        (tmp_path / 'package.json').write_text('{"name": "root", "private": true}')
        (tmp_path / 'pnpm-workspace.yaml').write_text('packages: [unclosed\n  - "oops"\n')
        (tmp_path / 'pnpm-lock.yaml').write_text("lockfileVersion: '9.0'\n")
        member_dir = _write_member(tmp_path, 'packages/app')

        with caplog.at_level(logging.DEBUG, logger=_WORKSPACE_LOGGER_NAME):
            find_covering_workspace(str(member_dir), (str(tmp_path),))

        assert 'Could not read' in caplog.text


class TestFileNamesHaveASingleSource:
    """workspace.py owns every file name in the npm module.

    Each handler previously declared its own copy, so the workspace coverage table and the
    handler that consumes it could drift apart over time without anything failing.
    """

    def test_each_handler_reuses_the_shared_name(self) -> None:
        from cycode.cli.files_collector.sca.npm import (
            restore_bun_dependencies,
            restore_deno_dependencies,
            restore_npm_dependencies,
            restore_pnpm_dependencies,
            restore_yarn_dependencies,
        )

        assert restore_yarn_dependencies.YARN_LOCK_FILE_NAME is workspace.YARN_LOCK_FILE_NAME
        assert restore_pnpm_dependencies.PNPM_LOCK_FILE_NAME is workspace.PNPM_LOCK_FILE_NAME
        assert restore_bun_dependencies.BUN_LOCK_FILE_NAME is workspace.BUN_LOCK_FILE_NAME
        assert restore_deno_dependencies.DENO_LOCK_FILE_NAME is workspace.DENO_LOCK_FILE_NAME
        assert restore_npm_dependencies.NPM_LOCK_FILE_NAME is workspace.NPM_LOCK_FILE_NAME
        assert restore_npm_dependencies.NPM_SHRINKWRAP_FILE_NAME is workspace.NPM_SHRINKWRAP_FILE_NAME

        for module in (
            restore_npm_dependencies.NPM_MANIFEST_FILE_NAME,
            restore_yarn_dependencies.YARN_MANIFEST_FILE_NAME,
            restore_pnpm_dependencies.PNPM_MANIFEST_FILE_NAME,
            restore_bun_dependencies.BUN_MANIFEST_FILE_NAME,
        ):
            assert module is workspace.MANIFEST_FILE_NAME

    def test_every_name_is_declared_only_in_workspace(self) -> None:
        """A new literal anywhere else in the module reintroduces exactly the drift this prevents."""
        module_dir = Path(workspace.__file__).parent
        names = (
            'package.json',
            'package-lock.json',
            'npm-shrinkwrap.json',
            'yarn.lock',
            'pnpm-lock.yaml',
            'pnpm-workspace.yaml',
            'bun.lock',
            'bun.lockb',
            'deno.lock',
        )

        offenders = {}
        for source in module_dir.glob('*.py'):
            if source.name == 'workspace.py':
                continue

            text = source.read_text(encoding='UTF-8')
            declared = [name for name in names if f"'{name}'" in text]
            if declared:
                offenders[source.name] = declared

        assert offenders == {}, f'file names must come from workspace.py, but found literals in: {offenders}'

    def test_the_alternative_lockfiles_come_from_the_shared_table(self) -> None:
        """npm declines a project owned by another package manager; bun.lockb is the deliberate exception."""
        from cycode.cli.files_collector.sca.npm.restore_npm_dependencies import _ALTERNATIVE_LOCK_FILES

        non_npm_names = {
            root_lock_file.file_name
            for root_lock_file in workspace.ROOT_LOCK_FILES
            if root_lock_file.package_manager != workspace.NPM_PACKAGE_MANAGER
        }

        assert set(_ALTERNATIVE_LOCK_FILES) <= non_npm_names
        assert non_npm_names - set(_ALTERNATIVE_LOCK_FILES) == {workspace.BUN_BINARY_LOCK_FILE_NAME}
