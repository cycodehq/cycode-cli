import os
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
import typer
from git import Repo
from typer.testing import CliRunner

from cycode.cli.apps.scan.pre_commit.pre_commit_command import (
    _resolve_repo_root,
    _validate_base_ref,
    pre_commit_command,
)


@contextmanager
def temporary_git_repository() -> Generator[tuple[str, Repo], None, None]:
    with tempfile.TemporaryDirectory() as temp_dir:
        repo = Repo.init(temp_dir, b='main')
        try:
            yield temp_dir, repo
        finally:
            repo.close()


class TestValidateBaseRef:
    def test_valid_base_ref_does_not_raise(self) -> None:
        with temporary_git_repository() as (temp_dir, repo):
            file_path = os.path.join(temp_dir, 'file.txt')
            with open(file_path, 'w') as f:
                f.write('content')
            repo.index.add(['file.txt'])
            repo.index.commit('initial')

            _validate_base_ref(temp_dir, 'HEAD')

    def test_invalid_base_ref_raises_bad_parameter(self) -> None:
        with temporary_git_repository() as (temp_dir, repo):
            file_path = os.path.join(temp_dir, 'file.txt')
            with open(file_path, 'w') as f:
                f.write('content')
            repo.index.add(['file.txt'])
            repo.index.commit('initial')

            with pytest.raises(typer.BadParameter):
                _validate_base_ref(temp_dir, 'not-a-real-ref')

    def test_empty_repository_with_default_head_does_not_raise(self) -> None:
        with temporary_git_repository() as (temp_dir, _repo):
            _validate_base_ref(temp_dir, 'HEAD')


class TestResolveRepoRoot:
    """Running from any subdirectory of the repo must resolve to the actual repo root.

    Regression test: git_proxy.get_repo() requires an exact match (root or .git dir) unless
    told to search parent directories, so a naive `os.getcwd()` breaks the moment the command
    is invoked from a subdirectory -- exactly how an IDE plugin scoped to the open file's
    folder, or a workspace subdirectory in a monorepo, would invoke it. The git pre-commit hook
    framework always invokes from the repo root, so this is a no-op there.
    """

    def test_resolves_root_from_subdirectory(self) -> None:
        with temporary_git_repository() as (temp_dir, repo):
            os.makedirs(os.path.join(temp_dir, 'sub'))
            file_path = os.path.join(temp_dir, 'sub', 'app.py')
            with open(file_path, 'w') as f:
                f.write('content')
            repo.index.add(['sub/app.py'])
            repo.index.commit('initial')

            resolved_root = _resolve_repo_root(os.path.join(temp_dir, 'sub'))

            assert os.path.realpath(resolved_root) == os.path.realpath(temp_dir)

    def test_resolves_root_when_already_at_root(self) -> None:
        with temporary_git_repository() as (temp_dir, repo):
            file_path = os.path.join(temp_dir, 'file.txt')
            with open(file_path, 'w') as f:
                f.write('content')
            repo.index.add(['file.txt'])
            repo.index.commit('initial')

            resolved_root = _resolve_repo_root(temp_dir)

            assert os.path.realpath(resolved_root) == os.path.realpath(temp_dir)


class TestPreCommitCommandPathResolution:
    """A relative --path value must reach scan_pre_commit already resolved to absolute.

    Regression test: get_pre_commit_modified_documents compares an always-absolute path
    (derived from the repo's working tree) against the raw `paths` strings. Without
    `resolve_path=True` on the CLI option, a relative path (the natural way to invoke this,
    e.g. `--path sub/app.py` from the repo root) would never match, silently dropping files
    from the scoped scan.
    """

    def test_relative_path_option_is_resolved_to_absolute(self, monkeypatch: pytest.MonkeyPatch) -> None:
        original_cwd = os.getcwd()
        with temporary_git_repository() as (temp_dir, repo):
            os.makedirs(os.path.join(temp_dir, 'sub'))
            file_path = os.path.join(temp_dir, 'sub', 'app.py')
            with open(file_path, 'w') as f:
                f.write('content')
            repo.index.add(['sub/app.py'])
            repo.index.commit('initial')

            app = typer.Typer()
            app.command()(pre_commit_command)

            # Actually chdir rather than patching os.getcwd(): on Windows/Python 3.9, Click's
            # path resolution does not consistently go through the patched os.getcwd symbol,
            # so the mock silently has no effect there and the test passes for the wrong reason
            # (or, as happened in CI, resolves against the real process cwd instead).
            monkeypatch.chdir(temp_dir)
            with patch('cycode.cli.apps.scan.pre_commit.pre_commit_command.scan_pre_commit') as mock_scan:
                result = CliRunner().invoke(app, ['--path', 'sub/app.py'], obj=MagicMock())

            # monkeypatch only restores the cwd at fixture teardown, which runs after this test
            # function returns -- but temporary_git_repository()'s cleanup (below, at the end of
            # this `with` block) runs now, inside the test. Windows can't delete a directory that
            # is still the process's cwd, so we must chdir back out before that cleanup happens.
            monkeypatch.chdir(original_cwd)

            assert result.exit_code == 0, result.output
            mock_scan.assert_called_once()
            _, kwargs = mock_scan.call_args
            assert [os.path.realpath(p) for p in kwargs['paths']] == [
                os.path.realpath(os.path.join(temp_dir, 'sub', 'app.py'))
            ]


class TestPreCommitCommandFromSubdirectory:
    """End-to-end: invoking the command from a repo subdirectory must not fail."""

    def test_scan_pre_commit_called_with_repo_root_not_subdirectory(self, monkeypatch: pytest.MonkeyPatch) -> None:
        original_cwd = os.getcwd()
        with temporary_git_repository() as (temp_dir, repo):
            os.makedirs(os.path.join(temp_dir, 'sub'))
            file_path = os.path.join(temp_dir, 'sub', 'app.py')
            with open(file_path, 'w') as f:
                f.write('content')
            repo.index.add(['sub/app.py'])
            repo.index.commit('initial')

            app = typer.Typer()
            app.command()(pre_commit_command)

            # Actually chdir rather than patching os.getcwd() -- see the comment in
            # TestPreCommitCommandPathResolution for why the mock is unreliable on Windows.
            monkeypatch.chdir(os.path.join(temp_dir, 'sub'))
            with patch('cycode.cli.apps.scan.pre_commit.pre_commit_command.scan_pre_commit') as mock_scan:
                result = CliRunner().invoke(app, [], obj=MagicMock())

            # See the matching comment in TestPreCommitCommandPathResolution: must chdir back out
            # before temporary_git_repository()'s cleanup runs, or Windows can't delete the dir.
            monkeypatch.chdir(original_cwd)

            assert result.exit_code == 0, result.output
            mock_scan.assert_called_once()
            args, _kwargs = mock_scan.call_args
            assert os.path.realpath(args[1]) == os.path.realpath(temp_dir)


class TestPreCommitCommandDefaults:
    """The default invocation (no new flags) must match the pre-existing hook behavior exactly."""

    def test_default_invocation_uses_head_and_staged_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        original_cwd = os.getcwd()
        with temporary_git_repository() as (temp_dir, repo):
            file_path = os.path.join(temp_dir, 'file.txt')
            with open(file_path, 'w') as f:
                f.write('content')
            repo.index.add(['file.txt'])
            repo.index.commit('initial')

            app = typer.Typer()
            app.command()(pre_commit_command)

            monkeypatch.chdir(temp_dir)
            # Simulate the pre-commit framework's own auto-passed staged filenames -- must be
            # silently swallowed, not treated as a --path scope, per the ignored hidden argument.
            with patch('cycode.cli.apps.scan.pre_commit.pre_commit_command.scan_pre_commit') as mock_scan:
                result = CliRunner().invoke(app, ['file.txt'], obj=MagicMock())
            monkeypatch.chdir(original_cwd)

            assert result.exit_code == 0, result.output
            mock_scan.assert_called_once()
            _, kwargs = mock_scan.call_args
            assert kwargs['base_ref'] == 'HEAD'
            assert kwargs['include_unstaged'] is False
            assert kwargs['paths'] is None
