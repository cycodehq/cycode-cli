import os
import tempfile
from collections.abc import Generator
from contextlib import contextmanager

from git import Repo

from cycode.cli import consts
from cycode.cli.files_collector.commit_range_documents import (
    get_diff_file_path,
    get_safe_head_reference_for_diff,
)
from cycode.cli.utils.path_utils import get_path_by_os


@contextmanager
def git_repository(path: str) -> Generator[Repo, None, None]:
    """Context manager for Git repositories that ensures proper cleanup on Windows."""
    repo = Repo.init(path)
    try:
        yield repo
    finally:
        # Properly close the repository to release file handles
        repo.close()


@contextmanager
def temporary_git_repository() -> Generator[tuple[str, Repo], None, None]:
    """Combined context manager for temporary directory with Git repository."""
    with tempfile.TemporaryDirectory() as temp_dir, git_repository(temp_dir) as repo:
        yield temp_dir, repo


class TestGetSafeHeadReferenceForDiff:
    """Test the safe HEAD reference functionality for git diff operations."""

    def test_returns_head_when_repository_has_commits(self) -> None:
        """Test that HEAD is returned when the repository has existing commits."""
        with temporary_git_repository() as (temp_dir, repo):
            test_file = os.path.join(temp_dir, 'test.py')
            with open(test_file, 'w') as f:
                f.write("print('test')")

            repo.index.add(['test.py'])
            repo.index.commit('Initial commit')

            result = get_safe_head_reference_for_diff(repo)
            assert result == consts.GIT_HEAD_COMMIT_REV

    def test_returns_empty_tree_hash_when_repository_has_no_commits(self) -> None:
        """Test that an empty tree hash is returned when the repository has no commits."""
        with temporary_git_repository() as (temp_dir, repo):
            result = get_safe_head_reference_for_diff(repo)
            expected_empty_tree_hash = consts.GIT_EMPTY_TREE_OBJECT
            assert result == expected_empty_tree_hash


class TestIndexDiffWithSafeHeadReference:
    """Test that index.diff works correctly with the safe head reference."""

    def test_index_diff_works_on_bare_repository(self) -> None:
        """Test that index.diff works on repositories with no commits."""
        with temporary_git_repository() as (temp_dir, repo):
            test_file = os.path.join(temp_dir, 'staged_file.py')
            with open(test_file, 'w') as f:
                f.write("print('staged content')")

            repo.index.add(['staged_file.py'])

            head_ref = get_safe_head_reference_for_diff(repo)
            diff_index = repo.index.diff(head_ref, create_patch=True, R=True)

            assert len(diff_index) == 1
            diff = diff_index[0]
            assert diff.b_path == 'staged_file.py'

    def test_index_diff_works_on_repository_with_commits(self) -> None:
        """Test that index.diff continues to work on repositories with existing commits."""
        with temporary_git_repository() as (temp_dir, repo):
            initial_file = os.path.join(temp_dir, 'initial.py')
            with open(initial_file, 'w') as f:
                f.write("print('initial')")

            repo.index.add(['initial.py'])
            repo.index.commit('Initial commit')

            new_file = os.path.join(temp_dir, 'new_file.py')
            with open(new_file, 'w') as f:
                f.write("print('new file')")

            with open(initial_file, 'w') as f:
                f.write("print('modified initial')")

            repo.index.add(['new_file.py', 'initial.py'])

            head_ref = get_safe_head_reference_for_diff(repo)
            diff_index = repo.index.diff(head_ref, create_patch=True, R=True)

            assert len(diff_index) == 2
            file_paths = {diff.b_path or diff.a_path for diff in diff_index}
            assert 'new_file.py' in file_paths
            assert 'initial.py' in file_paths
            assert head_ref == consts.GIT_HEAD_COMMIT_REV

    def test_sequential_operations_on_same_repository(self) -> None:
        """Test behavior when transitioning from bare to committed repository."""
        with temporary_git_repository() as (temp_dir, repo):
            test_file = os.path.join(temp_dir, 'test.py')
            with open(test_file, 'w') as f:
                f.write("print('test')")

            repo.index.add(['test.py'])

            head_ref_before = get_safe_head_reference_for_diff(repo)
            diff_before = repo.index.diff(head_ref_before, create_patch=True, R=True)

            expected_empty_tree = consts.GIT_EMPTY_TREE_OBJECT
            assert head_ref_before == expected_empty_tree
            assert len(diff_before) == 1

            repo.index.commit('First commit')

            new_file = os.path.join(temp_dir, 'new.py')
            with open(new_file, 'w') as f:
                f.write("print('new')")

            repo.index.add(['new.py'])

            head_ref_after = get_safe_head_reference_for_diff(repo)
            diff_after = repo.index.diff(head_ref_after, create_patch=True, R=True)

            assert head_ref_after == consts.GIT_HEAD_COMMIT_REV
            assert len(diff_after) == 1
            assert diff_after[0].b_path == 'new.py'


def test_git_mv_pre_commit_scan() -> None:
    with temporary_git_repository() as (temp_dir, repo):
        newfile_path = os.path.join(temp_dir, 'NEWFILE.txt')
        with open(newfile_path, 'w') as f:
            f.write('test content')

        repo.index.add(['NEWFILE.txt'])
        repo.index.commit('init')

        # Rename file but don't commit (this is the pre-commit scenario)
        renamed_path = os.path.join(temp_dir, 'RENAMED.txt')
        os.rename(newfile_path, renamed_path)
        repo.index.remove(['NEWFILE.txt'])
        repo.index.add(['RENAMED.txt'])

        head_ref = get_safe_head_reference_for_diff(repo)
        diff_index = repo.index.diff(head_ref, create_patch=True, R=True)

        for diff in diff_index:
            file_path = get_path_by_os(get_diff_file_path(diff, repo=repo))
            assert file_path == renamed_path


class TestGetDiffFilePath:
    """Test the get_diff_file_path function with various diff scenarios."""

    def test_diff_with_b_blob_and_working_tree(self) -> None:
        """Test that blob.abspath is returned when b_blob is available and repo has a working tree."""
        with temporary_git_repository() as (temp_dir, repo):
            test_file = os.path.join(temp_dir, 'test_file.py')
            with open(test_file, 'w') as f:
                f.write("print('original content')")

            repo.index.add(['test_file.py'])
            repo.index.commit('Initial commit')

            with open(test_file, 'w') as f:
                f.write("print('modified content')")

            repo.index.add(['test_file.py'])

            # Get diff of staged changes
            head_ref = get_safe_head_reference_for_diff(repo)
            diff_index = repo.index.diff(head_ref)

            assert len(diff_index) == 1

            result = get_diff_file_path(diff_index[0], repo=repo)

            assert result == test_file
            assert os.path.isabs(result)

    def test_diff_with_a_blob_only_and_working_tree(self) -> None:
        """Test that a_blob.abspath is used when b_blob is None but a_blob exists."""
        with temporary_git_repository() as (temp_dir, repo):
            test_file = os.path.join(temp_dir, 'to_delete.py')
            with open(test_file, 'w') as f:
                f.write("print('will be deleted')")

            repo.index.add(['to_delete.py'])
            repo.index.commit('Initial commit')

            os.remove(test_file)
            repo.index.remove(['to_delete.py'])

            # Get diff of staged changes
            head_ref = get_safe_head_reference_for_diff(repo)
            diff_index = repo.index.diff(head_ref)

            assert len(diff_index) == 1

            result = get_diff_file_path(diff_index[0], repo=repo)

            assert result == test_file
            assert os.path.isabs(result)

    def test_diff_with_b_path_fallback(self) -> None:
        """Test that b_path is used with working_tree_dir when blob is not available."""
        with temporary_git_repository() as (temp_dir, repo):
            test_file = os.path.join(temp_dir, 'new_file.py')
            with open(test_file, 'w') as f:
                f.write("print('new file')")

            repo.index.add(['new_file.py'])

            # for new files, there's no a_blob
            head_ref = get_safe_head_reference_for_diff(repo)
            diff_index = repo.index.diff(head_ref)
            diff = diff_index[0]

            assert len(diff_index) == 1

            result = get_diff_file_path(diff, repo=repo)
            assert result == test_file
            assert os.path.isabs(result)

            result = get_diff_file_path(diff, relative=True, repo=repo)
            assert test_file.endswith(result)
            assert not os.path.isabs(result)

    def test_diff_with_a_path_fallback(self) -> None:
        """Test that a_path is used when b_path is None."""
        with temporary_git_repository() as (temp_dir, repo):
            test_file = os.path.join(temp_dir, 'deleted_file.py')
            with open(test_file, 'w') as f:
                f.write("print('will be deleted')")

            repo.index.add(['deleted_file.py'])
            repo.index.commit('Initial commit')

            # for deleted files, b_path might be None, so a_path should be used
            os.remove(test_file)
            repo.index.remove(['deleted_file.py'])

            head_ref = get_safe_head_reference_for_diff(repo)
            diff_index = repo.index.diff(head_ref)

            assert len(diff_index) == 1
            diff = diff_index[0]

            result = get_diff_file_path(diff, repo=repo)
            assert result == test_file
            assert os.path.isabs(result)

            result = get_diff_file_path(diff, relative=True, repo=repo)
            assert test_file.endswith(result)
            assert not os.path.isabs(result)

    def test_diff_without_repo(self) -> None:
        """Test behavior when repo is None."""
        with temporary_git_repository() as (temp_dir, repo):
            test_file = os.path.join(temp_dir, 'test.py')
            with open(test_file, 'w') as f:
                f.write("print('test')")

            repo.index.add(['test.py'])
            head_ref = get_safe_head_reference_for_diff(repo)
            diff_index = repo.index.diff(head_ref)

            assert len(diff_index) == 1
            diff = diff_index[0]

            result = get_diff_file_path(diff, repo=None)

            expected_path = diff.b_path or diff.a_path
            assert result == expected_path
            assert not os.path.isabs(result)

    def test_diff_with_bare_repository(self) -> None:
        """Test behavior when the repository has no working tree directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            bare_repo = Repo.init(temp_dir, bare=True)

            try:
                # Create a regular repo to push to the bare repo
                with tempfile.TemporaryDirectory() as work_dir:
                    work_repo = Repo.init(work_dir, b='main')
                    try:
                        test_file = os.path.join(work_dir, 'test.py')
                        with open(test_file, 'w') as f:
                            f.write("print('test')")

                        work_repo.index.add(['test.py'])
                        work_repo.index.commit('Initial commit')

                        work_repo.create_remote('origin', temp_dir)
                        work_repo.remotes.origin.push('main:main')

                        with open(test_file, 'w') as f:
                            f.write("print('modified')")
                        work_repo.index.add(['test.py'])

                        # Get diff
                        diff_index = work_repo.index.diff('HEAD')
                        assert len(diff_index) == 1
                        diff = diff_index[0]

                        # Test with bare repo (no working_tree_dir)
                        result = get_diff_file_path(diff, repo=bare_repo)

                        # Should return a relative path since bare repo has no working tree
                        expected_path = diff.b_path or diff.a_path
                        assert result == expected_path
                        assert not os.path.isabs(result)
                    finally:
                        work_repo.close()
            finally:
                bare_repo.close()

    def test_diff_with_no_paths(self) -> None:
        """Test behavior when the diff has neither a_path nor b_path."""
        with temporary_git_repository() as (temp_dir, repo):

            class MockDiff:
                def __init__(self) -> None:
                    self.a_path = None
                    self.b_path = None
                    self.a_blob = None
                    self.b_blob = None

            result = get_diff_file_path(MockDiff(), repo=repo)
            assert result is None
