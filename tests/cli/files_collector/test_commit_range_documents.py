import os
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from io import StringIO
from unittest.mock import Mock, patch

import pytest
from git import Repo

from cycode.cli import consts
from cycode.cli.files_collector.commit_range_documents import (
    calculate_pre_push_commit_range,
    get_diff_file_path,
    get_safe_head_reference_for_diff,
    parse_pre_push_input,
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


class TestParsePrePushInput:
    """Test the parse_pre_push_input function with various pre-push hook input scenarios."""

    def test_parse_single_push_input(self) -> None:
        """Test parsing a single branch push input."""
        pre_push_input = 'refs/heads/main 1234567890abcdef refs/heads/main 0987654321fedcba'

        with patch('sys.stdin', StringIO(pre_push_input)):
            result = parse_pre_push_input()
            assert result == 'refs/heads/main 1234567890abcdef refs/heads/main 0987654321fedcba'

    def test_parse_multiple_push_input_returns_first_line(self) -> None:
        """Test parsing multiple branch push input returns only the first line."""
        pre_push_input = """refs/heads/main 1234567890abcdef refs/heads/main 0987654321fedcba
refs/heads/feature 1111111111111111 refs/heads/feature 2222222222222222"""

        with patch('sys.stdin', StringIO(pre_push_input)):
            result = parse_pre_push_input()
            assert result == 'refs/heads/main 1234567890abcdef refs/heads/main 0987654321fedcba'

    def test_parse_new_branch_push_input(self) -> None:
        """Test parsing input for pushing a new branch (remote object name is all zeros)."""
        pre_push_input = f'refs/heads/feature 1234567890abcdef refs/heads/feature {consts.EMPTY_COMMIT_SHA}'

        with patch('sys.stdin', StringIO(pre_push_input)):
            result = parse_pre_push_input()
            assert result == pre_push_input

    def test_parse_branch_deletion_input(self) -> None:
        """Test parsing input for deleting a branch (local object name is all zeros)."""
        pre_push_input = f'refs/heads/feature {consts.EMPTY_COMMIT_SHA} refs/heads/feature 1234567890abcdef'

        with patch('sys.stdin', StringIO(pre_push_input)):
            result = parse_pre_push_input()
            assert result == pre_push_input

    def test_parse_empty_input_raises_error(self) -> None:
        """Test that empty input raises ValueError."""
        with patch('sys.stdin', StringIO('')), pytest.raises(ValueError, match='Pre push input was not found'):
            parse_pre_push_input()

    def test_parse_whitespace_only_input_raises_error(self) -> None:
        """Test that whitespace-only input raises ValueError."""
        with patch('sys.stdin', StringIO('   \n\t  ')), pytest.raises(ValueError, match='Pre push input was not found'):
            parse_pre_push_input()


class TestCalculatePrePushCommitRange:
    """Test the calculate_pre_push_commit_range function with various Git repository scenarios."""

    def test_calculate_range_for_existing_branch_update(self) -> None:
        """Test calculating commit range for updating an existing branch."""
        push_details = 'refs/heads/main 1234567890abcdef refs/heads/main 0987654321fedcba'

        result = calculate_pre_push_commit_range(push_details)
        assert result == '0987654321fedcba..1234567890abcdef'

    def test_calculate_range_for_branch_deletion_returns_none(self) -> None:
        """Test that branch deletion returns None (no scanning needed)."""
        push_details = f'refs/heads/feature {consts.EMPTY_COMMIT_SHA} refs/heads/feature 1234567890abcdef'

        result = calculate_pre_push_commit_range(push_details)
        assert result is None

    def test_calculate_range_for_new_branch_with_merge_base(self) -> None:
        """Test calculating commit range for a new branch when merge base is found."""
        with temporary_git_repository() as (temp_dir, repo):
            # Create initial commit on main
            test_file = os.path.join(temp_dir, 'main.py')
            with open(test_file, 'w') as f:
                f.write("print('main')")

            repo.index.add(['main.py'])
            main_commit = repo.index.commit('Initial commit on main')

            # Create and switch to a feature branch
            feature_branch = repo.create_head('feature')
            feature_branch.checkout()

            # Add commits to a feature branch
            feature_file = os.path.join(temp_dir, 'feature.py')
            with open(feature_file, 'w') as f:
                f.write("print('feature')")

            repo.index.add(['feature.py'])
            feature_commit = repo.index.commit('Add feature')

            # Switch back to master to simulate we're pushing a feature branch
            repo.heads.master.checkout()

            # Test new branch push
            push_details = f'refs/heads/feature {feature_commit.hexsha} refs/heads/feature {consts.EMPTY_COMMIT_SHA}'

            with patch('os.getcwd', return_value=temp_dir):
                result = calculate_pre_push_commit_range(push_details)
                assert result == f'{main_commit.hexsha}..{feature_commit.hexsha}'

    def test_calculate_range_for_new_branch_no_merge_base_fallback_to_all(self) -> None:
        """Test that when no merge base is found, it falls back to scanning all commits."""
        with temporary_git_repository() as (temp_dir, repo):
            # Create a single commit
            test_file = os.path.join(temp_dir, 'test.py')
            with open(test_file, 'w') as f:
                f.write("print('test')")

            repo.index.add(['test.py'])
            commit = repo.index.commit('Initial commit')

            # Test a new branch push with no default branch available
            push_details = f'refs/heads/orphan {commit.hexsha} refs/heads/orphan {consts.EMPTY_COMMIT_SHA}'

            # Create a mock repo with a git interface that always raises exceptions for merge_base
            mock_repo = Mock()
            mock_git = Mock()
            mock_git.merge_base.side_effect = Exception('No merge base found')
            mock_repo.git = mock_git

            with (
                patch('os.getcwd', return_value=temp_dir),
                patch('cycode.cli.files_collector.commit_range_documents.git_proxy.get_repo', return_value=mock_repo),
            ):
                result = calculate_pre_push_commit_range(push_details)
                # Should fallback to --all when no merge base is found
                assert result == '--all'

    def test_calculate_range_with_origin_main_as_merge_base(self) -> None:
        """Test calculating commit range using origin/main as merge base."""
        with temporary_git_repository() as (temp_dir, repo):
            # Create the main branch with commits
            main_file = os.path.join(temp_dir, 'main.py')
            with open(main_file, 'w') as f:
                f.write("print('main')")

            repo.index.add(['main.py'])
            main_commit = repo.index.commit('Main commit')

            # Create origin/main reference (simulating a remote)
            repo.create_head('origin/main', main_commit)

            # Create feature branch from main
            feature_branch = repo.create_head('feature', main_commit)
            feature_branch.checkout()

            # Add feature commits
            feature_file = os.path.join(temp_dir, 'feature.py')
            with open(feature_file, 'w') as f:
                f.write("print('feature')")

            repo.index.add(['feature.py'])
            feature_commit = repo.index.commit('Feature commit')

            # Test new branch push
            push_details = f'refs/heads/feature {feature_commit.hexsha} refs/heads/feature {consts.EMPTY_COMMIT_SHA}'

            with patch('os.getcwd', return_value=temp_dir):
                result = calculate_pre_push_commit_range(push_details)
                assert result == f'{main_commit.hexsha}..{feature_commit.hexsha}'

    def test_calculate_range_with_origin_master_as_merge_base(self) -> None:
        """Test calculating commit range using origin/master as a merge base."""
        with temporary_git_repository() as (temp_dir, repo):
            # Create a main branch with commits
            master_file = os.path.join(temp_dir, 'master.py')
            with open(master_file, 'w') as f:
                f.write("print('master')")

            repo.index.add(['master.py'])
            master_commit = repo.index.commit('Master commit')

            # Create origin/master (master branch already exists by default)
            repo.create_head('origin/master', master_commit)

            # Create a feature branch
            feature_branch = repo.create_head('feature', master_commit)
            feature_branch.checkout()

            # Add feature commits
            feature_file = os.path.join(temp_dir, 'feature.py')
            with open(feature_file, 'w') as f:
                f.write("print('feature')")

            repo.index.add(['feature.py'])
            feature_commit = repo.index.commit('Feature commit')

            # Test new branch push
            push_details = f'refs/heads/feature {feature_commit.hexsha} refs/heads/feature {consts.EMPTY_COMMIT_SHA}'

            with patch('os.getcwd', return_value=temp_dir):
                result = calculate_pre_push_commit_range(push_details)
                assert result == f'{master_commit.hexsha}..{feature_commit.hexsha}'

    def test_calculate_range_exception_handling_fallback_to_all(self) -> None:
        """Test that exceptions during Git repository access fall back to --all."""
        push_details = f'refs/heads/feature 1234567890abcdef refs/heads/feature {consts.EMPTY_COMMIT_SHA}'

        # Mock git_proxy.get_repo to raise an exception and capture the exception handling
        with patch('cycode.cli.files_collector.commit_range_documents.git_proxy.get_repo') as mock_get_repo:
            mock_get_repo.side_effect = Exception('Test exception')
            result = calculate_pre_push_commit_range(push_details)
            assert result == '--all'

    def test_calculate_range_parsing_push_details(self) -> None:
        """Test that push details are correctly parsed into components."""
        # Test with standard format
        push_details = 'refs/heads/feature abc123def456 refs/heads/feature 789xyz456abc'

        result = calculate_pre_push_commit_range(push_details)
        assert result == '789xyz456abc..abc123def456'

    def test_calculate_range_with_tags(self) -> None:
        """Test calculating commit range when pushing tags."""
        push_details = f'refs/tags/v1.0.0 1234567890abcdef refs/tags/v1.0.0 {consts.EMPTY_COMMIT_SHA}'

        with temporary_git_repository() as (temp_dir, repo):
            # Create a commit
            test_file = os.path.join(temp_dir, 'test.py')
            with open(test_file, 'w') as f:
                f.write("print('test')")

            repo.index.add(['test.py'])
            commit = repo.index.commit('Test commit')

            # Create tag
            repo.create_tag('v1.0.0', commit)

            with patch('os.getcwd', return_value=temp_dir):
                result = calculate_pre_push_commit_range(push_details)
                # For new tags, should try to find a merge base or fall back to --all
                assert result in [f'{commit.hexsha}..{commit.hexsha}', '--all']


class TestPrePushHookIntegration:
    """Integration tests for pre-push hook functionality."""

    def test_simulate_pre_push_hook_input_format(self) -> None:
        """Test that our parsing handles the actual format Git sends to pre-push hooks."""
        # Simulate the exact format Git sends to pre-push hooks
        test_cases = [
            # Standard branch push
            'refs/heads/main 67890abcdef12345 refs/heads/main 12345abcdef67890',
            # New branch push
            f'refs/heads/feature 67890abcdef12345 refs/heads/feature {consts.EMPTY_COMMIT_SHA}',
            # Branch deletion
            f'refs/heads/old-feature {consts.EMPTY_COMMIT_SHA} refs/heads/old-feature 12345abcdef67890',
            # Tag push
            f'refs/tags/v1.0.0 67890abcdef12345 refs/tags/v1.0.0 {consts.EMPTY_COMMIT_SHA}',
        ]

        for push_input in test_cases:
            with patch('sys.stdin', StringIO(push_input)):
                parsed = parse_pre_push_input()
                assert parsed == push_input

                # Test that we can calculate the commit range for each case
                commit_range = calculate_pre_push_commit_range(parsed)

                if consts.EMPTY_COMMIT_SHA in push_input:
                    if push_input.startswith('refs/heads/') and push_input.split()[1] == consts.EMPTY_COMMIT_SHA:
                        # Branch deletion - should return None
                        assert commit_range is None
                    else:
                        # New branch/tag - should return a range or --all
                        assert commit_range is not None
                else:
                    # Regular update - should return proper range
                    parts = push_input.split()
                    expected_range = f'{parts[3]}..{parts[1]}'
                    assert commit_range == expected_range
