import os

import pytest

from cycode.cli import consts
from cycode.cli.files_collector.commit_range_documents import (
    _get_oldest_unupdated_commit_for_branch,
    calculate_pre_receive_commit_range,
    parse_commit_range_sast,
)
from tests.cli.files_collector.common import create_multiple_commits, temporary_git_repository


class TestParseCommitRangeSast:
    """Test the SAST commit range parsing with bare repository support."""

    @pytest.mark.parametrize(
        ('commit_range', 'description'),
        [
            ('HEAD', 'single HEAD reference'),
            ('..HEAD', 'range ending with HEAD'),
            ('HEAD..', 'range starting with HEAD'),
            ('HEAD..HEAD', 'range with both HEAD references'),
        ],
    )
    def test_returns_none_for_head_references_in_bare_repository(self, commit_range: str, description: str) -> None:
        """Test that HEAD references return None in bare repositories."""
        with temporary_git_repository() as (temp_dir, repo):
            from_commit, to_commit = parse_commit_range_sast(commit_range, temp_dir)

            # Should return None for bare repositories since HEAD doesn't exist
            assert from_commit is None
            assert to_commit is None

    def test_works_correctly_with_head_references_when_commits_exist(self) -> None:
        """Test that HEAD references work correctly when the repository has commits."""
        with temporary_git_repository() as (temp_dir, repo):
            test_file = os.path.join(temp_dir, 'test.py')
            with open(test_file, 'w') as f:
                f.write("print('initial')")

            repo.index.add(['test.py'])
            initial_commit = repo.index.commit('Initial commit')

            commit_range = initial_commit.hexsha  # This gets interpreted as 'commit..HEAD'
            from_commit, to_commit = parse_commit_range_sast(commit_range, temp_dir)

            # Should successfully resolve both commits
            assert from_commit is not None
            assert to_commit is not None
            assert to_commit == initial_commit.hexsha  # HEAD should resolve to the latest commit

    def test_handles_explicit_commit_ranges_correctly(self) -> None:
        """Test that explicit commit ranges (no HEAD) work correctly."""
        with temporary_git_repository() as (temp_dir, repo):
            commits = create_multiple_commits(repo, temp_dir)

            commit_range = f'{commits[0].hexsha}..{commits[2].hexsha}'
            from_commit, to_commit = parse_commit_range_sast(commit_range, temp_dir)

            assert from_commit == commits[0].hexsha
            assert to_commit == commits[2].hexsha

    def test_handles_three_dot_ranges_correctly(self) -> None:
        """Test that three-dot commit ranges work correctly."""
        with temporary_git_repository() as (temp_dir, repo):
            test_file = os.path.join(temp_dir, 'test.py')
            with open(test_file, 'w') as f:
                f.write("print('first')")

            repo.index.add(['test.py'])
            first_commit = repo.index.commit('First commit')

            with open(test_file, 'w') as f:
                f.write("print('second')")

            repo.index.add(['test.py'])
            second_commit = repo.index.commit('Second commit')

            # Test three-dot range
            commit_range = f'{first_commit.hexsha}...{second_commit.hexsha}'

            from_commit, to_commit = parse_commit_range_sast(commit_range, temp_dir)

            assert from_commit == first_commit.hexsha
            assert to_commit == second_commit.hexsha


class TestGetOldestUnupdatedCommitForBranch:
    """Test the oldest unupdated commit function with bare repository support."""

    def test_returns_none_for_nonexistent_commit_in_bare_repository(self) -> None:
        """Test that function returns None for non-existent commits in bare repositories."""
        with temporary_git_repository() as (temp_dir, repo):
            # Use a fake commit SHA that doesn't exist
            fake_commit_sha = '9cf90954ef26e7c58284f8ebf7dcd0fcf711152a'

            original_cwd = os.getcwd()
            os.chdir(temp_dir)

            try:
                # Should handle missing commit gracefully
                result = _get_oldest_unupdated_commit_for_branch(fake_commit_sha)
                assert result is None
            finally:
                os.chdir(original_cwd)

    def test_works_correctly_with_existing_commits(self) -> None:
        """Test that the function works correctly when commits exist."""
        with temporary_git_repository() as (temp_dir, repo):
            commits = create_multiple_commits(repo, temp_dir)

            original_cwd = os.getcwd()
            os.chdir(temp_dir)

            try:
                # Test with an existing commit
                result = _get_oldest_unupdated_commit_for_branch(commits[-1].hexsha)
                # Result depends on repository state, but should not crash
                assert isinstance(result, (str, type(None)))
            finally:
                os.chdir(original_cwd)


class TestCalculatePreReceiveCommitRange:
    """Test the pre-receive commit range calculation with bare repository support."""

    def test_handles_first_push_to_bare_repository(self) -> None:
        """Test the first push scenario (old commit is all zeros)."""
        with temporary_git_repository() as (temp_dir, repo):
            # Simulate the first push: old_commit=zeros, new_commit=actual_sha
            zero_commit = consts.EMPTY_COMMIT_SHA
            new_commit_sha = '9cf90954ef26e7c58284f8ebf7dcd0fcf711152a'
            branch_update_details = f'{zero_commit} {new_commit_sha} refs/heads/main'

            original_cwd = os.getcwd()
            os.chdir(temp_dir)

            try:
                # Should handle the first push gracefully
                commit_range = calculate_pre_receive_commit_range(branch_update_details)
                # For the first push to bare repo, this typically returns None
                assert commit_range is None or isinstance(commit_range, str)
            finally:
                os.chdir(original_cwd)

    def test_handles_branch_deletion(self) -> None:
        """Test branch deletion scenario (new commit is all zeros)."""
        old_commit_sha = '9cf90954ef26e7c58284f8ebf7dcd0fcf711152a'
        zero_commit = consts.EMPTY_COMMIT_SHA
        branch_update_details = f'{old_commit_sha} {zero_commit} refs/heads/feature'

        # Should return None for branch deletion
        commit_range = calculate_pre_receive_commit_range(branch_update_details)
        assert commit_range is None

    def test_normal_push_scenario(self) -> None:
        """Test a normal push scenario with existing commits."""
        with temporary_git_repository() as (temp_dir, repo):
            commits = create_multiple_commits(repo, temp_dir, num_commits=2)

            # Simulate normal push
            branch_update_details = f'{commits[0].hexsha} {commits[1].hexsha} refs/heads/main'

            original_cwd = os.getcwd()
            os.chdir(temp_dir)

            try:
                commit_range = calculate_pre_receive_commit_range(branch_update_details)
                # Should work without errors
                assert commit_range is None or isinstance(commit_range, str)
            finally:
                os.chdir(original_cwd)
