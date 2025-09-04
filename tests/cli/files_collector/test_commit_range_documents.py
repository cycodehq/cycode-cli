import os
import tempfile

from git import Repo

from cycode.cli import consts
from cycode.cli.files_collector.commit_range_documents import get_safe_head_reference_for_diff


class TestGetSafeHeadReferenceForDiff:
    """Test the safe HEAD reference functionality for git diff operations."""

    def test_returns_head_when_repository_has_commits(self) -> None:
        """Test that HEAD is returned when the repository has existing commits."""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Repo.init(temp_dir)

            test_file = os.path.join(temp_dir, 'test.py')
            with open(test_file, 'w') as f:
                f.write("print('test')")

            repo.index.add(['test.py'])
            repo.index.commit('Initial commit')

            result = get_safe_head_reference_for_diff(repo)
            assert result == consts.GIT_HEAD_COMMIT_REV

    def test_returns_empty_tree_hash_when_repository_has_no_commits(self) -> None:
        """Test that an empty tree hash is returned when the repository has no commits."""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Repo.init(temp_dir)

            result = get_safe_head_reference_for_diff(repo)
            expected_empty_tree_hash = consts.GIT_EMPTY_TREE_OBJECT
            assert result == expected_empty_tree_hash


class TestIndexDiffWithSafeHeadReference:
    """Test that index.diff works correctly with the safe head reference."""

    def test_index_diff_works_on_bare_repository(self) -> None:
        """Test that index.diff works on repositories with no commits."""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Repo.init(temp_dir)

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
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Repo.init(temp_dir)

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
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Repo.init(temp_dir)

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
