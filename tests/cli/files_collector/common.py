import os
import tempfile
from collections.abc import Generator
from contextlib import contextmanager

from git import Repo


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


def create_multiple_commits(repo: Repo, temp_dir: str, num_commits: int = 3) -> list:
    """Helper function to create multiple commits in the repository."""
    commits = []
    for i in range(num_commits):
        test_file = os.path.join(temp_dir, f'file{i}.py')
        with open(test_file, 'w') as f:
            f.write(f"print('file {i}')")

        repo.index.add([f'file{i}.py'])
        commit = repo.index.commit(f'Commit {i + 1}')
        commits.append(commit)
    return commits
