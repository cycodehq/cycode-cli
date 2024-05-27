from abc import ABC, abstractmethod
from functools import lru_cache
from typing import TYPE_CHECKING, Optional, Type

_GIT_ERROR_MESSAGE = """
Cycode CLI needs the git executable to be installed on the system.
Git executable must be available in the PATH.
Git 1.7.x or newer is required.
You can help Cycode CLI to locate the Git executable
by setting the GIT_PYTHON_GIT_EXECUTABLE=<path/to/git> environment variable.
""".strip().replace('\n', ' ')

try:
    import git
except ImportError:
    git = None

if TYPE_CHECKING:
    from git import PathLike, Repo


class GitProxyError(Exception):
    pass


class _AbstractGitProxy(ABC):
    @abstractmethod
    def get_repo(self, path: Optional['PathLike'] = None) -> 'Repo':
        ...

    @abstractmethod
    def get_null_tree(self) -> object:
        ...

    @abstractmethod
    def get_invalid_git_repository_error(self) -> Type[GitProxyError]:
        ...

    @abstractmethod
    def get_git_command_error(self) -> Type[GitProxyError]:
        ...


class _DummyGitProxy(_AbstractGitProxy):
    def get_repo(self, path: Optional['PathLike'] = None) -> 'Repo':
        raise RuntimeError(_GIT_ERROR_MESSAGE)

    def get_null_tree(self) -> object:
        return object()

    def get_invalid_git_repository_error(self) -> Type[GitProxyError]:
        return GitProxyError

    def get_git_command_error(self) -> Type[GitProxyError]:
        return GitProxyError


class _GitProxy(_AbstractGitProxy):
    def get_repo(self, path: Optional['PathLike'] = None) -> 'Repo':
        return git.Repo(path)

    def get_null_tree(self) -> object:
        return git.NULL_TREE

    @lru_cache(maxsize=None)  # noqa: B019
    def get_invalid_git_repository_error(self) -> Type[GitProxyError]:
        # we must cache it because we want to return the same class every time
        class InvalidGitRepositoryError(GitProxyError, git.InvalidGitRepositoryError):
            ...

        return InvalidGitRepositoryError

    @lru_cache(maxsize=None)  # noqa: B019
    def get_git_command_error(self) -> Type[GitProxyError]:
        # we must cache it because we want to return the same class every time
        class GitCommandError(GitProxyError, git.GitCommandError):
            ...

        return GitCommandError


git_proxy = _GitProxy() if git else _DummyGitProxy()
