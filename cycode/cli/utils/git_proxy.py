import types
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional

_GIT_ERROR_MESSAGE = """
Cycode CLI needs the Git executable to be installed on the system.
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
    def get_repo(self, path: Optional['PathLike'] = None, *args, **kwargs) -> 'Repo': ...

    @abstractmethod
    def get_null_tree(self) -> object: ...

    @abstractmethod
    def get_invalid_git_repository_error(self) -> type[BaseException]: ...

    @abstractmethod
    def get_git_command_error(self) -> type[BaseException]: ...


class _DummyGitProxy(_AbstractGitProxy):
    def get_repo(self, path: Optional['PathLike'] = None, *args, **kwargs) -> 'Repo':
        raise RuntimeError(_GIT_ERROR_MESSAGE)

    def get_null_tree(self) -> object:
        raise RuntimeError(_GIT_ERROR_MESSAGE)

    def get_invalid_git_repository_error(self) -> type[BaseException]:
        return GitProxyError

    def get_git_command_error(self) -> type[BaseException]:
        return GitProxyError


class _GitProxy(_AbstractGitProxy):
    def get_repo(self, path: Optional['PathLike'] = None, *args, **kwargs) -> 'Repo':
        return git.Repo(path, *args, **kwargs)

    def get_null_tree(self) -> object:
        return git.NULL_TREE

    def get_invalid_git_repository_error(self) -> type[BaseException]:
        return git.InvalidGitRepositoryError

    def get_git_command_error(self) -> type[BaseException]:
        return git.GitCommandError


def get_git_proxy(git_module: Optional[types.ModuleType]) -> _AbstractGitProxy:
    return _GitProxy() if git_module else _DummyGitProxy()


class GitProxyManager(_AbstractGitProxy):
    """We are using this manager for easy unit testing and mocking of the git module."""

    def __init__(self) -> None:
        self._git_proxy = get_git_proxy(git)

    def _set_dummy_git_proxy(self) -> None:
        self._git_proxy = _DummyGitProxy()

    def _set_git_proxy(self) -> None:
        self._git_proxy = _GitProxy()

    def get_repo(self, path: Optional['PathLike'] = None, *args, **kwargs) -> 'Repo':
        return self._git_proxy.get_repo(path, *args, **kwargs)

    def get_null_tree(self) -> object:
        return self._git_proxy.get_null_tree()

    def get_invalid_git_repository_error(self) -> type[BaseException]:
        return self._git_proxy.get_invalid_git_repository_error()

    def get_git_command_error(self) -> type[BaseException]:
        return self._git_proxy.get_git_command_error()


git_proxy = GitProxyManager()
