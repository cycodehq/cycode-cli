import types
from abc import ABC, abstractmethod
from functools import cache
from typing import TYPE_CHECKING

_GIT_ERROR_MESSAGE = """
Cycode CLI needs the Git executable to be installed on the system.
Git executable must be available in the PATH.
Git 1.7.x or newer is required.
You can help Cycode CLI to locate the Git executable
by setting the GIT_PYTHON_GIT_EXECUTABLE=<path/to/git> environment variable.
""".strip().replace('\n', ' ')

if TYPE_CHECKING:
    from git import PathLike, Repo


class GitProxyError(Exception):
    pass


# GitPython runs `git version` on import, so it is imported on first use rather than at CLI startup
@cache
def _import_git() -> types.ModuleType | None:
    try:
        import git
    except ImportError:
        return None
    return git


class _AbstractGitProxy(ABC):
    @abstractmethod
    def get_repo(self, path: 'PathLike | None' = None, *args, **kwargs) -> 'Repo': ...

    @abstractmethod
    def get_null_tree(self) -> object: ...

    @abstractmethod
    def get_invalid_git_repository_error(self) -> type[BaseException]: ...

    @abstractmethod
    def get_git_command_error(self) -> type[BaseException]: ...


class _DummyGitProxy(_AbstractGitProxy):
    def get_repo(self, path: 'PathLike | None' = None, *args, **kwargs) -> 'Repo':
        raise RuntimeError(_GIT_ERROR_MESSAGE)

    def get_null_tree(self) -> object:
        raise RuntimeError(_GIT_ERROR_MESSAGE)

    def get_invalid_git_repository_error(self) -> type[BaseException]:
        return GitProxyError

    def get_git_command_error(self) -> type[BaseException]:
        return GitProxyError


class _GitProxy(_AbstractGitProxy):
    def __init__(self, git_module: types.ModuleType) -> None:
        self._git = git_module

    def get_repo(self, path: 'PathLike | None' = None, *args, **kwargs) -> 'Repo':
        return self._git.Repo(path, *args, **kwargs)

    def get_null_tree(self) -> object:
        return self._git.NULL_TREE

    def get_invalid_git_repository_error(self) -> type[BaseException]:
        return self._git.InvalidGitRepositoryError

    def get_git_command_error(self) -> type[BaseException]:
        return self._git.GitCommandError


def get_git_proxy(git_module: types.ModuleType | None) -> _AbstractGitProxy:
    return _GitProxy(git_module) if git_module else _DummyGitProxy()


class GitProxyManager(_AbstractGitProxy):
    """We are using this manager for easy unit testing and mocking of the git module."""

    def __init__(self) -> None:
        self._git_proxy: _AbstractGitProxy | None = None

    def _get_git_proxy(self) -> _AbstractGitProxy:
        if self._git_proxy is None:
            self._git_proxy = get_git_proxy(_import_git())
        return self._git_proxy

    def _set_dummy_git_proxy(self) -> None:
        self._git_proxy = _DummyGitProxy()

    def _set_git_proxy(self) -> None:
        self._git_proxy = _GitProxy(_import_git())

    def get_repo(self, path: 'PathLike | None' = None, *args, **kwargs) -> 'Repo':
        return self._get_git_proxy().get_repo(path, *args, **kwargs)

    def get_null_tree(self) -> object:
        return self._get_git_proxy().get_null_tree()

    def get_invalid_git_repository_error(self) -> type[BaseException]:
        return self._get_git_proxy().get_invalid_git_repository_error()

    def get_git_command_error(self) -> type[BaseException]:
        return self._get_git_proxy().get_git_command_error()


git_proxy = GitProxyManager()
