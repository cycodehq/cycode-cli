import types
from abc import ABC, abstractmethod
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
    def get_repo(self, path: Optional['PathLike'] = None, *args, **kwargs) -> 'Repo':
        ...

    @abstractmethod
    def get_null_tree(self) -> object:
        ...

    @abstractmethod
    def get_invalid_git_repository_error(self) -> Type[BaseException]:
        ...

    @abstractmethod
    def get_git_command_error(self) -> Type[BaseException]:
        ...


class _DummyGitProxy(_AbstractGitProxy):
    def get_repo(self, path: Optional['PathLike'] = None, *args, **kwargs) -> 'Repo':
        raise RuntimeError(_GIT_ERROR_MESSAGE)

    def get_null_tree(self) -> object:
        raise RuntimeError(_GIT_ERROR_MESSAGE)

    def get_invalid_git_repository_error(self) -> Type[BaseException]:
        return GitProxyError

    def get_git_command_error(self) -> Type[BaseException]:
        return GitProxyError


class _GitProxy(_AbstractGitProxy):
    def get_repo(self, path: Optional['PathLike'] = None, *args, **kwargs) -> 'Repo':
        return git.Repo(path, *args, **kwargs)

    def get_null_tree(self) -> object:
        return git.NULL_TREE

    def get_invalid_git_repository_error(self) -> Type[BaseException]:
        return git.InvalidGitRepositoryError

    def get_git_command_error(self) -> Type[BaseException]:
        return git.GitCommandError


def get_git_proxy(git_module: Optional[types.ModuleType]) -> _AbstractGitProxy:
    return _GitProxy() if git_module else _DummyGitProxy()


git_proxy = get_git_proxy(git)
