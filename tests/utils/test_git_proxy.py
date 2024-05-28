import os
import tempfile

import git as real_git
import pytest

from cycode.cli.utils.git_proxy import _GIT_ERROR_MESSAGE, GitProxyError, _DummyGitProxy, _GitProxy, get_git_proxy


def test_get_git_proxy() -> None:
    proxy = get_git_proxy(git_module=None)
    assert isinstance(proxy, _DummyGitProxy)

    proxy2 = get_git_proxy(git_module=real_git)
    assert isinstance(proxy2, _GitProxy)


def test_dummy_git_proxy() -> None:
    proxy = _DummyGitProxy()

    with pytest.raises(RuntimeError) as exc:
        proxy.get_repo()
    assert str(exc.value) == _GIT_ERROR_MESSAGE

    with pytest.raises(RuntimeError) as exc2:
        proxy.get_null_tree()
    assert str(exc2.value) == _GIT_ERROR_MESSAGE

    assert proxy.get_git_command_error() is GitProxyError
    assert proxy.get_invalid_git_repository_error() is GitProxyError


def test_git_proxy() -> None:
    proxy = _GitProxy()

    repo = proxy.get_repo(os.getcwd(), search_parent_directories=True)
    assert isinstance(repo, real_git.Repo)

    assert proxy.get_null_tree() is real_git.NULL_TREE

    assert proxy.get_git_command_error() is real_git.GitCommandError
    assert proxy.get_invalid_git_repository_error() is real_git.InvalidGitRepositoryError

    with tempfile.TemporaryDirectory() as tmpdir:
        with pytest.raises(real_git.InvalidGitRepositoryError):
            proxy.get_repo(tmpdir)
        with pytest.raises(proxy.get_invalid_git_repository_error()):
            proxy.get_repo(tmpdir)

    with pytest.raises(real_git.GitCommandError):
        repo.git.show('blabla')
    with pytest.raises(proxy.get_git_command_error()):
        repo.git.show('blabla')
