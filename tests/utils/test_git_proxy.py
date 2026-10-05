import os
import tempfile
from unittest.mock import patch

import git as real_git
import pytest

from cycode.cli.utils.git_proxy import (
    _GIT_ERROR_MESSAGE,
    GitProxyError,
    GitProxyManager,
    _DummyGitProxy,
    _GitProxy,
    get_git_proxy,
)


def test_get_git_proxy() -> None:
    proxy = get_git_proxy(git_module=None)
    assert isinstance(proxy, _DummyGitProxy)

    proxy2 = get_git_proxy(git_module=real_git)
    assert isinstance(proxy2, _GitProxy)


def test_git_proxy_manager_imports_git_on_first_use_only() -> None:
    with patch('cycode.cli.utils.git_proxy._import_git', return_value=real_git) as mock_import_git:
        manager = GitProxyManager()
        # Importing GitPython runs `git version`, which commands that never touch git shouldn't pay for
        mock_import_git.assert_not_called()

        assert manager.get_null_tree() is real_git.NULL_TREE
        assert manager.get_git_command_error() is real_git.GitCommandError
        mock_import_git.assert_called_once()

    with patch('cycode.cli.utils.git_proxy._import_git', return_value=None):
        assert GitProxyManager().get_git_command_error() is GitProxyError


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
    proxy = _GitProxy(real_git)

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
