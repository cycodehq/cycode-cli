import os

from cycode.cli.utils.path_utils import is_sub_path
from tests.conftest import TEST_FILES_PATH


def test_is_sub_path_both_paths_are_same() -> None:
    path = os.path.join(TEST_FILES_PATH, 'hello')
    sub_path = os.path.join(TEST_FILES_PATH, 'hello')
    assert is_sub_path(path, sub_path) is True


def test_is_sub_path_path_is_not_subpath() -> None:
    path = os.path.join(TEST_FILES_PATH, 'hello')
    sub_path = os.path.join(TEST_FILES_PATH, 'hello.txt')
    assert is_sub_path(path, sub_path) is False


def test_is_sub_path_path_is_subpath() -> None:
    path = os.path.join(TEST_FILES_PATH, 'hello')
    sub_path = os.path.join(TEST_FILES_PATH, 'hello', 'random.txt')
    assert is_sub_path(path, sub_path) is True


def test_is_sub_path_path_not_exists() -> None:
    path = os.path.join(TEST_FILES_PATH, 'goodbye')
    sub_path = os.path.join(TEST_FILES_PATH, 'hello', 'random.txt')
    assert is_sub_path(path, sub_path) is False


def test_is_sub_path_subpath_not_exists() -> None:
    path = os.path.join(TEST_FILES_PATH, 'hello', 'random.txt')
    sub_path = os.path.join(TEST_FILES_PATH, 'goodbye')
    assert is_sub_path(path, sub_path) is False
