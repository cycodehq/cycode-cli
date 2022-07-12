import os
from pathlib import Path
from cli.utils.path_utils import is_sub_path


test_files_path = path = Path(__file__).parent.absolute()


def test_is_sub_path_both_paths_are_same():
    path = os.path.join(test_files_path, 'hello')
    sub_path = os.path.join(test_files_path, 'hello')
    assert is_sub_path(path, sub_path) is True


def test_is_sub_path_path_is_not_subpath():
    path = os.path.join(test_files_path, 'hello')
    sub_path = os.path.join(test_files_path, 'hello.txt')
    assert is_sub_path(path, sub_path) is False


def test_is_sub_path_path_is_subpath():
    path = os.path.join(test_files_path, 'hello')
    sub_path = os.path.join(test_files_path, 'hello', 'random.txt')
    assert is_sub_path(path, sub_path) is True


def test_is_sub_path_path_not_exists():
    path = os.path.join(test_files_path, 'goodbye')
    sub_path = os.path.join(test_files_path, 'hello', 'random.txt')
    assert is_sub_path(path, sub_path) is False


def test_is_sub_path_subpath_not_exists():
    path = os.path.join(test_files_path, 'hello', 'random.txt')
    sub_path = os.path.join(test_files_path, 'goodbye')
    assert is_sub_path(path, sub_path) is False