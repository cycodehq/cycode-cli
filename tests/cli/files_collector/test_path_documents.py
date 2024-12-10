from typing import TYPE_CHECKING

from cycode.cli.files_collector.path_documents import (
    _collect_top_level_ignore_files,
    _get_global_ignore_patterns,
    _walk_to_top,
)

if TYPE_CHECKING:
    from pyfakefs.fake_filesystem import FakeFilesystem


def test_walk_to_top() -> None:
    path = '/a/b/c/d/e/f/g'
    result = list(_walk_to_top(path))
    assert result == ['/a/b/c/d/e/f/g', '/a/b/c/d/e/f', '/a/b/c/d/e', '/a/b/c/d', '/a/b/c', '/a/b', '/a', '/']

    path = '/a/b/c'
    result = list(_walk_to_top(path))
    assert result == ['/a/b/c', '/a/b', '/a', '/']

    path = '/a'
    result = list(_walk_to_top(path))
    assert result == ['/a', '/']

    path = '/'
    result = list(_walk_to_top(path))
    assert result == ['/']

    path = 'a'
    result = list(_walk_to_top(path))
    assert result == ['a']


def _create_mocked_file_structure(fs: 'FakeFilesystem') -> None:
    fs.create_dir('/home/user/project')
    fs.create_dir('/home/user/.git')
    fs.create_file('/home/user/project/.gitignore', contents='*.pyc')
    fs.create_file('/home/user/project/.cycodeignore', contents='*.log')
    fs.create_dir('/home/user/project/subdir')
    fs.create_file('/home/user/project/subdir/.gitignore', contents='*.txt')


def test_collect_top_level_ignore_files(fs: 'FakeFilesystem') -> None:
    _create_mocked_file_structure(fs)

    # Test with path inside the project
    path = '/home/user/project/subdir'
    ignore_files = _collect_top_level_ignore_files(path)

    assert len(ignore_files) == 3
    assert '/home/user/project/subdir/.gitignore' in ignore_files
    assert '/home/user/project/.gitignore' in ignore_files
    assert '/home/user/project/.cycodeignore' in ignore_files

    # Test with a path that does not have any ignore files
    fs.remove('/home/user/project/.gitignore')
    path = '/home/user'
    ignore_files = _collect_top_level_ignore_files(path)

    assert len(ignore_files) == 0

    # Test with path at the top level with no ignore files
    path = '/home/user/.git'
    ignore_files = _collect_top_level_ignore_files(path)

    assert len(ignore_files) == 0

    # Test with path at the top level with a .gitignore
    path = '/home/user/project'
    ignore_files = _collect_top_level_ignore_files(path)

    assert len(ignore_files) == 1
    assert '/home/user/project/.cycodeignore' in ignore_files


def test_get_global_ignore_patterns(fs: 'FakeFilesystem') -> None:
    _create_mocked_file_structure(fs)
    ignore_patterns = _get_global_ignore_patterns('/home/user/project/subdir')
    assert ignore_patterns == ['*.txt', '*.pyc', '*.log']
