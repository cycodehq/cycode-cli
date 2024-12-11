from os.path import normpath
from typing import TYPE_CHECKING

from cycode.cli.files_collector.path_documents import (
    _collect_top_level_ignore_files,
    _get_global_ignore_patterns,
    _walk_to_top,
)

if TYPE_CHECKING:
    from pyfakefs.fake_filesystem import FakeFilesystem


# we are using normpath() in every test to provide multi-platform support


def test_walk_to_top() -> None:
    path = normpath('/a/b/c/d/e/f/g')
    result = list(_walk_to_top(path))
    assert result == [
        normpath('/a/b/c/d/e/f/g'),
        normpath('/a/b/c/d/e/f'),
        normpath('/a/b/c/d/e'),
        normpath('/a/b/c/d'),
        normpath('/a/b/c'),
        normpath('/a/b'),
        normpath('/a'),
        normpath('/'),
    ]

    path = normpath('/a')
    result = list(_walk_to_top(path))
    assert result == [normpath('/a'), normpath('/')]

    path = normpath('/')
    result = list(_walk_to_top(path))
    assert result == [normpath('/')]

    path = normpath('a')
    result = list(_walk_to_top(path))
    assert result == [normpath('a')]


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
    path = normpath('/home/user/project/subdir')
    ignore_files = _collect_top_level_ignore_files(path)

    assert len(ignore_files) == 3
    assert normpath('/home/user/project/subdir/.gitignore') in ignore_files
    assert normpath('/home/user/project/.gitignore') in ignore_files
    assert normpath('/home/user/project/.cycodeignore') in ignore_files

    # Test with a path that does not have any ignore files
    fs.remove('/home/user/project/.gitignore')
    path = normpath('/home/user')
    ignore_files = _collect_top_level_ignore_files(path)

    assert len(ignore_files) == 0

    # Test with path at the top level with no ignore files
    path = normpath('/home/user/.git')
    ignore_files = _collect_top_level_ignore_files(path)

    assert len(ignore_files) == 0

    # Test with path at the top level with a .gitignore
    path = normpath('/home/user/project')
    ignore_files = _collect_top_level_ignore_files(path)

    assert len(ignore_files) == 1
    assert normpath('/home/user/project/.cycodeignore') in ignore_files


def test_get_global_ignore_patterns(fs: 'FakeFilesystem') -> None:
    _create_mocked_file_structure(fs)
    ignore_patterns = _get_global_ignore_patterns('/home/user/project/subdir')

    assert len(ignore_patterns) == 3
    assert '*.txt' in ignore_patterns
    assert '*.pyc' in ignore_patterns
    assert '*.log' in ignore_patterns
