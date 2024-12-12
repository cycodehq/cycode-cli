import os
from os.path import normpath
from typing import TYPE_CHECKING, List

from cycode.cli.files_collector.walk_ignore import (
    _collect_top_level_ignore_files,
    _get_global_ignore_patterns,
    _walk_to_top,
    walk_ignore,
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

    fs.create_dir('/home/user/project/.cycode')
    fs.create_file('/home/user/project/.cycode/config.yaml')
    fs.create_dir('/home/user/project/.git')
    fs.create_file('/home/user/project/.git/HEAD')

    fs.create_file('/home/user/project/.gitignore', contents='*.pyc')
    fs.create_file('/home/user/project/ignored.pyc')
    fs.create_file('/home/user/project/presented.txt')

    fs.create_file('/home/user/project/.cycodeignore', contents='*.log')
    fs.create_file('/home/user/project/ignored2.log')
    fs.create_file('/home/user/project/ignored2.pyc')
    fs.create_file('/home/user/project/presented2.txt')

    fs.create_dir('/home/user/project/subproject')
    fs.create_file('/home/user/project/subproject/.gitignore', contents='*.txt')
    fs.create_file('/home/user/project/subproject/ignored.txt')
    fs.create_file('/home/user/project/subproject/ignored.log')
    fs.create_file('/home/user/project/subproject/ignored.pyc')
    fs.create_file('/home/user/project/subproject/presented.py')


def test_collect_top_level_ignore_files(fs: 'FakeFilesystem') -> None:
    _create_mocked_file_structure(fs)

    # Test with path inside the project
    path = normpath('/home/user/project/subproject')
    ignore_files = _collect_top_level_ignore_files(path)

    assert len(ignore_files) == 3
    assert normpath('/home/user/project/subproject/.gitignore') in ignore_files
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
    ignore_patterns = _get_global_ignore_patterns('/home/user/project/subproject')

    assert len(ignore_patterns) == 5
    # default global:
    assert '**/.git' in ignore_patterns
    assert '**/.cycode' in ignore_patterns
    # additional:
    assert '*.txt' in ignore_patterns
    assert '*.pyc' in ignore_patterns
    assert '*.log' in ignore_patterns


def _collect_walk_ignore_files(path: str) -> List[str]:
    files = []
    for root, _, filenames in walk_ignore(path):
        for filename in filenames:
            files.append(os.path.join(root, filename))

    return files


def test_walk_ignore(fs: 'FakeFilesystem') -> None:
    _create_mocked_file_structure(fs)

    path = normpath('/home/user/project')
    result = _collect_walk_ignore_files(path)

    assert len(result) == 6
    # ignored globally by default:
    assert normpath('/home/user/project/.git/HEAD') not in result
    assert normpath('/home/user/project/.cycode/config.yaml') not in result
    # ignored by .gitignore in project directory:
    assert normpath('/home/user/project/ignored.pyc') not in result
    assert normpath('/home/user/project/subproject/ignored.pyc') not in result
    # ignored by .gitignore in subproject directory:
    assert normpath('/home/user/project/subproject/ignored.txt') not in result
    # ignored by .cycodeignore in project directory:
    assert normpath('/home/user/project/ignored2.log') not in result
    assert normpath('/home/user/project/ignored2.pyc') not in result
    assert normpath('/home/user/project/subproject/ignored.log') not in result
    # presented after both .gitignore and .cycodeignore:
    assert normpath('/home/user/project/.gitignore') in result
    assert normpath('/home/user/project/.cycodeignore') in result
    assert normpath('/home/user/project/subproject/.gitignore') in result
    assert normpath('/home/user/project/presented.txt') in result
    assert normpath('/home/user/project/presented2.txt') in result
    assert normpath('/home/user/project/subproject/presented.py') in result

    path = normpath('/home/user/project/subproject')
    result = _collect_walk_ignore_files(path)

    assert len(result) == 2
    # ignored:
    assert normpath('/home/user/project/subproject/ignored.txt') not in result
    assert normpath('/home/user/project/subproject/ignored.log') not in result
    assert normpath('/home/user/project/subproject/ignored.pyc') not in result
    # presented:
    assert normpath('/home/user/project/subproject/presented.py') in result
