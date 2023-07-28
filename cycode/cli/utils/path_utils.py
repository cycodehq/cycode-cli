import os
from functools import lru_cache
from typing import AnyStr, Iterable, List, Optional

import pathspec
from binaryornot.check import is_binary


def get_relevant_files_in_path(path: str, exclude_patterns: Iterable[str]) -> List[str]:
    absolute_path = get_absolute_path(path)

    if not os.path.isfile(absolute_path) and not os.path.isdir(absolute_path):
        raise FileNotFoundError(f'the specified path was not found, path: {absolute_path}')

    if os.path.isfile(absolute_path):
        return [absolute_path]

    all_file_paths = set(_get_all_existing_files_in_directory(absolute_path))

    path_spec = pathspec.PathSpec.from_lines(pathspec.patterns.GitWildMatchPattern, exclude_patterns)
    excluded_file_paths = set(path_spec.match_files(all_file_paths))

    relevant_file_paths = all_file_paths - excluded_file_paths

    return [file_path for file_path in relevant_file_paths if os.path.isfile(file_path)]


@lru_cache(maxsize=None)
def is_sub_path(path: str, sub_path: str) -> bool:
    try:
        common_path = os.path.commonpath([get_absolute_path(path), get_absolute_path(sub_path)])
        return path == common_path
    except ValueError:
        # if paths are on the different drives
        return False


def get_absolute_path(path: str) -> str:
    if path.startswith('~'):
        return os.path.expanduser(path)
    return os.path.abspath(path)


def is_binary_file(filename: str) -> bool:
    return is_binary(filename)


def get_file_size(filename: str) -> int:
    return os.path.getsize(filename)


def get_path_by_os(filename: str) -> str:
    return filename.replace('/', os.sep)


def _get_all_existing_files_in_directory(path: str) -> List[str]:
    files: List[str] = []

    for root, _, filenames in os.walk(path):
        for filename in filenames:
            files.append(os.path.join(root, filename))

    return files


def is_path_exists(path: str) -> bool:
    return os.path.exists(path)


def get_file_dir(path: str) -> str:
    return os.path.dirname(path)


def join_paths(path: str, filename: str) -> str:
    return os.path.join(path, filename)


def get_file_content(file_path: str) -> Optional[AnyStr]:
    try:
        with open(file_path, 'r', encoding='UTF-8') as f:
            return f.read()
    except (FileNotFoundError, UnicodeDecodeError):
        return None
