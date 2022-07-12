from typing import Iterable, List
import pathspec
import os
from pathlib import Path
from binaryornot.check import is_binary


def get_relevant_files_in_path(path: str, exclude_patterns: Iterable[str]) -> List[str]:
    absolute_path = get_absolute_path(path)
    if not os.path.isfile(absolute_path) and not os.path.isdir(absolute_path):
        raise FileNotFoundError(f'the specified path was not found, path: {path}')

    if os.path.isfile(absolute_path):
        return [absolute_path]

    directory_files_paths = _get_all_existing_files_in_directory(absolute_path)
    file_paths = set({str(file_path) for file_path in directory_files_paths})
    spec = pathspec.PathSpec.from_lines(pathspec.patterns.GitWildMatchPattern, exclude_patterns)
    exclude_file_paths = set(spec.match_files(file_paths))

    return [file_path for file_path in (file_paths - exclude_file_paths) if os.path.isfile(file_path)]


def is_sub_path(path: str, sub_path: str) -> bool:
    common_path = os.path.commonpath([get_absolute_path(path), get_absolute_path(sub_path)])
    return path == common_path


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


def _get_all_existing_files_in_directory(path: str):
    directory = Path(path)
    return directory.rglob(r"*")


def is_path_exists(path: str):
    return os.path.exists(path)
