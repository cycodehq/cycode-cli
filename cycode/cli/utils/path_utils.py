import json
import os
from functools import lru_cache
from typing import AnyStr, List, Optional

from binaryornot.check import is_binary


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


def is_path_exists(path: str) -> bool:
    return os.path.exists(path)


def get_file_dir(path: str) -> str:
    return os.path.dirname(path)


def get_immediate_subdirectories(path: str) -> List[str]:
    return [f.name for f in os.scandir(path) if f.is_dir()]


def join_paths(path: str, filename: str) -> str:
    return os.path.join(path, filename)


def get_file_content(file_path: str) -> Optional[AnyStr]:
    try:
        with open(file_path, 'r', encoding='UTF-8') as f:
            return f.read()
    except (FileNotFoundError, UnicodeDecodeError):
        return None


def load_json(txt: str) -> Optional[dict]:
    try:
        return json.loads(txt)
    except json.JSONDecodeError:
        return None


def change_filename_extension(filename: str, extension: str) -> str:
    base_name, _ = os.path.splitext(filename)
    return f'{base_name}.{extension}'


def concat_unique_id(filename: str, unique_id: str) -> str:
    if filename.startswith(os.sep):
        # remove leading slash to join the path correctly
        filename = filename[len(os.sep) :]

    return os.path.join(unique_id, filename)
