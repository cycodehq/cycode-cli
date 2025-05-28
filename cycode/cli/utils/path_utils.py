import json
import os
from functools import cache
from typing import TYPE_CHECKING, AnyStr, Optional, Union

import typer
from binaryornot.helpers import is_binary_string

from cycode.cli.logger import logger

if TYPE_CHECKING:
    from os import PathLike


@cache
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


def _get_starting_chunk(filename: str, length: int = 1024) -> Optional[bytes]:
    # We are using our own implementation of get_starting_chunk
    # because the original one from binaryornot uses print()...

    try:
        with open(filename, 'rb') as f:
            return f.read(length)
    except OSError as e:
        logger.debug('Failed to read the starting chunk from file: %s', filename, exc_info=e)

    return None


def is_binary_file(filename: str) -> bool:
    # Check if the file extension is in a list of known binary types
    binary_extensions = ('.pyc',)
    if filename.endswith(binary_extensions):
        return True

    # Check if the starting chunk is a binary string
    chunk = _get_starting_chunk(filename)
    return is_binary_string(chunk)


def get_file_size(filename: str) -> int:
    return os.path.getsize(filename)


def get_path_by_os(filename: str) -> str:
    return filename.replace('/', os.sep)


def is_path_exists(path: str) -> bool:
    return os.path.exists(path)


def get_file_dir(path: str) -> str:
    return os.path.dirname(path)


def get_immediate_subdirectories(path: str) -> list[str]:
    return [f.name for f in os.scandir(path) if f.is_dir()]


def join_paths(path: str, filename: str) -> str:
    return os.path.join(path, filename)


def get_file_content(file_path: Union[str, 'PathLike']) -> Optional[AnyStr]:
    try:
        with open(file_path, encoding='UTF-8') as f:
            return f.read()
    except (FileNotFoundError, UnicodeDecodeError):
        return None
    except PermissionError:
        logger.warn('Permission denied to read the file: %s', file_path)


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


def get_path_from_context(ctx: typer.Context) -> Optional[str]:
    path = ctx.params.get('path')
    if path is None and 'paths' in ctx.params:
        path = ctx.params['paths'][0]
    return path


def normalize_file_path(path: str) -> str:
    if path.startswith('/'):
        return path[1:]
    if path.startswith('./'):
        return path[2:]
    return path
