import json
import ntpath
import os
import tempfile
from functools import cache
from typing import TYPE_CHECKING, AnyStr, Optional, Union

import typer

from cycode.cli.logger import logger
from cycode.cli.utils.binary_utils import is_binary_string

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


def atomic_write_text(filename: str, content: str) -> None:
    """Write via a temp file + rename so concurrent CLI processes never read a torn file."""
    directory = os.path.dirname(filename)
    file_descriptor, temp_filename = tempfile.mkstemp(dir=directory, prefix=f'.{os.path.basename(filename)}.')
    try:
        with os.fdopen(file_descriptor, 'w', encoding='UTF-8') as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())

        os.replace(temp_filename, filename)
    except Exception:
        if os.path.exists(temp_filename):
            os.remove(temp_filename)
        raise


def quarantine_corrupt_file(filename: str) -> None:
    # Renamed rather than deleted: the file may hold the only copy of the user's credentials,
    # and keeping it around leaves something to look at in the next bug report.
    try:
        os.replace(filename, f'{filename}.corrupt')
    except OSError as e:
        logger.warning('Failed to quarantine corrupt file, %s', {'filename': filename}, exc_info=e)


def load_json(txt: str) -> Optional[dict]:
    try:
        return json.loads(txt)
    except json.JSONDecodeError:
        return None


def change_filename_extension(filename: str, extension: str) -> str:
    base_name, _ = os.path.splitext(filename)
    return f'{base_name}.{extension}'


def _strip_path_anchor(path: str) -> str:
    """Drop the drive (``C:``, ``\\\\server\\share``) and the leading separators so the path becomes relative.

    ``os.path.join(prefix, path)`` throws the prefix away when ``path`` is absolute. On POSIX only a leading
    slash makes a path absolute, but on Windows a drive letter does too, and ``C:\\repo\\file`` doesn't start
    with a separator. ``ntpath.splitdrive`` is used on every OS so the behavior is the same everywhere
    (on POSIX it is a no-op for anything that doesn't look like ``X:``).
    """
    _, path = ntpath.splitdrive(path)
    return path.lstrip('/\\')


def concat_unique_id(filename: str, unique_id: str) -> str:
    """Prefix the file name with the unique id (e.g. a commit SHA) to build the name of the archive entry.

    The server reads the unique id back from the first path component, so the file name must become relative
    before joining; otherwise the prefix is lost and a Windows drive letter is reported as the commit id.
    """
    return os.path.join(unique_id, _strip_path_anchor(filename))


def get_path_from_context(ctx: typer.Context) -> Optional[str]:
    path = ctx.params.get('path')
    if path is None and 'paths' in ctx.params:
        path = ctx.params['paths'][0]
    return path


def normalize_file_path(path: str) -> str:
    """Make a path comparable with the file name the server reports back: no drive, no root, no leading ``./``."""
    if path.startswith(('./', '.\\')):
        return path[2:]
    return _strip_path_anchor(path)
