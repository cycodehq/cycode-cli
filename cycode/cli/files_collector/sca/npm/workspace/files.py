"""Filesystem access shared by the readers: identity for caching, and tolerant parsing."""

import json
import os
from pathlib import Path
from typing import Optional

from cycode.cli.utils.path_utils import get_absolute_path
from cycode.logger import get_logger

logger = get_logger('SCA NPM Workspace')

FileStamp = tuple[str, int, int]


def resolved_path(path: object) -> str:
    return os.path.realpath(get_absolute_path(str(path)))


def file_stamp(path: Path) -> Optional[FileStamp]:
    try:
        stat_result = path.stat()
    except OSError:
        return None

    return str(path), stat_result.st_mtime_ns, stat_result.st_size


def read_json_object(path: Path) -> Optional[dict]:
    try:
        content = json.loads(path.read_text(encoding='UTF-8'))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        logger.debug('Could not read an npm workspace file, %s', {'path': str(path), 'error': e})
        return None

    return content if isinstance(content, dict) else None
