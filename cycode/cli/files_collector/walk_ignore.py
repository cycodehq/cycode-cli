import os
from typing import Generator, Iterable, List, Tuple

from cycode.cli.utils.ignore_utils import IgnoreFilterManager
from cycode.cyclient import logger

_SUPPORTED_IGNORE_PATTERN_FILES = {  # oneday we will bring .cycodeignore or something like that
    '.gitignore',
}
_DEFAULT_GLOBAL_IGNORE_PATTERNS = [
    '.git',
    '.cycode',
]


def _walk_to_top(path: str) -> Iterable[str]:
    while os.path.dirname(path) != path:
        yield path
        path = os.path.dirname(path)

    if path:
        yield path  # Include the top-level directory


def _collect_top_level_ignore_files(path: str) -> List[str]:
    ignore_files = []
    top_paths = reversed(list(_walk_to_top(path)))  # we must reverse it to make top levels more prioritized
    for dir_path in top_paths:
        for ignore_file in _SUPPORTED_IGNORE_PATTERN_FILES:
            ignore_file_path = os.path.join(dir_path, ignore_file)
            if os.path.exists(ignore_file_path):
                logger.debug('Apply top level ignore file: %s', ignore_file_path)
                ignore_files.append(ignore_file_path)
    return ignore_files


def walk_ignore(path: str) -> Generator[Tuple[str, List[str], List[str]], None, None]:
    ignore_filter_manager = IgnoreFilterManager.build(
        path=path,
        global_ignore_file_paths=_collect_top_level_ignore_files(path),
        global_patterns=_DEFAULT_GLOBAL_IGNORE_PATTERNS,
    )
    yield from ignore_filter_manager.walk()
