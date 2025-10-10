import os
from collections.abc import Generator, Iterable

from cycode.cli import consts
from cycode.cli.logger import get_logger
from cycode.cli.utils.ignore_utils import IgnoreFilterManager

logger = get_logger('Ignores')

_SUPPORTED_IGNORE_PATTERN_FILES = {
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


def _collect_top_level_ignore_files(path: str, *, is_cycodeignore_allowed: bool = True) -> list[str]:
    ignore_files = []
    top_paths = reversed(list(_walk_to_top(path)))  # we must reverse it to make top levels more prioritized

    supported_files = set(_SUPPORTED_IGNORE_PATTERN_FILES)
    if is_cycodeignore_allowed:
        supported_files.add(consts.CYCODEIGNORE_FILENAME)
        logger.debug('.cycodeignore files included due to scan configuration')

    for dir_path in top_paths:
        for ignore_file in supported_files:
            ignore_file_path = os.path.join(dir_path, ignore_file)
            if os.path.exists(ignore_file_path):
                logger.debug('Reading top level ignore file: %s', ignore_file_path)
                ignore_files.append(ignore_file_path)
    return ignore_files


def walk_ignore(
    path: str, *, is_cycodeignore_allowed: bool = True
) -> Generator[tuple[str, list[str], list[str]], None, None]:
    ignore_file_paths = _collect_top_level_ignore_files(path, is_cycodeignore_allowed=is_cycodeignore_allowed)
    ignore_filter_manager = IgnoreFilterManager.build(
        path=path,
        global_ignore_file_paths=ignore_file_paths,
        global_patterns=_DEFAULT_GLOBAL_IGNORE_PATTERNS,
    )
    for dirpath, dirnames, filenames, ignored_dirnames, ignored_filenames in ignore_filter_manager.walk_with_ignored():
        rel_dirpath = '' if dirpath == path else os.path.relpath(dirpath, path)
        display_dir = rel_dirpath or '.'
        for is_dir, names in (
            (True, ignored_dirnames),
            (False, ignored_filenames),
        ):
            for name in names:
                full_path = os.path.join(path, display_dir, name)
                if is_dir:
                    full_path = os.path.join(full_path, '*')
                logger.debug('Ignoring match %s', full_path)

        yield dirpath, dirnames, filenames
