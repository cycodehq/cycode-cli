import os
from collections import defaultdict
from typing import Iterable, List

import pathspec
from pathspec.util import StrPath

from cycode.cli.utils.path_utils import get_file_content
from cycode.cyclient import logger

_SUPPORTED_IGNORE_PATTERN_FILES = {'.gitignore', '.cycodeignore'}
_DEFAULT_GLOBAL_IGNORE_PATTERNS = [
    '.git',
    '.cycode',
    '**/.git/**',
    '**/.cycode/**',
]


def _walk_to_top(path: str) -> Iterable[str]:
    while os.path.dirname(path) != path:
        yield path
        path = os.path.dirname(path)

    if path:
        yield path  # Include the top-level directory


def _collect_top_level_ignore_files(path: str) -> List[str]:
    ignore_files = []
    for dir_path in _walk_to_top(path):
        for ignore_file in _SUPPORTED_IGNORE_PATTERN_FILES:
            ignore_file_path = os.path.join(dir_path, ignore_file)
            if os.path.exists(ignore_file_path):
                logger.debug('Apply top level ignore file: %s', ignore_file_path)
                ignore_files.append(ignore_file_path)
    return ignore_files


def _get_global_ignore_patterns(path: str) -> List[str]:
    ignore_patterns = _DEFAULT_GLOBAL_IGNORE_PATTERNS.copy()
    for ignore_file in _collect_top_level_ignore_files(path):
        file_patterns = get_file_content(ignore_file).splitlines()
        ignore_patterns.extend(file_patterns)
    return ignore_patterns


def _should_include_path(ignore_patterns: List[str], path: StrPath) -> bool:
    path_spec = pathspec.PathSpec.from_lines(pathspec.patterns.GitWildMatchPattern, ignore_patterns)
    return not path_spec.match_file(path)  # works with both files and directories; negative match


def walk_ignore(path: str) -> List[str]:
    global_ignore_patterns = _get_global_ignore_patterns(path)
    path_to_ignore_patterns = defaultdict(list)

    for dirpath, dirnames, filenames in os.walk(path, topdown=True):
        # finds and processes ignore files first to get the patterns
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            if filename in _SUPPORTED_IGNORE_PATTERN_FILES:
                logger.debug('Apply ignore file: %s', filepath)
                # TODO(MarshalX): accumulate ignore pattern from previous levels
                path_to_ignore_patterns[dirpath].extend(get_file_content(filepath).splitlines())

        ignore_patterns = global_ignore_patterns + path_to_ignore_patterns.get(dirpath, [])

        # decrease recursion depth of os.walk() because of topdown=True by changing the list in-place
        # slicing ([:]) is mandatory to change dict in-place!
        dirnames[:] = [d for d in dirnames if _should_include_path(ignore_patterns, d)]
        filenames[:] = [f for f in filenames if _should_include_path(ignore_patterns, f)]

        yield dirpath, dirnames, filenames
