import os
from collections import defaultdict
from typing import TYPE_CHECKING, Iterable, List, Set, Tuple

import pathspec

from cycode.cli.files_collector.excluder import exclude_irrelevant_files
from cycode.cli.files_collector.iac.tf_content_generator import (
    generate_tf_content_from_tfplan,
    generate_tfplan_document_name,
    is_iac,
    is_tfplan_file,
)
from cycode.cli.models import Document
from cycode.cli.utils.path_utils import get_absolute_path, get_file_content
from cycode.cyclient import logger

if TYPE_CHECKING:
    from cycode.cli.utils.progress_bar import BaseProgressBar, ProgressBarSection


def _walk_to_top(path: str) -> Iterable[str]:
    while os.path.dirname(path) != path:
        yield path
        path = os.path.dirname(path)

    if path:
        yield path  # Include the top-level directory


_SUPPORTED_IGNORE_PATTERN_FILES = {'.gitignore', '.cycodeignore'}


def _collect_top_level_ignore_files(path: str) -> List[str]:
    ignore_files = []
    for dir_path in _walk_to_top(path):
        for ignore_file in _SUPPORTED_IGNORE_PATTERN_FILES:
            ignore_file_path = os.path.join(dir_path, ignore_file)
            if os.path.exists(ignore_file_path):
                logger.debug('Found top level ignore file: %s', ignore_file_path)
                ignore_files.append(ignore_file_path)
    return ignore_files


def _get_global_ignore_patterns(path: str) -> List[str]:
    ignore_patterns = []
    for ignore_file in _collect_top_level_ignore_files(path):
        file_patterns = get_file_content(ignore_file).splitlines()
        ignore_patterns.extend(file_patterns)
    return ignore_patterns


def _apply_ignore_patterns(ignore_patterns: List[str], files: Set[str]) -> Set[str]:
    if not ignore_patterns:
        return files

    path_spec = pathspec.PathSpec.from_lines(pathspec.patterns.GitWildMatchPattern, ignore_patterns)
    excluded_file_paths = set(path_spec.match_files(files))

    return files - excluded_file_paths


def _get_all_existing_files_in_directory(path: str, *, apply_ignore_patterns: bool = True) -> Set[str]:
    files: Set[str] = set()

    global_ignore_patterns = _get_global_ignore_patterns(path)
    path_to_ignore_patterns = defaultdict(list)

    for root, _, filenames in os.walk(path):
        for filename in filenames:
            filepath = os.path.join(root, filename)

            if filepath in _SUPPORTED_IGNORE_PATTERN_FILES:
                logger.debug('Found ignore file: %s', filepath)
                # TODO(MarshalX): accumulate ignore pattern from previous levels
                path_to_ignore_patterns[root].extend(get_file_content(filepath).splitlines())

            if apply_ignore_patterns and root in path_to_ignore_patterns:
                filtered_paths = _apply_ignore_patterns(
                    path_to_ignore_patterns[root],
                    {
                        filepath,
                    },
                )
                if filtered_paths:
                    files.update(filtered_paths)
            else:
                files.add(os.path.join(root, filename))

    if apply_ignore_patterns:
        logger.debug('Applying global ignore patterns %s', {'global_ignore_patterns': global_ignore_patterns})
        return _apply_ignore_patterns(global_ignore_patterns, files)

    return files


def _get_relevant_files_in_path(path: str, exclude_patterns: Iterable[str]) -> List[str]:
    absolute_path = get_absolute_path(path)

    if not os.path.isfile(absolute_path) and not os.path.isdir(absolute_path):
        raise FileNotFoundError(f'the specified path was not found, path: {absolute_path}')

    if os.path.isfile(absolute_path):
        return [absolute_path]

    all_file_paths = _get_all_existing_files_in_directory(absolute_path)

    path_spec = pathspec.PathSpec.from_lines(pathspec.patterns.GitWildMatchPattern, exclude_patterns)
    excluded_file_paths = set(path_spec.match_files(all_file_paths))

    relevant_file_paths = all_file_paths - excluded_file_paths

    return [file_path for file_path in relevant_file_paths if os.path.isfile(file_path)]


def _get_relevant_files(
    progress_bar: 'BaseProgressBar', progress_bar_section: 'ProgressBarSection', scan_type: str, paths: Tuple[str]
) -> List[str]:
    all_files_to_scan = []
    for path in paths:
        all_files_to_scan.extend(
            _get_relevant_files_in_path(path=path, exclude_patterns=['**/.git/**', '**/.cycode/**'])
        )

    # we are double the progress bar section length because we are going to process the files twice
    # first time to get the file list with respect of excluded patterns (excluding takes seconds to execute)
    # second time to get the files content
    progress_bar_section_len = len(all_files_to_scan) * 2
    progress_bar.set_section_length(progress_bar_section, progress_bar_section_len)

    relevant_files_to_scan = exclude_irrelevant_files(progress_bar, progress_bar_section, scan_type, all_files_to_scan)

    # after finishing the first processing (excluding),
    # we must update the progress bar stage with respect of excluded files.
    # now it's possible that we will not process x2 of the files count
    # because some of them were excluded, we should subtract the excluded files count
    # from the progress bar section length
    excluded_files_count = len(all_files_to_scan) - len(relevant_files_to_scan)
    progress_bar_section_len = progress_bar_section_len - excluded_files_count
    progress_bar.set_section_length(progress_bar_section, progress_bar_section_len)

    logger.debug(
        'Found all relevant files for scanning, %s', {'paths': paths, 'file_to_scan_count': len(relevant_files_to_scan)}
    )

    return relevant_files_to_scan


def _generate_document(file: str, scan_type: str, content: str, is_git_diff: bool) -> Document:
    if is_iac(scan_type) and is_tfplan_file(file, content):
        return _handle_tfplan_file(file, content, is_git_diff)

    return Document(file, content, is_git_diff, absolute_path=file)


def _handle_tfplan_file(file: str, content: str, is_git_diff: bool) -> Document:
    document_name = generate_tfplan_document_name(file)
    tf_content = generate_tf_content_from_tfplan(file, content)
    return Document(document_name, tf_content, is_git_diff)


def get_relevant_documents(
    progress_bar: 'BaseProgressBar',
    progress_bar_section: 'ProgressBarSection',
    scan_type: str,
    paths: Tuple[str],
    *,
    is_git_diff: bool = False,
) -> List[Document]:
    relevant_files = _get_relevant_files(progress_bar, progress_bar_section, scan_type, paths)

    documents: List[Document] = []
    for file in relevant_files:
        progress_bar.update(progress_bar_section)

        content = get_file_content(file)
        if not content:
            continue

        documents.append(_generate_document(file, scan_type, content, is_git_diff))

    return documents
