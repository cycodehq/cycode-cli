import os
from typing import TYPE_CHECKING, Iterable, List

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


def _get_all_existing_files_in_directory(path: str) -> List[str]:
    files: List[str] = []

    for root, _, filenames in os.walk(path):
        for filename in filenames:
            files.append(os.path.join(root, filename))

    return files


def _get_relevant_files_in_path(path: str, exclude_patterns: Iterable[str]) -> List[str]:
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


def _get_relevant_files(
    progress_bar: 'BaseProgressBar', progress_bar_section: 'ProgressBarSection', scan_type: str, path: str
) -> List[str]:
    all_files_to_scan = _get_relevant_files_in_path(path=path, exclude_patterns=['**/.git/**', '**/.cycode/**'])

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
        'Found all relevant files for scanning %s', {'path': path, 'file_to_scan_count': len(relevant_files_to_scan)}
    )

    return relevant_files_to_scan


def _generate_document(file: str, scan_type: str, content: str, is_git_diff: bool) -> Document:
    if is_iac(scan_type) and is_tfplan_file(file, content):
        return _handle_tfplan_file(file, content, is_git_diff)

    return Document(file, content, is_git_diff)


def _handle_tfplan_file(file: str, content: str, is_git_diff: bool) -> Document:
    document_name = generate_tfplan_document_name(file)
    tf_content = generate_tf_content_from_tfplan(file, content)
    return Document(document_name, tf_content, is_git_diff)


def get_relevant_document(
    progress_bar: 'BaseProgressBar',
    progress_bar_section: 'ProgressBarSection',
    scan_type: str,
    path: str,
    *,
    is_git_diff: bool = False,
) -> List[Document]:
    relevant_files = _get_relevant_files(progress_bar, progress_bar_section, scan_type, path)

    documents: List[Document] = []
    for file in relevant_files:
        progress_bar.update(progress_bar_section)

        content = get_file_content(file)
        if not content:
            continue

        documents.append(_generate_document(file, scan_type, content, is_git_diff))

    return documents
