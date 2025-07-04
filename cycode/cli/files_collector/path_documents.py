import os
from typing import TYPE_CHECKING

from cycode.cli.files_collector.file_excluder import excluder
from cycode.cli.files_collector.iac.tf_content_generator import (
    generate_tf_content_from_tfplan,
    generate_tfplan_document_name,
    is_iac,
    is_tfplan_file,
)
from cycode.cli.files_collector.walk_ignore import walk_ignore
from cycode.cli.logger import logger
from cycode.cli.models import Document
from cycode.cli.utils.path_utils import get_absolute_path, get_file_content

if TYPE_CHECKING:
    from cycode.cli.utils.progress_bar import BaseProgressBar, ProgressBarSection


def _get_all_existing_files_in_directory(path: str, *, walk_with_ignore_patterns: bool = True) -> list[str]:
    files: list[str] = []

    walk_func = walk_ignore if walk_with_ignore_patterns else os.walk
    for root, _, filenames in walk_func(path):
        for filename in filenames:
            files.append(os.path.join(root, filename))

    return files


def _get_relevant_files_in_path(path: str) -> list[str]:
    absolute_path = get_absolute_path(path)

    if not os.path.isfile(absolute_path) and not os.path.isdir(absolute_path):
        raise FileNotFoundError(f'the specified path was not found, path: {absolute_path}')

    if os.path.isfile(absolute_path):
        return [absolute_path]

    file_paths = _get_all_existing_files_in_directory(absolute_path)
    return [file_path for file_path in file_paths if os.path.isfile(file_path)]


def _get_relevant_files(
    progress_bar: 'BaseProgressBar', progress_bar_section: 'ProgressBarSection', scan_type: str, paths: tuple[str, ...]
) -> list[str]:
    all_files_to_scan = []
    for path in paths:
        all_files_to_scan.extend(_get_relevant_files_in_path(path))

    # we are double the progress bar section length because we are going to process the files twice
    # first time to get the file list with respect of excluded patterns (excluding takes seconds to execute)
    # second time to get the files content
    progress_bar_section_len = len(all_files_to_scan) * 2
    progress_bar.set_section_length(progress_bar_section, progress_bar_section_len)

    relevant_files_to_scan = excluder.exclude_irrelevant_files(
        progress_bar, progress_bar_section, scan_type, all_files_to_scan
    )

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
    paths: tuple[str, ...],
    *,
    is_git_diff: bool = False,
) -> list[Document]:
    relevant_files = _get_relevant_files(progress_bar, progress_bar_section, scan_type, paths)

    documents: list[Document] = []
    for file in relevant_files:
        progress_bar.update(progress_bar_section)

        content = get_file_content(file)
        if not content:
            continue

        documents.append(_generate_document(file, scan_type, content, is_git_diff))

    return documents
