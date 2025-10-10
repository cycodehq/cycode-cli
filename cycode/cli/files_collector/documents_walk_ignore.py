import os
from typing import TYPE_CHECKING

from cycode.cli import consts
from cycode.cli.logger import get_logger
from cycode.cli.utils.ignore_utils import IgnoreFilterManager

if TYPE_CHECKING:
    from cycode.cli.models import Document

logger = get_logger('Documents Ignores')


def _get_cycodeignore_path(repo_path: str) -> str:
    """Get the path to .cycodeignore file in the repository root."""
    return os.path.join(repo_path, consts.CYCODEIGNORE_FILENAME)


def _create_ignore_filter_manager(repo_path: str, cycodeignore_path: str) -> IgnoreFilterManager:
    """Create IgnoreFilterManager with .cycodeignore file."""
    return IgnoreFilterManager.build(
        path=repo_path,
        global_ignore_file_paths=[cycodeignore_path],
        global_patterns=[],
    )


def _log_ignored_files(repo_path: str, dirpath: str, ignored_dirnames: list[str], ignored_filenames: list[str]) -> None:
    """Log ignored files for debugging (similar to walk_ignore function)."""
    rel_dirpath = '' if dirpath == repo_path else os.path.relpath(dirpath, repo_path)
    display_dir = rel_dirpath or '.'

    for is_dir, names in (
        (True, ignored_dirnames),
        (False, ignored_filenames),
    ):
        for name in names:
            full_path = os.path.join(repo_path, display_dir, name)
            if is_dir:
                full_path = os.path.join(full_path, '*')
            logger.debug('Ignoring match %s', full_path)


def _build_allowed_paths_set(ignore_filter_manager: IgnoreFilterManager, repo_path: str) -> set[str]:
    """Build set of allowed file paths using walk_with_ignored."""
    allowed_paths = set()

    for dirpath, _dirnames, filenames, ignored_dirnames, ignored_filenames in ignore_filter_manager.walk_with_ignored():
        _log_ignored_files(repo_path, dirpath, ignored_dirnames, ignored_filenames)

        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            allowed_paths.add(file_path)

    return allowed_paths


def _get_document_check_path(document: 'Document', repo_path: str) -> str:
    """Get the normalized absolute path for a document to check against allowed paths."""
    check_path = document.absolute_path
    if not check_path:
        check_path = document.path if os.path.isabs(document.path) else os.path.join(repo_path, document.path)

    return os.path.normpath(check_path)


def _filter_documents_by_allowed_paths(
    documents: list['Document'], allowed_paths: set[str], repo_path: str
) -> list['Document']:
    """Filter documents by checking if their paths are in the allowed set."""
    filtered_documents = []

    for document in documents:
        try:
            check_path = _get_document_check_path(document, repo_path)

            if check_path in allowed_paths:
                filtered_documents.append(document)
            else:
                relative_path = os.path.relpath(check_path, repo_path)
                logger.debug('Filtered out document due to .cycodeignore: %s', relative_path)
        except Exception as e:
            logger.debug('Error processing document %s: %s', document.path, e)
            filtered_documents.append(document)

    return filtered_documents


def filter_documents_with_cycodeignore(
    documents: list['Document'], repo_path: str, is_cycodeignore_allowed: bool = True
) -> list['Document']:
    """Filter documents based on .cycodeignore patterns.

    This function uses .cycodeignore file in the repository root to filter out
    documents whose paths match any of those patterns.

    Args:
        documents: List of Document objects to filter
        repo_path: Path to the repository root
        is_cycodeignore_allowed: Whether .cycodeignore filtering is allowed by scan configuration

    Returns:
        List of Document objects that don't match any .cycodeignore patterns
    """
    if not is_cycodeignore_allowed:
        logger.debug('.cycodeignore filtering is not allowed by scan configuration')
        return documents

    cycodeignore_path = _get_cycodeignore_path(repo_path)

    if not os.path.exists(cycodeignore_path):
        logger.debug('.cycodeignore file does not exist in the repository root')
        return documents

    logger.info('Using %s for filtering documents', cycodeignore_path)

    ignore_filter_manager = _create_ignore_filter_manager(repo_path, cycodeignore_path)

    allowed_paths = _build_allowed_paths_set(ignore_filter_manager, repo_path)

    filtered_documents = _filter_documents_by_allowed_paths(documents, allowed_paths, repo_path)

    logger.debug('Filtered %d documents using .cycodeignore patterns', len(documents) - len(filtered_documents))
    return filtered_documents
