from typing import TYPE_CHECKING, List

from cycode.cli import consts
from cycode.cli.config import configuration_manager
from cycode.cli.user_settings.config_file_manager import ConfigFileManager
from cycode.cli.utils.path_utils import get_file_size, is_binary_file, is_sub_path
from cycode.cli.utils.string_utils import get_content_size, is_binary_content
from cycode.cyclient import logger

if TYPE_CHECKING:
    from cycode.cli.models import Document
    from cycode.cli.utils.progress_bar import BaseProgressBar, ProgressBarSection


def exclude_irrelevant_files(
    progress_bar: 'BaseProgressBar', progress_bar_section: 'ProgressBarSection', scan_type: str, filenames: List[str]
) -> List[str]:
    relevant_files = []
    for filename in filenames:
        progress_bar.update(progress_bar_section)
        if _is_relevant_file_to_scan(scan_type, filename):
            relevant_files.append(filename)

    is_sub_path.cache_clear()  # free up memory

    return relevant_files


def exclude_irrelevant_documents_to_scan(scan_type: str, documents_to_scan: List['Document']) -> List['Document']:
    logger.debug('Excluding irrelevant documents to scan')

    relevant_documents = []
    for document in documents_to_scan:
        if _is_relevant_document_to_scan(scan_type, document.path, document.content):
            relevant_documents.append(document)

    return relevant_documents


def _is_subpath_of_cycode_configuration_folder(filename: str) -> bool:
    return (
        is_sub_path(configuration_manager.global_config_file_manager.get_config_directory_path(), filename)
        or is_sub_path(configuration_manager.local_config_file_manager.get_config_directory_path(), filename)
        or filename.endswith(ConfigFileManager.get_config_file_route())
    )


def _is_path_configured_in_exclusions(scan_type: str, file_path: str) -> bool:
    exclusions_by_path = configuration_manager.get_exclusions_by_scan_type(scan_type).get(
        consts.EXCLUSIONS_BY_PATH_SECTION_NAME, []
    )
    return any(is_sub_path(exclusion_path, file_path) for exclusion_path in exclusions_by_path)


def _does_file_exceed_max_size_limit(filename: str) -> bool:
    return get_file_size(filename) > consts.FILE_MAX_SIZE_LIMIT_IN_BYTES


def _does_document_exceed_max_size_limit(content: str) -> bool:
    return get_content_size(content) > consts.FILE_MAX_SIZE_LIMIT_IN_BYTES


def _is_relevant_file_to_scan(scan_type: str, filename: str) -> bool:
    if _is_subpath_of_cycode_configuration_folder(filename):
        logger.debug('file is irrelevant because it is in cycode configuration directory, %s', {'filename': filename})
        return False

    if _is_path_configured_in_exclusions(scan_type, filename):
        logger.debug('file is irrelevant because the file path is in the ignore paths list, %s', {'filename': filename})
        return False

    if not _is_file_extension_supported(scan_type, filename):
        logger.debug('file is irrelevant because the file extension is not supported, %s', {'filename': filename})
        return False

    if is_binary_file(filename):
        logger.debug('file is irrelevant because it is binary file, %s', {'filename': filename})
        return False

    if scan_type != consts.SCA_SCAN_TYPE and _does_file_exceed_max_size_limit(filename):
        logger.debug('file is irrelevant because its exceeded max size limit, %s', {'filename': filename})
        return False

    if scan_type == consts.SCA_SCAN_TYPE and not _is_file_relevant_for_sca_scan(filename):
        return False

    return True


def _is_file_relevant_for_sca_scan(filename: str) -> bool:
    if any(sca_excluded_path in filename for sca_excluded_path in consts.SCA_EXCLUDED_PATHS):
        logger.debug("file is irrelevant because it is from node_modules's inner path, %s", {'filename': filename})
        return False

    return True


def _is_relevant_document_to_scan(scan_type: str, filename: str, content: str) -> bool:
    if _is_subpath_of_cycode_configuration_folder(filename):
        logger.debug(
            'document is irrelevant because it is in cycode configuration directory, %s', {'filename': filename}
        )
        return False

    if _is_path_configured_in_exclusions(scan_type, filename):
        logger.debug(
            'document is irrelevant because the document path is in the ignore paths list, %s', {'filename': filename}
        )
        return False

    if not _is_file_extension_supported(scan_type, filename):
        logger.debug('document is irrelevant because the file extension is not supported, %s', {'filename': filename})
        return False

    if is_binary_content(content):
        logger.debug('document is irrelevant because it is binary, %s', {'filename': filename})
        return False

    if scan_type != consts.SCA_SCAN_TYPE and _does_document_exceed_max_size_limit(content):
        logger.debug('document is irrelevant because its exceeded max size limit, %s', {'filename': filename})
        return False
    return True


def _is_file_extension_supported(scan_type: str, filename: str) -> bool:
    filename = filename.lower()

    if scan_type == consts.INFRA_CONFIGURATION_SCAN_TYPE:
        return filename.endswith(consts.INFRA_CONFIGURATION_SCAN_SUPPORTED_FILES)

    if scan_type == consts.SCA_SCAN_TYPE:
        return filename.endswith(consts.SCA_CONFIGURATION_SCAN_SUPPORTED_FILES)

    return not filename.endswith(consts.SECRET_SCAN_FILE_EXTENSIONS_TO_IGNORE)
