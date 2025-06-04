import timeit
from pathlib import Path
from typing import Optional

from cycode.cli import consts
from cycode.cli.exceptions import custom_exceptions
from cycode.cli.files_collector.models.in_memory_zip import InMemoryZip
from cycode.cli.models import Document
from cycode.logger import get_logger

logger = get_logger('ZIP')


def _validate_zip_file_size(scan_type: str, zip_file_size: int) -> None:
    max_size_limit = consts.ZIP_MAX_SIZE_LIMIT_IN_BYTES.get(scan_type, consts.DEFAULT_ZIP_MAX_SIZE_LIMIT_IN_BYTES)
    if zip_file_size > max_size_limit:
        raise custom_exceptions.ZipTooLargeError(max_size_limit)


def zip_documents(scan_type: str, documents: list[Document], zip_file: Optional[InMemoryZip] = None) -> InMemoryZip:
    if zip_file is None:
        zip_file = InMemoryZip()

    start_zip_creation_time = timeit.default_timer()

    for index, document in enumerate(documents):
        _validate_zip_file_size(scan_type, zip_file.size)

        logger.debug(
            'Adding file to ZIP, %s',
            {'index': index, 'filename': document.path, 'unique_id': document.unique_id},
        )
        zip_file.append(document.path, document.unique_id, document.content)

    zip_file.close()

    end_zip_creation_time = timeit.default_timer()
    zip_creation_time = int(end_zip_creation_time - start_zip_creation_time)
    logger.debug(
        'Finished to create ZIP file, %s',
        {'zip_creation_time': zip_creation_time, 'zip_size': zip_file.size, 'documents_count': len(documents)},
    )

    if zip_file.configuration_manager.get_debug_flag():
        zip_file_path = Path.joinpath(Path.cwd(), f'{scan_type}_scan_{end_zip_creation_time}.zip')
        logger.debug('Writing ZIP file to disk, %s', {'zip_file_path': zip_file_path})
        zip_file.write_on_disk(zip_file_path)

    return zip_file
