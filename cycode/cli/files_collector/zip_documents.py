import time
from typing import List, Optional

from cycode.cli import consts
from cycode.cli.exceptions import custom_exceptions
from cycode.cli.files_collector.models.in_memory_zip import InMemoryZip
from cycode.cli.models import Document
from cycode.cyclient import logger


def _validate_zip_file_size(scan_type: str, zip_file_size: int) -> None:
    if scan_type == consts.SCA_SCAN_TYPE:
        if zip_file_size > consts.SCA_ZIP_MAX_SIZE_LIMIT_IN_BYTES:
            raise custom_exceptions.ZipTooLargeError(consts.SCA_ZIP_MAX_SIZE_LIMIT_IN_BYTES)
    else:
        if zip_file_size > consts.ZIP_MAX_SIZE_LIMIT_IN_BYTES:
            raise custom_exceptions.ZipTooLargeError(consts.ZIP_MAX_SIZE_LIMIT_IN_BYTES)


def zip_documents(scan_type: str, documents: List[Document], zip_file: Optional[InMemoryZip] = None) -> InMemoryZip:
    if zip_file is None:
        zip_file = InMemoryZip()

    start_zip_creation_time = time.time()

    for index, document in enumerate(documents):
        _validate_zip_file_size(scan_type, zip_file.size)

        logger.debug(
            'adding file to zip, %s', {'index': index, 'filename': document.path, 'unique_id': document.unique_id}
        )
        zip_file.append(document.path, document.unique_id, document.content)

    zip_file.close()

    end_zip_creation_time = time.time()
    zip_creation_time = int(end_zip_creation_time - start_zip_creation_time)
    logger.debug('finished to create zip file, %s', {'zip_creation_time': zip_creation_time})

    return zip_file
