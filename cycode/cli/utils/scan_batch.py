import os
from multiprocessing.pool import ThreadPool
from typing import List, TYPE_CHECKING

import click
from halo import Halo

from cycode.cli.consts import SCAN_BATCH_MAX_SIZE_IN_BYTES, SCAN_BATCH_MAX_FILES_COUNT, SCAN_BATCH_SCANS_PER_CPU
from cycode.cli.models import Document

if TYPE_CHECKING:
    from cycode.cli.models import LocalScanResult


def split_documents_into_batches(
        documents: List[Document],
        max_size_mb: int = SCAN_BATCH_MAX_SIZE_IN_BYTES,
        max_files_count: int = SCAN_BATCH_MAX_FILES_COUNT,
) -> List[List[Document]]:
    batches = []

    current_size = 0
    current_batch = []
    for document in documents:
        document_size = len(document.content.encode('UTF-8'))

        if (current_size + document_size > max_size_mb) or (len(current_batch) >= max_files_count):
            batches.append(current_batch)

            current_batch = [document]
            current_size = document_size
        else:
            current_batch.append(document)
            current_size += document_size

    if current_batch:
        batches.append(current_batch)

    return batches


def run_scan_in_patches_parallel(
        scan_function,
        documents: List[Document],
        max_size_mb: int = SCAN_BATCH_MAX_SIZE_IN_BYTES,
        max_files_count: int = SCAN_BATCH_MAX_FILES_COUNT,
) -> List['LocalScanResult']:
    batches = split_documents_into_batches(documents, max_size_mb, max_files_count)

    spinner = Halo(spinner='dots')
    spinner.start('Scan in progress')

    def _scan_function(batch: List[Document]) -> 'LocalScanResult':
        try:
            return scan_function(batch)
        except Exception:
            spinner.fail()
            raise

    local_scan_results: List['LocalScanResult'] = []
    with ThreadPool(processes=os.cpu_count() * SCAN_BATCH_SCANS_PER_CPU) as pool:
        for i, result in enumerate(pool.imap(_scan_function, batches), 1):
            # TODO progress bar
            # click.secho(f'Batch {i} finished', fg='green')
            local_scan_results.append(result)

    spinner.succeed()
    return local_scan_results
