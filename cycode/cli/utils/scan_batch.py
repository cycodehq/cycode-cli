import os
from multiprocessing.pool import ThreadPool
from typing import List, TYPE_CHECKING, Callable

import click

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


class DummyProgressBar:
    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwargs):
        pass

    def update(self, *args, **kwargs):
        pass


def run_scan_in_patches_parallel(
        scan_function: Callable[[List[Document]], 'LocalScanResult'],
        documents: List[Document],
        max_size_mb: int = SCAN_BATCH_MAX_SIZE_IN_BYTES,
        max_files_count: int = SCAN_BATCH_MAX_FILES_COUNT,
        no_progress_meter: bool = False,
) -> List['LocalScanResult']:
    batches = split_documents_into_batches(documents, max_size_mb, max_files_count)
    if no_progress_meter:
        progress_bar = DummyProgressBar()
    else:
        progress_bar = click.progressbar(length=len(batches), label='Scan in progress', color=True)

    local_scan_results: List['LocalScanResult'] = []
    with ThreadPool(processes=os.cpu_count() * SCAN_BATCH_SCANS_PER_CPU) as pool:
        with progress_bar as bar:
            for result in pool.imap(scan_function, batches):
                local_scan_results.append(result)
                bar.update(1)

    return local_scan_results
