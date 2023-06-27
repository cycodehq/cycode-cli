import os
from multiprocessing.pool import ThreadPool
from typing import List

import click

from cycode.cli.consts import SCAN_BATCH_MAX_SIZE_IN_BYTES, SCAN_BATCH_MAX_FILES_COUNT, SCAN_BATCH_SCANS_PER_CPU
from cycode.cli.models import Document, DocumentDetections


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
):
    batches = split_documents_into_batches(documents, max_size_mb, max_files_count)

    aggregated_result: List[DocumentDetections] = []
    with ThreadPool(processes=os.cpu_count() * SCAN_BATCH_SCANS_PER_CPU) as pool:
        for i, result in enumerate(pool.imap(scan_function, batches), 1):
            # TODO progress bar
            click.secho(f"Batch {i} finished", fg="green")
            aggregated_result.extend(result)

    return aggregated_result
