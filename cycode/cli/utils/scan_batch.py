import os
from multiprocessing.pool import ThreadPool
from typing import TYPE_CHECKING, Callable, Dict, List, Tuple

from cycode.cli.consts import (
    SCAN_BATCH_MAX_FILES_COUNT,
    SCAN_BATCH_MAX_PARALLEL_SCANS,
    SCAN_BATCH_MAX_SIZE_IN_BYTES,
    SCAN_BATCH_SCANS_PER_CPU,
)
from cycode.cli.models import Document
from cycode.cli.utils.progress_bar import ScanProgressBarSection

if TYPE_CHECKING:
    from cycode.cli.models import CliError, LocalScanResult
    from cycode.cli.utils.progress_bar import BaseProgressBar


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


def _get_threads_count() -> int:
    cpu_count = os.cpu_count() or 1
    return min(cpu_count * SCAN_BATCH_SCANS_PER_CPU, SCAN_BATCH_MAX_PARALLEL_SCANS)


def run_parallel_batched_scan(
    scan_function: Callable[[List[Document]], Tuple[str, 'CliError', 'LocalScanResult']],
    documents: List[Document],
    progress_bar: 'BaseProgressBar',
    max_size_mb: int = SCAN_BATCH_MAX_SIZE_IN_BYTES,
    max_files_count: int = SCAN_BATCH_MAX_FILES_COUNT,
) -> Tuple[Dict[str, 'CliError'], List['LocalScanResult']]:
    batches = split_documents_into_batches(documents, max_size_mb, max_files_count)
    progress_bar.set_section_length(ScanProgressBarSection.SCAN, len(batches))  # * 3
    # TODO(MarshalX): we should multiply the count of batches in SCAN section because each batch has 3 steps:
    # 1. scan creation
    # 2. scan completion
    # 3. detection creation
    # it's not possible yet because not all scan types moved to polling mechanism
    # the progress bar could be significant improved (be more dynamic) in the future

    local_scan_results: List['LocalScanResult'] = []
    cli_errors: Dict[str, 'CliError'] = {}
    with ThreadPool(processes=_get_threads_count()) as pool:
        for scan_id, err, result in pool.imap(scan_function, batches):
            if result:
                local_scan_results.append(result)
            if err:
                cli_errors[scan_id] = err

            progress_bar.update(ScanProgressBarSection.SCAN)

    return cli_errors, local_scan_results
