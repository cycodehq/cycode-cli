import os
from multiprocessing.pool import ThreadPool
from typing import TYPE_CHECKING, Callable

from cycode.cli import consts
from cycode.cli.models import Document
from cycode.cli.utils.progress_bar import ScanProgressBarSection
from cycode.logger import get_logger

if TYPE_CHECKING:
    from cycode.cli.models import CliError, LocalScanResult
    from cycode.cli.utils.progress_bar import BaseProgressBar


logger = get_logger('Batching')


def _get_max_batch_size(scan_type: str) -> int:
    logger.debug(
        'You can customize the batch size by setting the environment variable "%s"',
        consts.SCAN_BATCH_MAX_SIZE_IN_BYTES_ENV_VAR_NAME,
    )

    custom_size = os.environ.get(consts.SCAN_BATCH_MAX_SIZE_IN_BYTES_ENV_VAR_NAME)
    if custom_size:
        logger.debug('Custom batch size is set, %s', {'custom_size': custom_size})
        return int(custom_size)

    return consts.SCAN_BATCH_MAX_SIZE_IN_BYTES.get(scan_type, consts.DEFAULT_SCAN_BATCH_MAX_SIZE_IN_BYTES)


def _get_max_batch_files_count(_: str) -> int:
    logger.debug(
        'You can customize the batch files count by setting the environment variable "%s"',
        consts.SCAN_BATCH_MAX_FILES_COUNT_ENV_VAR_NAME,
    )

    custom_files_count = os.environ.get(consts.SCAN_BATCH_MAX_FILES_COUNT_ENV_VAR_NAME)
    if custom_files_count:
        logger.debug('Custom batch files count is set, %s', {'custom_files_count': custom_files_count})
        return int(custom_files_count)

    return consts.DEFAULT_SCAN_BATCH_MAX_FILES_COUNT


def split_documents_into_batches(
    scan_type: str,
    documents: list[Document],
) -> list[list[Document]]:
    max_size = _get_max_batch_size(scan_type)
    max_files_count = _get_max_batch_files_count(scan_type)

    logger.debug(
        'Splitting documents into batches, %s',
        {'document_count': len(documents), 'max_batch_size': max_size, 'max_files_count': max_files_count},
    )

    batches = []

    current_size = 0
    current_batch = []
    for document in documents:
        document_size = len(document.content.encode('UTF-8'))

        exceeds_max_size = current_size + document_size > max_size
        if exceeds_max_size:
            logger.debug(
                'Going to create new batch because current batch size exceeds the limit, %s',
                {
                    'batch_index': len(batches),
                    'current_batch_size': current_size + document_size,
                    'max_batch_size': max_size,
                },
            )

        exceeds_max_files_count = len(current_batch) >= max_files_count
        if exceeds_max_files_count:
            logger.debug(
                'Going to create new batch because current batch files count exceeds the limit, %s',
                {
                    'batch_index': len(batches),
                    'current_batch_files_count': len(current_batch),
                    'max_batch_files_count': max_files_count,
                },
            )

        if exceeds_max_size or exceeds_max_files_count:
            batches.append(current_batch)

            current_batch = [document]
            current_size = document_size
        else:
            current_batch.append(document)
            current_size += document_size

    if current_batch:
        batches.append(current_batch)

    logger.debug('Documents were split into batches %s', {'batches_count': len(batches)})

    return batches


def _get_threads_count() -> int:
    cpu_count = os.cpu_count() or 1
    return min(cpu_count * consts.SCAN_BATCH_SCANS_PER_CPU, consts.SCAN_BATCH_MAX_PARALLEL_SCANS)


def run_parallel_batched_scan(
    scan_function: Callable[[list[Document]], tuple[str, 'CliError', 'LocalScanResult']],
    scan_type: str,
    documents: list[Document],
    progress_bar: 'BaseProgressBar',
) -> tuple[dict[str, 'CliError'], list['LocalScanResult']]:
    # batching is disabled for SCA; requested by Mor
    batches = [documents] if scan_type == consts.SCA_SCAN_TYPE else split_documents_into_batches(scan_type, documents)

    progress_bar.set_section_length(ScanProgressBarSection.SCAN, len(batches))  # * 3
    # TODO(MarshalX): we should multiply the count of batches in SCAN section because each batch has 3 steps:
    # 1. scan creation
    # 2. scan completion
    # 3. detection creation
    # it's not possible yet because not all scan types moved to polling mechanism
    # the progress bar could be significant improved (be more dynamic) in the future

    threads_count = _get_threads_count()
    local_scan_results: list[LocalScanResult] = []
    cli_errors: dict[str, CliError] = {}

    logger.debug('Running parallel batched scan, %s', {'threads_count': threads_count, 'batches_count': len(batches)})

    with ThreadPool(processes=threads_count) as pool:
        for scan_id, err, result in pool.imap(scan_function, batches):
            if result:
                local_scan_results.append(result)
            if err:
                cli_errors[scan_id] = err

            progress_bar.update(ScanProgressBarSection.SCAN)

    return cli_errors, local_scan_results
