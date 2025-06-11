import time
from platform import platform
from typing import TYPE_CHECKING, Callable, Optional

import typer

from cycode.cli import consts
from cycode.cli.apps.scan.aggregation_report import try_set_aggregation_report_url_if_needed
from cycode.cli.apps.scan.scan_parameters import get_scan_parameters
from cycode.cli.apps.scan.scan_result import (
    create_local_scan_result,
    enrich_scan_result_with_data_from_detection_rules,
    get_scan_result,
    get_sync_scan_result,
    print_local_scan_results,
)
from cycode.cli.config import configuration_manager
from cycode.cli.exceptions import custom_exceptions
from cycode.cli.exceptions.handle_scan_errors import handle_scan_exception
from cycode.cli.files_collector.path_documents import get_relevant_documents
from cycode.cli.files_collector.sca.sca_file_collector import add_sca_dependencies_tree_documents_if_needed
from cycode.cli.files_collector.zip_documents import zip_documents
from cycode.cli.models import CliError, Document, LocalScanResult
from cycode.cli.utils.progress_bar import ScanProgressBarSection
from cycode.cli.utils.scan_batch import run_parallel_batched_scan
from cycode.cli.utils.scan_utils import generate_unique_scan_id, set_issue_detected_by_scan_results
from cycode.cyclient.models import ZippedFileScanResult
from cycode.logger import get_logger

if TYPE_CHECKING:
    from cycode.cli.files_collector.models.in_memory_zip import InMemoryZip
    from cycode.cyclient.scan_client import ScanClient

start_scan_time = time.time()


logger = get_logger('Code Scanner')


def scan_disk_files(ctx: typer.Context, paths: tuple[str, ...]) -> None:
    scan_type = ctx.obj['scan_type']
    progress_bar = ctx.obj['progress_bar']

    try:
        documents = get_relevant_documents(progress_bar, ScanProgressBarSection.PREPARE_LOCAL_FILES, scan_type, paths)
        add_sca_dependencies_tree_documents_if_needed(ctx, scan_type, documents)
        scan_documents(ctx, documents, get_scan_parameters(ctx, paths))
    except Exception as e:
        handle_scan_exception(ctx, e)


def _should_use_sync_flow(command_scan_type: str, scan_type: str, sync_option: bool) -> bool:
    """Decide whether to use sync flow or async flow for the scan.

    Note:
        Passing `--sync` option does not mean that sync flow will be used in all cases.

    The logic:
    - for IAC scan, sync flow is always used
    - for SAST scan, sync flow is not supported
    - for SCA and Secrets scan, sync flow is supported only for path/repository scan

    """
    if not sync_option and scan_type != consts.IAC_SCAN_TYPE:
        return False

    if command_scan_type not in {'path', 'repository'}:
        return False

    if scan_type == consts.IAC_SCAN_TYPE:
        # sync in the only available flow for IAC scan; we do not use detector directly anymore
        return True

    if scan_type is consts.SAST_SCAN_TYPE:  # noqa: SIM103
        # SAST does not support sync flow
        return False

    return True


def _get_scan_documents_thread_func(
    ctx: typer.Context, is_git_diff: bool, is_commit_range: bool, scan_parameters: dict
) -> Callable[[list[Document]], tuple[str, CliError, LocalScanResult]]:
    cycode_client = ctx.obj['client']
    scan_type = ctx.obj['scan_type']
    severity_threshold = ctx.obj['severity_threshold']
    sync_option = ctx.obj['sync']
    command_scan_type = ctx.info_name

    def _scan_batch_thread_func(batch: list[Document]) -> tuple[str, CliError, LocalScanResult]:
        local_scan_result = error = error_message = None
        detections_count = relevant_detections_count = zip_file_size = 0

        scan_id = str(generate_unique_scan_id())
        scan_completed = False

        should_use_sync_flow = _should_use_sync_flow(command_scan_type, scan_type, sync_option)

        try:
            logger.debug('Preparing local files, %s', {'batch_files_count': len(batch)})
            zipped_documents = zip_documents(scan_type, batch)
            zip_file_size = zipped_documents.size
            scan_result = _perform_scan(
                cycode_client,
                zipped_documents,
                scan_type,
                is_git_diff,
                is_commit_range,
                scan_parameters,
                should_use_sync_flow,
            )

            enrich_scan_result_with_data_from_detection_rules(cycode_client, scan_result)

            local_scan_result = create_local_scan_result(
                scan_result, batch, command_scan_type, scan_type, severity_threshold
            )

            scan_completed = True
        except Exception as e:
            error = handle_scan_exception(ctx, e, return_exception=True)
            error_message = str(e)

        if local_scan_result:
            detections_count = local_scan_result.detections_count
            relevant_detections_count = local_scan_result.relevant_detections_count
            scan_id = local_scan_result.scan_id

        logger.debug(
            'Processing scan results, %s',
            {
                'all_violations_count': detections_count,
                'relevant_violations_count': relevant_detections_count,
                'scan_id': scan_id,
                'zip_file_size': zip_file_size,
            },
        )
        report_scan_status(
            cycode_client,
            scan_type,
            scan_id,
            scan_completed,
            relevant_detections_count,
            detections_count,
            len(batch),
            zip_file_size,
            command_scan_type,
            error_message,
        )

        return scan_id, error, local_scan_result

    return _scan_batch_thread_func


def scan_documents(
    ctx: typer.Context,
    documents_to_scan: list[Document],
    scan_parameters: dict,
    is_git_diff: bool = False,
    is_commit_range: bool = False,
) -> None:
    scan_type = ctx.obj['scan_type']
    progress_bar = ctx.obj['progress_bar']
    printer = ctx.obj.get('console_printer')

    if not documents_to_scan:
        progress_bar.stop()
        printer.print_error(
            CliError(
                code='no_relevant_files',
                message='Error: The scan could not be completed - relevant files to scan are not found. '
                'Enable verbose mode to see more details.',
            )
        )
        return

    scan_batch_thread_func = _get_scan_documents_thread_func(ctx, is_git_diff, is_commit_range, scan_parameters)
    errors, local_scan_results = run_parallel_batched_scan(
        scan_batch_thread_func, scan_type, documents_to_scan, progress_bar=progress_bar
    )

    try_set_aggregation_report_url_if_needed(ctx, scan_parameters, ctx.obj['client'], scan_type)

    progress_bar.set_section_length(ScanProgressBarSection.GENERATE_REPORT, 1)
    progress_bar.update(ScanProgressBarSection.GENERATE_REPORT)
    progress_bar.stop()

    set_issue_detected_by_scan_results(ctx, local_scan_results)
    print_local_scan_results(ctx, local_scan_results, errors)


def _perform_scan_async(
    cycode_client: 'ScanClient',
    zipped_documents: 'InMemoryZip',
    scan_type: str,
    scan_parameters: dict,
    is_commit_range: bool,
) -> ZippedFileScanResult:
    scan_async_result = cycode_client.zipped_file_scan_async(
        zipped_documents, scan_type, scan_parameters, is_commit_range=is_commit_range
    )
    logger.debug('Async scan request has been triggered successfully, %s', {'scan_id': scan_async_result.scan_id})

    return poll_scan_results(
        cycode_client,
        scan_async_result.scan_id,
        scan_type,
        scan_parameters,
    )


def _perform_scan_sync(
    cycode_client: 'ScanClient',
    zipped_documents: 'InMemoryZip',
    scan_type: str,
    scan_parameters: dict,
    is_git_diff: bool = False,
) -> 'ZippedFileScanResult':
    scan_results = cycode_client.zipped_file_scan_sync(zipped_documents, scan_type, scan_parameters, is_git_diff)
    logger.debug('Sync scan request has been triggered successfully, %s', {'scan_id': scan_results.id})
    return get_sync_scan_result(scan_type, scan_results)


def _perform_scan(
    cycode_client: 'ScanClient',
    zipped_documents: 'InMemoryZip',
    scan_type: str,
    is_git_diff: bool,
    is_commit_range: bool,
    scan_parameters: dict,
    should_use_sync_flow: bool = False,
) -> ZippedFileScanResult:
    if should_use_sync_flow:
        # it does not support commit range scans; should_use_sync_flow handles it
        return _perform_scan_sync(cycode_client, zipped_documents, scan_type, scan_parameters, is_git_diff)

    return _perform_scan_async(cycode_client, zipped_documents, scan_type, scan_parameters, is_commit_range)


def poll_scan_results(
    cycode_client: 'ScanClient',
    scan_id: str,
    scan_type: str,
    scan_parameters: dict,
    polling_timeout: Optional[int] = None,
) -> 'ZippedFileScanResult':
    if polling_timeout is None:
        polling_timeout = configuration_manager.get_scan_polling_timeout_in_seconds()

    last_scan_update_at = None
    end_polling_time = time.time() + polling_timeout

    while time.time() < end_polling_time:
        scan_details = cycode_client.get_scan_details(scan_type, scan_id)

        if scan_details.scan_update_at is not None and scan_details.scan_update_at != last_scan_update_at:
            last_scan_update_at = scan_details.scan_update_at
            logger.debug('Scan update, %s', {'scan_id': scan_details.id, 'scan_status': scan_details.scan_status})

            if scan_details.message:
                logger.debug('Scan message: %s', scan_details.message)

        if scan_details.scan_status == consts.SCAN_STATUS_COMPLETED:
            return get_scan_result(cycode_client, scan_type, scan_id, scan_details, scan_parameters)

        if scan_details.scan_status == consts.SCAN_STATUS_ERROR:
            raise custom_exceptions.ScanAsyncError(
                f'Error occurred while trying to scan zip file. {scan_details.message}'
            )

        time.sleep(consts.SCAN_POLLING_WAIT_INTERVAL_IN_SECONDS)

    raise custom_exceptions.ScanAsyncError(f'Failed to complete scan after {polling_timeout} seconds')


def report_scan_status(
    cycode_client: 'ScanClient',
    scan_type: str,
    scan_id: str,
    scan_completed: bool,
    output_detections_count: int,
    all_detections_count: int,
    files_to_scan_count: int,
    zip_size: int,
    command_scan_type: str,
    error_message: Optional[str],
) -> None:
    try:
        end_scan_time = time.time()
        scan_status = {
            'zip_size': zip_size,
            'execution_time': int(end_scan_time - start_scan_time),
            'output_detections_count': output_detections_count,
            'all_detections_count': all_detections_count,
            'scannable_files_count': files_to_scan_count,
            'status': 'Completed' if scan_completed else 'Error',
            'scan_command_type': command_scan_type,
            'operation_system': platform(),
            'error_message': error_message,
            'scan_type': scan_type,
        }

        cycode_client.report_scan_status(scan_type, scan_id, scan_status)
    except Exception as e:
        logger.debug('Failed to report scan status', exc_info=e)
