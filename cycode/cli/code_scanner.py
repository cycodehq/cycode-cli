import json
import logging
import os
import sys
import time
import traceback
from platform import platform
from typing import TYPE_CHECKING, Callable, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

import click
from git import NULL_TREE, InvalidGitRepositoryError, Repo

from cycode.cli import consts
from cycode.cli.ci_integrations import get_commit_range
from cycode.cli.config import configuration_manager
from cycode.cli.exceptions import custom_exceptions
from cycode.cli.files_collector.excluder import exclude_irrelevant_documents_to_scan
from cycode.cli.files_collector.models.in_memory_zip import InMemoryZip
from cycode.cli.files_collector.path_documents import get_relevant_document
from cycode.cli.files_collector.repository_documents import (
    calculate_pre_receive_commit_range,
    get_commit_range_modified_documents,
    get_diff_file_content,
    get_diff_file_path,
    get_git_repository_tree_file_entries,
    get_pre_commit_modified_documents,
    parse_commit_range,
)
from cycode.cli.files_collector.sca import sca_code_scanner
from cycode.cli.files_collector.sca.sca_code_scanner import perform_pre_scan_documents_actions
from cycode.cli.files_collector.zip_documents import zip_documents
from cycode.cli.models import CliError, CliErrors, Document, DocumentDetections, LocalScanResult, Severity
from cycode.cli.printers import ConsolePrinter
from cycode.cli.utils import scan_utils
from cycode.cli.utils.path_utils import (
    get_path_by_os,
)
from cycode.cli.utils.progress_bar import ScanProgressBarSection
from cycode.cli.utils.scan_batch import run_parallel_batched_scan
from cycode.cli.utils.scan_utils import set_issue_detected
from cycode.cli.utils.task_timer import TimeoutAfter
from cycode.cyclient import logger
from cycode.cyclient.config import set_logging_level
from cycode.cyclient.models import Detection, DetectionSchema, DetectionsPerFile, ZippedFileScanResult

if TYPE_CHECKING:
    from cycode.cyclient.models import ScanDetailsResponse
    from cycode.cyclient.scan_client import ScanClient

start_scan_time = time.time()


@click.command(short_help='Scan the git repository including its history.')
@click.argument('path', nargs=1, type=click.Path(exists=True, resolve_path=True), required=True)
@click.option(
    '--branch',
    '-b',
    default=None,
    help='Branch to scan, if not set scanning the default branch',
    type=str,
    required=False,
)
@click.pass_context
def scan_repository(context: click.Context, path: str, branch: str) -> None:
    try:
        logger.debug('Starting repository scan process, %s', {'path': path, 'branch': branch})

        scan_type = context.obj['scan_type']
        monitor = context.obj.get('monitor')
        if monitor and scan_type != consts.SCA_SCAN_TYPE:
            raise click.ClickException('Monitor flag is currently supported for SCA scan type only')

        progress_bar = context.obj['progress_bar']
        progress_bar.start()

        file_entries = list(get_git_repository_tree_file_entries(path, branch))
        progress_bar.set_section_length(ScanProgressBarSection.PREPARE_LOCAL_FILES, len(file_entries))

        documents_to_scan = []
        for file in file_entries:
            # FIXME(MarshalX): probably file could be tree or submodule too. we expect blob only
            progress_bar.update(ScanProgressBarSection.PREPARE_LOCAL_FILES)

            file_path = file.path if monitor else get_path_by_os(os.path.join(path, file.path))
            documents_to_scan.append(Document(file_path, file.data_stream.read().decode('UTF-8', errors='replace')))

        documents_to_scan = exclude_irrelevant_documents_to_scan(scan_type, documents_to_scan)

        perform_pre_scan_documents_actions(context, scan_type, documents_to_scan, is_git_diff=False)

        logger.debug('Found all relevant files for scanning %s', {'path': path, 'branch': branch})
        scan_documents(
            context, documents_to_scan, is_git_diff=False, scan_parameters=get_scan_parameters(context, path)
        )
    except Exception as e:
        _handle_exception(context, e)


@click.command(short_help='Scan all the commits history in this git repository.')
@click.argument('path', nargs=1, type=click.Path(exists=True, resolve_path=True), required=True)
@click.option(
    '--commit_range',
    '-r',
    help='Scan a commit range in this git repository, by default cycode scans all commit history (example: HEAD~1)',
    type=click.STRING,
    default='--all',
    required=False,
)
@click.pass_context
def scan_repository_commit_history(context: click.Context, path: str, commit_range: str) -> None:
    try:
        logger.debug('Starting commit history scan process, %s', {'path': path, 'commit_range': commit_range})
        scan_commit_range(context, path=path, commit_range=commit_range)
    except Exception as e:
        _handle_exception(context, e)


def scan_commit_range(
    context: click.Context, path: str, commit_range: str, max_commits_count: Optional[int] = None
) -> None:
    scan_type = context.obj['scan_type']

    progress_bar = context.obj['progress_bar']
    progress_bar.start()

    if scan_type not in consts.COMMIT_RANGE_SCAN_SUPPORTED_SCAN_TYPES:
        raise click.ClickException(f'Commit range scanning for {str.upper(scan_type)} is not supported')

    if scan_type == consts.SCA_SCAN_TYPE:
        return scan_sca_commit_range(context, path, commit_range)

    documents_to_scan = []
    commit_ids_to_scan = []

    repo = Repo(path)
    total_commits_count = int(repo.git.rev_list('--count', commit_range))
    logger.debug(f'Calculating diffs for {total_commits_count} commits in the commit range {commit_range}')

    progress_bar.set_section_length(ScanProgressBarSection.PREPARE_LOCAL_FILES, total_commits_count)

    scanned_commits_count = 0
    for commit in repo.iter_commits(rev=commit_range):
        if _does_reach_to_max_commits_to_scan_limit(commit_ids_to_scan, max_commits_count):
            logger.debug(f'Reached to max commits to scan count. Going to scan only {max_commits_count} last commits')
            progress_bar.update(ScanProgressBarSection.PREPARE_LOCAL_FILES, total_commits_count - scanned_commits_count)
            break

        progress_bar.update(ScanProgressBarSection.PREPARE_LOCAL_FILES)

        commit_id = commit.hexsha
        commit_ids_to_scan.append(commit_id)
        parent = commit.parents[0] if commit.parents else NULL_TREE
        diff = commit.diff(parent, create_patch=True, R=True)
        commit_documents_to_scan = []
        for blob in diff:
            blob_path = get_path_by_os(os.path.join(path, get_diff_file_path(blob)))
            commit_documents_to_scan.append(
                Document(
                    path=blob_path,
                    content=blob.diff.decode('UTF-8', errors='replace'),
                    is_git_diff_format=True,
                    unique_id=commit_id,
                )
            )

        logger.debug(
            'Found all relevant files in commit %s',
            {'path': path, 'commit_range': commit_range, 'commit_id': commit_id},
        )

        documents_to_scan.extend(exclude_irrelevant_documents_to_scan(scan_type, commit_documents_to_scan))
        scanned_commits_count += 1

    logger.debug('List of commit ids to scan, %s', {'commit_ids': commit_ids_to_scan})
    logger.debug('Starting to scan commit range (It may take a few minutes)')

    scan_documents(context, documents_to_scan, is_git_diff=True, is_commit_range=True)
    return None


@click.command(
    short_help='Execute scan in a CI environment which relies on the '
    'CYCODE_TOKEN and CYCODE_REPO_LOCATION environment variables'
)
@click.pass_context
def scan_ci(context: click.Context) -> None:
    scan_commit_range(context, path=os.getcwd(), commit_range=get_commit_range())


@click.command(short_help='Scan the files in the path provided in the command.')
@click.argument('path', nargs=1, type=click.Path(exists=True, resolve_path=True), required=True)
@click.pass_context
def scan_path(context: click.Context, path: str) -> None:
    progress_bar = context.obj['progress_bar']
    progress_bar.start()

    logger.debug('Starting path scan process, %s', {'path': path})
    scan_disk_files(context, path)


@click.command(short_help='Use this command to scan any content that was not committed yet.')
@click.argument('ignored_args', nargs=-1, type=click.UNPROCESSED)
@click.pass_context
def pre_commit_scan(context: click.Context, ignored_args: List[str]) -> None:
    scan_type = context.obj['scan_type']

    progress_bar = context.obj['progress_bar']
    progress_bar.start()

    if scan_type == consts.SCA_SCAN_TYPE:
        scan_sca_pre_commit(context)
        return

    diff_files = Repo(os.getcwd()).index.diff('HEAD', create_patch=True, R=True)

    progress_bar.set_section_length(ScanProgressBarSection.PREPARE_LOCAL_FILES, len(diff_files))

    documents_to_scan = []
    for file in diff_files:
        progress_bar.update(ScanProgressBarSection.PREPARE_LOCAL_FILES)
        documents_to_scan.append(Document(get_path_by_os(get_diff_file_path(file)), get_diff_file_content(file)))

    documents_to_scan = exclude_irrelevant_documents_to_scan(scan_type, documents_to_scan)
    scan_documents(context, documents_to_scan, is_git_diff=True)


@click.command(short_help='Use this command to scan commits on the server side before pushing them to the repository.')
@click.argument('ignored_args', nargs=-1, type=click.UNPROCESSED)
@click.pass_context
def pre_receive_scan(context: click.Context, ignored_args: List[str]) -> None:
    try:
        scan_type = context.obj['scan_type']
        if scan_type != consts.SECRET_SCAN_TYPE:
            raise click.ClickException(f'Commit range scanning for {scan_type.upper()} is not supported')

        if should_skip_pre_receive_scan():
            logger.info(
                'A scan has been skipped as per your request.'
                ' Please note that this may leave your system vulnerable to secrets that have not been detected'
            )
            return

        if is_verbose_mode_requested_in_pre_receive_scan():
            enable_verbose_mode(context)
            logger.debug('Verbose mode enabled, all log levels will be displayed')

        command_scan_type = context.info_name
        timeout = configuration_manager.get_pre_receive_command_timeout(command_scan_type)
        with TimeoutAfter(timeout):
            if scan_type not in consts.COMMIT_RANGE_SCAN_SUPPORTED_SCAN_TYPES:
                raise click.ClickException(f'Commit range scanning for {scan_type.upper()} is not supported')

            branch_update_details = parse_pre_receive_input()
            commit_range = calculate_pre_receive_commit_range(branch_update_details)
            if not commit_range:
                logger.info(
                    'No new commits found for pushed branch, %s', {'branch_update_details': branch_update_details}
                )
                return

            max_commits_to_scan = configuration_manager.get_pre_receive_max_commits_to_scan_count(command_scan_type)
            scan_commit_range(context, os.getcwd(), commit_range, max_commits_count=max_commits_to_scan)
            perform_post_pre_receive_scan_actions(context)
    except Exception as e:
        _handle_exception(context, e)


def scan_sca_pre_commit(context: click.Context) -> None:
    scan_type = context.obj['scan_type']
    scan_parameters = get_default_scan_parameters(context)
    git_head_documents, pre_committed_documents = get_pre_commit_modified_documents(
        context.obj['progress_bar'], ScanProgressBarSection.PREPARE_LOCAL_FILES
    )
    git_head_documents = exclude_irrelevant_documents_to_scan(scan_type, git_head_documents)
    pre_committed_documents = exclude_irrelevant_documents_to_scan(scan_type, pre_committed_documents)
    sca_code_scanner.perform_pre_hook_range_scan_actions(git_head_documents, pre_committed_documents)
    scan_commit_range_documents(
        context,
        git_head_documents,
        pre_committed_documents,
        scan_parameters,
        configuration_manager.get_sca_pre_commit_timeout_in_seconds(),
    )


def scan_sca_commit_range(context: click.Context, path: str, commit_range: str) -> None:
    scan_type = context.obj['scan_type']
    progress_bar = context.obj['progress_bar']

    scan_parameters = get_scan_parameters(context, path)
    from_commit_rev, to_commit_rev = parse_commit_range(commit_range, path)
    from_commit_documents, to_commit_documents = get_commit_range_modified_documents(
        progress_bar, ScanProgressBarSection.PREPARE_LOCAL_FILES, path, from_commit_rev, to_commit_rev
    )
    from_commit_documents = exclude_irrelevant_documents_to_scan(scan_type, from_commit_documents)
    to_commit_documents = exclude_irrelevant_documents_to_scan(scan_type, to_commit_documents)
    sca_code_scanner.perform_pre_commit_range_scan_actions(
        path, from_commit_documents, from_commit_rev, to_commit_documents, to_commit_rev
    )

    scan_commit_range_documents(context, from_commit_documents, to_commit_documents, scan_parameters=scan_parameters)


def scan_disk_files(context: click.Context, path: str) -> None:
    scan_parameters = get_scan_parameters(context, path)
    scan_type = context.obj['scan_type']
    progress_bar = context.obj['progress_bar']

    try:
        documents = get_relevant_document(progress_bar, ScanProgressBarSection.PREPARE_LOCAL_FILES, scan_type, path)
        perform_pre_scan_documents_actions(context, scan_type, documents)
        scan_documents(context, documents, scan_parameters=scan_parameters)
    except Exception as e:
        _handle_exception(context, e)


def set_issue_detected_by_scan_results(context: click.Context, scan_results: List[LocalScanResult]) -> None:
    set_issue_detected(context, any(scan_result.issue_detected for scan_result in scan_results))


def _get_scan_documents_thread_func(
    context: click.Context, is_git_diff: bool, is_commit_range: bool, scan_parameters: dict
) -> Callable[[List[Document]], Tuple[str, CliError, LocalScanResult]]:
    cycode_client = context.obj['client']
    scan_type = context.obj['scan_type']
    severity_threshold = context.obj['severity_threshold']
    command_scan_type = context.info_name

    def _scan_batch_thread_func(batch: List[Document]) -> Tuple[str, CliError, LocalScanResult]:
        local_scan_result = error = error_message = None
        detections_count = relevant_detections_count = zip_file_size = 0

        scan_id = str(_get_scan_id())
        scan_completed = False

        try:
            logger.debug('Preparing local files, %s', {'batch_size': len(batch)})
            zipped_documents = zip_documents(scan_type, batch)
            zip_file_size = zipped_documents.size

            scan_result = perform_scan(
                cycode_client, zipped_documents, scan_type, scan_id, is_git_diff, is_commit_range, scan_parameters
            )

            local_scan_result = create_local_scan_result(
                scan_result, batch, command_scan_type, scan_type, severity_threshold
            )

            scan_completed = True
        except Exception as e:
            error = _handle_exception(context, e, return_exception=True)
            error_message = str(e)

        if local_scan_result:
            detections_count = local_scan_result.detections_count
            relevant_detections_count = local_scan_result.relevant_detections_count
            scan_id = local_scan_result.scan_id

        logger.debug(
            'Finished scan process, %s',
            {
                'all_violations_count': detections_count,
                'relevant_violations_count': relevant_detections_count,
                'scan_id': scan_id,
                'zip_file_size': zip_file_size,
            },
        )
        _report_scan_status(
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
    context: click.Context,
    documents_to_scan: List[Document],
    is_git_diff: bool = False,
    is_commit_range: bool = False,
    scan_parameters: Optional[dict] = None,
) -> None:
    progress_bar = context.obj['progress_bar']

    if not documents_to_scan:
        progress_bar.stop()
        ConsolePrinter(context).print_error(
            CliError(
                code='no_relevant_files',
                message='Error: The scan could not be completed - relevant files to scan are not found.',
            )
        )
        return

    scan_batch_thread_func = _get_scan_documents_thread_func(context, is_git_diff, is_commit_range, scan_parameters)
    errors, local_scan_results = run_parallel_batched_scan(
        scan_batch_thread_func, documents_to_scan, progress_bar=progress_bar
    )

    progress_bar.set_section_length(ScanProgressBarSection.GENERATE_REPORT, 1)
    progress_bar.update(ScanProgressBarSection.GENERATE_REPORT)
    progress_bar.stop()

    set_issue_detected_by_scan_results(context, local_scan_results)
    print_results(context, local_scan_results, errors)


def scan_commit_range_documents(
    context: click.Context,
    from_documents_to_scan: List[Document],
    to_documents_to_scan: List[Document],
    scan_parameters: Optional[dict] = None,
    timeout: Optional[int] = None,
) -> None:
    cycode_client = context.obj['client']
    scan_type = context.obj['scan_type']
    severity_threshold = context.obj['severity_threshold']
    scan_command_type = context.info_name
    progress_bar = context.obj['progress_bar']

    local_scan_result = error_message = None
    scan_completed = False
    scan_id = str(_get_scan_id())

    from_commit_zipped_documents = InMemoryZip()
    to_commit_zipped_documents = InMemoryZip()

    try:
        progress_bar.set_section_length(ScanProgressBarSection.SCAN, 1)

        scan_result = init_default_scan_result(scan_id)
        if should_scan_documents(from_documents_to_scan, to_documents_to_scan):
            logger.debug('Preparing from-commit zip')
            from_commit_zipped_documents = zip_documents(scan_type, from_documents_to_scan)

            logger.debug('Preparing to-commit zip')
            to_commit_zipped_documents = zip_documents(scan_type, to_documents_to_scan)

            scan_result = perform_commit_range_scan_async(
                cycode_client,
                from_commit_zipped_documents,
                to_commit_zipped_documents,
                scan_type,
                scan_parameters,
                timeout,
            )

        progress_bar.update(ScanProgressBarSection.SCAN)
        progress_bar.set_section_length(ScanProgressBarSection.GENERATE_REPORT, 1)

        local_scan_result = create_local_scan_result(
            scan_result, to_documents_to_scan, scan_command_type, scan_type, severity_threshold
        )
        set_issue_detected_by_scan_results(context, [local_scan_result])

        progress_bar.update(ScanProgressBarSection.GENERATE_REPORT)
        progress_bar.stop()

        # errors will be handled with try-except block; printing will not occur on errors
        print_results(context, [local_scan_result])

        scan_completed = True
    except Exception as e:
        _handle_exception(context, e)
        error_message = str(e)

    zip_file_size = from_commit_zipped_documents.size + to_commit_zipped_documents.size

    detections_count = relevant_detections_count = 0
    if local_scan_result:
        detections_count = local_scan_result.detections_count
        relevant_detections_count = local_scan_result.relevant_detections_count
        scan_id = local_scan_result.scan_id

    logger.debug(
        'Finished scan process, %s',
        {
            'all_violations_count': detections_count,
            'relevant_violations_count': relevant_detections_count,
            'scan_id': scan_id,
            'zip_file_size': zip_file_size,
        },
    )
    _report_scan_status(
        cycode_client,
        scan_type,
        local_scan_result.scan_id,
        scan_completed,
        local_scan_result.relevant_detections_count,
        local_scan_result.detections_count,
        len(to_documents_to_scan),
        zip_file_size,
        scan_command_type,
        error_message,
    )


def should_scan_documents(from_documents_to_scan: List[Document], to_documents_to_scan: List[Document]) -> bool:
    return len(from_documents_to_scan) > 0 or len(to_documents_to_scan) > 0


def create_local_scan_result(
    scan_result: ZippedFileScanResult,
    documents_to_scan: List[Document],
    command_scan_type: str,
    scan_type: str,
    severity_threshold: str,
) -> LocalScanResult:
    document_detections = get_document_detections(scan_result, documents_to_scan)
    relevant_document_detections_list = exclude_irrelevant_document_detections(
        document_detections, scan_type, command_scan_type, severity_threshold
    )

    detections_count = sum([len(document_detection.detections) for document_detection in document_detections])
    relevant_detections_count = sum(
        [len(document_detections.detections) for document_detections in relevant_document_detections_list]
    )

    return LocalScanResult(
        scan_id=scan_result.scan_id,
        report_url=scan_result.report_url,
        document_detections=relevant_document_detections_list,
        issue_detected=len(relevant_document_detections_list) > 0,
        detections_count=detections_count,
        relevant_detections_count=relevant_detections_count,
    )


def perform_scan(
    cycode_client: 'ScanClient',
    zipped_documents: 'InMemoryZip',
    scan_type: str,
    scan_id: str,
    is_git_diff: bool,
    is_commit_range: bool,
    scan_parameters: dict,
) -> ZippedFileScanResult:
    if scan_type in (consts.SCA_SCAN_TYPE, consts.SAST_SCAN_TYPE):
        return perform_scan_async(cycode_client, zipped_documents, scan_type, scan_parameters)

    if is_commit_range:
        return cycode_client.commit_range_zipped_file_scan(scan_type, zipped_documents, scan_id)

    return cycode_client.zipped_file_scan(scan_type, zipped_documents, scan_id, scan_parameters, is_git_diff)


def perform_scan_async(
    cycode_client: 'ScanClient', zipped_documents: 'InMemoryZip', scan_type: str, scan_parameters: dict
) -> ZippedFileScanResult:
    scan_async_result = cycode_client.zipped_file_scan_async(zipped_documents, scan_type, scan_parameters)
    logger.debug('scan request has been triggered successfully, scan id: %s', scan_async_result.scan_id)

    return poll_scan_results(cycode_client, scan_async_result.scan_id)


def perform_commit_range_scan_async(
    cycode_client: 'ScanClient',
    from_commit_zipped_documents: 'InMemoryZip',
    to_commit_zipped_documents: 'InMemoryZip',
    scan_type: str,
    scan_parameters: dict,
    timeout: Optional[int] = None,
) -> ZippedFileScanResult:
    scan_async_result = cycode_client.multiple_zipped_file_scan_async(
        from_commit_zipped_documents, to_commit_zipped_documents, scan_type, scan_parameters
    )

    logger.debug('scan request has been triggered successfully, scan id: %s', scan_async_result.scan_id)
    return poll_scan_results(cycode_client, scan_async_result.scan_id, timeout)


def poll_scan_results(
    cycode_client: 'ScanClient', scan_id: str, polling_timeout: Optional[int] = None
) -> ZippedFileScanResult:
    if polling_timeout is None:
        polling_timeout = configuration_manager.get_scan_polling_timeout_in_seconds()

    last_scan_update_at = None
    end_polling_time = time.time() + polling_timeout

    while time.time() < end_polling_time:
        scan_details = cycode_client.get_scan_details(scan_id)

        if scan_details.scan_update_at is not None and scan_details.scan_update_at != last_scan_update_at:
            last_scan_update_at = scan_details.scan_update_at
            print_debug_scan_details(scan_details)

        if scan_details.scan_status == consts.SCAN_STATUS_COMPLETED:
            return _get_scan_result(cycode_client, scan_id, scan_details)

        if scan_details.scan_status == consts.SCAN_STATUS_ERROR:
            raise custom_exceptions.ScanAsyncError(
                f'Error occurred while trying to scan zip file. {scan_details.message}'
            )

        time.sleep(consts.SCAN_POLLING_WAIT_INTERVAL_IN_SECONDS)

    raise custom_exceptions.ScanAsyncError(f'Failed to complete scan after {polling_timeout} seconds')


def print_debug_scan_details(scan_details_response: 'ScanDetailsResponse') -> None:
    logger.debug(f'Scan update: (scan_id: {scan_details_response.id})')
    logger.debug(f'Scan status: {scan_details_response.scan_status}')

    if scan_details_response.message:
        logger.debug(f'Scan message: {scan_details_response.message}')


def print_results(
    context: click.Context, local_scan_results: List[LocalScanResult], errors: Optional[Dict[str, 'CliError']] = None
) -> None:
    printer = ConsolePrinter(context)
    printer.print_scan_results(local_scan_results, errors)


def get_document_detections(
    scan_result: ZippedFileScanResult, documents_to_scan: List[Document]
) -> List[DocumentDetections]:
    logger.debug('Get document detections')

    document_detections = []
    for detections_per_file in scan_result.detections_per_file:
        file_name = get_path_by_os(detections_per_file.file_name)
        commit_id = detections_per_file.commit_id

        logger.debug('Going to find document of violated file, %s', {'file_name': file_name, 'commit_id': commit_id})

        document = _get_document_by_file_name(documents_to_scan, file_name, commit_id)
        document_detections.append(DocumentDetections(document=document, detections=detections_per_file.detections))

    return document_detections


def exclude_irrelevant_document_detections(
    document_detections_list: List[DocumentDetections], scan_type: str, command_scan_type: str, severity_threshold: str
) -> List[DocumentDetections]:
    relevant_document_detections_list = []
    for document_detections in document_detections_list:
        relevant_detections = exclude_irrelevant_detections(
            document_detections.detections, scan_type, command_scan_type, severity_threshold
        )
        if relevant_detections:
            relevant_document_detections_list.append(
                DocumentDetections(document=document_detections.document, detections=relevant_detections)
            )

    return relevant_document_detections_list


def parse_pre_receive_input() -> str:
    """
    Parsing input to pushed branch update details

    Example input:
    old_value new_value refname
    -----------------------------------------------
    0000000000000000000000000000000000000000 9cf90954ef26e7c58284f8ebf7dcd0fcf711152a refs/heads/main
    973a96d3e925b65941f7c47fa16129f1577d499f 0000000000000000000000000000000000000000 refs/heads/feature-branch
    59564ef68745bca38c42fc57a7822efd519a6bd9 3378e52dcfa47fb11ce3a4a520bea5f85d5d0bf3 refs/heads/develop

    :return: first branch update details (input's first line)
    """
    # FIXME(MarshalX): this blocks main thread forever if called outside of pre-receive hook
    pre_receive_input = sys.stdin.read().strip()
    if not pre_receive_input:
        raise ValueError(
            'Pre receive input was not found. Make sure that you are using this command only in pre-receive hook'
        )

    # each line represents a branch update request, handle the first one only
    # TODO(MichalBor): support case of multiple update branch requests
    return pre_receive_input.splitlines()[0]


def get_default_scan_parameters(context: click.Context) -> dict:
    return {
        'monitor': context.obj.get('monitor'),
        'report': context.obj.get('report'),
        'package_vulnerabilities': context.obj.get('package-vulnerabilities'),
        'license_compliance': context.obj.get('license-compliance'),
    }


def get_scan_parameters(context: click.Context, path: str) -> dict:
    scan_parameters = get_default_scan_parameters(context)
    remote_url = try_get_git_remote_url(path)
    if remote_url:
        # TODO(MarshalX): remove hardcode
        context.obj['remote_url'] = remote_url
        scan_parameters.update(remote_url)
    return scan_parameters


def try_get_git_remote_url(path: str) -> Optional[dict]:
    try:
        git_remote_url = Repo(path).remotes[0].config_reader.get('url')
        return {
            'remote_url': git_remote_url,
        }
    except Exception as e:
        logger.debug('Failed to get git remote URL. %s', {'exception_message': str(e)})
        return None


def exclude_irrelevant_detections(
    detections: List[Detection], scan_type: str, command_scan_type: str, severity_threshold: str
) -> List[Detection]:
    relevant_detections = _exclude_detections_by_exclusions_configuration(detections, scan_type)
    relevant_detections = _exclude_detections_by_scan_type(relevant_detections, scan_type, command_scan_type)
    return _exclude_detections_by_severity(relevant_detections, scan_type, severity_threshold)


def _exclude_detections_by_severity(
    detections: List[Detection], scan_type: str, severity_threshold: str
) -> List[Detection]:
    if scan_type != consts.SCA_SCAN_TYPE or severity_threshold is None:
        return detections

    relevant_detections = []
    for detection in detections:
        severity = detection.detection_details.get('advisory_severity')
        if _does_severity_match_severity_threshold(severity, severity_threshold):
            relevant_detections.append(detection)

    return relevant_detections


def _exclude_detections_by_scan_type(
    detections: List[Detection], scan_type: str, command_scan_type: str
) -> List[Detection]:
    if command_scan_type == consts.PRE_COMMIT_COMMAND_SCAN_TYPE:
        return exclude_detections_in_deleted_lines(detections)

    exclude_in_deleted_lines = configuration_manager.get_should_exclude_detections_in_deleted_lines(command_scan_type)
    if (
        command_scan_type in consts.COMMIT_RANGE_BASED_COMMAND_SCAN_TYPES
        and scan_type == consts.SECRET_SCAN_TYPE
        and exclude_in_deleted_lines
    ):
        return exclude_detections_in_deleted_lines(detections)

    return detections


def exclude_detections_in_deleted_lines(detections: List[Detection]) -> List[Detection]:
    return [detection for detection in detections if detection.detection_details.get('line_type') != 'Removed']


def _exclude_detections_by_exclusions_configuration(detections: List[Detection], scan_type: str) -> List[Detection]:
    exclusions = configuration_manager.get_exclusions_by_scan_type(scan_type)
    return [detection for detection in detections if not _should_exclude_detection(detection, exclusions)]


def _should_exclude_detection(detection: Detection, exclusions: Dict) -> bool:
    exclusions_by_value = exclusions.get(consts.EXCLUSIONS_BY_VALUE_SECTION_NAME, [])
    if _is_detection_sha_configured_in_exclusions(detection, exclusions_by_value):
        logger.debug(
            'Going to ignore violations because is in the values to ignore list, %s',
            {'sha': detection.detection_details.get('sha512', '')},
        )
        return True

    exclusions_by_sha = exclusions.get(consts.EXCLUSIONS_BY_SHA_SECTION_NAME, [])
    if _is_detection_sha_configured_in_exclusions(detection, exclusions_by_sha):
        logger.debug(
            'Going to ignore violations because is in the shas to ignore list, %s',
            {'sha': detection.detection_details.get('sha512', '')},
        )
        return True

    exclusions_by_rule = exclusions.get(consts.EXCLUSIONS_BY_RULE_SECTION_NAME, [])
    if exclusions_by_rule:
        detection_rule = detection.detection_rule_id
        if detection_rule in exclusions_by_rule:
            logger.debug(
                'Going to ignore violations because is in the shas to ignore list, %s',
                {'detection_rule': detection_rule},
            )
            return True

    exclusions_by_package = exclusions.get(consts.EXCLUSIONS_BY_PACKAGE_SECTION_NAME, [])
    if exclusions_by_package:
        package = _get_package_name(detection)
        if package in exclusions_by_package:
            logger.debug(
                'Going to ignore violations because is in the packages to ignore list, %s', {'package': package}
            )
            return True

    return False


def _is_detection_sha_configured_in_exclusions(detection: Detection, exclusions: List[str]) -> bool:
    detection_sha = detection.detection_details.get('sha512', '')
    return detection_sha in exclusions


def _get_package_name(detection: Detection) -> str:
    package_name = detection.detection_details.get('vulnerable_component', '')
    package_version = detection.detection_details.get('vulnerable_component_version', '')

    if package_name == '':
        package_name = detection.detection_details.get('package_name', '')
        package_version = detection.detection_details.get('package_version', '')

    return f'{package_name}@{package_version}'


def _get_document_by_file_name(
    documents: List[Document], file_name: str, unique_id: Optional[str] = None
) -> Optional[Document]:
    for document in documents:
        if _normalize_file_path(document.path) == _normalize_file_path(file_name) and document.unique_id == unique_id:
            return document

    return None


def _handle_exception(context: click.Context, e: Exception, *, return_exception: bool = False) -> Optional[CliError]:
    context.obj['did_fail'] = True

    if context.obj['verbose']:
        click.secho(f'Error: {traceback.format_exc()}', fg='red')

    errors: CliErrors = {
        custom_exceptions.NetworkError: CliError(
            soft_fail=True,
            code='cycode_error',
            message='Cycode was unable to complete this scan. '
            'Please try again by executing the `cycode scan` command',
        ),
        custom_exceptions.ScanAsyncError: CliError(
            soft_fail=True,
            code='scan_error',
            message='Cycode was unable to complete this scan. '
            'Please try again by executing the `cycode scan` command',
        ),
        custom_exceptions.HttpUnauthorizedError: CliError(
            soft_fail=True,
            code='auth_error',
            message='Unable to authenticate to Cycode, your token is either invalid or has expired. '
            'Please re-generate your token and reconfigure it by running the `cycode configure` command',
        ),
        custom_exceptions.ZipTooLargeError: CliError(
            soft_fail=True,
            code='zip_too_large_error',
            message='The path you attempted to scan exceeds the current maximum scanning size cap (10MB). '
            'Please try ignoring irrelevant paths using the `cycode ignore --by-path` command '
            'and execute the scan again',
        ),
        custom_exceptions.TfplanKeyError: CliError(
            soft_fail=True,
            code='key_error',
            message=f'\n{e!s}\n'
            'A crucial field is missing in your terraform plan file. '
            'Please make sure that your file is well formed '
            'and execute the scan again',
        ),
        InvalidGitRepositoryError: CliError(
            soft_fail=False,
            code='invalid_git_error',
            message='The path you supplied does not correlate to a git repository. '
            'If you still wish to scan this path, use: `cycode scan path <path>`',
        ),
    }

    if type(e) in errors:
        error = errors[type(e)]

        if error.soft_fail is True:
            context.obj['soft_fail'] = True

        if return_exception:
            return error

        ConsolePrinter(context).print_error(error)
        return None

    if return_exception:
        return CliError(code='unknown_error', message=str(e))

    if isinstance(e, click.ClickException):
        raise e

    raise click.ClickException(str(e))


def _report_scan_status(
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
        logger.debug('Failed to report scan status, %s', {'exception_message': str(e)})


def _get_scan_id() -> UUID:
    return uuid4()


def _does_severity_match_severity_threshold(severity: str, severity_threshold: str) -> bool:
    detection_severity_value = Severity.try_get_value(severity)
    if detection_severity_value is None:
        return True

    return detection_severity_value >= Severity.try_get_value(severity_threshold)


def _get_scan_result(
    cycode_client: 'ScanClient', scan_id: str, scan_details: 'ScanDetailsResponse'
) -> ZippedFileScanResult:
    if not scan_details.detections_count:
        return init_default_scan_result(scan_id, scan_details.metadata)

    wait_for_detections_creation(cycode_client, scan_id, scan_details.detections_count)

    scan_detections = cycode_client.get_scan_detections(scan_id)
    return ZippedFileScanResult(
        did_detect=True,
        detections_per_file=_map_detections_per_file(scan_detections),
        scan_id=scan_id,
        report_url=_try_get_report_url(scan_details.metadata),
    )


def init_default_scan_result(scan_id: str, scan_metadata: Optional[str] = None) -> ZippedFileScanResult:
    return ZippedFileScanResult(
        did_detect=False, detections_per_file=[], scan_id=scan_id, report_url=_try_get_report_url(scan_metadata)
    )


def _try_get_report_url(metadata_json: Optional[str]) -> Optional[str]:
    if metadata_json is None:
        return None

    try:
        metadata_json = json.loads(metadata_json)
        return metadata_json.get('report_url')
    except json.JSONDecodeError:
        return None


def wait_for_detections_creation(cycode_client: 'ScanClient', scan_id: str, expected_detections_count: int) -> None:
    logger.debug('Waiting for detections to be created')

    scan_persisted_detections_count = 0
    polling_timeout = consts.DETECTIONS_COUNT_VERIFICATION_TIMEOUT_IN_SECONDS
    end_polling_time = time.time() + polling_timeout

    while time.time() < end_polling_time:
        scan_persisted_detections_count = cycode_client.get_scan_detections_count(scan_id)
        logger.debug(
            f'Excepted {expected_detections_count} detections, got {scan_persisted_detections_count} detections '
            f'({expected_detections_count - scan_persisted_detections_count} more; '
            f'{round(end_polling_time - time.time())} seconds left)'
        )
        if scan_persisted_detections_count == expected_detections_count:
            return

        time.sleep(consts.DETECTIONS_COUNT_VERIFICATION_WAIT_INTERVAL_IN_SECONDS)

    logger.debug(f'{scan_persisted_detections_count} detections has been created')
    raise custom_exceptions.ScanAsyncError(
        f'Failed to wait for detections to be created after {polling_timeout} seconds'
    )


def _map_detections_per_file(detections: List[dict]) -> List[DetectionsPerFile]:
    detections_per_files = {}
    for detection in detections:
        try:
            detection['message'] = detection['correlation_message']
            file_name = _get_file_name_from_detection(detection)
            if file_name is None:
                logger.debug('file name is missing from detection with id %s', detection.get('id'))
                continue
            if detections_per_files.get(file_name) is None:
                detections_per_files[file_name] = [DetectionSchema().load(detection)]
            else:
                detections_per_files[file_name].append(DetectionSchema().load(detection))
        except Exception as e:
            logger.debug('Failed to parse detection: %s', str(e))
            continue

    return [
        DetectionsPerFile(file_name=file_name, detections=file_detections)
        for file_name, file_detections in detections_per_files.items()
    ]


def _get_file_name_from_detection(detection: dict) -> str:
    if detection['category'] == 'SAST':
        return detection['detection_details']['file_path']

    return detection['detection_details']['file_name']


def _does_reach_to_max_commits_to_scan_limit(commit_ids: List[str], max_commits_count: Optional[int]) -> bool:
    if max_commits_count is None:
        return False

    return len(commit_ids) >= max_commits_count


def _normalize_file_path(path: str) -> str:
    if path.startswith('/'):
        return path[1:]
    if path.startswith('./'):
        return path[2:]
    return path


def perform_post_pre_receive_scan_actions(context: click.Context) -> None:
    if scan_utils.is_scan_failed(context):
        click.echo(consts.PRE_RECEIVE_REMEDIATION_MESSAGE)


def enable_verbose_mode(context: click.Context) -> None:
    context.obj['verbose'] = True
    set_logging_level(logging.DEBUG)


def is_verbose_mode_requested_in_pre_receive_scan() -> bool:
    return does_git_push_option_have_value(consts.VERBOSE_SCAN_FLAG)


def should_skip_pre_receive_scan() -> bool:
    return does_git_push_option_have_value(consts.SKIP_SCAN_FLAG)


def does_git_push_option_have_value(value: str) -> bool:
    option_count_env_value = os.getenv(consts.GIT_PUSH_OPTION_COUNT_ENV_VAR_NAME, '')
    option_count = int(option_count_env_value) if option_count_env_value.isdigit() else 0
    return any(os.getenv(f'{consts.GIT_PUSH_OPTION_ENV_VAR_PREFIX}{i}') == value for i in range(option_count))
