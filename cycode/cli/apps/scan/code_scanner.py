import logging
import os
import sys
import time
from platform import platform
from typing import TYPE_CHECKING, Callable, Optional
from uuid import UUID, uuid4

import click
import typer

from cycode.cli import consts
from cycode.cli.cli_types import SeverityOption
from cycode.cli.config import configuration_manager
from cycode.cli.console import console
from cycode.cli.exceptions import custom_exceptions
from cycode.cli.exceptions.handle_scan_errors import handle_scan_exception
from cycode.cli.files_collector.excluder import excluder
from cycode.cli.files_collector.models.in_memory_zip import InMemoryZip
from cycode.cli.files_collector.path_documents import get_relevant_documents
from cycode.cli.files_collector.repository_documents import (
    get_commit_range_modified_documents,
    get_diff_file_path,
    get_pre_commit_modified_documents,
    parse_commit_range,
)
from cycode.cli.files_collector.sca import sca_code_scanner
from cycode.cli.files_collector.sca.sca_code_scanner import perform_pre_scan_documents_actions
from cycode.cli.files_collector.zip_documents import zip_documents
from cycode.cli.models import CliError, Document, DocumentDetections, LocalScanResult
from cycode.cli.utils import scan_utils
from cycode.cli.utils.git_proxy import git_proxy
from cycode.cli.utils.path_utils import get_path_by_os
from cycode.cli.utils.progress_bar import ScanProgressBarSection
from cycode.cli.utils.scan_batch import run_parallel_batched_scan
from cycode.cli.utils.scan_utils import set_issue_detected
from cycode.cli.utils.shell_executor import shell
from cycode.cyclient.models import Detection, DetectionSchema, DetectionsPerFile, ZippedFileScanResult
from cycode.logger import get_logger, set_logging_level

if TYPE_CHECKING:
    from cycode.cyclient.models import ScanDetailsResponse
    from cycode.cyclient.scan_client import ScanClient

start_scan_time = time.time()


logger = get_logger('Code Scanner')


def scan_sca_pre_commit(ctx: typer.Context, repo_path: str) -> None:
    scan_type = ctx.obj['scan_type']
    scan_parameters = get_scan_parameters(ctx)
    git_head_documents, pre_committed_documents = get_pre_commit_modified_documents(
        progress_bar=ctx.obj['progress_bar'],
        progress_bar_section=ScanProgressBarSection.PREPARE_LOCAL_FILES,
        repo_path=repo_path,
    )
    git_head_documents = excluder.exclude_irrelevant_documents_to_scan(scan_type, git_head_documents)
    pre_committed_documents = excluder.exclude_irrelevant_documents_to_scan(scan_type, pre_committed_documents)
    sca_code_scanner.perform_pre_hook_range_scan_actions(repo_path, git_head_documents, pre_committed_documents)
    scan_commit_range_documents(
        ctx,
        git_head_documents,
        pre_committed_documents,
        scan_parameters,
        configuration_manager.get_sca_pre_commit_timeout_in_seconds(),
    )


def scan_sca_commit_range(ctx: typer.Context, path: str, commit_range: str) -> None:
    scan_type = ctx.obj['scan_type']
    progress_bar = ctx.obj['progress_bar']

    scan_parameters = get_scan_parameters(ctx, (path,))
    from_commit_rev, to_commit_rev = parse_commit_range(commit_range, path)
    from_commit_documents, to_commit_documents = get_commit_range_modified_documents(
        progress_bar, ScanProgressBarSection.PREPARE_LOCAL_FILES, path, from_commit_rev, to_commit_rev
    )
    from_commit_documents = excluder.exclude_irrelevant_documents_to_scan(scan_type, from_commit_documents)
    to_commit_documents = excluder.exclude_irrelevant_documents_to_scan(scan_type, to_commit_documents)
    sca_code_scanner.perform_pre_commit_range_scan_actions(
        path, from_commit_documents, from_commit_rev, to_commit_documents, to_commit_rev
    )

    scan_commit_range_documents(ctx, from_commit_documents, to_commit_documents, scan_parameters=scan_parameters)


def scan_disk_files(ctx: typer.Context, paths: tuple[str, ...]) -> None:
    scan_type = ctx.obj['scan_type']
    progress_bar = ctx.obj['progress_bar']

    try:
        documents = get_relevant_documents(progress_bar, ScanProgressBarSection.PREPARE_LOCAL_FILES, scan_type, paths)
        perform_pre_scan_documents_actions(ctx, scan_type, documents)
        scan_documents(ctx, documents, get_scan_parameters(ctx, paths))
    except Exception as e:
        handle_scan_exception(ctx, e)


def set_issue_detected_by_scan_results(ctx: typer.Context, scan_results: list[LocalScanResult]) -> None:
    set_issue_detected(ctx, any(scan_result.issue_detected for scan_result in scan_results))


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


def _enrich_scan_result_with_data_from_detection_rules(
    cycode_client: 'ScanClient', scan_result: ZippedFileScanResult
) -> None:
    detection_rule_ids = set()
    for detections_per_file in scan_result.detections_per_file:
        for detection in detections_per_file.detections:
            detection_rule_ids.add(detection.detection_rule_id)

    detection_rules = cycode_client.get_detection_rules(detection_rule_ids)
    detection_rules_by_id = {detection_rule.detection_rule_id: detection_rule for detection_rule in detection_rules}

    for detections_per_file in scan_result.detections_per_file:
        for detection in detections_per_file.detections:
            detection_rule = detection_rules_by_id.get(detection.detection_rule_id)
            if not detection_rule:
                # we want to make sure that BE returned it. better to not map data instead of failed scan
                continue

            if not detection.severity and detection_rule.classification_data:
                # it's fine to take the first one, because:
                # - for "secrets" and "iac" there is only one classification rule per-detection rule
                # - for "sca" and "sast" we get severity from detection service
                detection.severity = detection_rule.classification_data[0].severity

            # detection_details never was typed properly. so not a problem for now
            detection.detection_details['custom_remediation_guidelines'] = detection_rule.custom_remediation_guidelines
            detection.detection_details['remediation_guidelines'] = detection_rule.remediation_guidelines
            detection.detection_details['description'] = detection_rule.description
            detection.detection_details['policy_display_name'] = detection_rule.display_name


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

        scan_id = str(_generate_unique_id())
        scan_completed = False

        should_use_sync_flow = _should_use_sync_flow(command_scan_type, scan_type, sync_option)

        try:
            logger.debug('Preparing local files, %s', {'batch_files_count': len(batch)})
            zipped_documents = zip_documents(scan_type, batch)
            zip_file_size = zipped_documents.size
            scan_result = perform_scan(
                cycode_client,
                zipped_documents,
                scan_type,
                is_git_diff,
                is_commit_range,
                scan_parameters,
                should_use_sync_flow,
            )

            _enrich_scan_result_with_data_from_detection_rules(cycode_client, scan_result)

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


def scan_commit_range(
    ctx: typer.Context, path: str, commit_range: str, max_commits_count: Optional[int] = None
) -> None:
    scan_type = ctx.obj['scan_type']

    progress_bar = ctx.obj['progress_bar']
    progress_bar.start()

    if scan_type not in consts.COMMIT_RANGE_SCAN_SUPPORTED_SCAN_TYPES:
        raise click.ClickException(f'Commit range scanning for {str.upper(scan_type)} is not supported')

    if scan_type == consts.SCA_SCAN_TYPE:
        return scan_sca_commit_range(ctx, path, commit_range)

    documents_to_scan = []
    commit_ids_to_scan = []

    repo = git_proxy.get_repo(path)
    total_commits_count = int(repo.git.rev_list('--count', commit_range))
    logger.debug('Calculating diffs for %s commits in the commit range %s', total_commits_count, commit_range)

    progress_bar.set_section_length(ScanProgressBarSection.PREPARE_LOCAL_FILES, total_commits_count)

    for scanned_commits_count, commit in enumerate(repo.iter_commits(rev=commit_range)):
        if _does_reach_to_max_commits_to_scan_limit(commit_ids_to_scan, max_commits_count):
            logger.debug('Reached to max commits to scan count. Going to scan only %s last commits', max_commits_count)
            progress_bar.update(ScanProgressBarSection.PREPARE_LOCAL_FILES, total_commits_count - scanned_commits_count)
            break

        progress_bar.update(ScanProgressBarSection.PREPARE_LOCAL_FILES)

        commit_id = commit.hexsha
        commit_ids_to_scan.append(commit_id)
        parent = commit.parents[0] if commit.parents else git_proxy.get_null_tree()
        diff_index = commit.diff(parent, create_patch=True, R=True)
        commit_documents_to_scan = []
        for diff in diff_index:
            commit_documents_to_scan.append(
                Document(
                    path=get_path_by_os(get_diff_file_path(diff)),
                    content=diff.diff.decode('UTF-8', errors='replace'),
                    is_git_diff_format=True,
                    unique_id=commit_id,
                )
            )

        logger.debug(
            'Found all relevant files in commit %s',
            {'path': path, 'commit_range': commit_range, 'commit_id': commit_id},
        )

        documents_to_scan.extend(excluder.exclude_irrelevant_documents_to_scan(scan_type, commit_documents_to_scan))

    logger.debug('List of commit ids to scan, %s', {'commit_ids': commit_ids_to_scan})
    logger.debug('Starting to scan commit range (it may take a few minutes)')

    scan_documents(ctx, documents_to_scan, get_scan_parameters(ctx, (path,)), is_git_diff=True, is_commit_range=True)
    return None


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

    aggregation_report_url = _try_get_aggregation_report_url_if_needed(scan_parameters, ctx.obj['client'], scan_type)
    _set_aggregation_report_url(ctx, aggregation_report_url)

    progress_bar.set_section_length(ScanProgressBarSection.GENERATE_REPORT, 1)
    progress_bar.update(ScanProgressBarSection.GENERATE_REPORT)
    progress_bar.stop()

    set_issue_detected_by_scan_results(ctx, local_scan_results)
    print_results(ctx, local_scan_results, errors)


def scan_commit_range_documents(
    ctx: typer.Context,
    from_documents_to_scan: list[Document],
    to_documents_to_scan: list[Document],
    scan_parameters: Optional[dict] = None,
    timeout: Optional[int] = None,
) -> None:
    """In use by SCA only."""
    cycode_client = ctx.obj['client']
    scan_type = ctx.obj['scan_type']
    severity_threshold = ctx.obj['severity_threshold']
    scan_command_type = ctx.info_name
    progress_bar = ctx.obj['progress_bar']

    local_scan_result = error_message = None
    scan_completed = False
    scan_id = str(_generate_unique_id())
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
        set_issue_detected_by_scan_results(ctx, [local_scan_result])

        progress_bar.update(ScanProgressBarSection.GENERATE_REPORT)
        progress_bar.stop()

        # errors will be handled with try-except block; printing will not occur on errors
        print_results(ctx, [local_scan_result])

        scan_completed = True
    except Exception as e:
        handle_scan_exception(ctx, e)
        error_message = str(e)

    zip_file_size = from_commit_zipped_documents.size + to_commit_zipped_documents.size

    detections_count = relevant_detections_count = 0
    if local_scan_result:
        detections_count = local_scan_result.detections_count
        relevant_detections_count = local_scan_result.relevant_detections_count
        scan_id = local_scan_result.scan_id

    logger.debug(
        'Processing commit range scan results, %s',
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
        len(to_documents_to_scan),
        zip_file_size,
        scan_command_type,
        error_message,
    )


def should_scan_documents(from_documents_to_scan: list[Document], to_documents_to_scan: list[Document]) -> bool:
    return len(from_documents_to_scan) > 0 or len(to_documents_to_scan) > 0


def create_local_scan_result(
    scan_result: ZippedFileScanResult,
    documents_to_scan: list[Document],
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
    is_git_diff: bool,
    is_commit_range: bool,
    scan_parameters: dict,
    should_use_sync_flow: bool = False,
) -> ZippedFileScanResult:
    if should_use_sync_flow:
        # it does not support commit range scans; should_use_sync_flow handles it
        return perform_scan_sync(cycode_client, zipped_documents, scan_type, scan_parameters, is_git_diff)

    return perform_scan_async(cycode_client, zipped_documents, scan_type, scan_parameters, is_commit_range)


def perform_scan_async(
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


def perform_scan_sync(
    cycode_client: 'ScanClient',
    zipped_documents: 'InMemoryZip',
    scan_type: str,
    scan_parameters: dict,
    is_git_diff: bool = False,
) -> ZippedFileScanResult:
    scan_results = cycode_client.zipped_file_scan_sync(zipped_documents, scan_type, scan_parameters, is_git_diff)
    logger.debug('Sync scan request has been triggered successfully, %s', {'scan_id': scan_results.id})
    return ZippedFileScanResult(
        did_detect=True,
        detections_per_file=_map_detections_per_file_and_commit_id(scan_type, scan_results.detection_messages),
        scan_id=scan_results.id,
    )


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

    logger.debug(
        'Async commit range scan request has been triggered successfully, %s', {'scan_id': scan_async_result.scan_id}
    )
    return poll_scan_results(cycode_client, scan_async_result.scan_id, scan_type, scan_parameters, timeout)


def poll_scan_results(
    cycode_client: 'ScanClient',
    scan_id: str,
    scan_type: str,
    scan_parameters: dict,
    polling_timeout: Optional[int] = None,
) -> ZippedFileScanResult:
    if polling_timeout is None:
        polling_timeout = configuration_manager.get_scan_polling_timeout_in_seconds()

    last_scan_update_at = None
    end_polling_time = time.time() + polling_timeout

    while time.time() < end_polling_time:
        scan_details = cycode_client.get_scan_details(scan_type, scan_id)

        if scan_details.scan_update_at is not None and scan_details.scan_update_at != last_scan_update_at:
            last_scan_update_at = scan_details.scan_update_at
            print_debug_scan_details(scan_details)

        if scan_details.scan_status == consts.SCAN_STATUS_COMPLETED:
            return _get_scan_result(cycode_client, scan_type, scan_id, scan_details, scan_parameters)

        if scan_details.scan_status == consts.SCAN_STATUS_ERROR:
            raise custom_exceptions.ScanAsyncError(
                f'Error occurred while trying to scan zip file. {scan_details.message}'
            )

        time.sleep(consts.SCAN_POLLING_WAIT_INTERVAL_IN_SECONDS)

    raise custom_exceptions.ScanAsyncError(f'Failed to complete scan after {polling_timeout} seconds')


def print_debug_scan_details(scan_details_response: 'ScanDetailsResponse') -> None:
    logger.debug(
        'Scan update, %s', {'scan_id': scan_details_response.id, 'scan_status': scan_details_response.scan_status}
    )

    if scan_details_response.message:
        logger.debug('Scan message: %s', scan_details_response.message)


def print_results(
    ctx: typer.Context, local_scan_results: list[LocalScanResult], errors: Optional[dict[str, 'CliError']] = None
) -> None:
    printer = ctx.obj.get('console_printer')
    printer.update_ctx(ctx)
    printer.print_scan_results(local_scan_results, errors)


def get_document_detections(
    scan_result: ZippedFileScanResult, documents_to_scan: list[Document]
) -> list[DocumentDetections]:
    logger.debug('Getting document detections')

    document_detections = []
    for detections_per_file in scan_result.detections_per_file:
        file_name = get_path_by_os(detections_per_file.file_name)
        commit_id = detections_per_file.commit_id

        logger.debug(
            'Going to find the document of the violated file, %s', {'file_name': file_name, 'commit_id': commit_id}
        )

        document = _get_document_by_file_name(documents_to_scan, file_name, commit_id)
        document_detections.append(DocumentDetections(document=document, detections=detections_per_file.detections))

    return document_detections


def exclude_irrelevant_document_detections(
    document_detections_list: list[DocumentDetections],
    scan_type: str,
    command_scan_type: str,
    severity_threshold: str,
) -> list[DocumentDetections]:
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
    """Parse input to pushed branch update details.

    Example input:
    old_value new_value refname
    -----------------------------------------------
    0000000000000000000000000000000000000000 9cf90954ef26e7c58284f8ebf7dcd0fcf711152a refs/heads/main
    973a96d3e925b65941f7c47fa16129f1577d499f 0000000000000000000000000000000000000000 refs/heads/feature-branch
    59564ef68745bca38c42fc57a7822efd519a6bd9 3378e52dcfa47fb11ce3a4a520bea5f85d5d0bf3 refs/heads/develop

    :return: First branch update details (input's first line)
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


def _get_default_scan_parameters(ctx: typer.Context) -> dict:
    return {
        'monitor': ctx.obj.get('monitor'),
        'report': ctx.obj.get('report'),
        'package_vulnerabilities': ctx.obj.get('package-vulnerabilities'),
        'license_compliance': ctx.obj.get('license-compliance'),
        'command_type': ctx.info_name.replace('-', '_'),  # save backward compatibility
        'aggregation_id': str(_generate_unique_id()),
    }


def get_scan_parameters(ctx: typer.Context, paths: Optional[tuple[str, ...]] = None) -> dict:
    scan_parameters = _get_default_scan_parameters(ctx)

    if not paths:
        return scan_parameters

    scan_parameters['paths'] = paths

    if len(paths) != 1:
        logger.debug('Multiple paths provided, going to ignore remote url')
        return scan_parameters

    if not os.path.isdir(paths[0]):
        logger.debug('Path is not a directory, going to ignore remote url')
        return scan_parameters

    remote_url = try_get_git_remote_url(paths[0])
    if not remote_url:
        remote_url = try_to_get_plastic_remote_url(paths[0])

    if remote_url:
        # TODO(MarshalX): remove hardcode in context
        ctx.obj['remote_url'] = remote_url
        scan_parameters['remote_url'] = remote_url

    return scan_parameters


def try_get_git_remote_url(path: str) -> Optional[str]:
    try:
        remote_url = git_proxy.get_repo(path).remotes[0].config_reader.get('url')
        logger.debug('Found Git remote URL, %s', {'remote_url': remote_url, 'path': path})
        return remote_url
    except Exception:
        logger.debug('Failed to get Git remote URL. Probably not a Git repository')
        return None


def _get_plastic_repository_name(path: str) -> Optional[str]:
    """Get the name of the Plastic repository from the current working directory.

    The command to execute is:
        cm status --header --machinereadable --fieldseparator=":::"

    Example of status header in machine-readable format:
        STATUS:::0:::Project/RepoName:::OrgName@ServerInfo
    """
    try:
        command = [
            'cm',
            'status',
            '--header',
            '--machinereadable',
            f'--fieldseparator={consts.PLASTIC_VCS_DATA_SEPARATOR}',
        ]

        status = shell(
            command=command, timeout=consts.PLASTIC_VSC_CLI_TIMEOUT, working_directory=path, silent_exc_info=True
        )
        if not status:
            logger.debug('Failed to get Plastic repository name (command failed)')
            return None

        status_parts = status.split(consts.PLASTIC_VCS_DATA_SEPARATOR)
        if len(status_parts) < 2:
            logger.debug('Failed to parse Plastic repository name (command returned unexpected format)')
            return None

        return status_parts[2].strip()
    except Exception:
        logger.debug('Failed to get Plastic repository name. Probably not a Plastic repository')
        return None


def _get_plastic_repository_list(working_dir: Optional[str] = None) -> dict[str, str]:
    """Get the list of Plastic repositories and their GUIDs.

    The command to execute is:
        cm repo list --format="{repname}:::{repguid}"

    Example line with data:
        Project/RepoName:::tapo1zqt-wn99-4752-h61m-7d9k79d40r4v

    Each line represents an individual repository.
    """
    repo_name_to_guid = {}

    try:
        command = ['cm', 'repo', 'ls', f'--format={{repname}}{consts.PLASTIC_VCS_DATA_SEPARATOR}{{repguid}}']

        status = shell(
            command=command, timeout=consts.PLASTIC_VSC_CLI_TIMEOUT, working_directory=working_dir, silent_exc_info=True
        )
        if not status:
            logger.debug('Failed to get Plastic repository list (command failed)')
            return repo_name_to_guid

        status_lines = status.splitlines()
        for line in status_lines:
            data_parts = line.split(consts.PLASTIC_VCS_DATA_SEPARATOR)
            if len(data_parts) < 2:
                logger.debug('Failed to parse Plastic repository list line (unexpected format), %s', {'line': line})
                continue

            repo_name, repo_guid = data_parts
            repo_name_to_guid[repo_name.strip()] = repo_guid.strip()

        return repo_name_to_guid
    except Exception as e:
        logger.debug('Failed to get Plastic repository list', exc_info=e)
        return repo_name_to_guid


def try_to_get_plastic_remote_url(path: str) -> Optional[str]:
    repository_name = _get_plastic_repository_name(path)
    if not repository_name:
        return None

    repository_map = _get_plastic_repository_list(path)
    if repository_name not in repository_map:
        logger.debug('Failed to get Plastic repository GUID (repository not found in the list)')
        return None

    repository_guid = repository_map[repository_name]
    return f'{consts.PLASTIC_VCS_REMOTE_URI_PREFIX}{repository_guid}'


def exclude_irrelevant_detections(
    detections: list[Detection], scan_type: str, command_scan_type: str, severity_threshold: str
) -> list[Detection]:
    relevant_detections = _exclude_detections_by_exclusions_configuration(detections, scan_type)
    relevant_detections = _exclude_detections_by_scan_type(relevant_detections, scan_type, command_scan_type)
    return _exclude_detections_by_severity(relevant_detections, severity_threshold)


def _exclude_detections_by_severity(detections: list[Detection], severity_threshold: str) -> list[Detection]:
    relevant_detections = []
    for detection in detections:
        severity = detection.severity

        if _does_severity_match_severity_threshold(severity, severity_threshold):
            relevant_detections.append(detection)
        else:
            logger.debug(
                'Going to ignore violations because they are below the severity threshold, %s',
                {'severity': severity, 'severity_threshold': severity_threshold},
            )

    return relevant_detections


def _exclude_detections_by_scan_type(
    detections: list[Detection], scan_type: str, command_scan_type: str
) -> list[Detection]:
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


def exclude_detections_in_deleted_lines(detections: list[Detection]) -> list[Detection]:
    return [detection for detection in detections if detection.detection_details.get('line_type') != 'Removed']


def _exclude_detections_by_exclusions_configuration(detections: list[Detection], scan_type: str) -> list[Detection]:
    exclusions = configuration_manager.get_exclusions_by_scan_type(scan_type)
    return [detection for detection in detections if not _should_exclude_detection(detection, exclusions)]


def _should_exclude_detection(detection: Detection, exclusions: dict) -> bool:
    # FIXME(MarshalX): what the difference between by_value and by_sha?
    exclusions_by_value = exclusions.get(consts.EXCLUSIONS_BY_VALUE_SECTION_NAME, [])
    if _is_detection_sha_configured_in_exclusions(detection, exclusions_by_value):
        logger.debug(
            'Ignoring violation because its value is on the ignore list, %s',
            {'value_sha': detection.detection_details.get('sha512')},
        )
        return True

    exclusions_by_sha = exclusions.get(consts.EXCLUSIONS_BY_SHA_SECTION_NAME, [])
    if _is_detection_sha_configured_in_exclusions(detection, exclusions_by_sha):
        logger.debug(
            'Ignoring violation because its SHA value is on the ignore list, %s',
            {'sha': detection.detection_details.get('sha512')},
        )
        return True

    exclusions_by_rule = exclusions.get(consts.EXCLUSIONS_BY_RULE_SECTION_NAME, [])
    detection_rule_id = detection.detection_rule_id
    if detection_rule_id in exclusions_by_rule:
        logger.debug(
            'Ignoring violation because its Detection Rule ID is on the ignore list, %s',
            {'detection_rule_id': detection_rule_id},
        )
        return True

    exclusions_by_package = exclusions.get(consts.EXCLUSIONS_BY_PACKAGE_SECTION_NAME, [])
    package = _get_package_name(detection)
    if package and package in exclusions_by_package:
        logger.debug('Ignoring violation because its package@version is on the ignore list, %s', {'package': package})
        return True

    exclusions_by_cve = exclusions.get(consts.EXCLUSIONS_BY_CVE_SECTION_NAME, [])
    cve = _get_cve_identifier(detection)
    if cve and cve in exclusions_by_cve:
        logger.debug('Ignoring violation because its CVE is on the ignore list, %s', {'cve': cve})
        return True

    return False


def _is_detection_sha_configured_in_exclusions(detection: Detection, exclusions: list[str]) -> bool:
    detection_sha = detection.detection_details.get('sha512')
    return detection_sha in exclusions


def _get_package_name(detection: Detection) -> Optional[str]:
    package_name = detection.detection_details.get('vulnerable_component')
    package_version = detection.detection_details.get('vulnerable_component_version')

    if package_name is None:
        package_name = detection.detection_details.get('package_name')
        package_version = detection.detection_details.get('package_version')

    if package_name and package_version:
        return f'{package_name}@{package_version}'

    return None


def _get_cve_identifier(detection: Detection) -> Optional[str]:
    return detection.detection_details.get('alert', {}).get('cve_identifier')


def _get_document_by_file_name(
    documents: list[Document], file_name: str, unique_id: Optional[str] = None
) -> Optional[Document]:
    for document in documents:
        if _normalize_file_path(document.path) == _normalize_file_path(file_name) and document.unique_id == unique_id:
            return document

    return None


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
        logger.debug('Failed to report scan status', exc_info=e)


def _generate_unique_id() -> UUID:
    if 'PYTEST_TEST_UNIQUE_ID' in os.environ:
        return UUID(os.environ['PYTEST_TEST_UNIQUE_ID'])

    return uuid4()


def _does_severity_match_severity_threshold(severity: str, severity_threshold: str) -> bool:
    detection_severity_value = SeverityOption.get_member_weight(severity)
    severity_threshold_value = SeverityOption.get_member_weight(severity_threshold)
    if detection_severity_value < 0 or severity_threshold_value < 0:
        return True

    return detection_severity_value >= severity_threshold_value


def _get_scan_result(
    cycode_client: 'ScanClient',
    scan_type: str,
    scan_id: str,
    scan_details: 'ScanDetailsResponse',
    scan_parameters: dict,
) -> ZippedFileScanResult:
    if not scan_details.detections_count:
        return init_default_scan_result(scan_id)

    scan_raw_detections = cycode_client.get_scan_raw_detections(scan_id)

    return ZippedFileScanResult(
        did_detect=True,
        detections_per_file=_map_detections_per_file_and_commit_id(scan_type, scan_raw_detections),
        scan_id=scan_id,
        report_url=_try_get_aggregation_report_url_if_needed(scan_parameters, cycode_client, scan_type),
    )


def init_default_scan_result(scan_id: str) -> ZippedFileScanResult:
    return ZippedFileScanResult(
        did_detect=False,
        detections_per_file=[],
        scan_id=scan_id,
    )


def _set_aggregation_report_url(ctx: typer.Context, aggregation_report_url: Optional[str] = None) -> None:
    ctx.obj['aggregation_report_url'] = aggregation_report_url


def _try_get_aggregation_report_url_if_needed(
    scan_parameters: dict, cycode_client: 'ScanClient', scan_type: str
) -> Optional[str]:
    if not scan_parameters.get('report', False):
        return None

    aggregation_id = scan_parameters.get('aggregation_id')
    if aggregation_id is None:
        return None

    try:
        report_url_response = cycode_client.get_scan_aggregation_report_url(aggregation_id, scan_type)
        return report_url_response.report_url
    except Exception as e:
        logger.debug('Failed to get aggregation report url: %s', str(e))


def _map_detections_per_file_and_commit_id(scan_type: str, raw_detections: list[dict]) -> list[DetectionsPerFile]:
    """Convert a list of detections (async flow) to list of DetectionsPerFile objects (sync flow).

    Args:
        scan_type: Type of the scan.
        raw_detections: List of detections as is returned from the server.

    Note:
        This method fakes server response structure
        to be able to use the same logic for both async and sync scans.

    Note:
        Aggregation is performed by file name and commit ID (if available)

    """
    detections_per_files = {}
    for raw_detection in raw_detections:
        try:
            # FIXME(MarshalX): investigate this field mapping
            raw_detection['message'] = raw_detection['correlation_message']

            file_name = _get_file_name_from_detection(scan_type, raw_detection)
            detection: Detection = DetectionSchema().load(raw_detection)
            commit_id: Optional[str] = detection.detection_details.get('commit_id')  # could be None
            group_by_key = (file_name, commit_id)

            if group_by_key in detections_per_files:
                detections_per_files[group_by_key].append(detection)
            else:
                detections_per_files[group_by_key] = [detection]
        except Exception as e:
            logger.debug('Failed to parse detection', exc_info=e)
            continue

    return [
        DetectionsPerFile(file_name=file_name, detections=file_detections, commit_id=commit_id)
        for (file_name, commit_id), file_detections in detections_per_files.items()
    ]


def _get_file_name_from_detection(scan_type: str, raw_detection: dict) -> str:
    if scan_type == consts.SAST_SCAN_TYPE:
        return raw_detection['detection_details']['file_path']
    if scan_type == consts.SECRET_SCAN_TYPE:
        return _get_secret_file_name_from_detection(raw_detection)

    return raw_detection['detection_details']['file_name']


def _get_secret_file_name_from_detection(raw_detection: dict) -> str:
    file_path: str = raw_detection['detection_details']['file_path']
    file_name: str = raw_detection['detection_details']['file_name']
    return os.path.join(file_path, file_name)


def _does_reach_to_max_commits_to_scan_limit(commit_ids: list[str], max_commits_count: Optional[int]) -> bool:
    if max_commits_count is None:
        return False

    return len(commit_ids) >= max_commits_count


def _normalize_file_path(path: str) -> str:
    if path.startswith('/'):
        return path[1:]
    if path.startswith('./'):
        return path[2:]
    return path


def perform_post_pre_receive_scan_actions(ctx: typer.Context) -> None:
    if scan_utils.is_scan_failed(ctx):
        console.print(consts.PRE_RECEIVE_REMEDIATION_MESSAGE)


def enable_verbose_mode(ctx: typer.Context) -> None:
    ctx.obj['verbose'] = True
    set_logging_level(logging.DEBUG)


def is_verbose_mode_requested_in_pre_receive_scan() -> bool:
    return does_git_push_option_have_value(consts.VERBOSE_SCAN_FLAG)


def should_skip_pre_receive_scan() -> bool:
    return does_git_push_option_have_value(consts.SKIP_SCAN_FLAG)


def does_git_push_option_have_value(value: str) -> bool:
    option_count_env_value = os.getenv(consts.GIT_PUSH_OPTION_COUNT_ENV_VAR_NAME, '')
    option_count = int(option_count_env_value) if option_count_env_value.isdigit() else 0
    return any(os.getenv(f'{consts.GIT_PUSH_OPTION_ENV_VAR_PREFIX}{i}') == value for i in range(option_count))
