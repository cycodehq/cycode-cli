import os
from typing import TYPE_CHECKING, Optional

import click
import typer

from cycode.cli import consts
from cycode.cli.apps.scan.code_scanner import (
    poll_scan_results,
    report_scan_status,
    scan_documents,
)
from cycode.cli.apps.scan.scan_parameters import get_scan_parameters
from cycode.cli.apps.scan.scan_result import (
    create_local_scan_result,
    enrich_scan_result_with_data_from_detection_rules,
    init_default_scan_result,
    print_local_scan_results,
)
from cycode.cli.config import configuration_manager
from cycode.cli.exceptions.handle_scan_errors import handle_scan_exception
from cycode.cli.files_collector.commit_range_documents import (
    collect_commit_range_diff_documents,
    get_commit_range_modified_documents,
    get_diff_file_content,
    get_diff_file_path,
    get_pre_commit_modified_documents,
    get_safe_head_reference_for_diff,
    parse_commit_range_sast,
    parse_commit_range_sca,
)
from cycode.cli.files_collector.file_excluder import excluder
from cycode.cli.files_collector.models.in_memory_zip import InMemoryZip
from cycode.cli.files_collector.sca.sca_file_collector import (
    perform_sca_pre_commit_range_scan_actions,
    perform_sca_pre_hook_range_scan_actions,
)
from cycode.cli.files_collector.zip_documents import zip_documents
from cycode.cli.models import Document
from cycode.cli.utils.git_proxy import git_proxy
from cycode.cli.utils.path_utils import get_path_by_os
from cycode.cli.utils.progress_bar import ScanProgressBarSection
from cycode.cli.utils.scan_utils import generate_unique_scan_id, set_issue_detected_by_scan_results
from cycode.cyclient.models import ZippedFileScanResult
from cycode.logger import get_logger

if TYPE_CHECKING:
    from cycode.cyclient.scan_client import ScanClient

logger = get_logger('Commit Range Scanner')


def _does_git_push_option_have_value(value: str) -> bool:
    option_count_env_value = os.getenv(consts.GIT_PUSH_OPTION_COUNT_ENV_VAR_NAME, '')
    option_count = int(option_count_env_value) if option_count_env_value.isdigit() else 0
    return any(os.getenv(f'{consts.GIT_PUSH_OPTION_ENV_VAR_PREFIX}{i}') == value for i in range(option_count))


def is_verbose_mode_requested_in_pre_receive_scan() -> bool:
    return _does_git_push_option_have_value(consts.VERBOSE_SCAN_FLAG)


def should_skip_pre_receive_scan() -> bool:
    return _does_git_push_option_have_value(consts.SKIP_SCAN_FLAG)


def _perform_commit_range_scan_async(
    cycode_client: 'ScanClient',
    from_commit_zipped_documents: 'InMemoryZip',
    to_commit_zipped_documents: 'InMemoryZip',
    scan_type: str,
    scan_parameters: dict,
    timeout: Optional[int] = None,
) -> ZippedFileScanResult:
    scan_async_result = cycode_client.commit_range_scan_async(
        from_commit_zipped_documents, to_commit_zipped_documents, scan_type, scan_parameters
    )

    logger.debug(
        'Async commit range scan request has been triggered successfully, %s', {'scan_id': scan_async_result.scan_id}
    )
    return poll_scan_results(cycode_client, scan_async_result.scan_id, scan_type, scan_parameters, timeout)


def _scan_commit_range_documents(
    ctx: typer.Context,
    from_documents_to_scan: list[Document],
    to_documents_to_scan: list[Document],
    scan_parameters: Optional[dict] = None,
    timeout: Optional[int] = None,
) -> None:
    cycode_client = ctx.obj['client']
    scan_type = ctx.obj['scan_type']
    severity_threshold = ctx.obj['severity_threshold']
    scan_command_type = ctx.info_name
    progress_bar = ctx.obj['progress_bar']

    local_scan_result = error_message = None
    scan_completed = False
    scan_id = str(generate_unique_scan_id())
    from_commit_zipped_documents = InMemoryZip()
    to_commit_zipped_documents = InMemoryZip()

    try:
        progress_bar.set_section_length(ScanProgressBarSection.SCAN, 1)

        scan_result = init_default_scan_result(scan_id)
        if len(from_documents_to_scan) > 0 or len(to_documents_to_scan) > 0:
            logger.debug('Preparing from-commit zip')
            # for SAST it is files from to_commit with actual content to scan
            from_commit_zipped_documents = zip_documents(scan_type, from_documents_to_scan)

            logger.debug('Preparing to-commit zip')
            # for SAST it is files with diff between from_commit and to_commit
            to_commit_zipped_documents = zip_documents(scan_type, to_documents_to_scan)

            scan_result = _perform_commit_range_scan_async(
                cycode_client,
                from_commit_zipped_documents,
                to_commit_zipped_documents,
                scan_type,
                scan_parameters,
                timeout,
            )
            enrich_scan_result_with_data_from_detection_rules(cycode_client, scan_result)

        progress_bar.update(ScanProgressBarSection.SCAN)
        progress_bar.set_section_length(ScanProgressBarSection.GENERATE_REPORT, 1)

        documents_to_scan = to_documents_to_scan
        if scan_type == consts.SAST_SCAN_TYPE:
            # actually for SAST from_documents_to_scan is full files and to_documents_to_scan is diff files
            documents_to_scan = from_documents_to_scan

        local_scan_result = create_local_scan_result(
            scan_result, documents_to_scan, scan_command_type, scan_type, severity_threshold
        )
        set_issue_detected_by_scan_results(ctx, [local_scan_result])

        progress_bar.update(ScanProgressBarSection.GENERATE_REPORT)
        progress_bar.stop()

        # errors will be handled with try-except block; printing will not occur on errors
        print_local_scan_results(ctx, [local_scan_result])

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
    report_scan_status(
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


def _scan_sca_commit_range(ctx: typer.Context, repo_path: str, commit_range: str, **_) -> None:
    scan_parameters = get_scan_parameters(ctx, (repo_path,))

    from_commit_rev, to_commit_rev = parse_commit_range_sca(commit_range, repo_path)
    from_commit_documents, to_commit_documents, _ = get_commit_range_modified_documents(
        ctx.obj['progress_bar'], ScanProgressBarSection.PREPARE_LOCAL_FILES, repo_path, from_commit_rev, to_commit_rev
    )
    from_commit_documents = excluder.exclude_irrelevant_documents_to_scan(consts.SCA_SCAN_TYPE, from_commit_documents)
    to_commit_documents = excluder.exclude_irrelevant_documents_to_scan(consts.SCA_SCAN_TYPE, to_commit_documents)

    perform_sca_pre_commit_range_scan_actions(
        repo_path, from_commit_documents, from_commit_rev, to_commit_documents, to_commit_rev
    )

    _scan_commit_range_documents(ctx, from_commit_documents, to_commit_documents, scan_parameters=scan_parameters)


def _scan_secret_commit_range(
    ctx: typer.Context, repo_path: str, commit_range: str, max_commits_count: Optional[int] = None
) -> None:
    commit_diff_documents_to_scan = collect_commit_range_diff_documents(ctx, repo_path, commit_range, max_commits_count)
    diff_documents_to_scan = excluder.exclude_irrelevant_documents_to_scan(
        consts.SECRET_SCAN_TYPE, commit_diff_documents_to_scan
    )

    scan_documents(
        ctx, diff_documents_to_scan, get_scan_parameters(ctx, (repo_path,)), is_git_diff=True, is_commit_range=True
    )


def _scan_sast_commit_range(ctx: typer.Context, repo_path: str, commit_range: str, **_) -> None:
    scan_parameters = get_scan_parameters(ctx, (repo_path,))

    from_commit_rev, to_commit_rev = parse_commit_range_sast(commit_range, repo_path)
    _, commit_documents, diff_documents = get_commit_range_modified_documents(
        ctx.obj['progress_bar'],
        ScanProgressBarSection.PREPARE_LOCAL_FILES,
        repo_path,
        from_commit_rev,
        to_commit_rev,
        reverse_diff=False,
    )
    commit_documents = excluder.exclude_irrelevant_documents_to_scan(consts.SAST_SCAN_TYPE, commit_documents)
    diff_documents = excluder.exclude_irrelevant_documents_to_scan(consts.SAST_SCAN_TYPE, diff_documents)

    _scan_commit_range_documents(ctx, commit_documents, diff_documents, scan_parameters=scan_parameters)


_SCAN_TYPE_TO_COMMIT_RANGE_HANDLER = {
    consts.SCA_SCAN_TYPE: _scan_sca_commit_range,
    consts.SECRET_SCAN_TYPE: _scan_secret_commit_range,
    consts.SAST_SCAN_TYPE: _scan_sast_commit_range,
}


def scan_commit_range(ctx: typer.Context, repo_path: str, commit_range: str, **kwargs) -> None:
    scan_type = ctx.obj['scan_type']

    progress_bar = ctx.obj['progress_bar']
    progress_bar.start()

    if scan_type not in _SCAN_TYPE_TO_COMMIT_RANGE_HANDLER:
        raise click.ClickException(f'Commit range scanning for {scan_type.upper()} is not supported')

    _SCAN_TYPE_TO_COMMIT_RANGE_HANDLER[scan_type](ctx, repo_path, commit_range, **kwargs)


def _scan_sca_pre_commit(ctx: typer.Context, repo_path: str) -> None:
    scan_parameters = get_scan_parameters(ctx)

    git_head_documents, pre_committed_documents, _ = get_pre_commit_modified_documents(
        progress_bar=ctx.obj['progress_bar'],
        progress_bar_section=ScanProgressBarSection.PREPARE_LOCAL_FILES,
        repo_path=repo_path,
    )
    git_head_documents = excluder.exclude_irrelevant_documents_to_scan(consts.SCA_SCAN_TYPE, git_head_documents)
    pre_committed_documents = excluder.exclude_irrelevant_documents_to_scan(
        consts.SCA_SCAN_TYPE, pre_committed_documents
    )

    perform_sca_pre_hook_range_scan_actions(repo_path, git_head_documents, pre_committed_documents)

    _scan_commit_range_documents(
        ctx,
        git_head_documents,
        pre_committed_documents,
        scan_parameters,
        configuration_manager.get_sca_pre_commit_timeout_in_seconds(),
    )


def _scan_secret_pre_commit(ctx: typer.Context, repo_path: str) -> None:
    progress_bar = ctx.obj['progress_bar']
    repo = git_proxy.get_repo(repo_path)
    head_reference = get_safe_head_reference_for_diff(repo)
    diff_index = repo.index.diff(head_reference, create_patch=True, R=True)

    progress_bar.set_section_length(ScanProgressBarSection.PREPARE_LOCAL_FILES, len(diff_index))

    documents_to_scan = []
    for diff in diff_index:
        progress_bar.update(ScanProgressBarSection.PREPARE_LOCAL_FILES)
        documents_to_scan.append(
            Document(
                get_path_by_os(get_diff_file_path(diff, repo=repo)),
                get_diff_file_content(diff),
                is_git_diff_format=True,
            )
        )
    documents_to_scan = excluder.exclude_irrelevant_documents_to_scan(consts.SECRET_SCAN_TYPE, documents_to_scan)

    scan_documents(ctx, documents_to_scan, get_scan_parameters(ctx), is_git_diff=True)


def _scan_sast_pre_commit(ctx: typer.Context, repo_path: str, **_) -> None:
    scan_parameters = get_scan_parameters(ctx, (repo_path,))

    _, pre_committed_documents, diff_documents = get_pre_commit_modified_documents(
        progress_bar=ctx.obj['progress_bar'],
        progress_bar_section=ScanProgressBarSection.PREPARE_LOCAL_FILES,
        repo_path=repo_path,
    )
    pre_committed_documents = excluder.exclude_irrelevant_documents_to_scan(
        consts.SAST_SCAN_TYPE, pre_committed_documents
    )
    diff_documents = excluder.exclude_irrelevant_documents_to_scan(consts.SAST_SCAN_TYPE, diff_documents)

    _scan_commit_range_documents(ctx, pre_committed_documents, diff_documents, scan_parameters=scan_parameters)


_SCAN_TYPE_TO_PRE_COMMIT_HANDLER = {
    consts.SCA_SCAN_TYPE: _scan_sca_pre_commit,
    consts.SECRET_SCAN_TYPE: _scan_secret_pre_commit,
    consts.SAST_SCAN_TYPE: _scan_sast_pre_commit,
}


def scan_pre_commit(ctx: typer.Context, repo_path: str) -> None:
    scan_type = ctx.obj['scan_type']
    if scan_type not in _SCAN_TYPE_TO_PRE_COMMIT_HANDLER:
        raise click.ClickException(f'Pre-commit scanning for {scan_type.upper()} is not supported')

    _SCAN_TYPE_TO_PRE_COMMIT_HANDLER[scan_type](ctx, repo_path)
    logger.debug('Pre-commit scan completed successfully')
