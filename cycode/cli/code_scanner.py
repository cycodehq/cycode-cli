import click
import json
import logging
import os
import sys
import time
import traceback
from platform import platform
from uuid import uuid4, UUID
from git import Repo, NULL_TREE, InvalidGitRepositoryError
from sys import getsizeof

from halo import Halo

from cycode.cli.printers import ConsolePrinter
from cycode.cli.models import Document, DocumentDetections, Severity, CliError, CliErrors
from cycode.cli.ci_integrations import get_commit_range
from cycode.cli.consts import *
from cycode.cli.config import configuration_manager
from cycode.cli.utils.path_utils import is_sub_path, is_binary_file, get_file_size, get_relevant_files_in_path, \
    get_path_by_os, get_file_content
from cycode.cli.utils.string_utils import get_content_size, is_binary_content
from cycode.cli.utils.task_timer import TimeoutAfter
from cycode.cli.utils import scan_utils
from cycode.cli.user_settings.config_file_manager import ConfigFileManager
from cycode.cli.zip_file import InMemoryZip
from cycode.cli.exceptions.custom_exceptions import *
from cycode.cli.helpers import sca_code_scanner
from cycode.cyclient import logger
from cycode.cyclient.models import *

start_scan_time = time.time()


@click.command()
@click.argument("path", nargs=1, type=click.STRING, required=True)
@click.option('--branch', '-b',
              default=None,
              help='Branch to scan, if not set scanning the default branch',
              type=str,
              required=False)
@click.pass_context
def scan_repository(context: click.Context, path, branch):
    """ Scan git repository including its history """
    try:
        logger.debug('Starting repository scan process, %s', {'path': path, 'branch': branch})
        context.obj["path"] = path
        monitor = context.obj.get("monitor")
        scan_type = context.obj["scan_type"]
        if monitor and scan_type != SCA_SCAN_TYPE:
            raise click.ClickException(f"Monitor flag is currently supported for SCA scan type only")

        documents_to_scan = [
            Document(obj.path if monitor else get_path_by_os(os.path.join(path, obj.path)),
                     obj.data_stream.read().decode('utf-8', errors='replace'))
            for obj
            in get_git_repository_tree_file_entries(path, branch)]
        documents_to_scan = exclude_irrelevant_documents_to_scan(context, documents_to_scan)
        perform_pre_scan_documents_actions(context, scan_type, documents_to_scan, False)
        logger.debug('Found all relevant files for scanning %s', {'path': path, 'branch': branch})
        return scan_documents(context, documents_to_scan, is_git_diff=False,
                              scan_parameters=get_scan_parameters(context))
    except Exception as e:
        _handle_exception(context, e)


@click.command()
@click.argument("path",
                nargs=1,
                type=click.STRING,
                required=True)
@click.option("--commit_range", "-r",
              help='Scan a commit range in this git repository, by default cycode scans all '
                   'commit history (example: HEAD~1)',
              type=click.STRING,
              default="--all",
              required=False)
@click.pass_context
def scan_repository_commit_history(context: click.Context, path: str, commit_range: str):
    """	Scan all the commits history in this git repository """
    try:
        logger.debug('Starting commit history scan process, %s', {'path': path, 'commit_range': commit_range})
        return scan_commit_range(context, path=path, commit_range=commit_range)
    except Exception as e:
        _handle_exception(context, e)


def scan_commit_range(context: click.Context, path: str, commit_range: str, max_commits_count: Optional[int] = None):
    scan_type = context.obj["scan_type"]
    if scan_type not in COMMIT_RANGE_SCAN_SUPPORTED_SCAN_TYPES:
        raise click.ClickException(f"Commit range scanning for {str.upper(scan_type)} is not supported")

    if scan_type == SCA_SCAN_TYPE:
        return scan_sca_commit_range(context, path, commit_range)

    documents_to_scan = []
    commit_ids_to_scan = []

    repo = Repo(path)
    total_commits_count = repo.git.rev_list('--count', commit_range)
    scanned_commits_count = 0
    logger.info(f'Calculating diffs for {total_commits_count} commits in the commit range {commit_range}')
    for commit in repo.iter_commits(rev=commit_range):
        if _does_reach_to_max_commits_to_scan_limit(commit_ids_to_scan, max_commits_count):
            logger.info(f'Reached to max commits to scan count. Going to scan only {max_commits_count} last commits')
            break

        if _should_update_progress(scanned_commits_count):
            logger.info(f'Calculated diffs for {scanned_commits_count} out of {total_commits_count} commits')

        commit_id = commit.hexsha
        commit_ids_to_scan.append(commit_id)
        parent = commit.parents[0] if commit.parents else NULL_TREE
        diff = commit.diff(parent, create_patch=True, R=True)
        commit_documents_to_scan = []
        for blob in diff:
            doc = Document(get_path_by_os(os.path.join(path, get_diff_file_path(blob))),
                           blob.diff.decode('utf-8', errors='replace'), True, unique_id=commit_id)
            commit_documents_to_scan.append(doc)

        logger.debug('Found all relevant files in commit %s',
                     {'path': path, 'commit_range': commit_range, 'commit_id': commit_id})
        commit_documents_to_scan = exclude_irrelevant_documents_to_scan(context, commit_documents_to_scan)
        documents_to_scan.extend(commit_documents_to_scan)
        scanned_commits_count += 1

    logger.debug('List of commit ids to scan, %s', {'commit_ids': commit_ids_to_scan})
    logger.info('Starting to scan commit range (It may take a few minutes)')
    return scan_documents(context, documents_to_scan, is_git_diff=True, is_commit_range=True)


@click.command()
@click.pass_context
def scan_ci(context: click.Context):
    """ Execute scan in a CI environment which relies on the
    CYCODE_TOKEN and CYCODE_REPO_LOCATION environment variables """
    return scan_commit_range(context, path=os.getcwd(), commit_range=get_commit_range())


@click.command()
@click.argument("path", nargs=1, type=click.STRING, required=True)
@click.pass_context
def scan_path(context: click.Context, path):
    """	Scan the files in the path supplied in the command """
    logger.debug('Starting path scan process, %s', {'path': path})
    context.obj["path"] = path
    files_to_scan = get_relevant_files_in_path(path=path, exclude_patterns=["**/.git/**", "**/.cycode/**"])
    files_to_scan = exclude_irrelevant_files(context, files_to_scan)
    logger.debug('Found all relevant files for scanning %s', {'path': path, 'file_to_scan_count': len(files_to_scan)})
    return scan_disk_files(context, files_to_scan)


@click.command()
@click.argument("ignored_args", nargs=-1, type=click.UNPROCESSED)
@click.pass_context
def pre_commit_scan(context: click.Context, ignored_args: List[str]):
    """ Use this command to scan the content that was not committed yet """
    scan_type = context.obj['scan_type']
    if scan_type == SCA_SCAN_TYPE:
        return scan_sca_pre_commit(context)

    diff_files = Repo(os.getcwd()).index.diff("HEAD", create_patch=True, R=True)
    documents_to_scan = [Document(get_path_by_os(get_diff_file_path(file)), get_diff_file_content(file))
                         for file in diff_files]
    documents_to_scan = exclude_irrelevant_documents_to_scan(context, documents_to_scan)
    return scan_documents(context, documents_to_scan, is_git_diff=True)


@click.command()
@click.argument("ignored_args", nargs=-1, type=click.UNPROCESSED)
@click.pass_context
def pre_receive_scan(context: click.Context, ignored_args: List[str]):
    """ Use this command to scan commits on server side before pushing them to the repository """
    try:
        scan_type = context.obj['scan_type']
        if scan_type != SECRET_SCAN_TYPE:
            raise click.ClickException(f"Commit range scanning for {str.upper(scan_type)} is not supported")

        if should_skip_pre_receive_scan():
            logger.info(
                "A scan has been skipped as per your request."
                " Please note that this may leave your system vulnerable to secrets that have not been detected")
            return

        if is_verbose_mode_requested_in_pre_receive_scan():
            enable_verbose_mode(context)
            logger.debug('Verbose mode enabled, all log levels will be displayed')

        command_scan_type = context.info_name
        timeout = configuration_manager.get_pre_receive_command_timeout(command_scan_type)
        with TimeoutAfter(timeout):
            if scan_type not in COMMIT_RANGE_SCAN_SUPPORTED_SCAN_TYPES:
                raise click.ClickException(f"Commit range scanning for {str.upper(scan_type)} is not supported")

            branch_update_details = parse_pre_receive_input()
            commit_range = calculate_pre_receive_commit_range(branch_update_details)
            if not commit_range:
                logger.info('No new commits found for pushed branch, %s',
                            {'branch_update_details': branch_update_details})
                return

            max_commits_to_scan = configuration_manager.get_pre_receive_max_commits_to_scan_count(command_scan_type)
            scan_commit_range(context, os.getcwd(), commit_range, max_commits_count=max_commits_to_scan)
            perform_post_pre_receive_scan_actions(context)
    except Exception as e:
        _handle_exception(context, e)


def scan_sca_pre_commit(context: click.Context):
    scan_parameters = get_default_scan_parameters(context)
    git_head_documents, pre_committed_documents = get_pre_commit_modified_documents()
    git_head_documents = exclude_irrelevant_documents_to_scan(context, git_head_documents)
    pre_committed_documents = exclude_irrelevant_documents_to_scan(context, pre_committed_documents)
    sca_code_scanner.perform_pre_hook_range_scan_actions(git_head_documents, pre_committed_documents)
    return scan_commit_range_documents(context, git_head_documents, pre_committed_documents,
                                       scan_parameters,
                                       configuration_manager.get_sca_pre_commit_timeout_in_seconds())


def scan_sca_commit_range(context: click.Context, path: str, commit_range: str):
    context.obj["path"] = path
    scan_parameters = get_scan_parameters(context)
    from_commit_rev, to_commit_rev = parse_commit_range(commit_range, path)
    from_commit_documents, to_commit_documents = \
        get_commit_range_modified_documents(path, from_commit_rev, to_commit_rev)
    from_commit_documents = exclude_irrelevant_documents_to_scan(context, from_commit_documents)
    to_commit_documents = exclude_irrelevant_documents_to_scan(context, to_commit_documents)
    sca_code_scanner.perform_pre_commit_range_scan_actions(path, from_commit_documents, from_commit_rev,
                                                           to_commit_documents, to_commit_rev)

    return scan_commit_range_documents(context, from_commit_documents, to_commit_documents,
                                       scan_parameters=scan_parameters)


def scan_disk_files(context: click.Context, paths: List[str]):
    scan_parameters = get_scan_parameters(context)
    scan_type = context.obj['scan_type']
    is_git_diff = False
    documents: List[Document] = []
    for path in paths:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
            documents.append(Document(path, content, is_git_diff))

    perform_pre_scan_documents_actions(context, scan_type, documents, is_git_diff)
    return scan_documents(context, documents, is_git_diff=is_git_diff, scan_parameters=scan_parameters)


def scan_documents(context: click.Context, documents_to_scan: List[Document], is_git_diff: bool = False,
                   is_commit_range: bool = False, scan_parameters: dict = None):
    cycode_client = context.obj["client"]
    scan_type = context.obj["scan_type"]
    severity_threshold = context.obj["severity_threshold"]
    command_scan_type = context.info_name
    error_message = None
    all_detections_count = 0
    output_detections_count = 0
    scan_id = _get_scan_id(context)
    zipped_documents = InMemoryZip()

    try:
        logger.debug("Preparing local files")
        zipped_documents = zip_documents_to_scan(scan_type, zipped_documents, documents_to_scan)

        scan_result = perform_scan(context, cycode_client, zipped_documents, scan_type, scan_id, is_git_diff,
                                   is_commit_range,
                                   scan_parameters)

        all_detections_count, output_detections_count = \
            handle_scan_result(context, scan_result, command_scan_type, scan_type, severity_threshold,
                               documents_to_scan)
        scan_completed = True
    except Exception as e:
        _handle_exception(context, e)
        error_message = str(e)
        scan_completed = False

    zip_file_size = getsizeof(zipped_documents.in_memory_zip)
    logger.debug('Finished scan process, %s',
                 {'all_violations_count': all_detections_count, 'relevant_violations_count': output_detections_count,
                  'scan_id': str(scan_id), 'zip_file_size': zip_file_size})
    _report_scan_status(context, scan_type, str(scan_id), scan_completed, output_detections_count,
                        all_detections_count, len(documents_to_scan), zip_file_size, command_scan_type, error_message)


def scan_commit_range_documents(context: click.Context, from_documents_to_scan: List[Document],
                                to_documents_to_scan: List[Document], scan_parameters: dict = None,
                                timeout: int = None):
    cycode_client = context.obj["client"]
    scan_type = context.obj["scan_type"]
    severity_threshold = context.obj["severity_threshold"]
    scan_command_type = context.info_name
    error_message = None
    all_detections_count = 0
    output_detections_count = 0
    scan_id = _get_scan_id(context)
    from_commit_zipped_documents = InMemoryZip()
    to_commit_zipped_documents = InMemoryZip()

    try:
        scan_result = init_default_scan_result(str(scan_id))
        if should_scan_documents(from_documents_to_scan, to_documents_to_scan):
            logger.debug("Preparing from-commit zip")
            from_commit_zipped_documents = zip_documents_to_scan(scan_type, from_commit_zipped_documents,
                                                                 from_documents_to_scan)
            logger.debug("Preparing to-commit zip")
            to_commit_zipped_documents = zip_documents_to_scan(scan_type, to_commit_zipped_documents,
                                                               to_documents_to_scan)
            scan_result = perform_commit_range_scan_async(context, cycode_client, from_commit_zipped_documents,
                                                          to_commit_zipped_documents, scan_type, scan_parameters,
                                                          timeout)
        all_detections_count, output_detections_count = \
            handle_scan_result(context, scan_result, scan_command_type, scan_type, severity_threshold,
                               to_documents_to_scan)
        scan_completed = True
    except Exception as e:
        _handle_exception(context, e)
        error_message = str(e)
        scan_completed = False

    zip_file_size = getsizeof(from_commit_zipped_documents.in_memory_zip) + getsizeof(
        to_commit_zipped_documents.in_memory_zip)
    logger.debug('Finished scan process, %s',
                 {'all_violations_count': all_detections_count, 'relevant_violations_count': output_detections_count,
                  'scan_id': str(scan_id), 'zip_file_size': zip_file_size})
    _report_scan_status(context, scan_type, str(scan_id), scan_completed, output_detections_count,
                        all_detections_count, len(to_documents_to_scan), zip_file_size, scan_command_type,
                        error_message)


def should_scan_documents(from_documents_to_scan: List[Document], to_documents_to_scan: List[Document]) -> bool:
    return len(from_documents_to_scan) > 0 or len(to_documents_to_scan) > 0


def handle_scan_result(context, scan_result, command_scan_type, scan_type, severity_threshold, to_documents_to_scan):
    document_detections_list = enrich_scan_result(scan_result, to_documents_to_scan)
    relevant_document_detections_list = exclude_irrelevant_scan_results(document_detections_list, scan_type,
                                                                        command_scan_type, severity_threshold)
    context.obj['report_url'] = scan_result.report_url
    print_results(context, relevant_document_detections_list)
    context.obj['issue_detected'] = len(relevant_document_detections_list) > 0
    all_detections_count = sum(
        [len(document_detections.detections) for document_detections in document_detections_list])
    output_detections_count = sum(
        [len(document_detections.detections) for document_detections in relevant_document_detections_list])
    return all_detections_count, output_detections_count


def perform_pre_scan_documents_actions(context: click.Context, scan_type: str, documents_to_scan: List[Document],
                                       is_git_diff: bool = False):
    if scan_type == SCA_SCAN_TYPE:
        logger.debug(
            f"Perform pre scan document actions")
        sca_code_scanner.add_dependencies_tree_document(context, documents_to_scan, is_git_diff)


def zip_documents_to_scan(scan_type: str, zip: InMemoryZip, documents: List[Document]):
    start_zip_creation_time = time.time()

    for index, document in enumerate(documents):
        zip_file_size = getsizeof(zip.in_memory_zip)
        validate_zip_file_size(scan_type, zip_file_size)

        logger.debug('adding file to zip, %s',
                     {'index': index, 'filename': document.path, 'unique_id': document.unique_id})
        zip.append(document.path, document.unique_id, document.content)
    zip.close()

    end_zip_creation_time = time.time()
    zip_creation_time = int(end_zip_creation_time - start_zip_creation_time)
    logger.debug('finished to create zip file, %s', {'zip_creation_time': zip_creation_time})
    return zip


def validate_zip_file_size(scan_type, zip_file_size):
    if scan_type == SCA_SCAN_TYPE:
        if zip_file_size > SCA_ZIP_MAX_SIZE_LIMIT_IN_BYTES:
            raise ZipTooLargeError(SCA_ZIP_MAX_SIZE_LIMIT_IN_BYTES)
    else:
        if zip_file_size > ZIP_MAX_SIZE_LIMIT_IN_BYTES:
            raise ZipTooLargeError(ZIP_MAX_SIZE_LIMIT_IN_BYTES)


def perform_scan(context, cycode_client, zipped_documents: InMemoryZip, scan_type: str, scan_id: UUID,
                 is_git_diff: bool,
                 is_commit_range: bool, scan_parameters: dict):
    if scan_type == SCA_SCAN_TYPE or scan_type == SAST_SCAN_TYPE:
        return perform_scan_async(context, cycode_client, zipped_documents, scan_type, scan_parameters)

    scan_result = cycode_client.commit_range_zipped_file_scan(scan_type, zipped_documents, scan_id) \
        if is_commit_range else cycode_client.zipped_file_scan(scan_type, zipped_documents, scan_id,
                                                               scan_parameters, is_git_diff)

    return scan_result


def perform_scan_async(context: click.Context, cycode_client, zipped_documents: InMemoryZip, scan_type: str,
                       scan_parameters: dict) -> ZippedFileScanResult:
    scan_async_result = cycode_client.zipped_file_scan_async(zipped_documents, scan_type, scan_parameters)
    logger.debug("scan request has been triggered successfully, scan id: %s", scan_async_result.scan_id)

    return poll_scan_results(context, cycode_client, scan_async_result.scan_id)


def perform_commit_range_scan_async(context: click.Context, cycode_client, from_commit_zipped_documents: InMemoryZip,
                                    to_commit_zipped_documents: InMemoryZip, scan_type: str,
                                    scan_parameters: dict, timeout: int = None) -> ZippedFileScanResult:
    scan_async_result = \
        cycode_client.multiple_zipped_file_scan_async(from_commit_zipped_documents, to_commit_zipped_documents,
                                                      scan_type, scan_parameters)
    logger.debug("scan request has been triggered successfully, scan id: %s", scan_async_result.scan_id)
    return poll_scan_results(context, cycode_client, scan_async_result.scan_id, timeout)


def poll_scan_results(context: click.Context, cycode_client, scan_id: str, polling_timeout: int = None):
    if polling_timeout is None:
        polling_timeout = configuration_manager.get_scan_polling_timeout_in_seconds()

    last_scan_update_at = None
    end_polling_time = time.time() + polling_timeout
    spinner = Halo(spinner='dots')
    spinner.start("Scan in progress")
    while time.time() < end_polling_time:
        scan_details = cycode_client.get_scan_details(scan_id)
        if scan_details.scan_update_at is not None and scan_details.scan_update_at != last_scan_update_at:
            click.echo()
            last_scan_update_at = scan_details.scan_update_at
            print_scan_details(scan_details)
        if scan_details.scan_status == SCAN_STATUS_COMPLETED:
            spinner.succeed()
            return _get_scan_result(cycode_client, scan_id, scan_details)
        if scan_details.scan_status == SCAN_STATUS_ERROR:
            spinner.fail()
            raise ScanAsyncError(f'error occurred while trying to scan zip file. {scan_details.message}')
        time.sleep(SCAN_POLLING_WAIT_INTERVAL_IN_SECONDS)

    spinner.stop_and_persist(symbol="⏰".encode('utf-8'), text='Timeout')
    raise ScanAsyncError(f'Failed to complete scan after {polling_timeout} seconds')


def print_scan_details(scan_details_response: ScanDetailsResponse):
    logger.info(f"Scan update: (scan_id: {scan_details_response.id})")
    logger.info(f"Scan status: {scan_details_response.scan_status}")
    if scan_details_response.message is not None:
        logger.info(f"Scan message: {scan_details_response.message}")


def print_results(context: click.Context, document_detections_list: List[DocumentDetections]) -> None:
    printer = ConsolePrinter(context)
    printer.print_scan_results(document_detections_list)


def enrich_scan_result(
        scan_result: ZippedFileScanResult, documents_to_scan: List[Document]
) -> List[DocumentDetections]:
    logger.debug('enriching scan result')
    document_detections_list = []
    for detections_per_file in scan_result.detections_per_file:
        file_name = get_path_by_os(detections_per_file.file_name)
        commit_id = detections_per_file.commit_id
        logger.debug("going to find document of violated file, %s", {'file_name': file_name, 'commit_id': commit_id})
        document = _get_document_by_file_name(documents_to_scan, file_name, commit_id)
        document_detections_list.append(
            DocumentDetections(document=document, detections=detections_per_file.detections))

    return document_detections_list


def exclude_irrelevant_scan_results(document_detections_list: List[DocumentDetections], scan_type: str,
                                    command_scan_type: str, severity_threshold: str) -> List[DocumentDetections]:
    relevant_document_detections_list = []
    for document_detections in document_detections_list:
        relevant_detections = exclude_irrelevant_detections(scan_type, command_scan_type, severity_threshold,
                                                            document_detections.detections)
        if relevant_detections:
            relevant_document_detections_list.append(DocumentDetections(document=document_detections.document,
                                                                        detections=relevant_detections))

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
    pre_receive_input = sys.stdin.read().strip()
    if not pre_receive_input:
        raise ValueError(
            "Pre receive input was not found. Make sure that you are using this command only in pre-receive hook")

    # each line represents a branch update request, handle the first one only
    # TODO support case of multiple update branch requests
    branch_update_details = pre_receive_input.splitlines()[0]
    return branch_update_details


def calculate_pre_receive_commit_range(branch_update_details: str) -> Optional[str]:
    end_commit = get_end_commit_from_branch_update_details(branch_update_details)

    # branch is deleted, no need to perform scan
    if end_commit == EMPTY_COMMIT_SHA:
        return

    start_commit = get_oldest_unupdated_commit_for_branch(end_commit)

    # no new commit to update found
    if not start_commit:
        return

    return f'{start_commit}~1...{end_commit}'


def get_end_commit_from_branch_update_details(update_details: str) -> str:
    # update details pattern: <start_commit> <end_commit> <ref>
    _, end_commit, _ = update_details.split()
    return end_commit


def get_oldest_unupdated_commit_for_branch(commit: str) -> Optional[str]:
    # get a list of commits by chronological order that are not in the remote repository yet
    # more info about rev-list command: https://git-scm.com/docs/git-rev-list
    not_updated_commits = Repo(os.getcwd()).git.rev_list(commit, '--topo-order', '--reverse', '--not', '--all')
    commits = not_updated_commits.splitlines()
    if not commits:
        return None
    return commits[0]


def get_diff_file_path(file):
    return file.b_path if file.b_path else file.a_path


def get_diff_file_content(file):
    return file.diff.decode('utf-8', errors='replace')


def should_process_git_object(obj, depth):
    return obj.type == 'blob' and obj.size > 0


def get_git_repository_tree_file_entries(path: str, branch: str):
    return Repo(path).tree(branch).traverse(predicate=should_process_git_object)


def get_default_scan_parameters(context: click.Context) -> dict:
    return {
        "monitor": context.obj.get("monitor"),
        "report": context.obj.get("report"),
        "package_vulnerabilities": context.obj.get("package-vulnerabilities"),
        "license_compliance": context.obj.get("license-compliance")
    }


def get_scan_parameters(context: click.Context) -> dict:
    path = context.obj["path"]
    scan_parameters = get_default_scan_parameters(context)
    remote_url = try_get_git_remote_url(path)
    if remote_url:
        context.obj["remote_url"] = remote_url
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


def exclude_irrelevant_documents_to_scan(context: click.Context, documents_to_scan: List[Document]) -> \
        List[Document]:
    scan_type = context.obj['scan_type']
    logger.debug("excluding irrelevant documents to scan")
    return [document for document in documents_to_scan if
            _is_relevant_document_to_scan(scan_type, document.path, document.content)]


def exclude_irrelevant_files(context: click.Context, filenames: List[str]) -> List[str]:
    scan_type = context.obj['scan_type']
    return [filename for filename in filenames if _is_relevant_file_to_scan(scan_type, filename)]


def exclude_irrelevant_detections(scan_type: str, command_scan_type: str, severity_threshold: str, detections) -> List:
    relevant_detections = exclude_detections_by_exclusions_configuration(scan_type, detections)
    relevant_detections = exclude_detections_by_scan_type(scan_type, command_scan_type, relevant_detections)
    relevant_detections = exclude_detections_by_severity(scan_type, severity_threshold, relevant_detections)

    return relevant_detections


def exclude_detections_by_severity(scan_type: str, severity_threshold: str, detections) -> List:
    if scan_type != SCA_SCAN_TYPE or severity_threshold is None:
        return detections

    return [detection for detection in detections if
            _does_severity_match_severity_threshold(detection.detection_details.get('advisory_severity'),
                                                    severity_threshold)]


def exclude_detections_by_scan_type(scan_type: str, command_scan_type: str, detections) -> List:
    if command_scan_type == PRE_COMMIT_COMMAND_SCAN_TYPE:
        return exclude_detections_in_deleted_lines(detections)

    if command_scan_type in COMMIT_RANGE_BASED_COMMAND_SCAN_TYPES \
            and scan_type == SECRET_SCAN_TYPE \
            and configuration_manager.get_should_exclude_detections_in_deleted_lines(command_scan_type):
        return exclude_detections_in_deleted_lines(detections)
    return detections


def exclude_detections_in_deleted_lines(detections) -> List:
    return [detection for detection in detections if detection.detection_details.get('line_type') != 'Removed']


def exclude_detections_by_exclusions_configuration(scan_type: str, detections) -> List:
    exclusions = configuration_manager.get_exclusions_by_scan_type(scan_type)
    return [detection for detection in detections if not _should_exclude_detection(detection, exclusions)]


def get_pre_commit_modified_documents():
    repo = Repo(os.getcwd())
    diff_files = repo.index.diff(GIT_HEAD_COMMIT_REV, create_patch=True, R=True)
    git_head_documents = []
    pre_committed_documents = []
    for file in diff_files:
        diff_file_path = get_diff_file_path(file)
        file_path = get_path_by_os(diff_file_path)

        file_content = sca_code_scanner.get_file_content_from_commit(repo, GIT_HEAD_COMMIT_REV, diff_file_path)
        if file_content is not None:
            git_head_documents.append(Document(file_path, file_content))

        if os.path.exists(file_path):
            file_content = get_file_content(file_path)
            pre_committed_documents.append(Document(file_path, file_content))

    return git_head_documents, pre_committed_documents


def get_commit_range_modified_documents(path: str, from_commit_rev: str, to_commit_rev: str) -> (
        List[Document], List[Document]):
    from_commit_documents = []
    to_commit_documents = []
    repo = Repo(path)
    diff = repo.commit(from_commit_rev).diff(to_commit_rev)
    modified_files_diff = [change for change in diff if change.change_type != COMMIT_DIFF_DELETED_FILE_CHANGE_TYPE]
    for blob in modified_files_diff:
        diff_file_path = get_diff_file_path(blob)
        file_path = get_path_by_os(diff_file_path)

        file_content = sca_code_scanner.get_file_content_from_commit(repo, from_commit_rev, diff_file_path)
        if file_content is not None:
            from_commit_documents.append(Document(file_path, file_content))

        file_content = sca_code_scanner.get_file_content_from_commit(repo, to_commit_rev, diff_file_path)
        if file_content is not None:
            to_commit_documents.append(Document(file_path, file_content))

    return from_commit_documents, to_commit_documents


def _should_exclude_detection(detection, exclusions: Dict) -> bool:
    exclusions_by_value = exclusions.get(EXCLUSIONS_BY_VALUE_SECTION_NAME, [])
    if _is_detection_sha_configured_in_exclusions(detection, exclusions_by_value):
        logger.debug('Going to ignore violations because is in the values to ignore list, %s',
                     {'sha': detection.detection_details.get('sha512', '')})
        return True

    exclusions_by_sha = exclusions.get(EXCLUSIONS_BY_SHA_SECTION_NAME, [])
    if _is_detection_sha_configured_in_exclusions(detection, exclusions_by_sha):
        logger.debug('Going to ignore violations because is in the shas to ignore list, %s',
                     {'sha': detection.detection_details.get('sha512', '')})
        return True

    exclusions_by_rule = exclusions.get(EXCLUSIONS_BY_RULE_SECTION_NAME, [])
    if exclusions_by_rule:
        detection_rule = detection.detection_rule_id
        if detection_rule in exclusions_by_rule:
            logger.debug('Going to ignore violations because is in the shas to ignore list, %s',
                         {'detection_rule': detection_rule})
            return True

    exclusions_by_package = exclusions.get(EXCLUSIONS_BY_PACKAGE_SECTION_NAME, [])
    if exclusions_by_package:
        package = _get_package_name(detection)
        if package in exclusions_by_package:
            logger.debug('Going to ignore violations because is in the packages to ignore list, %s',
                         {'package': package})
            return True

    return False


def _is_detection_sha_configured_in_exclusions(detection, exclusions: List[str]) -> bool:
    detection_sha = detection.detection_details.get('sha512', '')
    return detection_sha in exclusions


def _is_path_configured_in_exclusions(scan_type: str, file_path: str) -> bool:
    exclusions_by_path = configuration_manager.get_exclusions_by_scan_type(scan_type).get(
        EXCLUSIONS_BY_PATH_SECTION_NAME, [])
    for exclusion_path in exclusions_by_path:
        if is_sub_path(exclusion_path, file_path):
            return True
    return False


def _get_package_name(detection) -> str:
    package_name = detection.detection_details.get('vulnerable_component', '')
    package_version = detection.detection_details.get('vulnerable_component_version', '')

    if package_name == '':
        package_name = detection.detection_details.get('package_name', '')
        package_version = detection.detection_details.get('package_version', '')

    return f'{package_name}@{package_version}'


def _is_file_relevant_for_sca_scan(filename: str) -> bool:
    if any([sca_excluded_path in filename for sca_excluded_path in SCA_EXCLUDED_PATHS]):
        logger.debug("file is irrelevant because it is from node_modules's inner path, %s",
                     {'filename': filename})
        return False
    return True


def _is_relevant_file_to_scan(scan_type: str, filename: str) -> bool:
    if _is_subpath_of_cycode_configuration_folder(filename):
        logger.debug("file is irrelevant because it is in cycode configuration directory, %s",
                     {'filename': filename})
        return False

    if _is_path_configured_in_exclusions(scan_type, filename):
        logger.debug("file is irrelevant because the file path is in the ignore paths list, %s",
                     {'filename': filename})
        return False

    if not _is_file_extension_supported(scan_type, filename):
        logger.debug("file is irrelevant because the file extension is not supported, %s",
                     {'filename': filename})
        return False

    if is_binary_file(filename):
        logger.debug("file is irrelevant because it is binary file, %s",
                     {'filename': filename})
        return False

    if scan_type != SCA_SCAN_TYPE and _does_file_exceed_max_size_limit(filename):
        logger.debug("file is irrelevant because its exceeded max size limit, %s",
                     {'filename': filename})
        return False

    if scan_type == SCA_SCAN_TYPE and not _is_file_relevant_for_sca_scan(filename):
        return False

    return True


def _is_relevant_document_to_scan(scan_type: str, filename: str, content: str) -> bool:
    if _is_subpath_of_cycode_configuration_folder(filename):
        logger.debug("document is irrelevant because it is in cycode configuration directory, %s",
                     {'filename': filename})
        return False

    if _is_path_configured_in_exclusions(scan_type, filename):
        logger.debug("document is irrelevant because the document path is in the ignore paths list, %s",
                     {'filename': filename})
        return False

    if not _is_file_extension_supported(scan_type, filename):
        logger.debug("document is irrelevant because the file extension is not supported, %s",
                     {'filename': filename})
        return False

    if is_binary_content(content):
        logger.debug("document is irrelevant because it is binary, %s",
                     {'filename': filename})
        return False

    if scan_type != SCA_SCAN_TYPE and _does_document_exceed_max_size_limit(content):
        logger.debug("document is irrelevant because its exceeded max size limit, %s",
                     {'filename': filename})
        return False
    return True


def _is_file_extension_supported(scan_type: str, filename: str) -> bool:
    if scan_type == INFRA_CONFIGURATION_SCAN_TYPE:
        return any(filename.lower().endswith(supported_file_extension) for supported_file_extension in
                   INFRA_CONFIGURATION_SCAN_SUPPORTED_FILES)
    if scan_type == SCA_SCAN_TYPE:
        return any(filename.lower().endswith(supported_file) for supported_file in
                   SCA_CONFIGURATION_SCAN_SUPPORTED_FILES)
    return all(not filename.lower().endswith(file_extension_to_ignore) for file_extension_to_ignore in
               SECRET_SCAN_FILE_EXTENSIONS_TO_IGNORE)


def _does_file_exceed_max_size_limit(filename: str) -> bool:
    return FILE_MAX_SIZE_LIMIT_IN_BYTES < get_file_size(filename)


def _get_document_by_file_name(documents: List[Document], file_name: str, unique_id: Optional[str] = None) \
        -> Optional[Document]:
    return next(
        (document for document in documents if _normalize_file_path(document.path) == _normalize_file_path(file_name)
         and document.unique_id == unique_id), None)


def _does_document_exceed_max_size_limit(content: str) -> bool:
    return FILE_MAX_SIZE_LIMIT_IN_BYTES < get_content_size(content)


def _is_subpath_of_cycode_configuration_folder(filename: str) -> bool:
    return is_sub_path(configuration_manager.global_config_file_manager.get_config_directory_path(), filename) \
        or is_sub_path(configuration_manager.local_config_file_manager.get_config_directory_path(), filename) \
        or filename.endswith(ConfigFileManager.get_config_file_route())


def _handle_exception(context: click.Context, e: Exception):
    context.obj['did_fail'] = True

    if context.obj['verbose']:
        click.secho(f'Error: {traceback.format_exc()}', fg='red', nl=False)

    errors: CliErrors = {
        NetworkError: CliError(
            soft_fail=True,
            code='cycode_error',
            message='Cycode was unable to complete this scan. '
                    'Please try again by executing the `cycode scan` command'
        ),
        ScanAsyncError: CliError(
            soft_fail=True,
            code='scan_error',
            message='Cycode was unable to complete this scan. '
                    'Please try again by executing the `cycode scan` command'
        ),
        HttpUnauthorizedError: CliError(
            soft_fail=True,
            code='auth_error',
            message='Unable to authenticate to Cycode, your token is either invalid or has expired. '
                    'Please re-generate your token and reconfigure it by running the `cycode configure` command'
        ),
        ZipTooLargeError: CliError(
            soft_fail=True,
            code='zip_too_large_error',
            message='The path you attempted to scan exceeds the current maximum scanning size cap (10MB). '
                    'Please try ignoring irrelevant paths using the ‘cycode ignore --by-path’ command '
                    'and execute the scan again'
        ),
        InvalidGitRepositoryError: CliError(
            soft_fail=False,
            code='invalid_git_error',
            message='The path you supplied does not correlate to a git repository. '
                    'Should you still wish to scan this path, use: ‘cycode scan path <path>’'
        ),
    }

    if type(e) in errors:
        error = errors[type(e)]

        if error.soft_fail is True:
            context.obj['soft_fail'] = True

        return ConsolePrinter(context).print_error(error)

    if isinstance(e, click.ClickException):
        raise e

    raise click.ClickException(str(e))


def _report_scan_status(context: click.Context, scan_type: str, scan_id: str, scan_completed: bool,
                        output_detections_count: int, all_detections_count: int, files_to_scan_count: int,
                        zip_size: int, command_scan_type: str, error_message: Optional[str]):
    try:
        cycode_client = context.obj["client"]
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
            'scan_type': scan_type
        }

        cycode_client.report_scan_status(scan_type, scan_id, scan_status)
    except Exception as e:
        logger.debug('Failed to report scan status, %s', {'exception_message': str(e)})
        pass


def _get_scan_id(context: click.Context):
    scan_id = uuid4()
    context.obj['scan_id'] = scan_id
    return scan_id


def _does_severity_match_severity_threshold(severity: str, severity_threshold: str) -> bool:
    detection_severity_value = Severity.try_get_value(severity)
    if detection_severity_value is None:
        return True

    return detection_severity_value >= Severity.try_get_value(severity_threshold)


def _get_scan_result(cycode_client, scan_id: str, scan_details: ScanDetailsResponse) -> ZippedFileScanResult:
    scan_result = init_default_scan_result(scan_id, scan_details.metadata)
    if not scan_details.detections_count:
        return scan_result

    wait_for_detections_creation(cycode_client, scan_id, scan_details.detections_count)
    scan_detections = cycode_client.get_scan_detections(scan_id)
    scan_result.detections_per_file = _map_detections_per_file(scan_detections)
    scan_result.did_detect = True
    return scan_result


def init_default_scan_result(scan_id: str, scan_metadata: str = None) -> ZippedFileScanResult:
    return ZippedFileScanResult(did_detect=False, detections_per_file=[],
                                scan_id=scan_id,
                                report_url=_try_get_report_url(scan_metadata))


def _try_get_report_url(metadata: str) -> Optional[str]:
    if metadata is None:
        return None
    try:
        metadata = json.loads(metadata)
        return metadata.get('report_url')
    except ValueError:
        return None


def wait_for_detections_creation(cycode_client, scan_id: str, expected_detections_count: int):
    logger.debug("waiting for detections to be created")
    scan_persisted_detections_count = 0
    end_polling_time = time.time() + DETECTIONS_COUNT_VERIFICATION_TIMEOUT_IN_SECONDS
    spinner = Halo(spinner='dots')
    spinner.start("Please wait until printing scan result...")
    while time.time() < end_polling_time:
        scan_persisted_detections_count = cycode_client.get_scan_detections_count(scan_id)
        if scan_persisted_detections_count == expected_detections_count:
            spinner.succeed()
            return
        time.sleep(DETECTIONS_COUNT_VERIFICATION_WAIT_INTERVAL_IN_SECONDS)
    spinner.stop_and_persist(symbol="⏰".encode('utf-8'), text='Timeout')
    logger.debug("%i detections has been created", scan_persisted_detections_count)


def _map_detections_per_file(detections) -> List[DetectionsPerFile]:
    detections_per_files = {}
    for detection in detections:
        try:
            detection['message'] = detection['correlation_message']
            file_name = _get_file_name_from_detection(detection)
            if file_name is None:
                logger.debug("file name is missing from detection with id %s", detection.get('id'))
                continue
            if detections_per_files.get(file_name) is None:
                detections_per_files[file_name] = [DetectionSchema().load(detection)]
            else:
                detections_per_files[file_name].append(DetectionSchema().load(detection))
        except Exception as e:
            logger.debug("Failed to parse detection: %s", str(e))
            continue

    return [DetectionsPerFile(file_name=file_name, detections=file_detections)
            for file_name, file_detections in detections_per_files.items()]


def _get_file_name_from_detection(detection):
    if detection['category'] == "SAST":
        return detection['detection_details']['file_path']

    return detection['detection_details']['file_name']


def _does_reach_to_max_commits_to_scan_limit(commit_ids: List, max_commits_count: Optional[int]) -> bool:
    return max_commits_count is not None and len(commit_ids) >= max_commits_count


def _should_update_progress(scanned_commits_count: int) -> bool:
    return scanned_commits_count and scanned_commits_count % PROGRESS_UPDATE_COMMITS_INTERVAL == 0


def parse_commit_range(commit_range: str, path: str) -> (str, str):
    from_commit_rev = None
    to_commit_rev = None
    for commit in Repo(path).iter_commits(rev=commit_range):
        if not to_commit_rev:
            to_commit_rev = commit.hexsha
        from_commit_rev = commit.hexsha

    return from_commit_rev, to_commit_rev


def _normalize_file_path(path: str):
    if path.startswith("/"):
        return path[1:]
    if path.startswith("./"):
        return path[2:]
    return path


def perform_post_pre_receive_scan_actions(context: click.Context):
    if scan_utils.is_scan_failed(context):
        click.echo(PRE_RECEIVE_REMEDIATION_MESSAGE)


def enable_verbose_mode(context: click.Context):
    context.obj["verbose"] = True
    logger.setLevel(logging.DEBUG)


def is_verbose_mode_requested_in_pre_receive_scan() -> bool:
    return does_git_push_option_have_value(VERBOSE_SCAN_FLAG)


def should_skip_pre_receive_scan() -> bool:
    return does_git_push_option_have_value(SKIP_SCAN_FLAG)


def does_git_push_option_have_value(value: str) -> bool:
    option_count_env_value = os.getenv(GIT_PUSH_OPTION_COUNT_ENV_VAR_NAME, '')
    option_count = int(option_count_env_value) if option_count_env_value.isdigit() else 0
    return any(os.getenv(f'{GIT_PUSH_OPTION_ENV_VAR_PREFIX}{i}') == value for i in range(option_count))
