import click
import os
import time
import traceback
from platform import platform
from uuid import uuid4, UUID
from typing import Optional
from git import Repo, NULL_TREE, InvalidGitRepositoryError
from sys import getsizeof
from cli.printers import ResultsPrinter
from typing import List, Dict
from cli.models import Document, DocumentDetections
from cli.ci_integrations import get_commit_range
from cli.consts import SECRET_SCAN_TYPE, INFRA_CONFIGURATION_SCAN_TYPE, INFRA_CONFIGURATION_SCAN_SUPPORTED_FILES, \
    SECRET_SCAN_FILE_EXTENSIONS_TO_IGNORE, EXCLUSIONS_BY_VALUE_SECTION_NAME, EXCLUSIONS_BY_SHA_SECTION_NAME, \
    EXCLUSIONS_BY_RULE_SECTION_NAME, EXCLUSIONS_BY_PATH_SECTION_NAME, FILE_MAX_SIZE_LIMIT_IN_BYTES, \
    PRE_COMMIT_SCAN_COMMAND_TYPE, ZIP_MAX_SIZE_LIMIT_IN_BYTES
from cli.config import configuration_manager
from cli.utils.path_utils import is_sub_path, is_binary_file, get_file_size, get_relevant_files_in_path, get_path_by_os
from cli.utils.string_utils import get_content_size, is_binary_content
from cli.zip_file import InMemoryZip
from cli.exceptions.custom_exceptions import CycodeError, HttpUnauthorizedError, ZipTooLargeError
from cyclient import logger
from cyclient.models import ZippedFileScanResult

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
        documents_to_scan = [
            Document(get_path_by_os(obj.path), obj.data_stream.read().decode('utf-8', errors='replace'))
            for obj
            in get_git_repository_tree_file_entries(path, branch)]
        documents_to_scan = exclude_irrelevant_documents_to_scan(context, documents_to_scan)
        logger.debug('Found all relevant files for scanning %s', {'path': path, 'branch': branch})
        return scan_documents(context, documents_to_scan, is_git_diff=False)
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


def scan_commit_range(context: click.Context, path: str, commit_range: str):
    scan_type = context.obj["scan_type"]

    if scan_type != SECRET_SCAN_TYPE:
        raise click.ClickException(f"Commit range scanning for {str.upper(scan_type)} is not supported")

    documents_to_scan = []
    for commit in Repo(path).iter_commits(rev=commit_range):
        commit_id = commit.hexsha
        parent = commit.parents[0] if commit.parents else NULL_TREE
        diff = commit.diff(parent, create_patch=True, R=True)
        for blob in diff:
            doc = Document(get_path_by_os(get_diff_file_path(blob)),
                           blob.diff.decode('utf-8', errors='replace'), True, commit_id)
            documents_to_scan.append(doc)

            documents_to_scan = exclude_irrelevant_documents_to_scan(context, documents_to_scan)
            logger.debug('Found all relevant files for scanning %s', {'path': path, 'commit_range': commit_range})
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
    files_to_scan = get_relevant_files_in_path(path=path, exclude_patterns=["**/.git/**", "**/.cycode/**"])
    files_to_scan = exclude_irrelevant_files(context, files_to_scan)
    logger.debug('Found all relevant files for scanning %s', {'path': path, 'file_to_scan_count': len(files_to_scan)})
    return scan_disk_files(context, files_to_scan)


@click.command()
@click.argument("ignored_args", nargs=-1, type=click.UNPROCESSED)
@click.pass_context
def pre_commit_scan(context: click.Context, ignored_args: List[str]):
    """ Use this command to scan the content that was not committed yet """
    diff_files = Repo(os.getcwd()).index.diff("HEAD", create_patch=True, R=True)
    documents_to_scan = [Document(get_path_by_os(get_diff_file_path(file)), get_diff_file_content(file))
                         for file in diff_files]
    documents_to_scan = exclude_irrelevant_documents_to_scan(context, documents_to_scan)
    return scan_documents(context, documents_to_scan, is_git_diff=True)


def scan_disk_files(context: click.Context, paths: List[str]):
    is_git_diff = False
    documents = []
    for path in paths:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
            documents.append(Document(path, content, is_git_diff))

    return scan_documents(context, documents, is_git_diff=is_git_diff)


def scan_documents(context: click.Context, documents_to_scan: List[Document],
                   is_git_diff: bool = False, is_commit_range: bool = False):
    cycode_client = context.obj["client"]
    scan_type = context.obj["scan_type"]
    scan_command_type = context.info_name
    error_message = None
    all_detections_count = 0
    output_detections_count = 0
    scan_id = uuid4()
    zipped_documents = InMemoryZip()

    try:
        zipped_documents = zip_documents_to_scan(zipped_documents, documents_to_scan)
        scan_result = perform_scan(cycode_client, zipped_documents, scan_type, scan_id, is_git_diff, is_commit_range)
        document_detections_list = enrich_scan_result(scan_result, documents_to_scan)
        relevant_document_detections_list = exclude_irrelevant_scan_results(document_detections_list, scan_type,
                                                                            scan_command_type)
        print_results(context, relevant_document_detections_list)

        context.obj['issue_detected'] = len(relevant_document_detections_list) > 0
        all_detections_count = sum(
            [len(document_detections.detections) for document_detections in document_detections_list])
        output_detections_count = sum(
            [len(document_detections.detections) for document_detections in relevant_document_detections_list])
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
                        all_detections_count, len(documents_to_scan), zip_file_size, scan_command_type, error_message)


def zip_documents_to_scan(zip: InMemoryZip, documents: List[Document]):
    start_zip_creation_time = time.time()
    for index, document in enumerate(documents):
        zip_file_size = getsizeof(zip.in_memory_zip)
        if zip_file_size > ZIP_MAX_SIZE_LIMIT_IN_BYTES:
            raise ZipTooLargeError(ZIP_MAX_SIZE_LIMIT_IN_BYTES)

        logger.debug('adding file to zip, %s', {'index': index, 'filename': document.path})
        zip.append(document.path, document.unique_id, document.content)
    zip.close()

    end_zip_creation_time = time.time()
    zip_creation_time = int(end_zip_creation_time - start_zip_creation_time)
    logger.debug('finished to create zip file, %s', {'zip_creation_time': zip_creation_time})
    return zip


def perform_scan(cycode_client, zipped_documents: InMemoryZip, scan_type: str, scan_id: UUID, is_git_diff: bool,
                 is_commit_range: bool):
    scan_result = cycode_client.commit_range_zipped_file_scan(scan_type, zipped_documents, scan_id) \
        if is_commit_range else cycode_client.zipped_file_scan(scan_type, zipped_documents, scan_id, is_git_diff)

    return scan_result


def print_results(context: click.Context, document_detections_list: List[DocumentDetections]):
    output_type = context.obj['output']
    printer = ResultsPrinter()
    printer.print_results(context, document_detections_list, output_type)


def enrich_scan_result(scan_result: ZippedFileScanResult, documents_to_scan: List[Document]) -> List[
    DocumentDetections]:
    logger.debug('enriching scan result')
    document_detections_list = []
    for detections_per_file in scan_result.detections_per_file:
        file_name = get_path_by_os(detections_per_file.file_name)
        logger.debug("going to find document of violated file, %s", {'file_name': file_name})
        document = _get_document_by_file_name(documents_to_scan, file_name)
        document_detections_list.append(
            DocumentDetections(document=document, detections=detections_per_file.detections))

    return document_detections_list


def exclude_irrelevant_scan_results(document_detections_list: List[DocumentDetections], scan_type: str,
                                    scan_command_type: str) -> List[DocumentDetections]:
    relevant_document_detections_list = []
    for document_detections in document_detections_list:
        relevant_detections = exclude_irrelevant_detections(scan_type, scan_command_type,
                                                            document_detections.detections)
        if relevant_detections:
            relevant_document_detections_list.append(DocumentDetections(document=document_detections.document,
                                                                        detections=relevant_detections))

    return relevant_document_detections_list


def get_diff_file_path(file):
    return file.b_path if file.b_path else file.a_path


def get_diff_file_content(file):
    return file.diff.decode('utf-8', errors='replace')


def should_process_git_object(obj, depth):
    return obj.type == 'blob' and obj.size > 0


def get_git_repository_tree_file_entries(path: str, branch: str):
    return Repo(path).tree(branch).traverse(predicate=should_process_git_object)


def exclude_irrelevant_documents_to_scan(context: click.Context, documents_to_scan: List[Document]) -> \
        List[Document]:
    scan_type = context.obj['scan_type']
    logger.debug("excluding irrelevant documents to scan")
    return [document for document in documents_to_scan if
            _is_relevant_document_to_scan(scan_type, document.path, document.content)]


def exclude_irrelevant_files(context: click.Context, filenames: List[str]) -> List[str]:
    scan_type = context.obj['scan_type']
    return [filename for filename in filenames if _is_relevant_file_to_scan(scan_type, filename)]


def exclude_irrelevant_detections(scan_type: str, scan_command_type: str, detections) -> List:
    relevant_detections = exclude_detections_by_exclusions_configuration(scan_type, detections)
    relevant_detections = exclude_detections_by_scan_command_type(scan_command_type, relevant_detections)
    return relevant_detections


def exclude_detections_by_scan_command_type(scan_command_type: str, detections) -> List:
    if scan_command_type != PRE_COMMIT_SCAN_COMMAND_TYPE:
        return detections

    return exclude_detections_for_pre_commit_scan_command_type(detections)


def exclude_detections_for_pre_commit_scan_command_type(detections) -> List:
    return [detection for detection in detections if detection.detection_details.get('line_type') != 'Removed']


def exclude_detections_by_exclusions_configuration(scan_type: str, detections) -> List:
    exclusions = configuration_manager.get_exclusions_by_scan_type(scan_type)
    return [detection for detection in detections if not _should_exclude_detection(detection, exclusions)]


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

    if _does_file_exceed_max_size_limit(filename):
        logger.debug("file is irrelevant because its exceeded max size limit, %s",
                     {'filename': filename})
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

    if _does_document_exceed_max_size_limit(content):
        logger.debug("document is irrelevant because its exceeded max size limit, %s",
                     {'filename': filename})
        return False
    return True


def _is_file_extension_supported(scan_type: str, filename: str) -> bool:
    if scan_type == INFRA_CONFIGURATION_SCAN_TYPE:
        return any(filename.lower().endswith(supported_file_extension) for supported_file_extension in
                   INFRA_CONFIGURATION_SCAN_SUPPORTED_FILES)
    return all(not filename.lower().endswith(file_extension_to_ignore) for file_extension_to_ignore in
               SECRET_SCAN_FILE_EXTENSIONS_TO_IGNORE)


def _does_file_exceed_max_size_limit(filename: str) -> bool:
    return FILE_MAX_SIZE_LIMIT_IN_BYTES < get_file_size(filename)


def _get_document_by_file_name(documents: List[Document], file_name: str) -> Optional[Document]:
    return next((document for document in documents if document.path == file_name), None)


def _does_document_exceed_max_size_limit(content: str) -> bool:
    return FILE_MAX_SIZE_LIMIT_IN_BYTES < get_content_size(content)


def _is_subpath_of_cycode_configuration_folder(filename: str) -> bool:
    return is_sub_path(configuration_manager.global_config_file_manager.get_config_directory_path(), filename) \
           or is_sub_path(configuration_manager.local_config_file_manager.get_config_directory_path(), filename)


def _handle_exception(context: click.Context, e: Exception):
    context.obj["did_fail"] = True
    verbose = context.obj["verbose"]
    if verbose:
        click.secho(f'Error: {traceback.format_exc()}', fg='red', nl=False)
    if isinstance(e, CycodeError):
        click.secho('Cycode was unable to complete this scan. Please try again by executing the `cycode scan` command',
                    fg='red', nl=False)
        context.obj["soft_fail"] = True
    elif isinstance(e, HttpUnauthorizedError):
        click.secho('Unable to authenticate to Cycode, your token is either invalid or has expired. '
                    'Please re-generate your token and reconfigure it by running the `cycode configure` command',
                    fg='red', nl=False)
        context.obj["soft_fail"] = True
    elif isinstance(e, ZipTooLargeError):
        click.secho('The path you attempted to scan exceeds the current maximum scanning size cap (10MB). '
                    'Please try ignoring irrelevant paths using the ‘cycode ignore --by-path’ '
                    'command and execute the scan again',
                    fg='red', nl=False)
        context.obj["soft_fail"] = True
    elif isinstance(e, InvalidGitRepositoryError):
        click.secho('The path you supplied does not correlate to a git repository. Should you still wish to scan '
                    'this path, use: ‘cycode scan path <path>’',
                    fg='red', nl=False)
    elif isinstance(e, click.ClickException):
        raise e
    else:
        raise click.ClickException(str(e))


def _report_scan_status(context: click.Context, scan_type: str, scan_id: str, scan_completed: bool,
                        output_detections_count: int, all_detections_count: int, files_to_scan_count: int,
                        zip_size: int, scan_command_type: str, error_message: Optional[str]):
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
            'scan_command_type': scan_command_type,
            'operation_system': platform(),
            'error_message': error_message
        }

        cycode_client.report_scan_status(scan_type, scan_id, scan_status)
    except Exception as e:
        logger.debug('Failed to report scan status, %s', {'exception_message': str(e)})
        pass
