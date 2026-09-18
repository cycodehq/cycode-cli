import os
import zipfile
from os.path import normpath
from unittest.mock import MagicMock, Mock, patch

import pytest

from cycode.cli import consts
from cycode.cli.apps.scan.code_scanner import (
    _get_scan_documents_thread_func,
    _perform_scan,
    _run_presigned_upload_scan,
    scan_disk_files,
    scan_documents,
)
from cycode.cli.exceptions import custom_exceptions
from cycode.cli.files_collector.file_excluder import _is_file_relevant_for_sca_scan
from cycode.cli.files_collector.path_documents import _generate_document
from cycode.cli.models import Document


def test_is_file_relevant_for_sca_scan() -> None:
    path = os.path.join('some_package', 'node_modules', 'package.json')
    assert _is_file_relevant_for_sca_scan(path) is False
    path = os.path.join('some_package', 'node_modules', 'package.lock')
    assert _is_file_relevant_for_sca_scan(path) is False
    path = os.path.join('some_package', 'package.json')
    assert _is_file_relevant_for_sca_scan(path) is True
    path = os.path.join('some_package', 'package.lock')
    assert _is_file_relevant_for_sca_scan(path) is True


def test_generate_document() -> None:
    is_git_diff = False

    path = 'path/to/nowhere.txt'
    content = 'nothing important here'

    non_iac_document = Document(path, content, is_git_diff)
    generated_document = _generate_document(path, consts.SCA_SCAN_TYPE, content, is_git_diff)

    assert non_iac_document.path == generated_document.path
    assert non_iac_document.content == generated_document.content
    assert non_iac_document.is_git_diff_format == generated_document.is_git_diff_format

    path = 'path/to/nowhere.tf'
    content = """provider "aws" {
        profile = "chili"
        region = "us-east-1"
        }

        resource "aws_s3_bucket" "chili-env-var-test" {
          bucket = "chili-env-var-test"
        }"""

    iac_document = Document(path, content, is_git_diff)
    generated_document = _generate_document(path, consts.IAC_SCAN_TYPE, content, is_git_diff)
    assert iac_document.path == generated_document.path
    assert iac_document.content == generated_document.content
    assert iac_document.is_git_diff_format == generated_document.is_git_diff_format

    content = """
    {
       "resource_changes":[
          {
             "type":"aws_s3_bucket_public_access_block",
             "name":"efrat-env-var-test",
             "change":{
                "actions":[
                   "create"
                ],
                "after":{
                   "block_public_acls":false,
                   "block_public_policy":true,
                   "ignore_public_acls":false,
                   "restrict_public_buckets":true
                }
             }
          ]
       }
    """

    generated_tfplan_document = _generate_document(path, consts.IAC_SCAN_TYPE, content, is_git_diff)

    assert isinstance(generated_tfplan_document, Document)
    assert generated_tfplan_document.path.endswith('.tf')
    assert generated_tfplan_document.is_git_diff_format == is_git_diff


@patch('cycode.cli.apps.scan.code_scanner.get_relevant_documents')
@patch('cycode.cli.apps.scan.code_scanner.scan_documents')
@patch('cycode.cli.apps.scan.code_scanner.get_scan_parameters')
@patch('cycode.cli.apps.scan.code_scanner.os.path.isdir')
def test_entrypoint_cycode_added_to_documents(
    mock_isdir: Mock,
    mock_get_scan_parameters: Mock,
    mock_scan_documents: Mock,
    mock_get_relevant_documents: Mock,
) -> None:
    """Test that entrypoint.cycode file is added to documents in scan_disk_files."""
    # Arrange
    mock_ctx = MagicMock()
    mock_ctx.obj = {
        'scan_type': consts.SAST_SCAN_TYPE,
        'progress_bar': MagicMock(),
    }
    mock_get_scan_parameters.return_value = {}
    mock_isdir.return_value = True  # Path is a directory

    mock_documents = [
        Document('/test/path/file1.py', 'content1', is_git_diff_format=False),
        Document('/test/path/file2.js', 'content2', is_git_diff_format=False),
    ]
    mock_get_relevant_documents.return_value = mock_documents.copy()
    test_path = '/Users/test/repositories'

    # Act
    scan_disk_files(mock_ctx, (test_path,))

    # Assert
    call_args = mock_scan_documents.call_args
    documents_passed = call_args[0][1]

    # Verify entrypoint document was added
    entrypoint_docs = [doc for doc in documents_passed if doc.path.endswith(consts.CYCODE_ENTRYPOINT_FILENAME)]
    assert len(entrypoint_docs) == 1

    entrypoint_doc = entrypoint_docs[0]
    # Normalize paths for cross-platform compatibility
    expected_path = normpath(os.path.join(os.path.abspath(test_path), consts.CYCODE_ENTRYPOINT_FILENAME))
    assert normpath(entrypoint_doc.path) == expected_path
    assert entrypoint_doc.content == ''
    assert entrypoint_doc.is_git_diff_format is False
    assert normpath(entrypoint_doc.absolute_path) == normpath(entrypoint_doc.path)


@patch('cycode.cli.apps.scan.code_scanner.get_relevant_documents')
@patch('cycode.cli.apps.scan.code_scanner.scan_documents')
@patch('cycode.cli.apps.scan.code_scanner.get_scan_parameters')
@patch('cycode.cli.apps.scan.code_scanner.os.path.isdir')
def test_entrypoint_cycode_not_added_for_single_file(
    mock_isdir: Mock,
    mock_get_scan_parameters: Mock,
    mock_scan_documents: Mock,
    mock_get_relevant_documents: Mock,
) -> None:
    """Test that entrypoint.cycode file is NOT added when path is a single file."""
    # Arrange
    mock_ctx = MagicMock()
    mock_ctx.obj = {
        'scan_type': consts.SAST_SCAN_TYPE,
        'progress_bar': MagicMock(),
    }
    mock_get_scan_parameters.return_value = {}
    mock_isdir.return_value = False  # Path is a file, not a directory

    mock_documents = [
        Document('/test/path/file1.py', 'content1', is_git_diff_format=False),
    ]
    mock_get_relevant_documents.return_value = mock_documents.copy()
    test_path = '/Users/test/file.py'

    # Act
    scan_disk_files(mock_ctx, (test_path,))

    # Assert
    call_args = mock_scan_documents.call_args
    documents_passed = call_args[0][1]

    # Verify entrypoint document was NOT added
    entrypoint_docs = [doc for doc in documents_passed if doc.path.endswith(consts.CYCODE_ENTRYPOINT_FILENAME)]
    assert len(entrypoint_docs) == 0
    # Verify only the original documents are present
    assert len(documents_passed) == len(mock_documents)


@pytest.mark.parametrize(
    ('scan_type', 'command_scan_type', 'sync_option', 'expect_presigned'),
    [
        # SAST keeps uploading directly to S3 via a presigned URL (regression guard for the new sync gate).
        (consts.SAST_SCAN_TYPE, 'path', False, True),
        # Async secret scans now upload as a single file directly to S3 via a presigned URL.
        (consts.SECRET_SCAN_TYPE, 'path', False, True),
        # A --sync secret scan must stay on the batched inline path and never build one giant zip.
        (consts.SECRET_SCAN_TYPE, 'path', True, False),
    ],
)
@patch('cycode.cli.apps.scan.code_scanner.print_local_scan_results')
@patch('cycode.cli.apps.scan.code_scanner.set_issue_detected_by_scan_results')
@patch('cycode.cli.apps.scan.code_scanner.try_set_aggregation_report_url_if_needed')
@patch('cycode.cli.apps.scan.code_scanner.run_parallel_batched_scan')
@patch('cycode.cli.apps.scan.code_scanner._run_presigned_upload_scan')
def test_scan_documents_routes_upload_by_scan_type_and_sync(
    mock_presigned_upload: Mock,
    mock_batched_scan: Mock,
    mock_aggregation: Mock,
    mock_set_issue: Mock,
    mock_print: Mock,
    scan_type: str,
    command_scan_type: str,
    sync_option: bool,
    expect_presigned: bool,
) -> None:
    mock_presigned_upload.return_value = ([], [])
    mock_batched_scan.return_value = ([], [])

    mock_ctx = MagicMock()
    mock_ctx.info_name = command_scan_type
    mock_ctx.obj = {
        'scan_type': scan_type,
        'progress_bar': MagicMock(),
        'console_printer': MagicMock(),
        'client': MagicMock(),
        'severity_threshold': None,
        'sync': sync_option,
    }
    documents = [Document('/repo/file.py', 'content', is_git_diff_format=False)]

    scan_documents(mock_ctx, documents, {})

    assert mock_presigned_upload.called is expect_presigned
    assert mock_batched_scan.called is (not expect_presigned)


@patch('cycode.cli.apps.scan.code_scanner._perform_scan_async')
@patch('cycode.cli.apps.scan.code_scanner._perform_scan_v4_async')
def test_perform_scan_falls_back_to_api_when_presigned_upload_raises_wrapped_error(
    mock_v4_async: Mock, mock_async: Mock
) -> None:
    # RequestConnectionError is a CycodeError, not a requests.RequestException — the fallback must still catch it.
    mock_v4_async.side_effect = custom_exceptions.RequestConnectionError
    fallback_result = object()
    mock_async.return_value = fallback_result

    result = _perform_scan(
        cycode_client=MagicMock(),
        zipped_documents=MagicMock(),
        scan_type=consts.SAST_SCAN_TYPE,
        is_git_diff=False,
        is_commit_range=False,
        scan_parameters={},
    )

    assert result is fallback_result
    mock_v4_async.assert_called_once()
    mock_async.assert_called_once()


def _presigned_scan_ctx() -> MagicMock:
    ctx = MagicMock()
    ctx.obj = {
        'client': MagicMock(),
        'scan_type': consts.SECRET_SCAN_TYPE,
        'severity_threshold': None,
        'sync': False,
        'progress_bar': MagicMock(),
    }
    return ctx


@pytest.mark.parametrize(
    ('is_64bit', 'expected_skip_batching', 'expected_zip_calls'),
    [
        # 64-bit: ZIP64 lifts the entries limit, so everything still goes up as a single ZIP
        (True, True, 1),
        # 32-bit: the archive can't hold that many entries; route to batches without zipping first
        (False, None, 0),
    ],
)
@patch('cycode.cli.apps.scan.code_scanner.run_parallel_batched_scan')
@patch('cycode.cli.apps.scan.code_scanner.zip_documents')
@patch('cycode.cli.apps.scan.code_scanner.is_64bit')
def test_run_presigned_upload_scan_routes_by_files_count(
    mock_is_64bit: Mock,
    mock_zip_documents: Mock,
    mock_run_parallel_batched_scan: Mock,
    is_64bit: bool,
    expected_skip_batching: bool,
    expected_zip_calls: int,
) -> None:
    mock_is_64bit.return_value = is_64bit
    documents = [Document(f'file_{index}.txt', 'content') for index in range(consts.ZIP_MAX_FILES_COUNT + 1)]

    _run_presigned_upload_scan(_presigned_scan_ctx(), False, False, {}, documents, MagicMock(), MagicMock())

    assert mock_zip_documents.call_count == expected_zip_calls
    assert mock_run_parallel_batched_scan.call_args.kwargs.get('skip_batching') is expected_skip_batching


@patch('cycode.cli.apps.scan.code_scanner.run_parallel_batched_scan')
@patch('cycode.cli.apps.scan.code_scanner.zip_documents')
def test_run_presigned_upload_scan_falls_back_to_batches_on_large_zip_file(
    mock_zip_documents: Mock, mock_run_parallel_batched_scan: Mock
) -> None:
    # safety net: zipfile raises LargeZipFile directly instead of our own ZipTooLargeError
    mock_zip_documents.side_effect = zipfile.LargeZipFile('Files count would require ZIP64 extensions')

    _run_presigned_upload_scan(
        _presigned_scan_ctx(), False, False, {}, [Document('file.txt', 'content')], MagicMock(), MagicMock()
    )

    assert mock_run_parallel_batched_scan.call_args.kwargs.get('skip_batching') is None


@patch('cycode.cli.apps.scan.code_scanner.run_parallel_batched_scan')
@patch('cycode.cli.apps.scan.code_scanner.zip_documents')
@patch('cycode.cli.apps.scan.code_scanner._get_scan_documents_thread_func')
def test_run_presigned_upload_scan_reuses_the_archive_it_built(
    mock_get_thread_func: Mock, mock_zip_documents: Mock, mock_run_parallel_batched_scan: Mock
) -> None:
    # the archive built to check that everything fits is the one we upload; don't compress it twice
    zipped_documents = mock_zip_documents.return_value

    _run_presigned_upload_scan(
        _presigned_scan_ctx(), False, False, {}, [Document('file.txt', 'content')], MagicMock(), MagicMock()
    )

    mock_zip_documents.assert_called_once()
    assert mock_get_thread_func.call_args.args[-1] is zipped_documents
    assert mock_run_parallel_batched_scan.call_args.kwargs.get('skip_batching') is True


@patch('cycode.cli.apps.scan.code_scanner._perform_scan')
@patch('cycode.cli.apps.scan.code_scanner.zip_documents')
def test_scan_batch_thread_func_does_not_rezip_a_prezipped_batch(
    mock_zip_documents: Mock, mock_perform_scan: Mock
) -> None:
    prezipped = MagicMock()
    ctx = MagicMock()
    ctx.obj = {
        'client': MagicMock(),
        'scan_type': consts.SECRET_SCAN_TYPE,
        'severity_threshold': None,
        'sync': False,
        'progress_bar': MagicMock(),
    }

    scan_batch_thread_func = _get_scan_documents_thread_func(ctx, False, False, {}, prezipped)
    scan_batch_thread_func([Document('file.txt', 'content')])

    mock_zip_documents.assert_not_called()
    assert mock_perform_scan.call_args.args[1] is prezipped
    # the buffer is released once the batch is done with it
    prezipped.cleanup.assert_called_once()
