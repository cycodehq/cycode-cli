import os
from os.path import normpath
from unittest.mock import MagicMock, Mock, patch

import pytest

from cycode.cli import consts
from cycode.cli.apps.scan.code_scanner import _perform_scan, scan_disk_files, scan_documents
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
    ('scan_type', 'command_scan_type', 'sync_option', 'secret_async_env', 'expect_presigned'),
    [
        # SAST keeps uploading directly to S3 via a presigned URL (regression guard for the new sync gate).
        (consts.SAST_SCAN_TYPE, 'path', False, False, True),
        # Secret scans use the previous batched flow by default (presigned async is opt-in).
        (consts.SECRET_SCAN_TYPE, 'path', False, False, False),
        # With CYCODE_SECRET_SCAN_ASYNC enabled, secret scans upload as a single file directly to S3.
        (consts.SECRET_SCAN_TYPE, 'path', False, True, True),
        # A --sync secret scan must stay on the batched inline path even when async is enabled.
        (consts.SECRET_SCAN_TYPE, 'path', True, True, False),
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
    secret_async_env: bool,
    expect_presigned: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if secret_async_env:
        monkeypatch.setenv(consts.SECRET_SCAN_ASYNC_ENV_VAR_NAME, 'true')

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
