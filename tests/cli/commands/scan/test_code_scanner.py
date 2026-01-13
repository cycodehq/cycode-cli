import os
from unittest.mock import MagicMock, Mock, patch

from cycode.cli import consts
from cycode.cli.apps.scan.code_scanner import scan_disk_files
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
def test_entrypoint_cycode_added_to_documents(
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
    entrypoint_docs = [
        doc for doc in documents_passed if doc.path.endswith(consts.CYCODE_ENTRYPOINT_FILENAME)
    ]
    assert len(entrypoint_docs) == 1

    entrypoint_doc = entrypoint_docs[0]
    assert entrypoint_doc.path == os.path.join(test_path, consts.CYCODE_ENTRYPOINT_FILENAME)
    assert entrypoint_doc.content == ''
    assert entrypoint_doc.is_git_diff_format is False
    assert entrypoint_doc.absolute_path == entrypoint_doc.path
