import os

from cycode.cli import consts
from cycode.cli.apps.scan.code_scanner import _does_severity_match_severity_threshold
from cycode.cli.files_collector.excluder import _is_file_relevant_for_sca_scan
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


def test_does_severity_match_severity_threshold() -> None:
    assert _does_severity_match_severity_threshold('INFO', 'LOW') is False

    assert _does_severity_match_severity_threshold('LOW', 'LOW') is True
    assert _does_severity_match_severity_threshold('LOW', 'MEDIUM') is False

    assert _does_severity_match_severity_threshold('MEDIUM', 'LOW') is True
    assert _does_severity_match_severity_threshold('MEDIUM', 'MEDIUM') is True
    assert _does_severity_match_severity_threshold('MEDIUM', 'HIGH') is False

    assert _does_severity_match_severity_threshold('HIGH', 'MEDIUM') is True
    assert _does_severity_match_severity_threshold('HIGH', 'HIGH') is True
    assert _does_severity_match_severity_threshold('HIGH', 'CRITICAL') is False

    assert _does_severity_match_severity_threshold('CRITICAL', 'HIGH') is True
    assert _does_severity_match_severity_threshold('CRITICAL', 'CRITICAL') is True

    assert _does_severity_match_severity_threshold('NON_EXISTENT', 'LOW') is True
    assert _does_severity_match_severity_threshold('LOW', 'NON_EXISTENT') is True
