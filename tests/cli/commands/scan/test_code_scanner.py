import os

from cycode.cli import consts
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
    generated_document = _generate_document(path, consts.INFRA_CONFIGURATION_SCAN_TYPE, content, is_git_diff)
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

    generated_tfplan_document = _generate_document(path, consts.INFRA_CONFIGURATION_SCAN_TYPE, content, is_git_diff)

    assert type(generated_tfplan_document) == Document
    assert generated_tfplan_document.path.endswith('.tf')
    assert generated_tfplan_document.is_git_diff_format == is_git_diff
