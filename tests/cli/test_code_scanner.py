import os
from typing import TYPE_CHECKING

import click
import pytest
from click import ClickException
from git import InvalidGitRepositoryError
from requests import Response

from cycode.cli import consts
from cycode.cli.code_scanner import _handle_exception, _is_file_relevant_for_sca_scan, _generate_document
from cycode.cli.exceptions import custom_exceptions
from cycode.cli.models import Document
from cycode.cyclient import logger

if TYPE_CHECKING:
    from _pytest.monkeypatch import MonkeyPatch


@pytest.fixture()
def ctx() -> click.Context:
    return click.Context(click.Command('path'), obj={'verbose': False, 'output': 'text'})


@pytest.mark.parametrize(
    'exception, expected_soft_fail',
    [
        (custom_exceptions.NetworkError(400, 'msg', Response()), True),
        (custom_exceptions.ScanAsyncError('msg'), True),
        (custom_exceptions.HttpUnauthorizedError('msg', Response()), True),
        (custom_exceptions.ZipTooLargeError(1000), True),
        (custom_exceptions.TfplanKeyError('msg'), True),
        (InvalidGitRepositoryError(), None),
    ],
)
def test_handle_exception_soft_fail(
    ctx: click.Context, exception: custom_exceptions.CycodeError, expected_soft_fail: bool
) -> None:
    with ctx:
        _handle_exception(ctx, exception)

        assert ctx.obj.get('did_fail') is True
        assert ctx.obj.get('soft_fail') is expected_soft_fail


def test_handle_exception_unhandled_error(ctx: click.Context) -> None:
    with ctx, pytest.raises(ClickException):
        _handle_exception(ctx, ValueError('test'))

        assert ctx.obj.get('did_fail') is True
        assert ctx.obj.get('soft_fail') is None


def test_handle_exception_click_error(ctx: click.Context) -> None:
    with ctx, pytest.raises(ClickException):
        _handle_exception(ctx, click.ClickException('test'))

        assert ctx.obj.get('did_fail') is True
        assert ctx.obj.get('soft_fail') is None


def test_handle_exception_verbose(monkeypatch: 'MonkeyPatch') -> None:
    ctx = click.Context(click.Command('path'), obj={'verbose': True, 'output': 'text'})

    def mock_secho(msg: str, *_, **__) -> None:
        assert 'Error:' in msg

    monkeypatch.setattr(click, 'secho', mock_secho)

    with ctx, pytest.raises(ClickException):
        _handle_exception(ctx, ValueError('test'))


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

    # scan_type != iac
    path = 'path/to/nowhere.txt'
    content = 'nothing important here'

    non_iac_document = Document(path, content, is_git_diff)
    generated_document = _generate_document(path, consts.SCA_SCAN_TYPE, content, is_git_diff)

    assert non_iac_document.path == generated_document.path
    assert non_iac_document.content == generated_document.content
    assert non_iac_document.is_git_diff_format == generated_document.is_git_diff_format

    # scan_type == iac and tfplan_file == False
    path = 'path/to/nowhere.tf'
    content = '''provider "aws" {
        profile = "chili"
        region = "us-east-1"
        }

        resource "aws_s3_bucket" "chili-env-var-test" {
          bucket = "chili-env-var-test"
        }'''

    iac_document = Document(path, content, is_git_diff)
    generated_document = _generate_document(path, consts.INFRA_CONFIGURATION_SCAN_TYPE, content, is_git_diff)
    assert iac_document.path == generated_document.path
    assert iac_document.content == generated_document.content
    assert iac_document.is_git_diff_format == generated_document.is_git_diff_format

    # scan_type == iac and tfplan_file == True

    # path = 'path/to/nowhere.json'
    content = '''
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
    '''

    generated_tfplan_document = _generate_document(path, consts.INFRA_CONFIGURATION_SCAN_TYPE, content, is_git_diff)

    assert generated_tfplan_document.path.endswith('.tf')
    assert generated_tfplan_document.content
    assert generated_tfplan_document.is_git_diff_format == is_git_diff