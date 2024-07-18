import json
from typing import TYPE_CHECKING
from uuid import uuid4

import pytest
import responses
from click.testing import CliRunner

from cycode.cli.commands.main_cli import main_cli
from cycode.cli.utils.git_proxy import git_proxy
from tests.conftest import CLI_ENV_VARS, TEST_FILES_PATH, ZIP_CONTENT_PATH
from tests.cyclient.mocked_responses.scan_client import mock_scan_responses
from tests.cyclient.test_scan_client import get_zipped_file_scan_response, get_zipped_file_scan_url

_PATH_TO_SCAN = TEST_FILES_PATH.joinpath('zip_content').absolute()

if TYPE_CHECKING:
    from cycode.cyclient.scan_client import ScanClient


def _is_json(plain: str) -> bool:
    try:
        json.loads(plain)
        return True
    except (ValueError, TypeError):
        return False


@responses.activate
@pytest.mark.parametrize('output', ['text', 'json'])
def test_passing_output_option(output: str, scan_client: 'ScanClient', api_token_response: responses.Response) -> None:
    scan_type = 'secret'
    scan_id = uuid4()

    mock_scan_responses(responses, scan_type, scan_client, scan_id, ZIP_CONTENT_PATH)
    responses.add(get_zipped_file_scan_response(get_zipped_file_scan_url(scan_type, scan_client), ZIP_CONTENT_PATH))
    responses.add(api_token_response)

    args = ['--output', output, 'scan', '--soft-fail', 'path', str(_PATH_TO_SCAN)]
    result = CliRunner().invoke(main_cli, args, env=CLI_ENV_VARS)

    except_json = output == 'json'

    assert _is_json(result.output) == except_json

    if except_json:
        output = json.loads(result.output)
        assert 'scan_id' in output
    else:
        assert 'Scan ID' in result.output


@responses.activate
def test_optional_git_with_path_scan(scan_client: 'ScanClient', api_token_response: responses.Response) -> None:
    mock_scan_responses(responses, 'secret', scan_client, uuid4(), ZIP_CONTENT_PATH)
    responses.add(get_zipped_file_scan_response(get_zipped_file_scan_url('secret', scan_client), ZIP_CONTENT_PATH))
    responses.add(api_token_response)

    # fake env without Git executable
    git_proxy._set_dummy_git_proxy()

    args = ['--output', 'json', 'scan', 'path', str(_PATH_TO_SCAN)]
    result = CliRunner().invoke(main_cli, args, env=CLI_ENV_VARS)

    # do NOT expect error about not found Git executable
    assert 'GIT_PYTHON_GIT_EXECUTABLE' not in result.output

    # reset the git proxy
    git_proxy._set_git_proxy()


@responses.activate
def test_required_git_with_path_repository(scan_client: 'ScanClient', api_token_response: responses.Response) -> None:
    responses.add(api_token_response)

    # fake env without Git executable
    git_proxy._set_dummy_git_proxy()

    args = ['--output', 'json', 'scan', 'repository', str(_PATH_TO_SCAN)]
    result = CliRunner().invoke(main_cli, args, env=CLI_ENV_VARS)

    # expect error about not found Git executable
    assert 'GIT_PYTHON_GIT_EXECUTABLE' in result.output

    # reset the git proxy
    git_proxy._set_git_proxy()
