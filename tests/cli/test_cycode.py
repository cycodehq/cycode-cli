import json

import pytest
from typing import TYPE_CHECKING

import responses
from click.testing import CliRunner

from cli.cycode import main_cli
from tests.conftest import TEST_FILES_PATH, CLI_ENV_VARS
from tests.cyclient.test_scan_client import get_zipped_file_scan_response, get_zipped_file_scan_url

_PATH_TO_SCAN = TEST_FILES_PATH.joinpath('zip_content').absolute()

if TYPE_CHECKING:
    from cyclient.scan_client import ScanClient


def _is_json(plain: str) -> bool:
    try:
        json.loads(plain)
        return True
    except (ValueError, TypeError):
        return False


@responses.activate
@pytest.mark.parametrize('output', ['text', 'json'])
def test_passing_output_option_to_scan(output: str, scan_client: 'ScanClient', api_token_response: responses.Response):
    scan_type = 'secret'

    responses.add(get_zipped_file_scan_response(get_zipped_file_scan_url(scan_type, scan_client)))
    responses.add(api_token_response)
    # scan report is not mocked. This raise connection error on attempt to report scan. it doesn't perform real request

    args = ['scan', '--soft-fail', '--output', output, 'path', str(_PATH_TO_SCAN)]
    result = CliRunner().invoke(main_cli, args, env=CLI_ENV_VARS)

    except_json = output == 'json'

    assert _is_json(result.output) == except_json

    if except_json:
        output = json.loads(result.output)
        assert 'scan_id' in output
    else:
        assert 'Scan Results' in result.output
