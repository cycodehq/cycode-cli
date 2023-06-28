import json

import pytest
from typing import TYPE_CHECKING

import responses
from click.testing import CliRunner

from cycode.cli.main import main_cli
from tests.conftest import TEST_FILES_PATH, CLI_ENV_VARS
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
@pytest.mark.parametrize('option_space', ['scan', 'global'])
def test_passing_output_option(
        output: str, option_space: str, scan_client: 'ScanClient', api_token_response: responses.Response
):
    scan_type = 'secret'

    responses.add(get_zipped_file_scan_response(get_zipped_file_scan_url(scan_type, scan_client)))
    responses.add(api_token_response)
    # Scan report is not mocked.
    # This raises connection error on the attempt to report scan.
    # It doesn't perform real request

    args = ['scan', '--soft-fail', 'path', str(_PATH_TO_SCAN)]

    if option_space == 'global':
        global_args = ['--output', output]
        global_args.extend(args)

        args = global_args
    elif option_space == 'scan':
        # test backward compatability with old style command
        args.insert(2, '--output')
        args.insert(3, output)

    result = CliRunner().invoke(main_cli, args, env=CLI_ENV_VARS)

    except_json = output == 'json'

    assert _is_json(result.output) == except_json

    if except_json:
        output = json.loads(result.output)
        assert 'scan_id' in output
    else:
        assert 'Scan Results' in result.output
