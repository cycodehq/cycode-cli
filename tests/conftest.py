from pathlib import Path

import pytest
import responses

from cycode.cyclient.cycode_token_based_client import CycodeTokenBasedClient
from cycode.cyclient.scan_client import ScanClient
from cycode.cyclient.scan_config.scan_config_creator import create_scan_client

_EXPECTED_API_TOKEN = 'someJWT'

_CLIENT_ID = 'b1234568-0eaa-1234-beb8-6f0c12345678'
_CLIENT_SECRET = 'a12345a-42b2-1234-3bdd-c0130123456'

CLI_ENV_VARS = {'CYCODE_CLIENT_ID': _CLIENT_ID, 'CYCODE_CLIENT_SECRET': _CLIENT_SECRET}

TEST_FILES_PATH = Path(__file__).parent.joinpath('test_files').absolute()


@pytest.fixture(scope='session')
def test_files_path() -> Path:
    return TEST_FILES_PATH


@pytest.fixture(scope='session')
def scan_client() -> ScanClient:
    return create_scan_client(_CLIENT_ID, _CLIENT_SECRET, hide_response_log=False)


@pytest.fixture(scope='session')
def token_based_client() -> CycodeTokenBasedClient:
    return CycodeTokenBasedClient(_CLIENT_ID, _CLIENT_SECRET)


@pytest.fixture(scope='session')
def api_token_url(token_based_client: CycodeTokenBasedClient) -> str:
    return f'{token_based_client.api_url}/api/v1/auth/api-token'


@pytest.fixture(scope='session')
def api_token_response(api_token_url: str) -> responses.Response:
    return responses.Response(
        method=responses.POST,
        url=api_token_url,
        json={
            'token': _EXPECTED_API_TOKEN,
            'refresh_token': '12345678-0c68-1234-91ba-a13123456789',
            'expires_in': 86400,
        },
        status=200,
    )


@pytest.fixture(scope='session')
@responses.activate
def api_token(token_based_client: CycodeTokenBasedClient, api_token_response: responses.Response) -> str:
    responses.add(api_token_response)
    return token_based_client.api_token
