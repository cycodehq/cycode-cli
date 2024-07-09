from pathlib import Path
from typing import Optional

import pytest
import responses

from cycode.cli.user_settings.credentials_manager import CredentialsManager
from cycode.cyclient.client_creator import create_scan_client
from cycode.cyclient.cycode_token_based_client import CycodeTokenBasedClient
from cycode.cyclient.scan_client import ScanClient

# not real JWT with userId and tenantId fields
_EXPECTED_API_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJ1c2VySWQiOiJibGFibGEiLCJ0ZW5hbnRJZCI6ImJsYWJsYSJ9.8RfoWBfciuj8nwc7UB8uOUJchVuaYpYlgf1G2QHiWTk'  # noqa: E501

_CLIENT_ID = 'b1234568-0eaa-1234-beb8-6f0c12345678'
_CLIENT_SECRET = 'a12345a-42b2-1234-3bdd-c0130123456'

CLI_ENV_VARS = {'CYCODE_CLIENT_ID': _CLIENT_ID, 'CYCODE_CLIENT_SECRET': _CLIENT_SECRET}

TEST_FILES_PATH = Path(__file__).parent.joinpath('test_files').absolute()
MOCKED_RESPONSES_PATH = Path(__file__).parent.joinpath('cyclient/mocked_responses/data').absolute()
ZIP_CONTENT_PATH = TEST_FILES_PATH.joinpath('zip_content').absolute()


@pytest.fixture(scope='session')
def test_files_path() -> Path:
    return TEST_FILES_PATH


@pytest.fixture(scope='session')
def scan_client() -> ScanClient:
    return create_scan_client(_CLIENT_ID, _CLIENT_SECRET, hide_response_log=False)


def create_token_based_client(
    client_id: Optional[str] = None, client_secret: Optional[str] = None
) -> CycodeTokenBasedClient:
    CredentialsManager.FILE_NAME = 'unit-tests-credentials.yaml'

    if client_id is None:
        client_id = _CLIENT_ID
    if client_secret is None:
        client_secret = _CLIENT_SECRET

    return CycodeTokenBasedClient(client_id, client_secret)


@pytest.fixture(scope='session')
def token_based_client() -> CycodeTokenBasedClient:
    return create_token_based_client()


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
    return token_based_client.get_access_token()
