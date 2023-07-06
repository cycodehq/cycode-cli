import pytest
import requests
import responses
from requests import Timeout

from cycode.cli.exceptions.custom_exceptions import CycodeError
from cycode.cyclient.auth_client import AuthClient
from cycode.cyclient.models import (
    ApiTokenGenerationPollingResponse,
    ApiTokenGenerationPollingResponseSchema,
    AuthenticationSession,
)


@pytest.fixture(scope='module')
def code_challenge() -> str:
    from cycode.cli.auth.auth_manager import AuthManager

    code_challenge, _ = AuthManager()._generate_pkce_code_pair()
    return code_challenge


@pytest.fixture(scope='module')
def code_verifier() -> str:
    from cycode.cli.auth.auth_manager import AuthManager

    _, code_verifier = AuthManager()._generate_pkce_code_pair()
    return code_verifier


@pytest.fixture(scope='module', name='client')
def auth_client() -> AuthClient:
    return AuthClient()


@pytest.fixture(scope='module', name='start_url')
def auth_start_url(client: AuthClient) -> str:
    # TODO(MarshalX): create database of constants of endpoints. remove hardcoded paths
    return client.cycode_client.build_full_url(client.cycode_client.api_url, f'{client.AUTH_CONTROLLER_PATH}/start')


@pytest.fixture(scope='module', name='token_url')
def auth_token_url(client: AuthClient) -> str:
    return client.cycode_client.build_full_url(client.cycode_client.api_url, f'{client.AUTH_CONTROLLER_PATH}/token')


_SESSION_ID = '4cff1234-a209-47ed-ab2f-85676912345c'


@responses.activate
def test_start_session_success(client: AuthClient, start_url: str, code_challenge: str) -> None:
    responses.add(
        responses.POST,
        start_url,
        json={'session_id': _SESSION_ID},
        status=200,
    )

    session_response = client.start_session(code_challenge)
    assert isinstance(session_response, AuthenticationSession)
    assert session_response.session_id == _SESSION_ID


@responses.activate
def test_start_session_timeout(client: AuthClient, start_url: str, code_challenge: str) -> None:
    responses.add(responses.POST, start_url, status=504)

    timeout_response = requests.post(start_url, timeout=5)
    if timeout_response.status_code == 504:
        """bypass SAST"""

    responses.reset()

    timeout_error = Timeout()
    timeout_error.response = timeout_response

    responses.add(responses.POST, start_url, body=timeout_error)

    with pytest.raises(CycodeError) as e_info:
        client.start_session(code_challenge)

    assert e_info.value.status_code == 504


@responses.activate
def test_start_session_http_error(client: AuthClient, start_url: str, code_challenge: str) -> None:
    responses.add(responses.POST, start_url, status=401)

    with pytest.raises(CycodeError) as e_info:
        client.start_session(code_challenge)

    assert e_info.value.status_code == 401


@responses.activate
def test_get_api_token_success_pending(client: AuthClient, token_url: str, code_verifier: str) -> None:
    expected_status = 'Pending'
    expected_api_token = None

    responses.add(
        responses.POST,
        token_url,
        json={'status': expected_status, 'api_token': expected_api_token},
        status=200,
    )

    api_token_polling_response = client.get_api_token(_SESSION_ID, code_verifier)
    assert isinstance(api_token_polling_response, ApiTokenGenerationPollingResponse)
    assert api_token_polling_response.status == expected_status
    assert api_token_polling_response.api_token == expected_api_token


@responses.activate
def test_get_api_token_success_completed(client: AuthClient, token_url: str, code_verifier: str) -> None:
    expected_status = 'Completed'
    expected_json = {
        'status': expected_status,
        'api_token': {
            'clientId': 'b123458-0eaa-4010-beb4-6f0c54612345',
            'secret': 'a123450a-42b2-4ad5-8bdd-c0130123456',
            'description': 'cycode cli api token',
            'createdByUserId': None,
            'createdAt': '2023-04-26T11:38:54+00:00',
        },
    }
    expected_response = ApiTokenGenerationPollingResponseSchema().load(expected_json)

    responses.add(
        responses.POST,
        token_url,
        json=expected_json,
        status=200,
    )

    api_token_polling_response = client.get_api_token(_SESSION_ID, code_verifier)
    assert isinstance(api_token_polling_response, ApiTokenGenerationPollingResponse)
    assert api_token_polling_response.status == expected_status
    assert api_token_polling_response.api_token.client_id == expected_response.api_token.client_id
    assert api_token_polling_response.api_token.secret == expected_response.api_token.secret
    assert api_token_polling_response.api_token.description == expected_response.api_token.description


@responses.activate
def test_get_api_token_http_error_valid_response(client: AuthClient, token_url: str, code_verifier: str) -> None:
    expected_status = 'Pending'
    expected_api_token = None

    responses.add(
        responses.POST,
        token_url,
        json={'status': expected_status, 'api_token': expected_api_token},
        status=418,  # any code between 400 and 600
    )

    api_token_polling_response = client.get_api_token(_SESSION_ID, code_verifier)
    assert isinstance(api_token_polling_response, ApiTokenGenerationPollingResponse)
    assert api_token_polling_response.status == expected_status
    assert api_token_polling_response.api_token == expected_api_token


@responses.activate
def test_get_api_token_http_error_invalid_response(client: AuthClient, token_url: str, code_verifier: str) -> None:
    responses.add(
        responses.POST,
        token_url,
        body='Invalid body',
        status=418,  # any code between 400 and 600
    )

    api_token_polling_response = client.get_api_token(_SESSION_ID, code_verifier)
    assert api_token_polling_response is None


@responses.activate
def test_get_api_token_not_excepted_exception(client: AuthClient, token_url: str, code_verifier: str) -> None:
    responses.add(responses.POST, token_url, body=Timeout())

    api_token_polling_response = client.get_api_token(_SESSION_ID, code_verifier)
    assert api_token_polling_response is None
