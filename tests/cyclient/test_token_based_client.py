import arrow
import pytest
import responses

from cyclient.cycode_token_based_client import CycodeTokenBasedClient


_CLIENT_ID = 'b1234568-0eaa-1234-beb8-6f0c12345678'
_CLIENT_SECRET = 'a12345a-42b2-1234-3bdd-c0130123456'

_EXPECTED_API_TOKEN = 'someJWT'


@pytest.fixture(scope='module', name='client')
def token_based_client() -> CycodeTokenBasedClient:
    return CycodeTokenBasedClient(_CLIENT_ID, _CLIENT_SECRET)


@pytest.fixture(scope='module')
def api_token_url(client: CycodeTokenBasedClient) -> str:
    return f'{client.api_url}/api/v1/auth/api-token'


@pytest.fixture(scope='module')
def api_token_response(api_token_url) -> responses.Response:
    return responses.Response(
        method=responses.POST,
        url=api_token_url,
        json={
            'token': _EXPECTED_API_TOKEN,
            'refresh_token': '12345678-0c68-1234-91ba-a13123456789',
            'expires_in': 86400
        },
        status=200
    )


@pytest.fixture(scope='module')
@responses.activate
def api_token(client: CycodeTokenBasedClient, api_token_response: responses.Response) -> str:
    responses.add(api_token_response)
    return client.api_token


@responses.activate
def test_api_token_new(client: CycodeTokenBasedClient, api_token_response: responses.Response):
    responses.add(api_token_response)

    api_token = client.api_token

    assert api_token == _EXPECTED_API_TOKEN


@responses.activate
def test_api_token_expired(client: CycodeTokenBasedClient, api_token_response: responses.Response):
    responses.add(api_token_response)

    # this property performs HTTP req to refresh the token. IDE doesn't know it
    client.api_token

    # mark token as expired
    client._expires_in = arrow.utcnow().shift(hours=-1)

    # refresh token
    api_token_refreshed = client.api_token

    assert api_token_refreshed == _EXPECTED_API_TOKEN


def test_get_request_headers(client: CycodeTokenBasedClient, api_token: str):
    token_based_headers = {
        'Authorization': f'Bearer {_EXPECTED_API_TOKEN}'
    }
    expected_headers = {**client.MANDATORY_HEADERS, **token_based_headers}

    assert client.get_request_headers() == expected_headers
