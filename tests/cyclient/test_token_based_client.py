import arrow
import responses

from cycode.cyclient.cycode_token_based_client import CycodeTokenBasedClient
from tests.conftest import _EXPECTED_API_TOKEN


@responses.activate
def test_api_token_new(token_based_client: CycodeTokenBasedClient, api_token_response: responses.Response) -> None:
    responses.add(api_token_response)

    api_token = token_based_client.api_token

    assert api_token == _EXPECTED_API_TOKEN


@responses.activate
def test_api_token_expired(token_based_client: CycodeTokenBasedClient, api_token_response: responses.Response) -> None:
    responses.add(api_token_response)

    # this property performs HTTP req to refresh the token. IDE doesn't know it
    token_based_client.api_token  # noqa: B018

    # mark token as expired
    token_based_client._expires_in = arrow.utcnow().shift(hours=-1)

    # refresh token
    api_token_refreshed = token_based_client.api_token

    assert api_token_refreshed == _EXPECTED_API_TOKEN


def test_get_request_headers(token_based_client: CycodeTokenBasedClient, api_token: str) -> None:
    token_based_headers = {'Authorization': f'Bearer {_EXPECTED_API_TOKEN}'}
    expected_headers = {**token_based_client.MANDATORY_HEADERS, **token_based_headers}

    assert token_based_client.get_request_headers() == expected_headers
