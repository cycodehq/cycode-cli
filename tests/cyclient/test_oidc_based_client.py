import arrow
import responses

from cycode.cyclient.cycode_oidc_based_client import CycodeOidcBasedClient
from tests.conftest import _EXPECTED_API_TOKEN, create_oidc_based_client


@responses.activate
def test_access_token_new(
    oidc_based_client: CycodeOidcBasedClient, oidc_api_token_response: responses.Response
) -> None:
    responses.add(oidc_api_token_response)

    api_token = oidc_based_client.get_access_token()

    assert api_token == _EXPECTED_API_TOKEN


@responses.activate
def test_access_token_expired(
    oidc_based_client: CycodeOidcBasedClient, oidc_api_token_response: responses.Response
) -> None:
    responses.add(oidc_api_token_response)

    oidc_based_client.get_access_token()

    oidc_based_client._expires_in = arrow.utcnow().shift(hours=-1)

    api_token_refreshed = oidc_based_client.get_access_token()

    assert api_token_refreshed == _EXPECTED_API_TOKEN


def test_get_request_headers(oidc_based_client: CycodeOidcBasedClient, oidc_api_token: str) -> None:
    expected_headers = {
        **oidc_based_client.MANDATORY_HEADERS,
        'Authorization': f'Bearer {_EXPECTED_API_TOKEN}',
    }

    assert oidc_based_client.get_request_headers() == expected_headers


@responses.activate
def test_access_token_cached(
    oidc_based_client: CycodeOidcBasedClient, oidc_api_token_response: responses.Response
) -> None:
    responses.add(oidc_api_token_response)
    oidc_based_client.get_access_token()

    client2 = create_oidc_based_client()
    assert client2._access_token == oidc_based_client._access_token
    assert client2._expires_in == oidc_based_client._expires_in


@responses.activate
def test_access_token_cached_creator_changed(
    oidc_based_client: CycodeOidcBasedClient, oidc_api_token_response: responses.Response
) -> None:
    responses.add(oidc_api_token_response)
    oidc_based_client.get_access_token()

    client2 = create_oidc_based_client('client_id2', 'different-token')
    assert client2._access_token is None
    assert client2._expires_in is None


@responses.activate
def test_access_token_invalidation(
    oidc_based_client: CycodeOidcBasedClient, oidc_api_token_response: responses.Response
) -> None:
    responses.add(oidc_api_token_response)
    oidc_based_client.get_access_token()

    expected_access_token = oidc_based_client._access_token
    expected_expires_in = oidc_based_client._expires_in

    oidc_based_client.invalidate_access_token()
    assert oidc_based_client._access_token is None
    assert oidc_based_client._expires_in is None

    client2 = create_oidc_based_client()
    assert client2._access_token == expected_access_token
    assert client2._expires_in == expected_expires_in

    client2.invalidate_access_token(in_storage=True)
    assert client2._access_token is None
    assert client2._expires_in is None

    client3 = create_oidc_based_client()
    assert client3._access_token is None
    assert client3._expires_in is None
