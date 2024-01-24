import arrow
import responses

from cycode.cyclient.cycode_token_based_client import CycodeTokenBasedClient
from tests.conftest import _EXPECTED_API_TOKEN, create_token_based_client


@responses.activate
def test_access_token_new(token_based_client: CycodeTokenBasedClient, api_token_response: responses.Response) -> None:
    responses.add(api_token_response)

    api_token = token_based_client.get_access_token()

    assert api_token == _EXPECTED_API_TOKEN


@responses.activate
def test_access_token_expired(
    token_based_client: CycodeTokenBasedClient, api_token_response: responses.Response
) -> None:
    responses.add(api_token_response)

    token_based_client.get_access_token()

    # mark token as expired
    token_based_client._expires_in = arrow.utcnow().shift(hours=-1)

    # refresh token
    api_token_refreshed = token_based_client.get_access_token()

    assert api_token_refreshed == _EXPECTED_API_TOKEN


def test_get_request_headers(token_based_client: CycodeTokenBasedClient, api_token: str) -> None:
    token_based_headers = {'Authorization': f'Bearer {_EXPECTED_API_TOKEN}'}
    expected_headers = {**token_based_client.MANDATORY_HEADERS, **token_based_headers}

    assert token_based_client.get_request_headers() == expected_headers


@responses.activate
def test_access_token_cached(
    token_based_client: CycodeTokenBasedClient, api_token_response: responses.Response
) -> None:
    # save to cache
    responses.add(api_token_response)
    token_based_client.get_access_token()

    # load from cache
    client2 = create_token_based_client()
    assert client2._access_token == token_based_client._access_token
    assert client2._expires_in == token_based_client._expires_in


@responses.activate
def test_access_token_cached_creator_changed(
    token_based_client: CycodeTokenBasedClient, api_token_response: responses.Response
) -> None:
    # save to cache
    responses.add(api_token_response)
    token_based_client.get_access_token()

    # load from cache with another client id and client secret
    client2 = create_token_based_client('client_id2', 'client_secret2')
    assert client2._access_token is None
    assert client2._expires_in is None


@responses.activate
def test_access_token_invalidation(
    token_based_client: CycodeTokenBasedClient, api_token_response: responses.Response
) -> None:
    # save to cache
    responses.add(api_token_response)
    token_based_client.get_access_token()

    expected_access_token = token_based_client._access_token
    expected_expires_in = token_based_client._expires_in

    # invalidate in runtime
    token_based_client.invalidate_access_token()
    assert token_based_client._access_token is None
    assert token_based_client._expires_in is None

    # load from cache
    client2 = create_token_based_client()
    assert client2._access_token == expected_access_token
    assert client2._expires_in == expected_expires_in

    # invalidate in storage
    client2.invalidate_access_token(in_storage=True)
    assert client2._access_token is None
    assert client2._expires_in is None

    # load from cache again
    client3 = create_token_based_client()
    assert client3._access_token is None
    assert client3._expires_in is None
