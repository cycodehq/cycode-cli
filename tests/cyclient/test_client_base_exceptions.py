from unittest.mock import MagicMock

import pytest
import responses
from requests.exceptions import (
    ConnectionError as RequestsConnectionError,
)
from requests.exceptions import (
    HTTPError,
    SSLError,
    Timeout,
)

from cycode.cli.exceptions.custom_exceptions import (
    HttpUnauthorizedError,
    RequestConnectionError,
    RequestHttpError,
    RequestSslError,
    RequestTimeoutError,
)
from cycode.cyclient import config
from cycode.cyclient.cycode_client_base import CycodeClientBase


def _make_client() -> CycodeClientBase:
    return CycodeClientBase(config.cycode_api_url)


# --- _handle_exception mapping ---


def test_handle_exception_timeout() -> None:
    client = _make_client()
    with pytest.raises(RequestTimeoutError):
        client._handle_exception(Timeout('timed out'))


def test_handle_exception_ssl_error() -> None:
    client = _make_client()
    with pytest.raises(RequestSslError):
        client._handle_exception(SSLError('cert verify failed'))


def test_handle_exception_connection_error() -> None:
    client = _make_client()
    with pytest.raises(RequestConnectionError):
        client._handle_exception(RequestsConnectionError('refused'))


def test_handle_exception_http_error_401() -> None:
    response = MagicMock()
    response.status_code = 401
    response.text = 'Unauthorized'
    error = HTTPError(response=response)

    client = _make_client()
    with pytest.raises(HttpUnauthorizedError):
        client._handle_exception(error)


def test_handle_exception_http_error_500() -> None:
    response = MagicMock()
    response.status_code = 500
    response.text = 'Internal Server Error'
    error = HTTPError(response=response)

    client = _make_client()
    with pytest.raises(RequestHttpError) as exc_info:
        client._handle_exception(error)
    assert exc_info.value.status_code == 500


def test_handle_exception_unknown_error_reraises() -> None:
    client = _make_client()
    with pytest.raises(RuntimeError, match='something unexpected'):
        client._handle_exception(RuntimeError('something unexpected'))


# --- HTTP integration via responses mock ---


@responses.activate
def test_get_returns_response_on_success() -> None:
    client = _make_client()
    url = f'{client.api_url}/test-endpoint'
    responses.add(responses.GET, url, json={'ok': True}, status=200)

    response = client.get('test-endpoint')
    assert response.status_code == 200
    assert response.json() == {'ok': True}


@responses.activate
def test_post_returns_response_on_success() -> None:
    client = _make_client()
    url = f'{client.api_url}/test-endpoint'
    responses.add(responses.POST, url, json={'created': True}, status=201)

    response = client.post('test-endpoint', body={'data': 'value'})
    assert response.status_code == 201


@responses.activate
def test_get_raises_timeout_error() -> None:
    client = _make_client()
    url = f'{client.api_url}/slow-endpoint'
    responses.add(responses.GET, url, body=Timeout('Connection timed out'))

    with pytest.raises(RequestTimeoutError):
        client.get('slow-endpoint')


@responses.activate
def test_get_raises_ssl_error() -> None:
    client = _make_client()
    url = f'{client.api_url}/ssl-endpoint'
    responses.add(responses.GET, url, body=SSLError('certificate verify failed'))

    with pytest.raises(RequestSslError):
        client.get('ssl-endpoint')


@responses.activate
def test_get_raises_connection_error() -> None:
    client = _make_client()
    url = f'{client.api_url}/down-endpoint'
    responses.add(responses.GET, url, body=RequestsConnectionError('Connection refused'))

    with pytest.raises(RequestConnectionError):
        client.get('down-endpoint')


@responses.activate
def test_get_raises_http_unauthorized_error() -> None:
    client = _make_client()
    url = f'{client.api_url}/auth-endpoint'
    responses.add(responses.GET, url, json={'error': 'unauthorized'}, status=401)

    with pytest.raises(HttpUnauthorizedError):
        client.get('auth-endpoint')


@responses.activate
def test_get_raises_http_error_on_500() -> None:
    client = _make_client()
    url = f'{client.api_url}/error-endpoint'
    responses.add(responses.GET, url, json={'error': 'server error'}, status=500)

    with pytest.raises(RequestHttpError) as exc_info:
        client.get('error-endpoint')
    assert exc_info.value.status_code == 500


@responses.activate
def test_get_raises_http_error_on_403() -> None:
    client = _make_client()
    url = f'{client.api_url}/forbidden-endpoint'
    responses.add(responses.GET, url, json={'error': 'forbidden'}, status=403)

    with pytest.raises(RequestHttpError) as exc_info:
        client.get('forbidden-endpoint')
    assert exc_info.value.status_code == 403
