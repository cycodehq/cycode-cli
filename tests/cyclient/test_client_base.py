from cycode.cyclient import config
from cycode.cyclient.cycode_client_base import CycodeClientBase, get_cli_user_agent


def test_mandatory_headers() -> None:
    expected_headers = {
        'User-Agent': get_cli_user_agent(),
    }

    client = CycodeClientBase(config.cycode_api_url)

    assert expected_headers == client.MANDATORY_HEADERS


def test_get_request_headers() -> None:
    client = CycodeClientBase(config.cycode_api_url)

    assert client.get_request_headers() == client.MANDATORY_HEADERS


def test_get_request_headers_with_additional() -> None:
    client = CycodeClientBase(config.cycode_api_url)

    additional_headers = {'Authorize': 'Token test'}
    expected_headers = {**client.MANDATORY_HEADERS, **additional_headers}

    assert client.get_request_headers(additional_headers) == expected_headers


def test_build_full_url() -> None:
    url = config.cycode_api_url
    client = CycodeClientBase(url)

    endpoint = 'test'
    expected_url = f'{url}/{endpoint}'

    assert client.build_full_url(url, endpoint) == expected_url
