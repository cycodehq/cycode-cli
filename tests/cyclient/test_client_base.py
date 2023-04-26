from cyclient import config, __version__
from cyclient.cycode_client_base import CycodeClientBase


def test_mandatory_headers():
    expected_headers = {
        'User-Agent': f'cycode-cli_{__version__}',
    }

    client = CycodeClientBase(config.cycode_api_url)
    
    assert client.MANDATORY_HEADERS == expected_headers


def test_get_request_headers():
    client = CycodeClientBase(config.cycode_api_url)

    assert client.get_request_headers() == client.MANDATORY_HEADERS


def test_get_request_headers_with_additional():
    client = CycodeClientBase(config.cycode_api_url)

    additional_headers = {
        'Authorize': 'Token test'
    }
    expected_headers = {**client.MANDATORY_HEADERS, **additional_headers}

    assert client.get_request_headers(additional_headers) == expected_headers


def test_build_full_url():
    url = config.cycode_api_url
    client = CycodeClientBase(url)

    endpoint = 'test'
    expected_url = f'{url}/{endpoint}'

    assert client.build_full_url(url, endpoint) == expected_url
