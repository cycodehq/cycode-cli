from cycode.cyclient import config
from cycode.cyclient.cycode_dev_based_client import CycodeDevBasedClient


def test_get_request_headers():
    client = CycodeDevBasedClient(config.cycode_api_url)

    dev_based_headers = {'X-Tenant-Id': config.dev_tenant_id}
    expected_headers = {**client.MANDATORY_HEADERS, **dev_based_headers}

    assert client.get_request_headers() == expected_headers


def test_build_full_url():
    url = config.cycode_api_url
    client = CycodeDevBasedClient(url)

    endpoint = 'test'
    expected_url = f'{url}:{endpoint}'

    assert client.build_full_url(url, endpoint) == expected_url
