from cycode.cyclient import config
from cycode.cyclient.cycode_client import CycodeClient


def test_init_values_from_config() -> None:
    client = CycodeClient()

    assert client.api_url == config.cycode_api_url
    assert client.timeout == config.timeout
