from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cycode.cyclient.cycode_client_base import CycodeClientBase

_CLI_ACTIVATION_PATH = 'scans/api/v4/cli-activation'


class CliActivationClient:
    def __init__(self, cycode_client: 'CycodeClientBase') -> None:
        self._cycode_client = cycode_client

    def report_activation(self) -> None:
        self._cycode_client.put(url_path=_CLI_ACTIVATION_PATH)
