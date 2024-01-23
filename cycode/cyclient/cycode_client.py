from cycode.cyclient import config
from cycode.cyclient.cycode_client_base import CycodeClientBase


class CycodeClient(CycodeClientBase):
    def __init__(self) -> None:
        super().__init__(config.cycode_api_url)
        self.timeout = config.timeout
