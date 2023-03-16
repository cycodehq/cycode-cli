from cyclient import config, __version__
from cyclient.cycode_client_base import CycodeClientBase


class CycodeClient(CycodeClientBase):

    MANDATORY_HEADERS: dict = {
        "User-Agent": f'cycode-cli_{__version__}',
    }

    def __init__(self):
        super().__init__(config.cycode_api_url)
        self.timeout = config.timeout

