from typing import Optional

from cycode.cyclient.config import dev_tenant_id
from cycode.cyclient.cycode_client_base import CycodeClientBase

"""
Send requests with api token
"""


class CycodeDevBasedClient(CycodeClientBase):
    def __init__(self, api_url: str) -> None:
        super().__init__(api_url)

    def get_request_headers(self, additional_headers: Optional[dict] = None, **_) -> dict[str, str]:
        headers = super().get_request_headers(additional_headers=additional_headers)
        headers['X-Tenant-Id'] = dev_tenant_id

        return headers

    def build_full_url(self, url: str, endpoint: str) -> str:
        return f'{url}:{endpoint}'
