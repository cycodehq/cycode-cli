from cyclient.config import dev_tenant_id
from cyclient.cycode_client_base import CycodeClientBase

"""
Send requests with api token
"""


class CycodeDevBasedClient(CycodeClientBase):

    def __init__(self, api_url):
        super().__init__(api_url)

    def get_request_headers(self, additional_headers: dict = None):
        headers = super().get_request_headers(additional_headers=additional_headers)
        headers['X-Tenant-Id'] = dev_tenant_id

        return headers

    def append_to_endpoind(self):
        return ":"
