from cyclient.config import dev_tenant_id
from cyclient.cycode_client import CycodeClient

"""
Send requests with api token
"""


class CycodeDevBasedClient(CycodeClient):

    def __init__(self):
        super().__init__()

    def get_request_headers(self, additional_headers: dict = None):
        headers = super().get_request_headers(additional_headers=additional_headers)
        headers['X-Tenant-Id'] = dev_tenant_id

        return headers
