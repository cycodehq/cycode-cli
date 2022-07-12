from typing import List

from . import config
from .client import CycodeClient
from .config import get_logger
from .models import K8SResource, ResourcesCollection
from .utils import split_list


class K8SUpdaterClient:

    def __init__(self, client_id: str = None, client_secret: str = None):
        self.cycode_client = CycodeClient(client_secret=client_secret, client_id=client_id)
        self.base_path = 'api/v1' if config.dev_mode else 'kubernetes-connector/api/v1'
        self.logger = get_logger(__name__)

    def publish_resources(self, resource_type: str, resources: List[K8SResource], namespace: str = None):
        for batch in split_list(resources, config.batch_size):
            self._send_batch(ResourcesCollection(resource_type, namespace, batch, len(resources)))

    def _send_batch(self, batch: ResourcesCollection):
        path = f'{self.base_path}/resources'
        try:
            self.logger.debug(f'Publishing batch resources {batch.type}, {len(batch.resources)}/{batch.total_count}')
            response = self.cycode_client.post(url_path=path, body=batch.to_json())
            response.raise_for_status()
        except Exception as ex:
            self.logger.exception(
                f'Failed to publish resources. Type: {batch.type}, count: {len(batch.resources)}/{batch.total_count}',
                ex)
