from mock.mock import MagicMock, patch, call

from cyclient import K8SUpdaterClient
from cyclient.models import ResourcesCollection, K8SResource, InternalMetadata
from tests import PODS_MOCK


@patch("cyclient.config.batch_size", int(len(PODS_MOCK) / 3))
@patch("cyclient.config.dev_mode", True)
def test_publish_namespaced_resources():
    updater = K8SUpdaterClient('test_client_id', 'test_client_secret')
    updater.cycode_client = MagicMock()
    updater.publish_resources('pod', PODS_MOCK, 'default')
    calls = [call(url_path='api/v1/resources', body=ResourcesCollection('pod', 'default', PODS_MOCK[:3], len(PODS_MOCK)).to_json())]
    updater.cycode_client.post.assert_has_calls(calls)
    assert updater.cycode_client.post.call_count == 4


@patch("cyclient.config.dev_mode", True)
def test_publish_not_namespaced_resources():
    updater = K8SUpdaterClient('test_client_id', 'test_client_secret')
    updater.cycode_client = MagicMock()
    resource = K8SResource('role1', 'clusterrole', None, {})
    updater.publish_resources('clusterrole', [resource])
    calls = [call(url_path='api/v1/resources', body=ResourcesCollection('clusterrole', None, [resource], 1).to_json())]
    updater.cycode_client.post.assert_has_calls(calls)
