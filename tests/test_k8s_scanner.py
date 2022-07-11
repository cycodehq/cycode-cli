from copy import deepcopy

from mock.mock import MagicMock, call

from cli.k8s_scanner import KubernetesScanner
from cyclient.models import InternalMetadata
from tests import PODS_MOCK, K8S_POD_MOCK


def test_publish_resources_per_namespaces(mocker):
    mocker.patch('kubectl_client.kubectl.get_all_resources_per_namespace', return_value=PODS_MOCK)
    client_mock = MagicMock()
    scanner = KubernetesScanner(client_mock)
    scanner.publish_resources('pod', ['default', 'cycode'], True)
    calls = [call('pod', PODS_MOCK, 'default'), call('pod', PODS_MOCK, 'cycode')]
    client_mock.publish_resources.assert_has_calls(calls)


def test_publish_not_namespaces_resources(mocker):
    mocker.patch('kubectl_client.kubectl.get_all_not_namespaced_resources', return_value=PODS_MOCK)
    client_mock = MagicMock()
    scanner = KubernetesScanner(client_mock)
    scanner.publish_resources('pod', ['default', 'cycode'], False)
    client_mock.publish_resources.assert_called_once_with('pod', PODS_MOCK)


def test_populate_additional_fields(mocker):
    mocker.patch('kubectl_client.kubectl.get_owner_references', return_value=[])
    scanner = KubernetesScanner(MagicMock())
    resource = deepcopy(K8S_POD_MOCK)
    scanner.populate_additional_fields([resource], 'default')
    # Verify in the json content
    internal_metadata = resource.content.get('internal_metadata')
    assert internal_metadata is not None
    assert internal_metadata.get('root_entity_name') == 'nginx-deployment'
    assert internal_metadata.get('root_entity_type') == 'Deployment'
    # Verify in the root entity
    assert resource.internal_metadata.root_entity_name == 'nginx-deployment'
    assert resource.internal_metadata.root_entity_type == 'Deployment'
