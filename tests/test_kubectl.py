import json

import pytest

from cyclient.models import OwnerReference
from kubectl_client import kubectl
from tests import K8S_POD_MOCK, POD_MOCK, list_to_str


def test_get_namespaces(mocker):
    mocker.patch('kubectl_client.kubectl.shell', return_value='default\ncycode')
    namespaces = kubectl.get_namespaces()
    assert namespaces == ['default', 'cycode']


def test_get_owner_references(mocker):
    mocker.patch('kubectl_client.kubectl.get_resource', return_value=K8S_POD_MOCK)
    owner_references = kubectl.get_owner_references('pod', 'pod-id', 'namespace')
    assert list_to_str(owner_references) == list_to_str([
        OwnerReference(
            kind="Deployment",
            name="nginx-deployment",
        )
    ])


@pytest.mark.parametrize('namespace,expected_cmd', [
    [
        None,
        ['kubectl', 'get', 'pod', 'default', '--no-headers', '-o', 'json']
    ],
    [
        'cycode',
        ['kubectl', 'get', 'pod', 'default', '--no-headers', '-o', 'json', '-n', 'cycode']
    ],
])
def test_get_resource(mocker, namespace, expected_cmd):
    mocker.patch('kubectl_client.kubectl.shell', return_value=json.dumps(POD_MOCK))
    resource = kubectl.get_resource('pod', 'default', namespace)
    assert resource.type == 'pod'
    assert resource.namespace == 'default'
    assert resource.name == 'pod-template-123xyz'
    assert resource.content == POD_MOCK
    kubectl.shell.assert_called_once_with(expected_cmd)
