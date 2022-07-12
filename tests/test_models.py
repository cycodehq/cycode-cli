from cyclient.models import ResourcesCollection, InternalMetadata, K8SResource
from tests import PODS_MOCK


def test_batch_resources_to_json():
    batch = ResourcesCollection('pod', 'default', PODS_MOCK, 77777)
    json_dict = batch.to_json()
    assert 'resources' in json_dict.keys()
    assert 'namespace' in json_dict.keys()
    assert 'total_count' in json_dict.keys()
    assert 'type' in json_dict.keys()
    assert json_dict['total_count'] == 77777
    assert json_dict['type'] == 'pod'
    assert json_dict['namespace'] == 'default'
    assert json_dict['resources'][0]['name'] == 'pod_name_1'


def test_internal_metadata_to_json():
    resource = K8SResource('nginx-template-123-456', 'pod', 'cycode', {})
    resource.internal_metadata = InternalMetadata('nginx-template', 'deployment')
    batch = ResourcesCollection('pod', 'cycode', [resource], 1)
    json_dict = batch.to_json()
    internal_metadata = json_dict['resources'][0]['internal_metadata']
    assert internal_metadata['root_entity_name'] == 'nginx-template'
    assert internal_metadata['root_entity_type'] == 'deployment'
