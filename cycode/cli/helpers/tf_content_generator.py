import json
from typing import List

from cycode.cli.exceptions.custom_exceptions import TfplanKeyError
from cycode.cli.models import ResourceChange
from cycode.cli.utils.path_utils import load_json

ACTIONS_LISTS_TO_OMIT_RESOURCE = [['delete']]


def generate_tf_content_from_tfplan(tfplan: str) -> str:
    planned_resources = _extract_resources(tfplan)
    return _generate_tf_content(planned_resources)


def _generate_tf_content(resource_changes: List[ResourceChange]) -> str:
    tf_content = ''
    for resource_change in resource_changes:
        if resource_change.actions not in ACTIONS_LISTS_TO_OMIT_RESOURCE:
            tf_content += _generate_resource_content(resource_change)
    return tf_content


def _generate_resource_content(resource_change: ResourceChange) -> str:
    resource_content = f'resource "{resource_change.resource_type}" "{resource_change.name}" {{\n'
    if resource_change.values is not None:
        for key, value in resource_change.values.items():
            resource_content += f'  {key} = {json.dumps(value)}\n'
    resource_content += '}\n\n'
    return resource_content


def _extract_resources(tfplan: str) -> List[ResourceChange]:
    tfplan_json = load_json(tfplan)
    resources: List[ResourceChange] = []
    try:
        resource_changes = tfplan_json['resource_changes']
        for resource_change in resource_changes:
            resources.append(
                ResourceChange(
                    resource_type=resource_change['type'],
                    name=resource_change['name'],
                    actions=resource_change['change']['actions'],
                    values=resource_change['change']['after'],
                )
            )
    except KeyError as e:
        raise TfplanKeyError('Error occurred while parsing tfplan file.') from e
    return resources
