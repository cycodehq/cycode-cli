import json
import time

from cycode.cli import consts
from cycode.cli.exceptions.custom_exceptions import TfplanKeyError
from cycode.cli.models import ResourceChange
from cycode.cli.utils.path_utils import change_filename_extension, load_json

ACTIONS_TO_OMIT_RESOURCE = ['delete']


def generate_tfplan_document_name(path: str) -> str:
    document_name = change_filename_extension(path, 'tf')
    timestamp = int(time.time())
    return f'{timestamp}-{document_name}'


def is_iac(scan_type: str) -> bool:
    return scan_type == consts.IAC_SCAN_TYPE


def is_tfplan_file(file: str, content: str) -> bool:
    if not file.endswith('.json'):
        return False
    tf_plan = load_json(content)
    if not isinstance(tf_plan, dict):
        return False
    return 'resource_changes' in tf_plan


def generate_tf_content_from_tfplan(filename: str, tfplan: str) -> str:
    planned_resources = _extract_resources(tfplan, filename)
    return _generate_tf_content(planned_resources)


def _generate_tf_content(resource_changes: list[ResourceChange]) -> str:
    tf_content = ''
    for resource_change in resource_changes:
        if not any(item in resource_change.actions for item in ACTIONS_TO_OMIT_RESOURCE):
            tf_content += _generate_resource_content(resource_change)
    return tf_content


def _generate_resource_content(resource_change: ResourceChange) -> str:
    resource_content = f'resource "{resource_change.resource_type}" "{_get_resource_name(resource_change)}" {{\n'
    if resource_change.values is not None:
        for key, value in resource_change.values.items():
            resource_content += f'  {key} = {json.dumps(value)}\n'
    resource_content += '}\n\n'
    return resource_content


def _get_resource_name(resource_change: ResourceChange) -> str:
    parts = [resource_change.module_address, resource_change.name]

    if resource_change.index is not None:
        parts.append(str(resource_change.index))

    valid_parts = [part for part in parts if part]

    return '.'.join(valid_parts)


def _extract_resources(tfplan: str, filename: str) -> list[ResourceChange]:
    tfplan_json = load_json(tfplan)
    resources: list[ResourceChange] = []
    try:
        resource_changes = tfplan_json['resource_changes']
        for resource_change in resource_changes:
            resources.append(
                ResourceChange(
                    module_address=resource_change.get('module_address'),
                    resource_type=resource_change['type'],
                    name=resource_change['name'],
                    index=resource_change.get('index'),
                    actions=resource_change['change']['actions'],
                    values=resource_change['change']['after'],
                )
            )
    except (KeyError, TypeError) as e:
        raise TfplanKeyError(filename) from e
    return resources
