import json
from typing import List

from cycode.cli.models import ChangeResource


def generate_tf_content_from_tfplan(tfplan: str) -> str:
    planned_resources = _extract_resources(tfplan)
    return _generate_tf_content(planned_resources)


def _extract_resources(tfplan: str) -> List[ChangeResource]:
    try:
        tfplan_json = json.loads(tfplan)
        resources: List[ChangeResource] = []
        for change in tfplan_json.get('resource_changes', []):
            if change['change'] and change['change']['after']:
                resources.append(
                    ChangeResource(resource_type=change['type'], name=change['name'], values=change['change']['after'])
                )
        return resources

    except (ValueError, TypeError):
        return []


def _generate_tf_content(resources: List[ChangeResource]) -> str:
    tf_content = ''
    for resource in resources:
        tf_content += f'resource \"{resource.resource_type}\" \"{resource.name}\" {{\n'
        for key, value in resource.values.items():
            tf_content += f'  {key} = {json.dumps(value)}\n'
        tf_content += '}\n\n'

    return tf_content
