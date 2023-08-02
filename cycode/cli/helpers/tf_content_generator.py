import json
from typing import List, Optional

from cycode.cli.exceptions.custom_exceptions import TfplanKeyError
from cycode.cli.models import ChangeResource


def _generate_tf_content(resources: List[ChangeResource]) -> str:
    tf_content = ''
    for resource in resources:
        tf_content += f'resource \"{resource.resource_type}\" \"{resource.name}\" {{\n'
        for key, value in resource.values.items():
            tf_content += f'  {key} = {json.dumps(value)}\n'
        tf_content += '}\n\n'
    return tf_content


def generate_tf_content_from_tfplan(tfplan: str) -> str:
    planned_resources = _extract_resources(tfplan)
    return _generate_tf_content(planned_resources)


def _try_get_tfplan(tfplan: Optional[str]) -> json:
    if tfplan is None:
        return None

    try:
        return json.loads(tfplan)
    except json.JSONDecodeError:
        return None


def _extract_resources(tfplan: str) -> List[ChangeResource]:
    tfplan_json = _try_get_tfplan(tfplan).get('resource_changes')
    resources: List[ChangeResource] = []
    for resource_change in tfplan_json:
        try:
            resources.append(
                ChangeResource(
                    resource_type=resource_change['type'],
                    name=resource_change['name'],
                    values=resource_change['change']['after'],
                )
            )
        except KeyError as e:
            raise TfplanKeyError('Error occurred while parsing tfplan file.') from e
    return resources
