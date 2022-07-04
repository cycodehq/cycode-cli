import json
from typing import List, Dict

from cyclient.models import K8SResource, OwnerReference
from kubectl_client.shell_executor import shell
import click


class Resource:
    def __init__(self, name: str, type: str, namespace: str):
        self.name = name
        self.type = type

        if namespace != '<none>':
            self.namespace = namespace
        else:
            self.namespace = None

    def __repr__(self) -> str:
        return (
            f"name:{self.name}, type:{self.type}, namespace: {self.namespace}"
        )


def get_resources(resource_type: str) -> List[Resource]:
    command = ["kubectl", "get", resource_type, "--all-namespaces", "--no-headers",
               '-o', 'custom-columns=:metadata.name,:metadata.namespace']
    res = shell(command)

    resources = []
    if res is None:
        click.echo(f"failed to execute kubectl command: {command}")

    if "No resources found" in res:
        return resources

    for resource in res.splitlines():
        full_resource_definition = resource.split()
        name = full_resource_definition[0]
        namespace = full_resource_definition[1]
        resources.append(Resource(name=name, namespace=namespace, type=resource_type))
    return resources


def get_namespaces() -> List[str]:
    command_result = shell(["kubectl", "get", "namespaces", "--no-headers", '-o', 'custom-columns=:metadata.name'])
    if not command_result:
        return []

    return command_result.splitlines()


def get_owner_references(resource_type: str, resource_name: str, namespace: str) -> List[OwnerReference]:
    resource = get_resource(resource_type, resource_name, namespace)
    if not resource:
        return []

    return extract_owner_references(resource.content)


def get_resource(resource_type: str, resource_name: str, namespace: str) -> K8SResource:
    cmd = ["kubectl", "get", resource_type, resource_name, "--no-headers", '-o', 'json']
    if namespace:
        cmd.extend(["-n", namespace])
    command_result = shell(cmd)
    if not command_result:
        return None

    return _create_resource(resource_type, json.loads(command_result))


def get_all_not_namespaced_resources(resource_type: str) -> List[K8SResource]:
    cli_res = shell(['kubectl', 'get', resource_type, '-o', 'json'])
    items = _get_items(cli_res)
    return _create_resources(resource_type, items)


def get_all_resources_per_namespace(resource_type: str, namespace: str) -> List[K8SResource]:
    cli_res = shell(['kubectl', 'get', resource_type, '--namespace', namespace, '-o', 'json'])
    items = _get_items(cli_res)
    return _create_resources(resource_type, items)


def get_resource_yaml(resource_type: str, resource_name: str, namespace):
    return shell(["kubectl", "get", resource_type, resource_name, "-n", namespace, "-o", "yaml"])


def get_resource_json(resource_type: str, resource_name: str, namespace):
    if namespace is not None:
        return shell(["kubectl", "get", resource_type, resource_name, "-n", namespace, "-o", "json"])
    else:
        return shell(["kubectl", "get", resource_type, resource_name, "-o", "json"])


def _get_items(command_result: str):
    result = json.loads(command_result)
    return result.get('items')


def _create_resources(resource_type: str, items: List) -> List[K8SResource]:
    return [_create_resource(resource_type, item) for item in items or []]


def _create_resource(resource_type: str, item: Dict) -> K8SResource:
    metadata = item.get('metadata', {})
    return K8SResource(
        name=metadata.get('name'),
        resource_type=resource_type,
        namespace=metadata.get('namespace'),
        content=item
    )


def extract_owner_references(content: Dict) -> List[OwnerReference]:
    metadata = content.get('metadata', {})
    references = metadata.get('ownerReferences')

    if references is None:
        return []

    return [_create_owner_reference(item) for item in references]


def _create_owner_reference(item: Dict) -> OwnerReference:
    return OwnerReference(
        name=item.get('name'),
        kind=item.get('kind'),
    )
