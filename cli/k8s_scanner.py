import concurrent.futures

import click
from typing import List

from cyclient import K8SUpdaterClient
from cyclient.config import get_logger
from cyclient.models import K8SResource, OwnerReference, InternalMetadata
from cyclient.utils import cpu_count
from kubectl_client import kubectl

SUPPORTED_RESOURCES = [
    "deployment",
    "replicaset",
    "pod",
    "configmap",
    "daemonset",
    "endpoints",
    "rolebinding",
    "namespace",
    "role",
    "clusterrolebinding",
    "clusterrole",

    "cronjob",
    "horizontalpodautoscaler",
    "ingress",
    "job",
    "limitrange",
    "networkpolicy",
    "poddisruptionbudget",
    "podsecuritypolicy",
    "replicationcontroller",
    "resourcequota",
    "serviceaccount",
    "service",
    "statefulset"
]

# https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/#not-all-objects-are-in-a-namespace
# kubectl api-resources --namespaced=false
NOT_NAMESPACED_RESOURCES = [
    "componentstatuses",
    "namespaces",
    "nodes",
    "persistentvolumes",
    "mutatingwebhookconfigurations",
    "validatingwebhookconfigurations",
    "customresourcedefinitions",
    "apiservices",
    "tokenreviews",
    "selfsubjectaccessreviews",
    "selfsubjectrulesreviews",
    "subjectaccessreviews",
    "certificatesigningrequests",
    "flowschemas",
    "prioritylevelconfigurations",
    "ingressclasses",
    "runtimeclasses",
    "podsecuritypolicies",
    "clusterrolebindings",
    "clusterroles",
    "priorityclasses",
    "csidrivers",
    "csinodes",
    "storageclasses",
    "volumeattachments",
]


class KubernetesScanner:

    def __init__(self, cycode_client: K8SUpdaterClient):
        self.logger = get_logger(__name__)
        self.cycode_client = cycode_client

    def publish_cluster_resources(self):
        namespaces = kubectl.get_namespaces()
        if not namespaces:
            self.logger.error('Could not get namespaces')
            return

        with concurrent.futures.ThreadPoolExecutor(max_workers=cpu_count() * 2) as executor:
            futures = [executor.submit(self.publish_resources, resource_type, namespaces,
                                       resource_type not in NOT_NAMESPACED_RESOURCES)
                       for resource_type in SUPPORTED_RESOURCES]

            concurrent.futures.as_completed(futures)

    def _publish_resources_per_namespaces(self, resource_type: str, namespaces: List[str]):
        # todo: make it async?
        for namespace in namespaces:
            resources = kubectl.get_all_resources_per_namespace(resource_type, namespace)
            if not resources:
                self.logger.debug(f'Resources {resource_type} in namespace {namespace} not found, skipping publishing')
                continue

            self.populate_additional_fields(resources, namespace)
            self.cycode_client.publish_resources(resource_type, resources, namespace)

    def publish_resources(self, resource_type: str, namespaces: List[str], namespaced: bool):
        if namespaced:
            self._publish_resources_per_namespaces(resource_type, namespaces)
        else:
            self._publish_not_namespaced_resources(resource_type)
        click.echo(f'Finished publishing resources {resource_type}.')

    def _publish_not_namespaced_resources(self, resource_type):
        resources = kubectl.get_all_not_namespaced_resources(resource_type)
        if not resources:
            self.logger.debug(f'Resources {resource_type} not found, skipping publishing')
            return

        self.populate_additional_fields(resources)
        self.cycode_client.publish_resources(resource_type, resources)

    def populate_additional_fields(self, resources: List[K8SResource], namespace=None):
        for resource in resources:
            self._add_owner_resource_metadata(resource, namespace)

    def _add_owner_resource_metadata(self, resource: K8SResource, namespace: str):
        owners = kubectl.extract_owner_references(resource.content)
        if not owners:
            return

        if len(owners) > 1:
            self.logger.warning(f'Skipping resource with multiple owners: {resource.type} {resource.name}')
            return

        root_resource = self._get_root_resource(owners[0], namespace)
        internal_metadata = InternalMetadata(root_resource.name, root_resource.kind)
        resource.content['internal_metadata'] = internal_metadata.to_json()
        resource.internal_metadata = internal_metadata

    def _get_root_resource(self, owner: OwnerReference, namespace: str) -> OwnerReference:
        root_owner = owner
        while owner is not None:
            owner = self._get_root_reference(owner, namespace)
            if owner is not None:
                root_owner = owner

        return root_owner

    def _get_root_reference(self, resource_owner: OwnerReference, namespace: str) -> OwnerReference:
        self.logger.debug(f'Getting resource owner for: {resource_owner}')
        owner_references = kubectl.get_owner_references(resource_owner.kind, resource_owner.name, namespace)
        return owner_references[0] if len(owner_references) == 1 else None
