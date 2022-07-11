from cyclient.models import K8SResource

PODS_MOCK = [
    K8SResource('pod_name_1', 'pod', 'default', {}),
    K8SResource('pod_name_2', 'pod', 'default', {}),
    K8SResource('pod_name_3', 'pod', 'default', {}),
    K8SResource('pod_name_4', 'pod', 'default', {}),
    K8SResource('pod_name_5', 'pod', 'default', {}),
    K8SResource('cycode_pod_name_1', 'pod', 'cycode', {}),
    K8SResource('cycode_pod_name_2', 'pod', 'cycode', {}),
    K8SResource('cycode_pod_name_3', 'pod', 'cycode', {}),
    K8SResource('cycode_pod_name_4', 'pod', 'cycode', {}),
    K8SResource('cycode_pod_name_5', 'pod', 'cycode', {}),
    K8SResource('cycode_pod_name_6', 'pod', 'cycode', {}),
]

POD_MOCK = {
    'metadata': {
        "name": "pod-template-123xyz",
        "namespace": "default",
        'ownerReferences': [
            {
                "kind": "Deployment",
                "name": "nginx-deployment",
            }
        ]
    }
}

K8S_POD_MOCK = K8SResource('pod-template-123xyz', 'pod', 'default', POD_MOCK)


def list_to_str(values):
    return ",".join([str(val) for val in values])
