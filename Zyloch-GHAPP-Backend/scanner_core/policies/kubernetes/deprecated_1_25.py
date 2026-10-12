"""Deprecated APIs removed in Kubernetes 1.25 (converted from deprecated-1-25.rego)."""
from scanner_core.policies import register

DEPRECATED_APIS = {
    "RuntimeClass": {
        "old": ["node.k8s.io/v1beta1"],
        "new": "node.k8s.io/v1",
        "since": "1.20",
    },
    "PodDisruptionBudget": {
        "old": ["policy/v1beta1"],
        "new": "policy/v1",
        "since": "1.21",
    },
    "PodSecurityPolicy": {
        "old": ["policy/v1beta1"],
        "new": "<removed>",
        "since": "1.21",
    },
    "EndpointSlice": {
        "old": ["discovery.k8s.io/v1beta1"],
        "new": "discovery.k8s.io/v1",
        "since": "1.21",
    },
    "CronJob": {
        "old": ["batch/v1beta1"],
        "new": "batch/v1",
        "since": "1.21",
    },
    "HorizontalPodAutoscaler": {
        "old": ["autoscaling/v2beta1"],
        "new": "autoscaling/v2",
        "since": "1.23",
    },
}
register("1.25", DEPRECATED_APIS)
