"""Deprecated APIs removed in Kubernetes 1.26 (converted from deprecated-1-26.rego)."""
from scanner_core.policies import register

DEPRECATED_APIS = {
    "HorizontalPodAutoscaler": {
        "old": ["autoscaling/v2beta2"],
        "new": "autoscaling/v2",
        "since": "1.23",
    },
    "FlowSchema": {
        "old": ["flowcontrol.apiserver.k8s.io/v1beta1"],
        "new": "flowcontrol.apiserver.k8s.io/v1beta3",
        "since": "1.26",
    },
    "PriorityLevelConfiguration": {
        "old": ["flowcontrol.apiserver.k8s.io/v1beta1"],
        "new": "flowcontrol.apiserver.k8s.io/v1beta3",
        "since": "1.26",
    },
}
register("1.26", DEPRECATED_APIS)
