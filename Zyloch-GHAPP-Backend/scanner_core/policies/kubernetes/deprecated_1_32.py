"""Deprecated APIs removed in Kubernetes 1.32 (converted from deprecated-1-32.rego)."""
from scanner_core.policies import register

DEPRECATED_APIS = {
    "FlowSchema": {
        "old": ["flowcontrol.apiserver.k8s.io/v1beta3"],
        "new": "flowcontrol.apiserver.k8s.io/v1",
        "since": "1.29",
    },
    "PriorityLevelConfiguration": {
        "old": ["flowcontrol.apiserver.k8s.io/v1beta3"],
        "new": "flowcontrol.apiserver.k8s.io/v1",
        "since": "1.29",
    },
}
register("1.32", DEPRECATED_APIS)
