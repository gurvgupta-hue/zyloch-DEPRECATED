"""Deprecated APIs removed in Kubernetes 1.29 (converted from deprecated-1-29.rego)."""
from scanner_core.policies import register

DEPRECATED_APIS = {
    "FlowSchema": {
        "old": ["flowcontrol.apiserver.k8s.io/v1beta2"],
        "new": "flowcontrol.apiserver.k8s.io/v1beta3",
        "since": "1.26",
    },
    "PriorityLevelConfiguration": {
        "old": ["flowcontrol.apiserver.k8s.io/v1beta2"],
        "new": "flowcontrol.apiserver.k8s.io/v1beta3",
        "since": "1.26",
    },
}
register("1.29", DEPRECATED_APIS)
