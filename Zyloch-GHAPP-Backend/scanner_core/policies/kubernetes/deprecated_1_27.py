"""Deprecated APIs removed in Kubernetes 1.27 (converted from deprecated-1-27.rego)."""
from scanner_core.policies import register

DEPRECATED_APIS = {
    "CSIStorageCapacity": {
        "old": ["storage.k8s.io/v1beta1"],
        "new": "storage.k8s.io/v1",
        "since": "1.24",
    },
}
register("1.27", DEPRECATED_APIS)
