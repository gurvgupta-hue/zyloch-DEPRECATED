"""Auto-generated from: policies/terraform/azurerm_storageaccount/min_tls_version_check.rego
"""
from typing import List
from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import STORAGE_ACCOUNT_TLS_INSECURE


class Policy(BasePolicy):
    name = "azurerm_storageaccount_min_tls_version_check"

    def check(self, resource, metadata=None) -> List[Violation]:
        # TLS1_0 and TLS1_1 are insecure and should be flagged
        INSECURE_TLS_VERSIONS = {"TLS1_0", "TLS1_1"}
        
        values = resource.get("values", {})
        min_tls_version = values.get("min_tls_version", "")
        
        # Skip validation if empty (no TLS version specified is acceptable)
        if not min_tls_version or not str(min_tls_version).strip():
            return []
        
        # Normalize to uppercase for comparison
        tls_normalized = str(min_tls_version).strip().upper()
        
        # Flag insecure TLS versions (TLS1_0, TLS1_1)
        if tls_normalized in INSECURE_TLS_VERSIONS:
            return [Violation(
                self.name, 
                STORAGE_ACCOUNT_TLS_INSECURE, 
                resource,
                params={"value": min_tls_version, "minimum": "TLS1_2"}
            )]
        
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
