"""Auto-generated from: policies/terraform/azure_keyvault/network_acls_bypass_check.rego
"""
from typing import List, Optional

from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import NETWORK_ACLS_BYPASS


class Policy(BasePolicy):
    """Policy validator for Azure Key Vault network ACLs bypass settings."""
    
    name = "azure_keyvault_network_acls_bypass_check"

    def check(self, resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
        """Validate that Key Vault network ACLs bypass is correctly configured.
        
        Args:
            resource: Terraform resource dictionary
            metadata: Optional metadata dictionary
            
        Returns:
            List of policy violations found
        """
        values = resource.get("values", {})
        network_acls = values.get("network_acls", {})
        bypass = network_acls.get("bypass") if isinstance(network_acls, dict) else None
        if bypass and bypass != "AzureServices":
            return [Violation(
                self.name,
                NETWORK_ACLS_BYPASS,
                resource,
                params={"bypass": bypass}
            )]
        return []


def check(resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
    """Check function wrapper for policy validation."""
    return Policy().check(resource, metadata)
