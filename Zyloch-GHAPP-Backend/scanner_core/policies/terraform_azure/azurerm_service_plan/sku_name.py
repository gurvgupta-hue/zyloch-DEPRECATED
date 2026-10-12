"""Auto-generated from: policies/terraform/azurerm_service_plan/sku_name.rego
"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import SERVICE_PLAN_SKU_MISSING


ALLOWED_SKU_NAMES = {
    "B1", "B2", "B3", "D1", "F1",
    "I1", "I2", "I3", "I1v2", "I1mv2",
    "I2v2", "I2mv2", "I3v2", "I3mv2",
    "I4v2", "I4mv2", "I5v2", "I5mv2",
    "I6v2", "P1v2", "P2v2", "P3v2",
    "P0v3", "P1v3", "P2v3", "P3v3",
    "P1mv3", "P2mv3", "P3mv3", "P4mv3",
    "P5mv3", "S1", "S2", "S3",
    "SHARED", "EP1", "EP2", "EP3",
    "FC1", "WS1", "WS2", "WS3", "Y1"
}


class Policy(BasePolicy):
    name = "azurerm_service_plan_sku_name"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        sku_name = values.get("sku_name", "")
        
        # Check if sku_name is not set or not in allowed values
        if not sku_name or sku_name not in ALLOWED_SKU_NAMES:
            return [Violation(
                self.name,
                SERVICE_PLAN_SKU_MISSING,
                resource,
                issue_type=IssueType.IncorrectValue,
                severity=Severity.MEDIUM
            )]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
