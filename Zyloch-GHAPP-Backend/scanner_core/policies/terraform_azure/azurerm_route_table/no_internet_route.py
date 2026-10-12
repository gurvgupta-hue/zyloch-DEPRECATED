"""Auto-generated from: policies/terraform/azurerm_route_table/no_internet_route.rego"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import ROUTE_TABLE_INTERNET_ROUTE


class Policy(BasePolicy):
    name = "azurerm_route_table_no_internet_route"
    # Rego rule targets individual route entries; apply to azurerm_route
    RESOURCE_TYPES = {"azurerm_route"}

    def check(self, resource, metadata=None):
        # This rule applies to route resources (azurerm_route)
        if resource.get("type") != "azurerm_route":
            return []
        
        values = resource.get("values", {})
        next_hop_type = values.get("next_hop_type")
        
        if next_hop_type == "Internet":
            # Use the associated route table name if available
            rt_name = values.get("route_table_name") or resource.get("name", "")
            route_name = values.get("name", "")
            return [Violation(
                self.name,
                ROUTE_TABLE_INTERNET_ROUTE,
                resource,
                params={"rt_name": rt_name, "route_name": route_name}
            )]
        
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
