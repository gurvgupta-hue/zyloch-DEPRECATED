"""Auto-generated from: policies/terraform/azurerm_mssql_elasticpool/per_database_settings_check.rego"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import PER_DB_SETTINGS_INVALID
from .helpers import db_settings_valid


class Policy(BasePolicy):
    name = "azurerm_mssql_elasticpool_per_database_settings"

    def check(self, resource, metadata=None):
        if resource.get('type') != 'azurerm_mssql_elasticpool':
            return []
        
        # per_database_settings is expected under values or change.after
        values = resource.get('values') or resource.get('change', {}).get('after', {})
        db_settings = values.get('per_database_settings') or []
        
        # Check each per_database_settings entry
        for entry in db_settings:
            if not db_settings_valid(entry):
                return [Violation(
                    self.name,
                    PER_DB_SETTINGS_INVALID,
                    resource,
                    issue_type=IssueType.IncorrectValue,
                    severity=Severity.MEDIUM
                )]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
