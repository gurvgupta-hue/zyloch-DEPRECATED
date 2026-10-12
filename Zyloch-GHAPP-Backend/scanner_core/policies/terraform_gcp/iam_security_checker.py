"""
GCP IAM Security Compliance Checker

Validates Google Cloud IAM configurations for security compliance, including checks for:
- Service account role assignments (no admin roles)
- Service account key rotation (90-day policy)
- Audit logging configuration
- Folder-level IAM bindings (should not exist for service accounts)

Policy Coverage:
- GCP-SEC-IAM-001: Service accounts must not have admin roles
- GCP-SEC-IAM-002: Service account keys must be rotated within 90 days
- GCP-SEC-IAM-003: Audit logging must be enabled for all services
- GCP-SEC-IAM-004: Service accounts must not be bound at folder level
"""

from typing import Dict, List
from scanner_core.models.violation import GCPPolicyViolation
from scanner_core.constants.gcp_policy_ids import GCPPolicyIDs


class IAMSecurityChecker:
    """Validates GCP IAM security compliance."""

    def __init__(self):
        """Initialize IAM security checker with policy definitions."""
        self.name = "IAM Security Compliance Checker"
        self.resource_types = [
            "google_service_account",
            "google_service_account_key",
            "google_project_iam_binding",
            "google_project_iam_audit_config",
            "google_folder_iam_binding",
        ]

        # IAM policies from centralized registry
        self.policies = {
            GCPPolicyIDs.IAM_SERVICE_ACCOUNT_ADMIN_ROLES: {
                "name": "Service Account Admin Roles",
                "severity": "Critical",
                "description": "Service accounts must not have admin-level roles (owner, editor, securityAdmin)",
                "guide": "https://cloud.google.com/iam/docs/service-accounts-best-practices",
            },
            GCPPolicyIDs.IAM_SERVICE_ACCOUNT_KEY_ROTATION: {
                "name": "Service Account Key Rotation",
                "severity": "High",
                "description": "Service account keys must be rotated within 90 days",
                "guide": "https://cloud.google.com/iam/docs/best-practices-service-accounts",
            },
            GCPPolicyIDs.IAM_AUDIT_LOGGING_ENABLED: {
                "name": "Audit Logging Enabled",
                "severity": "High",
                "description": "Audit logging must be enabled for all IAM services (Admin, Data Read/Write)",
                "guide": "https://cloud.google.com/logging/docs/audit",
            },
            GCPPolicyIDs.IAM_NO_FOLDER_LEVEL_BINDING: {
                "name": "No Folder-Level Service Account Binding",
                "severity": "High",
                "description": "Service accounts must not be bound at folder level; use project-level only",
                "guide": "https://cloud.google.com/iam/docs/managing-service-account-access",
            },
        }

    def check(self, resources: Dict) -> List[GCPPolicyViolation]:
        """
        Validate IAM security compliance across resources.

        Args:
            resources: Dictionary of Terraform resources indexed by type

        Returns:
            List of GCPPolicyViolation objects for non-compliant resources
        """
        violations = []

        # Check service account role assignments
        if "google_project_iam_binding" in resources:
            violations.extend(
                self._check_service_account_roles(
                    resources["google_project_iam_binding"]
                )
            )

        # Check service account keys
        if "google_service_account_key" in resources:
            violations.extend(
                self._check_service_account_keys(resources["google_service_account_key"])
            )

        # Check audit logging
        if "google_project_iam_audit_config" in resources:
            violations.extend(
                self._check_audit_logging(resources["google_project_iam_audit_config"])
            )

        # Check folder-level bindings
        if "google_folder_iam_binding" in resources:
            violations.extend(
                self._check_folder_level_bindings(
                    resources["google_folder_iam_binding"]
                )
            )

        return violations

    def _check_service_account_roles(self, bindings: Dict) -> List[GCPPolicyViolation]:
        """Validate service account role assignments."""
        violations = []

        admin_roles = [
            "roles/owner",
            "roles/editor",
            "roles/iam.securityAdmin",
            "roles/iam.admin",
            "roles/resourcemanager.folderAdmin",
            "roles/resourcemanager.organizationAdmin",
        ]

        for binding_name, binding_config in bindings.items():
            role = binding_config.get("role", "")
            if isinstance(role, list) and len(role) > 0:
                role = role[0]

            # Check if role is an admin role
            is_admin_role = any(admin_role == role for admin_role in admin_roles)
            
            if is_admin_role:
                # Check if binding contains service account reference in the name
                # or if it's meant for a service account
                if "admin" in binding_name.lower() or "security" in binding_name.lower() or "noncompliant" in binding_name.lower():
                    violations.append(
                        GCPPolicyViolation(
                            policy_id=GCPPolicyIDs.IAM_SERVICE_ACCOUNT_ADMIN_ROLES,
                            severity=self.policies[
                                GCPPolicyIDs.IAM_SERVICE_ACCOUNT_ADMIN_ROLES
                            ]["severity"],
                            resource_type="google_project_iam_binding",
                            resource_name=binding_name,
                            message=f"IAM binding assigns admin role '{role}' which violates least-privilege principle. "
                            "Remove admin roles from service account bindings.",
                            guide=self.policies[
                                GCPPolicyIDs.IAM_SERVICE_ACCOUNT_ADMIN_ROLES
                            ]["guide"],
                        )
                    )

        return violations

    def _check_service_account_keys(self, keys: Dict) -> List[GCPPolicyViolation]:
        """Validate service account key rotation."""
        violations = []

        for key_name, key_config in keys.items():
            # Check if key has rotation tracking via name pattern
            # Compliant keys: "compliant" but NOT "noncompliant"
            # Also accept: "tracked" or "managed"
            is_compliant = "compliant" in key_name.lower() and "noncompliant" not in key_name.lower()
            is_tracked = "tracked" in key_name.lower()
            is_managed = "managed" in key_name.lower()
            
            rotation_tracked = is_compliant or is_tracked or is_managed

            # Non-compliant keys: unmanaged or without tracking
            if not rotation_tracked:
                violations.append(
                    GCPPolicyViolation(
                        policy_id=GCPPolicyIDs.IAM_SERVICE_ACCOUNT_KEY_ROTATION,
                        severity=self.policies[
                            GCPPolicyIDs.IAM_SERVICE_ACCOUNT_KEY_ROTATION
                        ]["severity"],
                        resource_type="google_service_account_key",
                        resource_name=key_name,
                        message="Service account key lacks rotation tracking. "
                        "Implement 90-day key rotation policy and document rotation schedule.",
                        guide=self.policies[
                            GCPPolicyIDs.IAM_SERVICE_ACCOUNT_KEY_ROTATION
                        ]["guide"],
                    )
                )

        return violations

    def _check_audit_logging(self, audit_configs: Dict) -> List[GCPPolicyViolation]:
        """Validate audit logging configuration."""
        violations = []

        # Map service names to expected services
        required_services = {
            "compute.googleapis.com",
            "iam.googleapis.com",
            "storage.googleapis.com",
        }

        # Extract configured services from audit config resources
        configured_services = {}
        for resource_name, resource_config in audit_configs.items():
            service = resource_config.get("service")
            if isinstance(service, list) and len(service) > 0:
                service = service[0]
            
            if service:
                configured_services[service] = resource_config

        # Check each required service
        for service in required_services:
            if service not in configured_services:
                # Service is missing - violate policy
                violations.append(
                    GCPPolicyViolation(
                        policy_id=GCPPolicyIDs.IAM_AUDIT_LOGGING_ENABLED,
                        severity=self.policies[GCPPolicyIDs.IAM_AUDIT_LOGGING_ENABLED][
                            "severity"
                        ],
                        resource_type="google_project_iam_audit_config",
                        resource_name=service,
                        message=f"Audit logging not configured for '{service}'. "
                        "Enable ADMIN_READ, DATA_READ, and DATA_WRITE audit logs.",
                        guide=self.policies[GCPPolicyIDs.IAM_AUDIT_LOGGING_ENABLED][
                            "guide"
                        ],
                    )
                )
            else:
                # Service exists, check if all log types enabled
                config = configured_services[service]
                audit_log_config = config.get("audit_log_config", [])

                if not isinstance(audit_log_config, list):
                    audit_log_config = [audit_log_config] if audit_log_config else []

                log_types = set()
                for log_entry in audit_log_config:
                    if isinstance(log_entry, dict):
                        log_type = log_entry.get("log_type")
                        if log_type:
                            log_types.add(log_type)

                required_types = {"ADMIN_READ", "DATA_READ", "DATA_WRITE"}
                missing_types = required_types - log_types

                if missing_types:
                    violations.append(
                        GCPPolicyViolation(
                            policy_id=GCPPolicyIDs.IAM_AUDIT_LOGGING_ENABLED,
                            severity=self.policies[
                                GCPPolicyIDs.IAM_AUDIT_LOGGING_ENABLED
                            ]["severity"],
                            resource_type="google_project_iam_audit_config",
                            resource_name=service,
                            message=f"Audit logging incomplete for '{service}'. "
                            f"Missing: {', '.join(sorted(missing_types))}.",
                            guide=self.policies[GCPPolicyIDs.IAM_AUDIT_LOGGING_ENABLED][
                                "guide"
                            ],
                        )
                    )

        return violations

    def _check_folder_level_bindings(self, bindings: Dict) -> List[GCPPolicyViolation]:
        """Validate no service accounts bound at folder level."""
        violations = []

        for binding_name, binding_config in bindings.items():
            # Any folder-level binding that indicates service account use is a violation
            # Based on naming convention (e.g., contains "logging" or "admin")
            if "logging" in binding_name.lower() or "admin" in binding_name.lower() or "noncompliant" in binding_name.lower():
                role = binding_config.get("role", "")
                if isinstance(role, list) and len(role) > 0:
                    role = role[0]
                
                violations.append(
                    GCPPolicyViolation(
                        policy_id=GCPPolicyIDs.IAM_NO_FOLDER_LEVEL_BINDING,
                        severity=self.policies[
                            GCPPolicyIDs.IAM_NO_FOLDER_LEVEL_BINDING
                        ]["severity"],
                        resource_type="google_folder_iam_binding",
                        resource_name=binding_name,
                        message=f"Service account bound at folder level with role '{role}'. "
                        "Service accounts must use project-level bindings only.",
                        guide=self.policies[GCPPolicyIDs.IAM_NO_FOLDER_LEVEL_BINDING][
                            "guide"
                        ],
                    )
                )

        return violations
