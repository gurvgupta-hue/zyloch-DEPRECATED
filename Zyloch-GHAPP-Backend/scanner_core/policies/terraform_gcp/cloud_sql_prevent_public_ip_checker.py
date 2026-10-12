"""
Cloud SQL Prevent Public IP Checker

This checker validates that Cloud SQL instances are not publicly accessible.
It ensures that 'authorized_networks' does not contain '0.0.0.0/0' and
that 'ip_configuration' is properly configured.
"""

from typing import List, Dict, Any
from scanner_core.models.violation import GCPPolicyViolation
from scanner_core.constants.gcp_policy_ids import GCPPolicyIDs


class CloudSqlPreventPublicIpChecker:
    """
    Checks that Cloud SQL instances do not allow public access.
    Validates ip_configuration and authorized_networks settings.
    """

    GUIDE = "https://myguide.com"
    POLICY_ID = GCPPolicyIDs.CLOUD_SQL_PREVENT_PUBLIC_IP

    def check(self, resources: Dict[str, Any]) -> List[GCPPolicyViolation]:
        """
        Check Cloud SQL instances for public IP vulnerabilities.

        Args:
            resources: Dictionary containing terraform resources.
                      Expected format: {"google_sql_database_instance": {"resource_name": {...}}}

        Returns:
            List of violations for instances with public IP access.
        """
        violations = []

        sql_instances = resources.get("google_sql_database_instance", {})

        if not isinstance(sql_instances, dict):
            return violations

        for resource_name, resource in sql_instances.items():
            resource_violations = self._validate_instance(resource, resource_name)
            violations.extend(resource_violations)

        return violations

    def _validate_instance(self, resource: Dict[str, Any], resource_name: str) -> List[GCPPolicyViolation]:
        """
        Validate a single Cloud SQL instance.

        Args:
            resource: The Cloud SQL instance configuration
            resource_name: Name of the resource

        Returns:
            List of violations found
        """
        violations = []

        # Check if settings exists
        if not self._has_field(resource, "settings"):
            return violations

        settings = self._unwrap_field(resource.get("settings"))
        if not isinstance(settings, dict):
            return violations

        if not self._has_field(settings, "ip_configuration"):
            violations.append(
                self._create_violation(
                    resource_name,
                    "'ip_configuration' must be defined and must allow only trusted networks"
                )
            )
            return violations

        ip_config = self._unwrap_field(settings.get("ip_configuration"))

        # Check for 0.0.0.0 in authorized networks
        if self._has_field(ip_config, "authorized_networks"):
            authorized_networks = ip_config.get("authorized_networks", [])
            if self._contains_public_cidr(authorized_networks):
                violations.append(
                    self._create_violation(
                        resource_name,
                        "'authorized_network' address must not contain the cidr: '0.0.0.0/0'"
                    )
                )

        # If no authorized networks defined, check other requirements
        if not self._has_field(ip_config, "authorized_networks"):
            ipv4_enabled = ip_config.get("ipv4_enabled", False)
            has_private_network = self._has_field(ip_config, "private_network")

            if ipv4_enabled:
                violations.append(
                    self._create_violation(
                        resource_name,
                        "'ipv4_enabled' must be disabled when there are no authorized networks defined"
                    )
                )
            elif not has_private_network:
                violations.append(
                    self._create_violation(
                        resource_name,
                        "'ipv4_enabled' must be disabled and 'private_network' must be defined when there are no authorized networks defined"
                    )
                )

        return violations

    def _unwrap_field(self, value: Any) -> Any:
        """
        Unwrap a field that may be a single-element list (tfplan.json format).
        e.g. [{"key": "val"}] -> {"key": "val"}

        Args:
            value: The field value (dict, list, or other)

        Returns:
            The unwrapped dict, or the original value.
        """
        if isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict):
            return value[0]
        if isinstance(value, list) and len(value) == 0:
            return {}
        return value

    def _has_field(self, obj: Any, field: str) -> bool:
        """
        Check if a field exists in an object/dict.
        Handles tfplan.json list-of-dicts format by unwrapping first.

        Args:
            obj: Object to check
            field: Field name

        Returns:
            True if field exists and is not None/empty, False otherwise.
        """
        if not isinstance(obj, dict):
            return False
        value = obj.get(field)
        if value is None:
            return False
        # Empty list means field not configured in tfplan.json
        if isinstance(value, list) and len(value) == 0:
            return False
        return True

    def _contains_public_cidr(self, authorized_networks: Any) -> bool:
        """
        Check if authorized networks contain public CIDR (0.0.0.0/0).

        Args:
            authorized_networks: List or dict of authorized networks

        Returns:
            True if public CIDR found, False otherwise.
        """
        networks = self._normalize_networks(authorized_networks)

        if networks is None:
            return False

        for network in networks:
            if isinstance(network, dict):
                value = network.get("value", "")
                if value and "0.0.0.0" in value:
                    return True

        return False

    def _normalize_networks(self, networks: Any) -> Any:
        """
        Normalize networks to a list format.

        Args:
            networks: Networks configuration (list or dict)

        Returns:
            List of networks or None
        """
        if isinstance(networks, list):
            return networks
        elif isinstance(networks, dict):
            return [networks]
        return None

    def _create_violation(self, resource_name: str, message: str) -> GCPPolicyViolation:
        """
        Create a policy violation.

        Args:
            resource_name: Name of the violating resource
            message: Violation message

        Returns:
            GCPPolicyViolation object
        """
        policy = GCPPolicyIDs.get(self.POLICY_ID)
        severity = policy.security_level if policy else "CRITICAL"

        return GCPPolicyViolation(
            policy_id=self.POLICY_ID,
            resource_type="google_sql_database_instance",
            resource_name=resource_name,
            message=message,
            severity=severity,
            guide=self.GUIDE
        )
