"""
Google Cloud Logging Security Compliance Checker

Validates Google Cloud Logging and Cloud Audit Logs configuration for security compliance,
including checks for:
- Audit logging enablement (ADMIN_READ, DATA_READ, DATA_WRITE)
- Log sink configuration (export to centralized destination)
- Log retention policies (minimum 365 days)
- Log analytics enablement

Policy Coverage:
- GCP-SEC-LOGGING-001: Audit logging enabled for all access types
- GCP-SEC-LOGGING-002: Log sinks configured to centralized destination
- GCP-SEC-LOGGING-003: Log retention policy meets organizational standards (≥365 days)
- GCP-SEC-LOGGING-004: Log analytics enabled for compliance
"""

from typing import Dict, List
from scanner_core.models.violation import GCPPolicyViolation
from scanner_core.constants.gcp_policy_ids import GCPPolicyIDs


class LoggingSecurityChecker:
    """Validates Google Cloud Logging security compliance."""

    def __init__(self):
        """Initialize Logging security checker with policy definitions."""
        self.name = "Cloud Logging Security Compliance Checker"
        self.resource_types = [
            "google_logging_project_sink",
            "google_logging_project_bucket_config",
            "google_project_iam_audit_config",
            "google_logging_metric",
        ]

        # Logging policies from centralized registry
        self.policies = {
            GCPPolicyIDs.LOGGING_AUDIT_ENABLED: {
                "name": "Audit Logging Enabled",
                "severity": "High",
                "description": "Cloud Audit Logs must be enabled for ADMIN_READ, DATA_READ, and DATA_WRITE",
                "guide": "https://cloud.google.com/logging/docs/audit",
            },
            GCPPolicyIDs.LOGGING_SINK_CONFIGURED: {
                "name": "Log Sink Configured",
                "severity": "High",
                "description": "Log sinks must be configured to export logs to centralized destination",
                "guide": "https://cloud.google.com/logging/docs/export",
            },
            GCPPolicyIDs.LOGGING_RETENTION_POLICY: {
                "name": "Log Retention Policy",
                "severity": "Medium",
                "description": "Log retention must meet organizational policy (minimum 365 days)",
                "guide": "https://cloud.google.com/logging/docs/retention-pricing",
            },
            GCPPolicyIDs.LOGGING_ANALYTICS_ENABLED: {
                "name": "Log Analytics Enabled",
                "severity": "Medium",
                "description": "Log analytics must be enabled for compliance and forensics",
                "guide": "https://cloud.google.com/logging/docs/log-analytics",
            },
        }

    def check(self, resources: Dict) -> List[GCPPolicyViolation]:
        """
        Validate Logging security compliance across resources.

        Args:
            resources: Dictionary of Terraform resources indexed by type

        Returns:
            List of GCPPolicyViolation objects for non-compliant resources
        """
        violations = []

        # Check log sinks
        if "google_logging_project_sink" in resources:
            violations.extend(
                self._check_log_sinks(resources["google_logging_project_sink"])
            )

        # Check logging buckets
        if "google_logging_project_bucket_config" in resources:
            violations.extend(
                self._check_logging_buckets(
                    resources["google_logging_project_bucket_config"]
                )
            )

        # Check audit config
        if "google_project_iam_audit_config" in resources:
            violations.extend(
                self._check_audit_config(resources["google_project_iam_audit_config"])
            )

        return violations

    def _check_log_sinks(self, sinks: Dict) -> List[GCPPolicyViolation]:
        """Validate log sinks are configured to centralized destination."""
        violations = []

        for sink_name, sink_config in sinks.items():
            # Check if sink is configured to centralized destination
            if not self._has_centralized_destination(sink_config):
                violations.append(
                    GCPPolicyViolation(
                        policy_id=GCPPolicyIDs.LOGGING_SINK_CONFIGURED,
                        severity=self.policies[GCPPolicyIDs.LOGGING_SINK_CONFIGURED][
                            "severity"
                        ],
                        resource_type="google_logging_project_sink",
                        resource_name=sink_name,
                        message="Log sink must be configured to export to centralized destination "
                        "(BigQuery, Cloud Storage, or Pub/Sub). Default bucket is not sufficient.",
                        guide=self.policies[GCPPolicyIDs.LOGGING_SINK_CONFIGURED]["guide"],
                    )
                )

        return violations

    def _check_logging_buckets(self, buckets: Dict) -> List[GCPPolicyViolation]:
        """Validate logging bucket retention and analytics."""
        violations = []

        for bucket_name, bucket_config in buckets.items():
            # Check retention days
            if not self._has_sufficient_retention(bucket_config):
                violations.append(
                    GCPPolicyViolation(
                        policy_id=GCPPolicyIDs.LOGGING_RETENTION_POLICY,
                        severity=self.policies[GCPPolicyIDs.LOGGING_RETENTION_POLICY][
                            "severity"
                        ],
                        resource_type="google_logging_project_bucket_config",
                        resource_name=bucket_name,
                        message="Log retention must be at least 365 days to meet organizational policy. "
                        "Configure retention_days >= 365.",
                        guide=self.policies[GCPPolicyIDs.LOGGING_RETENTION_POLICY]["guide"],
                    )
                )

            # Check analytics enabled
            if not self._has_analytics_enabled(bucket_config):
                violations.append(
                    GCPPolicyViolation(
                        policy_id=GCPPolicyIDs.LOGGING_ANALYTICS_ENABLED,
                        severity=self.policies[GCPPolicyIDs.LOGGING_ANALYTICS_ENABLED][
                            "severity"
                        ],
                        resource_type="google_logging_project_bucket_config",
                        resource_name=bucket_name,
                        message="Log analytics must be enabled for compliance analysis and forensics. "
                        "Set enable_analytics = true.",
                        guide=self.policies[GCPPolicyIDs.LOGGING_ANALYTICS_ENABLED]["guide"],
                    )
                )

        return violations

    def _check_audit_config(self, audit_configs: Dict) -> List[GCPPolicyViolation]:
        """Validate audit logging for all access types."""
        violations = []

        for config_name, config_data in audit_configs.items():
            # Check if all required audit log types are present
            audit_log_config = config_data.get("audit_log_config", [])

            # Normalize to list if needed
            if not isinstance(audit_log_config, list):
                audit_log_config = [audit_log_config] if audit_log_config else []

            # Extract log types
            log_types = set()
            for log_entry in audit_log_config:
                if isinstance(log_entry, dict):
                    log_type = log_entry.get("log_type")
                    if log_type:
                        log_types.add(log_type)

            # Check for all required log types
            required_types = {"ADMIN_READ", "DATA_READ", "DATA_WRITE"}
            missing_types = required_types - log_types

            if missing_types:
                violations.append(
                    GCPPolicyViolation(
                        policy_id=GCPPolicyIDs.LOGGING_AUDIT_ENABLED,
                        severity=self.policies[GCPPolicyIDs.LOGGING_AUDIT_ENABLED][
                            "severity"
                        ],
                        resource_type="google_project_iam_audit_config",
                        resource_name=config_name,
                        message=f"Audit logging must be enabled for all access types. Missing: {', '.join(sorted(missing_types))}. "
                        "Configure ADMIN_READ, DATA_READ, and DATA_WRITE.",
                        guide=self.policies[GCPPolicyIDs.LOGGING_AUDIT_ENABLED]["guide"],
                    )
                )

        return violations

    def _has_centralized_destination(self, sink: Dict) -> bool:
        """Check if log sink exports to centralized destination."""
        destination = sink.get("destination", "")

        if isinstance(destination, list) and len(destination) > 0:
            destination = destination[0]

        if not destination:
            return False

        # Compliant destinations (centralized logging)
        compliant_patterns = [
            "storage.googleapis.com",  # Cloud Storage
            "bigquery.googleapis.com",  # BigQuery
            "pubsub.googleapis.com",  # Pub/Sub
            "logging.googleapis.com/projects/",  # Cross-project logging
        ]

        # Non-compliant: default bucket only
        if "buckets/_Default" in destination:
            return False

        # Check if destination matches compliant patterns
        return any(pattern in destination for pattern in compliant_patterns)

    def _has_sufficient_retention(self, bucket: Dict) -> bool:
        """Check if logging bucket has sufficient retention period."""
        retention_days = bucket.get("retention_days")

        if isinstance(retention_days, list) and len(retention_days) > 0:
            retention_days = retention_days[0]

        if retention_days is None:
            return False

        # Minimum 365 days required
        return int(retention_days) >= 365

    def _has_analytics_enabled(self, bucket: Dict) -> bool:
        """Check if log analytics is enabled."""
        enable_analytics = bucket.get("enable_analytics")

        if isinstance(enable_analytics, list) and len(enable_analytics) > 0:
            enable_analytics = enable_analytics[0]

        return bool(enable_analytics)
