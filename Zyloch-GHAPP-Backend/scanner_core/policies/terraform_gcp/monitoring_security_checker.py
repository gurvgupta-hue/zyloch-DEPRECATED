"""
Google Cloud Monitoring Security Compliance Checker

Validates Google Cloud Monitoring and Alert Policies configuration for security compliance,
including checks for:
- Cloud Monitoring API enabled
- Alert policies defined for critical metrics
- Uptime checks configured
- Monitoring dashboards configured

Policy Coverage:
- GCP-SEC-MONITORING-001: Monitoring alert policies defined
- GCP-SEC-MONITORING-002: Uptime checks configured for critical services
- GCP-SEC-MONITORING-003: Monitoring dashboards configured
- GCP-SEC-MONITORING-004: Comprehensive metrics monitoring enabled
"""

from typing import Dict, List
from scanner_core.models.violation import GCPPolicyViolation
from scanner_core.constants.gcp_policy_ids import GCPPolicyIDs


class MonitoringSecurityChecker:
    """Validates Google Cloud Monitoring security compliance."""

    def __init__(self):
        """Initialize Monitoring security checker with policy definitions."""
        self.name = "Cloud Monitoring Security Compliance Checker"
        self.resource_types = [
            "google_monitoring_alert_policy",
            "google_monitoring_uptime_check_config",
            "google_monitoring_dashboard",
            "google_logging_metric",
        ]

        # Monitoring policies from centralized registry
        self.policies = {
            GCPPolicyIDs.MONITORING_ALERTS_ENABLED: {
                "name": "Monitoring Alerts Enabled",
                "severity": "High",
                "description": "Alert policies must be defined for critical metrics",
                "guide": "https://cloud.google.com/monitoring/alerts",
            },
            GCPPolicyIDs.MONITORING_UPTIME_CHECKS: {
                "name": "Uptime Checks Configured",
                "severity": "High",
                "description": "Uptime checks must be configured for critical services",
                "guide": "https://cloud.google.com/monitoring/uptime-checks",
            },
            GCPPolicyIDs.MONITORING_DASHBOARD_CONFIGURED: {
                "name": "Monitoring Dashboard Configured",
                "severity": "Medium",
                "description": "Monitoring dashboards must be configured for visibility",
                "guide": "https://cloud.google.com/monitoring/dashboards",
            },
            GCPPolicyIDs.MONITORING_COMPREHENSIVE_METRICS: {
                "name": "Comprehensive Metrics Monitoring",
                "severity": "Medium",
                "description": "Monitoring must cover comprehensive set of critical metrics",
                "guide": "https://cloud.google.com/monitoring/api",
            },
        }

    def check(self, resources: Dict) -> List[GCPPolicyViolation]:
        """
        Validate Monitoring security compliance across resources.

        Args:
            resources: Dictionary of Terraform resources indexed by type

        Returns:
            List of GCPPolicyViolation objects for non-compliant resources
        """
        violations = []

        # Check alert policies
        if "google_monitoring_alert_policy" in resources:
            has_alerts = len(resources["google_monitoring_alert_policy"]) > 0
        else:
            has_alerts = False

        # Check uptime checks
        if "google_monitoring_uptime_check_config" in resources:
            violations.extend(
                self._check_uptime_checks(
                    resources["google_monitoring_uptime_check_config"]
                )
            )
        else:
            # No uptime checks configured
            violations.append(
                GCPPolicyViolation(
                    policy_id=GCPPolicyIDs.MONITORING_UPTIME_CHECKS,
                    severity=self.policies[GCPPolicyIDs.MONITORING_UPTIME_CHECKS][
                        "severity"
                    ],
                    resource_type="google_monitoring_uptime_check_config",
                    resource_name="none",
                    message="No uptime checks configured. Uptime checks must be configured for critical services "
                    "to monitor availability and response time.",
                    guide=self.policies[GCPPolicyIDs.MONITORING_UPTIME_CHECKS]["guide"],
                )
            )

        # Check dashboards
        if "google_monitoring_dashboard" in resources:
            violations.extend(
                self._check_dashboards(resources["google_monitoring_dashboard"])
            )
        else:
            # No dashboards configured
            violations.append(
                GCPPolicyViolation(
                    policy_id=GCPPolicyIDs.MONITORING_DASHBOARD_CONFIGURED,
                    severity=self.policies[GCPPolicyIDs.MONITORING_DASHBOARD_CONFIGURED][
                        "severity"
                    ],
                    resource_type="google_monitoring_dashboard",
                    resource_name="none",
                    message="No monitoring dashboards configured. Dashboards provide visibility into system health "
                    "and must be created for critical services.",
                    guide=self.policies[GCPPolicyIDs.MONITORING_DASHBOARD_CONFIGURED][
                        "guide"
                    ],
                )
            )

        # Check if alert policies are configured
        if not has_alerts:
            violations.append(
                GCPPolicyViolation(
                    policy_id=GCPPolicyIDs.MONITORING_ALERTS_ENABLED,
                    severity=self.policies[GCPPolicyIDs.MONITORING_ALERTS_ENABLED][
                        "severity"
                    ],
                    resource_type="google_monitoring_alert_policy",
                    resource_name="none",
                    message="No monitoring alert policies configured. Alert policies must be defined for critical metrics "
                    "to notify teams of issues.",
                    guide=self.policies[GCPPolicyIDs.MONITORING_ALERTS_ENABLED]["guide"],
                )
            )

        # Check metrics coverage
        if "google_logging_metric" in resources:
            violations.extend(self._check_metrics(resources["google_logging_metric"]))

        return violations

    def _check_uptime_checks(self, uptime_checks: Dict) -> List[GCPPolicyViolation]:
        """Validate uptime checks are configured with proper settings."""
        violations = []

        for check_name, check_config in uptime_checks.items():
            # Verify uptime check has monitoring regions
            selected_regions = check_config.get("selected_regions", [])

            if not selected_regions:
                violations.append(
                    GCPPolicyViolation(
                        policy_id=GCPPolicyIDs.MONITORING_UPTIME_CHECKS,
                        severity=self.policies[GCPPolicyIDs.MONITORING_UPTIME_CHECKS][
                            "severity"
                        ],
                        resource_type="google_monitoring_uptime_check_config",
                        resource_name=check_name,
                        message="Uptime check must be configured with selected regions for global monitoring. "
                        "Configure selected_regions with at least 3 regions.",
                        guide=self.policies[GCPPolicyIDs.MONITORING_UPTIME_CHECKS][
                            "guide"
                        ],
                    )
                )

        return violations

    def _check_dashboards(self, dashboards: Dict) -> List[GCPPolicyViolation]:
        """Validate monitoring dashboards are configured."""
        violations = []

        for dashboard_name, dashboard_config in dashboards.items():
            # Basic validation that dashboard has content
            dashboard_json = dashboard_config.get("dashboard_json", "")

            if isinstance(dashboard_json, list) and len(dashboard_json) > 0:
                dashboard_json = dashboard_json[0]

            if not dashboard_json or dashboard_json == "":
                violations.append(
                    GCPPolicyViolation(
                        policy_id=GCPPolicyIDs.MONITORING_DASHBOARD_CONFIGURED,
                        severity=self.policies[GCPPolicyIDs.MONITORING_DASHBOARD_CONFIGURED][
                            "severity"
                        ],
                        resource_type="google_monitoring_dashboard",
                        resource_name=dashboard_name,
                        message="Monitoring dashboard must be configured with charts and metrics. "
                        "Dashboard JSON configuration is empty.",
                        guide=self.policies[GCPPolicyIDs.MONITORING_DASHBOARD_CONFIGURED][
                            "guide"
                        ],
                    )
                )

        return violations

    def _check_metrics(self, metrics: Dict) -> List[GCPPolicyViolation]:
        """Validate comprehensive metrics monitoring."""
        violations = []

        # Check for minimal metrics coverage
        metric_filters = []
        for metric_name, metric_config in metrics.items():
            filter_config = metric_config.get("filter", "")
            if filter_config:
                metric_filters.append(filter_config)

        # If only critical metrics are monitored (too narrow), flag it
        if len(metric_filters) > 0:
            all_filters = " ".join(metric_filters)
            # Check if monitoring is too narrow (only critical)
            if (
                "severity=CRITICAL" in all_filters
                and "severity >= ERROR" not in all_filters
            ):
                # Find the minimal metric resource
                for metric_name, metric_config in metrics.items():
                    if "CRITICAL" in str(metric_config.get("filter", "")):
                        violations.append(
                            GCPPolicyViolation(
                                policy_id=GCPPolicyIDs.MONITORING_COMPREHENSIVE_METRICS,
                                severity=self.policies[
                                    GCPPolicyIDs.MONITORING_COMPREHENSIVE_METRICS
                                ]["severity"],
                                resource_type="google_logging_metric",
                                resource_name=metric_name,
                                message="Monitoring metrics are too narrow (only critical level). "
                                "Comprehensive monitoring requires metrics for ERROR, WARNING, and INFO levels.",
                                guide=self.policies[
                                    GCPPolicyIDs.MONITORING_COMPREHENSIVE_METRICS
                                ]["guide"],
                            )
                        )

        return violations
