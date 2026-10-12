"""
GCP Policy IDs and Messages

Centralized repository of GCP security policy details with fast lookup.
Organized by resource type for easy management and reusability.
"""

from typing import Optional, Dict, List
from dataclasses import dataclass


@dataclass(frozen=True)
class Policy:
    """Represents a single GCP security policy record."""
    policy_id: str
    resource_type: str
    security_level: str
    message: str
    guide: str = "https://myguide.com"


class GCPPolicyIDs:
    """Centralized repository of GCP security policies with fast lookup."""

    # ==================== BigQuery Policies ====================
    BIGQUERY_DATASET_PRIVATE = "GCP-SEC-BQ-001"
    BIGQUERY_DATASET_PUBLIC_ALLUSERS = "GCP-SEC-BQ-001"
    BIGQUERY_DATASET_AUTHENTICATED_USERS = "GCP-SEC-BQ-002"
    BIGQUERY_DATASET_KMS_ENCRYPTION = "GCP-SEC-BQ-003"
    BIGQUERY_DATASET_IAM_RESTRICTED = "GCP-SEC-BQ-004"
    BIGQUERY_TABLE_ENCRYPTION = "GCP-SEC-BQ-005"
    BIGQUERY_TABLE_COLUMN_SECURITY = "GCP-SEC-BQ-006"

    # ==================== Cloud SQL Policies ====================
    CLOUD_SQL_PREVENT_PUBLIC_IP = "GCP-SEC-CLOUD-001"

    # ==================== Storage Bucket Policies ====================
    STORAGE_BUCKET_NO_PUBLIC = "GCP-SEC-STORAGE-001"
    BUCKET_LOGGING_ENABLED = "GCP-SEC-STORAGE-002"
    STORAGE_BUCKET_VERSIONING_ENABLED = "GCP-SEC-STORAGE-003"
    STORAGE_BUCKET_PUBLIC_ACCESS_PREVENTION = "GCP-SEC-STORAGE-004"

    # ==================== VM & Compute Policies ====================
    COMPUTE_INSTANCE_DEFAULT_SVC_ACCOUNT = "GCP-SEC-VM-005"
    VM_BLOCK_PROJECT_WIDE_SSH_KEY = "GCP-SEC-VM-006"
    VM_SERIAL_PORT_NOT_ENABLED = "GCP-SEC-VM-007"
    NO_IP_FORWARDING = "GCP-SEC-VM-008"
    
    # ==================== VM Encryption Policies ====================
    VM_ENCRYPTION_REQUIRED = "GCP-SEC-VM-001"
    VM_SHIELDED_VM_FEATURES = "GCP-SEC-VM-002"
    VM_PUBLIC_IP_RESTRICTION = "GCP-SEC-VM-003"
    VM_METADATA_SECURITY = "GCP-SEC-VM-004"
    VM_SERVICE_ACCOUNT_SECURITY = "GCP-SEC-VM-005"

    # ==================== VPC & Network Policies ====================
    VPC_FIREWALL_PREVENT_SSH_ACCESS = "GCP-SEC-VPC-005"
    VPC_FIREWALL_RESTRICT_RDP = "GCP-SEC-VPC-006"
    VPC_FIREWALL_RESTRICT_FTP = "GCP-SEC-VPC-007"
    VPC_NETWORK_AUTO_SUBNETS = "GCP-SEC-VPC-001"
    VPC_SUBNET_FLOW_LOGS = "GCP-SEC-VPC-002"
    VPC_SUBNET_PRIVATE_IP_ACCESS = "GCP-SEC-VPC-003"
    VPC_FIREWALL_UNRESTRICTED_ACCESS = "GCP-SEC-VPC-004"

    # ==================== GKE Policies ====================
    GKE_LEGACY_AUTHORIZATION_DISABLED = "GCP-SEC-GKE-001"

    # ==================== DNS & DNSSEC Policies ====================
    DNSSEC_ENABLED = "GCP-SEC-DNS-001"

    # ==================== KMS & Encryption Policies ====================
    KMS_ENCRYPTION_KEY_90_DAYS = "GCP-SEC-KMS-001"
    ENCRYPTION_KEY_365_ROTATION = "GCP-SEC-KMS-002"

    # ==================== IAM & Authentication Policies ====================
    PROJECT_OS_LOGIN = "GCP-SEC-IAM-005"

    # ==================== Load Balancer & SSL Policies ====================
    LOADBALANCER_SSL_FORWARDING_RULE = "GCP-SEC-LB-001"

    # ==================== Cloud Functions Policies ====================
    CLOUD_FUNCTIONS_NOT_PUBLIC = "GCP-SEC-CLOUD-002"
    CLOUD_FUNCTIONS_VPC_CONNECTOR = "GCP-SEC-CLOUD-003"

    # ==================== Load Balancer Security Policies ====================
    LB_CIPHER_SUITE_STRENGTH = "GCP-SEC-LB-002"
    LB_CDN_ENABLED = "GCP-SEC-LB-003"
    LB_SECURITY_POLICY = "GCP-SEC-LB-004"

    # ==================== Logging Security Policies ====================
    LOGGING_AUDIT_ENABLED = "GCP-SEC-LOGGING-001"
    LOGGING_SINK_CONFIGURED = "GCP-SEC-LOGGING-002"
    LOGGING_RETENTION_POLICY = "GCP-SEC-LOGGING-003"
    LOGGING_ANALYTICS_ENABLED = "GCP-SEC-LOGGING-004"

    # ==================== Monitoring Security Policies ====================
    MONITORING_ALERTS_ENABLED = "GCP-SEC-MONITORING-001"
    MONITORING_UPTIME_CHECKS = "GCP-SEC-MONITORING-002"
    MONITORING_DASHBOARD_CONFIGURED = "GCP-SEC-MONITORING-003"
    MONITORING_COMPREHENSIVE_METRICS = "GCP-SEC-MONITORING-004"

    # ==================== IAM Security Policies ====================
    IAM_SERVICE_ACCOUNT_ADMIN_ROLES = "GCP-SEC-IAM-001"
    IAM_SERVICE_ACCOUNT_KEY_ROTATION = "GCP-SEC-IAM-002"
    IAM_AUDIT_LOGGING_ENABLED = "GCP-SEC-IAM-003"
    IAM_NO_FOLDER_LEVEL_BINDING = "GCP-SEC-IAM-004"

    _policies = [
        # BigQuery Policies - Core Access Control
        Policy(
            "GCP-SEC-BQ-001",
            "google_bigquery_dataset",
            "High",
            "'access.special_group' must not be equal to 'allAuthenticatedUsers'"
        ),
        Policy(
            "GCP-SEC-BQ-001",
            "google_bigquery_dataset",
            "Critical",
            "BigQuery dataset must not allow public access via 'allUsers' special group"
        ),
        Policy(
            "GCP-SEC-BQ-002",
            "google_bigquery_dataset",
            "Critical",
            "BigQuery dataset must restrict access - 'allAuthenticatedUsers' special group not permitted"
        ),
        # BigQuery Policies - Encryption
        Policy(
            "GCP-SEC-BQ-003",
            "google_bigquery_dataset",
            "High",
            "BigQuery dataset must use KMS customer-managed encryption keys (CMK) for data protection"
        ),
        # BigQuery Policies - IAM
        Policy(
            "GCP-SEC-BQ-004",
            "google_bigquery_dataset",
            "High",
            "BigQuery dataset IAM access must follow least privilege principle - restrict to specific users/groups"
        ),
        # BigQuery Policies - Table Encryption
        Policy(
            "GCP-SEC-BQ-005",
            "google_bigquery_table",
            "High",
            "BigQuery table must define encryption_configuration with KMS key for sensitive data protection"
        ),
        # BigQuery Policies - Column-level Security
        Policy(
            "GCP-SEC-BQ-006",
            "google_bigquery_table",
            "Medium",
            "BigQuery table containing PII must have column-level security via policy tags"
        ),
        # Cloud SQL Policies
        Policy(
            "GCP-SEC-CLOUD-001",
            "google_sql_database_instance",
            "Critical",
            "Cloud SQL instance must not be publicly accessible"
        ),
        # Storage Bucket Policies
        Policy(
            "GCP-SEC-STORAGE-001",
            "google_storage_bucket",
            "High",
            "Storage bucket must not be publicly accessible"
        ),
        Policy(
            "GCP-SEC-STORAGE-002",
            "google_storage_bucket",
            "Medium",
            "Storage bucket logging must be enabled"
        ),
        Policy(
            "GCP-SEC-STORAGE-003",
            "google_storage_bucket",
            "High",
            "Storage bucket versioning must be enabled"
        ),
        Policy(
            "GCP-SEC-STORAGE-004",
            "google_storage_bucket",
            "High",
            "Storage bucket public access prevention must be enforced"
        ),
        # VM & Compute Policies
        Policy(
            "GCP-SEC-VM-005",
            "google_compute_instance",
            "High",
            "Compute instance must not use default service account"
        ),
        Policy(
            "GCP-SEC-VM-006",
            "google_compute_instance",
            "High",
            "VM must block project-wide SSH keys"
        ),
        Policy(
            "GCP-SEC-VM-007",
            "google_compute_instance",
            "Medium",
            "VM serial port must not be enabled"
        ),
        Policy(
            "GCP-SEC-VM-008",
            "google_compute_instance",
            "High",
            "IP forwarding must not be enabled"
        ),
        # VM Encryption Policies
        Policy(
            "GCP-SEC-VM-001",
            "google_compute_instance",
            "High",
            "Compute Engine disks must have encryption configured (CSEK, KMS, or Google-managed)"
        ),
        Policy(
            "GCP-SEC-VM-002",
            "google_compute_instance",
            "High",
            "Production instances should enable Shielded VM features (Secure Boot, vTPM, Integrity Monitoring)"
        ),
        Policy(
            "GCP-SEC-VM-003",
            "google_compute_instance",
            "Critical",
            "Instances should not have public IP addresses unless explicitly required"
        ),
        Policy(
            "GCP-SEC-VM-004",
            "google_compute_instance",
            "Medium",
            "Metadata should have secure defaults (enable OS login, disable project SSH keys)"
        ),
        Policy(
            "GCP-SEC-VM-005",
            "google_compute_instance",
            "High",
            "Service accounts should follow least privilege principle with minimal scopes"
        ),
        # VPC & Network Policies
        Policy(
            "GCP-SEC-VPC-005",
            "google_compute_firewall",
            "High",
            "VPC firewall must prevent SSH access (port 22)"
        ),
        Policy(
            "GCP-SEC-VPC-006",
            "google_compute_firewall",
            "High",
            "VPC firewall must restrict RDP access (port 3389)"
        ),
        Policy(
            "GCP-SEC-VPC-007",
            "google_compute_firewall",
            "High",
            "VPC firewall must not allow FTP access (port 21)"
        ),
        # VPC & Network Policies - Extended
        Policy(
            "GCP-SEC-VPC-001",
            "google_compute_network",
            "Medium",
            "VPC network must have auto_create_subnetworks set to false for manual subnet control"
        ),
        Policy(
            "GCP-SEC-VPC-002",
            "google_compute_subnetwork",
            "High",
            "Subnetwork must have flow logging enabled via log_config block for network traffic monitoring"
        ),
        Policy(
            "GCP-SEC-VPC-003",
            "google_compute_subnetwork",
            "Medium",
            "Subnetwork should have private_ip_google_access enabled to allow GCP service access without public IPs"
        ),
        Policy(
            "GCP-SEC-VPC-004",
            "google_compute_firewall",
            "Critical",
            "Firewall rule must specify restricted ports when allowing ingress from 0.0.0.0/0"
        ),
        # GKE Policies
        Policy(
            "GCP-SEC-GKE-001",
            "google_container_cluster",
            "High",
            "GKE cluster must not use legacy authorization"
        ),
        # DNS Policies
        Policy(
            "GCP-SEC-DNS-001",
            "google_dns_managed_zone",
            "Medium",
            "DNS managed zone must have DNSSEC enabled"
        ),
        # KMS & Encryption Policies
        Policy(
            "GCP-SEC-KMS-001",
            "google_kms_crypto_key",
            "High",
            "KMS encryption key rotation must be set to 90 days"
        ),
        Policy(
            "GCP-SEC-KMS-002",
            "google_kms_crypto_key",
            "High",
            "KMS encryption key rotation must be set to 365 days"
        ),
        # IAM Policies
        Policy(
            "GCP-SEC-IAM-005",
            "google_compute_project",
            "High",
            "Project must have OS Login enabled"
        ),
        # Load Balancer Policies
        Policy(
            "GCP-SEC-LB-001",
            "google_compute_ssl_policy",
            "High",
            "SSL policy must enforce minimum TLS version 1.2 or higher"
        ),
        Policy(
            "GCP-SEC-LB-002",
            "google_compute_ssl_policy",
            "High",
            "SSL policy must use MODERN or RESTRICTED profile (no weak COMPATIBLE)"
        ),
        Policy(
            "GCP-SEC-LB-003",
            "google_compute_backend_service",
            "Medium",
            "Backend service should have Cloud CDN enabled for performance"
        ),
        Policy(
            "GCP-SEC-LB-004",
            "google_compute_backend_service",
            "Critical",
            "Backend service must be protected by Cloud Armor security policy"
        ),
        # Cloud Functions Policies
        Policy(
            "GCP-SEC-CLOUD-002",
            "google_cloudfunctions_function",
            "Critical",
            "Cloud Function must not be publicly accessible (no allUsers or allAuthenticatedUsers)"
        ),
        Policy(
            "GCP-SEC-CLOUD-003",
            "google_cloudfunctions_function",
            "High",
            "Cloud Function must define vpc_connector for network isolation"
        ),
        # Logging Security Policies
        Policy(
            "GCP-SEC-LOGGING-001",
            "google_project_iam_audit_config",
            "High",
            "Cloud Audit Logs must be enabled for ADMIN_READ, DATA_READ, and DATA_WRITE"
        ),
        Policy(
            "GCP-SEC-LOGGING-002",
            "google_logging_project_sink",
            "High",
            "Log sinks must be configured to export logs to centralized destination (BigQuery, Storage, or Pub/Sub)"
        ),
        Policy(
            "GCP-SEC-LOGGING-003",
            "google_logging_project_bucket_config",
            "Medium",
            "Log retention must be at least 365 days to meet organizational policy"
        ),
        Policy(
            "GCP-SEC-LOGGING-004",
            "google_logging_project_bucket_config",
            "Medium",
            "Log analytics must be enabled for compliance analysis and forensics"
        ),
        # Monitoring Security Policies
        Policy(
            "GCP-SEC-MONITORING-001",
            "google_monitoring_alert_policy",
            "High",
            "Alert policies must be defined for critical metrics to notify teams of issues"
        ),
        Policy(
            "GCP-SEC-MONITORING-002",
            "google_monitoring_uptime_check_config",
            "High",
            "Uptime checks must be configured for critical services to monitor availability"
        ),
        Policy(
            "GCP-SEC-MONITORING-003",
            "google_monitoring_dashboard",
            "Medium",
            "Monitoring dashboards must be configured for visibility into system health"
        ),
        Policy(
            "GCP-SEC-MONITORING-004",
            "google_logging_metric",
            "Medium",
            "Monitoring must cover comprehensive set of critical metrics (ERROR, WARNING, INFO)"
        ),
        # IAM Security Policies
        Policy(
            "GCP-SEC-IAM-001",
            "google_project_iam_binding",
            "Critical",
            "Service accounts must not have admin-level roles (owner, editor, securityAdmin)"
        ),
        Policy(
            "GCP-SEC-IAM-002",
            "google_service_account_key",
            "High",
            "Service account keys must be rotated within 90 days to reduce credential compromise risk"
        ),
        Policy(
            "GCP-SEC-IAM-003",
            "google_project_iam_audit_config",
            "High",
            "Audit logging must be enabled for all services with ADMIN_READ, DATA_READ, and DATA_WRITE log types"
        ),
        Policy(
            "GCP-SEC-IAM-004",
            "google_folder_iam_binding",
            "High",
            "Service accounts must not be bound at folder level; use project-level bindings only"
        ),
    ]

    # Pre-index policies for O(1) lookup
    _index: Dict[str, Policy] = {p.policy_id: p for p in _policies}
    
    # Index by resource type for filtering
    _resource_index: Dict[str, List[Policy]] = {}
    
    @classmethod
    def _build_resource_index(cls):
        """Build resource type index on first use."""
        if not cls._resource_index:
            for policy in cls._policies:
                if policy.resource_type not in cls._resource_index:
                    cls._resource_index[policy.resource_type] = []
                cls._resource_index[policy.resource_type].append(policy)

    @classmethod
    def get(cls, policy_id: str) -> Optional[Policy]:
        """
        Returns the Policy object matching the given ID.

        Args:
            policy_id (str): Policy identifier (e.g. 'GCP-SEC-001').

        Returns:
            Policy | None: The Policy object if found, otherwise None.
        """
        return cls._index.get(policy_id)

    @classmethod
    def get_by_resource_type(cls, resource_type: str) -> List[Policy]:
        """
        Returns all policies applicable to a given resource type.

        Args:
            resource_type (str): GCP resource type (e.g. 'google_bigquery_dataset').

        Returns:
            List[Policy]: List of policies for the resource type.
        """
        cls._build_resource_index()
        return cls._resource_index.get(resource_type, [])

    @classmethod
    def get_all(cls) -> List[Policy]:
        """
        Returns all policies.

        Returns:
            List[Policy]: List of all policies.
        """
        return cls._policies

    @classmethod
    def list_constants(cls) -> Dict[str, str]:
        """
        Returns all policy constants as a dictionary.
        Useful for introspection and documentation.

        Returns:
            Dict[str, str]: Mapping of constant names to policy IDs.
        """
        return {
            name: getattr(cls, name)
            for name in dir(cls)
            if name.isupper() and not name.startswith('_')
        }
