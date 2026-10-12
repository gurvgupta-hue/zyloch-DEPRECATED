"""Centralized common violation message constants."""

MIN_TLS_NOT_SET = "min_tls_version is not set"
MIN_TLS_INVALID = "min_tls_version value invalid"
MIN_TLS_TOO_WEAK = "min_tls_version too weak"
STORAGE_ACCOUNT_TLS_INSECURE = "min_tls_version '{value}' is insecure. Minimum required: {minimum}"

# templates with placeholder for values
MIN_TLS_INVALID_TPL = "min_tls_version value invalid: {val}"
MIN_TLS_TOO_WEAK_TPL = "min_tls_version too weak: {val}"

OWNER_TAG_MISSING = "Resource must have an 'owner' tag"

FUNCTION_APP_MISSING_SITE_CONFIG = "Function App missing site_config"
FUNCTION_RUNTIME_DEPRECATED = "Function runtime is deprecated"

HTTPS_ONLY_REQUIRED = "HTTPS only must be enabled"
FTPS_ALLALLOWED = "FTPS must not be 'AllAllowed'"

# Additional centralized messages used across terraform policies
SERVICE_BUS_SKU_MISSING = "Service Bus SKU must be set"
SOFT_DELETE_RETENTION_MIN = "Soft delete retention should be at least 7 days"
KEY_VAULT_SKU_MISSING = "Key Vault SKU must be set"
NETWORK_ACLS_BYPASS = "Network ACLs bypass is set to {bypass}"
KEY_VAULT_PURGE_PROTECTION = "Key Vault purge protection should be enabled"
SYNAPSE_PUBLIC_NETWORK_DISABLED = "Synapse public network access should be disabled"
SYNAPSE_MANAGED_VNET = "Synapse workspace should enable managed virtual network"
STORAGE_SOFT_DELETE_REQUIRED = "Soft delete should be enabled for storage accounts"
SERVICE_PLAN_SKU_MISSING = "Service plan SKU/name must be set"
SERVICE_PLAN_OS_UNEXPECTED = "Unexpected service plan os type: {os_type}"
MINIMUM_TLS_1_2_REQUIRED = "Minimum TLS version must be >= 1.2"
HTTPS_TRAFFIC_ONLY_REQUIRED = "HTTPS traffic only must be enabled"
REPLICATION_NOT_ALLOWED = "Replication type {replication} is not allowed"
STORAGE_KIND_UNEXPECTED = "Unexpected storage account kind: {kind}"
OVERLY_PERMISSIVE_TCP = "Overly permissive TCP rule"
INBOUND_SSH_ALLOWED = "Inbound SSH from internet is allowed"
INBOUND_RDP_ALLOWED = "Inbound RDP from internet is allowed"
PUBLIC_NETWORK_DISABLED = "Public network access should be disabled"
SERVER_IDENTITY_REQUIRED = "Server should have identity configured"
MSSQL_SKU_REQUIRED = "SKU is required for MSSQL database"
SSH_PASSWORD_AUTH_ENABLED = "SSH password authentication is enabled"
MANAGED_DISK_PUBLIC_NETWORK_DISABLED = "Managed disk public network access should be disabled"
MANAGED_DISK_ENCRYPTION_REQUIRED = "Managed disk should be encrypted with a disk_encryption_set"
COSMOSDB_KIND_UNEXPECTED = "Unexpected Cosmos DB kind: {kind}"
AUTOMATIC_FAILOVER_REQUIRED = "Automatic failover should be enabled"
CONTAINER_APP_REVISION_MODE = "Container app should use automatic revision mode"

# Additional messages from translated Rego policies
ROUTE_TABLE_INTERNET_ROUTE = "Route Table {rt_name} has a route {route_name} with next_hop_type 'Internet', which is not allowed"
FIREWALL_THREAT_INTEL_ALERT_REQUIRED = "Firewall {name} must have threat_intel_mode set to 'Alert'"
PER_DB_SETTINGS_INVALID = "Each per_database_settings entry must contain valid min_capacity and max_capacity."
IDENTITY_TYPE_INVALID = "identity.type must be one of: {allowed}; identity.type is '{actual}'"
ALWAYS_ON_REQUIRED = "Always on must be enabled"

# Cosmos DB messages
COSMOSDB_CONSISTENCY_POLICY_REQUIRED = "consistency_policy block is required"
COSMOSDB_CONSISTENCY_LEVEL_INVALID = "consistency_level must be one of {allowed}"
COSMOSDB_GEO_LOCATION_REQUIRED = "At least one geo_location entry is required"
COSMOSDB_OFFER_TYPE_REQUIRED = "offer_type is required and must be 'Standard'"
CONTAINER_APP_TEMPLATE = "template must be defined and not empty"

# EventGrid namespace messages
EVENTGRID_SKU_INVALID = "sku must be one of {allowed}"
EVENTGRID_CAPACITY_INVALID = "capacity must be >= 1"
EVENTGRID_IDENTITY_TYPE_INVALID = "identity.type must be one of {allowed}"

# Load Balancer messages
LB_FRONTEND_IP_CONFIGURATION_REQUIRED = "Load Balancer {name} must have at least one frontend IP configuration"

# MSSQL Database messages
MSSQL_MAX_SIZE_REQUIRED = "max_size_gb must be greater than 0"
MSSQL_SKU_INVALID = "sku must be one of {allowed}"

# MSSQL Elastic Pool messages
MSSQL_ELASTICPOOL_SKU_NAME_INVALID = "sku.name must be a valid DTU or vCore value. Got: {name}"
MSSQL_ELASTICPOOL_SKU_TIER_INVALID = "sku.tier must be a valid tier value. Got: {tier}"

# MSSQL Managed Instance messages
MSSQL_MANAGED_INSTANCE_LICENSE_TYPE_INVALID = "license_type must be one of {allowed}"
MSSQL_MANAGED_INSTANCE_SKU_NAME_INVALID = "sku.name must be one of {allowed}"
MSSQL_MANAGED_INSTANCE_STORAGE_SIZE_INVALID = "storage_size_in_gb must be set and multiple of 32"
MSSQL_MANAGED_INSTANCE_VCORES_INVALID = "vcores must be a valid value for the selected SKU"

# Storage Blob messages
STORAGE_BLOB_TYPE_INVALID = "type must be one of {allowed}"
STORAGE_BLOB_SIZE_REQUIRED = "size is required if source_uri is not set"
STORAGE_BLOB_ACCESS_TIER_INVALID = "access_tier must be one of {allowed}"

# Storage Account messages
STORAGE_ACCOUNT_ACCESS_TIER_INVALID = "access_tier must be one of {allowed}"
STORAGE_ACCOUNT_ACCESS_TIER_NOT_ALLOWED = "access_tier is only allowed for account_kind: BlobStorage, FileStorage, or StorageV2"
STORAGE_ACCOUNT_KIND_INVALID = "account_kind must be one of {allowed}"
STORAGE_ACCOUNT_TIER_REQUIRED = "account_tier is required and must be one of Standard or Premium"
STORAGE_ACCOUNT_TIER_INVALID = "account_tier must be one of {allowed}"
STORAGE_ACCOUNT_TIER_PREMIUM_REQUIRED = "For BlockBlobStorage and FileStorage, account_tier must be Premium"
STORAGE_ACCOUNT_MIN_TLS_VERSION_INVALID = "min_tls_version must be one of {allowed}"

# Virtual Network messages
VNET_SUBNET_CIDR_INVALID = "Subnet {subnet_name} has CIDR {cidr} which must start with {required_prefix}"
VNET_SUBNET_OUTBOUND_ACCESS_ENABLED = "Subnet {subnet_name} has default outbound internet access enabled (must be disabled)"
VNET_ADDRESS_SPACE_INVALID = "VNet {vnet_name} must use 10.x.x.x address space, found {cidr}"
VNET_DDOS_PROTECTION_REQUIRED = "VNet {vnet_name} must have a DDoS protection plan attached"
VNET_DNS_SERVERS_REQUIRED = "VNet {vnet_name} must define at least one custom DNS server"
VNET_PRIVATE_ENDPOINT_POLICIES_REQUIRED = "VNet {vnet_name} must have private endpoint vnet policies enabled"

# Application Gateway specific messages
APP_GW_HTTP_LISTENER_INSECURE = "Application Gateway listener {listener} is using insecure protocol HTTP. Use HTTPS instead."
APP_GW_TLS_MIN_REQUIRED = "Application Gateway listener {listener} does not enforce TLS 1.2+. Found {found}"

# Map message text -> metadata (issue_type and severity)
from .base import IssueType, Severity

VIOLATION_DEFINITIONS = {
	# TLS / Transport Security mappings
	MIN_TLS_NOT_SET: {"issue_type": IssueType.Security, "severity": Severity.HIGH, "code": "AZ-SEC-TLS-001"},
	MIN_TLS_INVALID: {"issue_type": IssueType.Security, "severity": Severity.HIGH, "code": "AZ-SEC-TLS-002"},
	MIN_TLS_TOO_WEAK: {"issue_type": IssueType.Security, "severity": Severity.HIGH, "code": "AZ-SEC-TLS-003"},
	STORAGE_ACCOUNT_TLS_INSECURE: {"issue_type": IssueType.Security, "severity": Severity.HIGH, "code": "AZ-SEC-TLS-004"},
	HTTPS_ONLY_REQUIRED: {"issue_type": IssueType.Security, "severity": Severity.HIGH, "code": "AZ-SEC-TLS-005"},
	FTPS_ALLALLOWED: {"issue_type": IssueType.Security, "severity": Severity.HIGH, "code": "AZ-SEC-TLS-006"},
	MINIMUM_TLS_1_2_REQUIRED: {"issue_type": IssueType.Security, "severity": Severity.HIGH, "code": "AZ-SEC-TLS-007"},
	HTTPS_TRAFFIC_ONLY_REQUIRED: {"issue_type": IssueType.Security, "severity": Severity.HIGH, "code": "AZ-SEC-TLS-008"},

	# Tagging mappings
	OWNER_TAG_MISSING: {"issue_type": IssueType.MissingValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-TAG-001"},

	# Function App mappings
	FUNCTION_APP_MISSING_SITE_CONFIG: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-FUNC-001"},
	FUNCTION_RUNTIME_DEPRECATED: {"issue_type": IssueType.Deprecated, "severity": Severity.LOW, "code": "AZ-SEC-FUNC-002"},

	# Service Bus mappings
	SERVICE_BUS_SKU_MISSING: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-SB-001"},

	# Key Vault mappings
	SOFT_DELETE_RETENTION_MIN: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-KV-001"},
	KEY_VAULT_SKU_MISSING: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-KV-002"},
	KEY_VAULT_PURGE_PROTECTION: {"issue_type": IssueType.Security, "severity": Severity.HIGH, "code": "AZ-SEC-KV-003"},
	NETWORK_ACLS_BYPASS: {"issue_type": IssueType.Security, "severity": Severity.HIGH, "code": "AZ-SEC-KV-004"},

	# Synapse mappings
	SYNAPSE_PUBLIC_NETWORK_DISABLED: {"issue_type": IssueType.Security, "severity": Severity.HIGH, "code": "AZ-SEC-SYN-001"},
	SYNAPSE_MANAGED_VNET: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-SYN-002"},

	# Storage mappings
	STORAGE_SOFT_DELETE_REQUIRED: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-STORAGE-001"},
	REPLICATION_NOT_ALLOWED: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-STORAGE-002"},
	STORAGE_KIND_UNEXPECTED: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-STORAGE-003"},
	STORAGE_BLOB_TYPE_INVALID: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-STORAGE-004"},
	STORAGE_BLOB_SIZE_REQUIRED: {"issue_type": IssueType.MissingValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-STORAGE-005"},
	STORAGE_BLOB_ACCESS_TIER_INVALID: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-STORAGE-006"},
	STORAGE_ACCOUNT_ACCESS_TIER_INVALID: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-STORAGE-007"},
	STORAGE_ACCOUNT_ACCESS_TIER_NOT_ALLOWED: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-STORAGE-008"},
	STORAGE_ACCOUNT_KIND_INVALID: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-STORAGE-009"},
	STORAGE_ACCOUNT_TIER_REQUIRED: {"issue_type": IssueType.MissingValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-STORAGE-010"},
	STORAGE_ACCOUNT_TIER_INVALID: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-STORAGE-011"},
	STORAGE_ACCOUNT_TIER_PREMIUM_REQUIRED: {"issue_type": IssueType.IncorrectValue, "severity": Severity.HIGH, "code": "AZ-SEC-STORAGE-012"},
	STORAGE_ACCOUNT_MIN_TLS_VERSION_INVALID: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-STORAGE-013"},

	# App Service / Service Plan mappings
	SERVICE_PLAN_SKU_MISSING: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-APP-001"},
	ALWAYS_ON_REQUIRED: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-APP-002"},

	# Network Security Group mappings
	OVERLY_PERMISSIVE_TCP: {"issue_type": IssueType.Security, "severity": Severity.HIGH, "code": "AZ-SEC-NSG-001"},
	INBOUND_SSH_ALLOWED: {"issue_type": IssueType.Security, "severity": Severity.CRITICAL, "code": "AZ-SEC-NSG-002"},
	INBOUND_RDP_ALLOWED: {"issue_type": IssueType.Security, "severity": Severity.CRITICAL, "code": "AZ-SEC-NSG-003"},

	# Network / Public Access mappings
	PUBLIC_NETWORK_DISABLED: {"issue_type": IssueType.Security, "severity": Severity.HIGH, "code": "AZ-SEC-NET-001"},

	# IAM / Identity mappings
	SERVER_IDENTITY_REQUIRED: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-IAM-001"},
	SSH_PASSWORD_AUTH_ENABLED: {"issue_type": IssueType.Security, "severity": Severity.HIGH, "code": "AZ-SEC-IAM-002"},
	IDENTITY_TYPE_INVALID: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-IAM-003"},

	# Managed Disk mappings
	MANAGED_DISK_PUBLIC_NETWORK_DISABLED: {"issue_type": IssueType.Security, "severity": Severity.HIGH, "code": "AZ-SEC-DISK-001"},
	MANAGED_DISK_ENCRYPTION_REQUIRED: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-DISK-002"},

	# Cosmos DB mappings
	COSMOSDB_KIND_UNEXPECTED: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-CDB-001"},
	AUTOMATIC_FAILOVER_REQUIRED: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-CDB-002"},
	COSMOSDB_CONSISTENCY_POLICY_REQUIRED: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-CDB-003"},
	COSMOSDB_CONSISTENCY_LEVEL_INVALID: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-CDB-004"},
	COSMOSDB_GEO_LOCATION_REQUIRED: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-CDB-005"},
	COSMOSDB_OFFER_TYPE_REQUIRED: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-CDB-006"},

	# Container App mappings
	CONTAINER_APP_REVISION_MODE: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-CA-001"},
	CONTAINER_APP_TEMPLATE: {"issue_type": IssueType.MissingValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-CA-002"},

	# Route Table mappings
	ROUTE_TABLE_INTERNET_ROUTE: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-RT-001"},

	# Firewall mappings
	FIREWALL_THREAT_INTEL_ALERT_REQUIRED: {"issue_type": IssueType.Security, "severity": Severity.HIGH, "code": "AZ-SEC-FW-001"},

	# SQL / MSSQL mappings
	MSSQL_SKU_REQUIRED: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-SQL-001"},
	PER_DB_SETTINGS_INVALID: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-SQL-002"},
	MSSQL_MAX_SIZE_REQUIRED: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-SQL-003"},
	MSSQL_SKU_INVALID: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-SQL-004"},
	MSSQL_ELASTICPOOL_SKU_NAME_INVALID: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-SQL-005"},
	MSSQL_ELASTICPOOL_SKU_TIER_INVALID: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-SQL-006"},
	MSSQL_MANAGED_INSTANCE_LICENSE_TYPE_INVALID: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-SQL-007"},
	MSSQL_MANAGED_INSTANCE_SKU_NAME_INVALID: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-SQL-008"},
	MSSQL_MANAGED_INSTANCE_STORAGE_SIZE_INVALID: {"issue_type": IssueType.MissingValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-SQL-009"},
	MSSQL_MANAGED_INSTANCE_VCORES_INVALID: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-SQL-010"},

	# Application Gateway mappings
	APP_GW_HTTP_LISTENER_INSECURE: {"issue_type": IssueType.Security, "severity": Severity.HIGH, "code": "AZ-SEC-AGW-001"},
	APP_GW_TLS_MIN_REQUIRED: {"issue_type": IssueType.Security, "severity": Severity.HIGH, "code": "AZ-SEC-AGW-002"},

	# EventGrid mappings
	EVENTGRID_SKU_INVALID: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-EG-001"},
	EVENTGRID_CAPACITY_INVALID: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-EG-002"},
	EVENTGRID_IDENTITY_TYPE_INVALID: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-EG-003"},

	# Load Balancer mappings
	LB_FRONTEND_IP_CONFIGURATION_REQUIRED: {"issue_type": IssueType.MissingValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-LB-001"},

	# Virtual Network mappings
	VNET_SUBNET_CIDR_INVALID: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-VNET-001"},
	VNET_SUBNET_OUTBOUND_ACCESS_ENABLED: {"issue_type": IssueType.Security, "severity": Severity.HIGH, "code": "AZ-SEC-VNET-002"},
	VNET_ADDRESS_SPACE_INVALID: {"issue_type": IssueType.IncorrectValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-VNET-003"},
	VNET_DDOS_PROTECTION_REQUIRED: {"issue_type": IssueType.MissingValue, "severity": Severity.HIGH, "code": "AZ-SEC-VNET-004"},
	VNET_DNS_SERVERS_REQUIRED: {"issue_type": IssueType.MissingValue, "severity": Severity.MEDIUM, "code": "AZ-SEC-VNET-005"},
	VNET_PRIVATE_ENDPOINT_POLICIES_REQUIRED: {"issue_type": IssueType.Security, "severity": Severity.MEDIUM, "code": "AZ-SEC-VNET-006"},
}

