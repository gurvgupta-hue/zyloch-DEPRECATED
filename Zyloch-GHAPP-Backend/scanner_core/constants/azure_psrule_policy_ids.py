from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass(frozen=True)
class AzurePSRulePolicy:
    """Represents a single PSRule Azure policy record."""
    rule_name: str       # PSRule ruleName as it appears in scan output
    policy_id: str       # Internal AZ-SEC-* identifier
    title: str           # Short human-readable title
    category: str        # Service / domain category
    resource_type: str   # Azure resource type this rule targets
    severity: str        # CRITICAL | HIGH | MEDIUM | LOW
    description: str     # What the rule checks


class AzurePSRulePolicyIDs:
    """
    Mapping from PSRule ruleName → internal AZ-SEC-* policy ID.
    Use AzurePSRulePolicyMetadata.lookup(rule_name) to get the full record.
    """

    # ==================== Storage ====================
    STORAGE_SECURE_TRANSFER       = "AZ-SEC-STG-001"
    STORAGE_HTTPS_ONLY            = "AZ-SEC-STG-002"
    STORAGE_MIN_TLS               = "AZ-SEC-STG-003"
    STORAGE_BLOB_PUBLIC_ACCESS    = "AZ-SEC-STG-004"
    STORAGE_FIREWALL              = "AZ-SEC-STG-005"
    STORAGE_SOFT_DELETE           = "AZ-SEC-STG-006"
    STORAGE_VERSIONING            = "AZ-SEC-STG-007"
    STORAGE_ACCESS_KEY            = "AZ-SEC-STG-008"
    STORAGE_DEFENDER              = "AZ-SEC-STG-009"
    STORAGE_BLOB_RETENTION        = "AZ-SEC-STG-010"
    STORAGE_CONTAINER_SOFT_DELETE = "AZ-SEC-STG-011"
    STORAGE_MANAGED_IDENTITY      = "AZ-SEC-STG-012"
    STORAGE_LOGGING               = "AZ-SEC-STG-013"

    # ==================== Key Vault ====================
    KEYVAULT_SOFT_DELETE          = "AZ-SEC-KV-001"
    KEYVAULT_PURGE_PROTECT        = "AZ-SEC-KV-002"
    KEYVAULT_RBAC                 = "AZ-SEC-KV-003"
    KEYVAULT_FIREWALL             = "AZ-SEC-KV-004"
    KEYVAULT_LOGGING              = "AZ-SEC-KV-005"
    KEYVAULT_SECRET_EXPIRY        = "AZ-SEC-KV-006"
    KEYVAULT_KEY_EXPIRY           = "AZ-SEC-KV-007"
    KEYVAULT_CERT_EXPIRY          = "AZ-SEC-KV-008"
    KEYVAULT_PRIVATE_ENDPOINT     = "AZ-SEC-KV-009"
    KEYVAULT_MANAGED_IDENTITY     = "AZ-SEC-KV-010"

    # ==================== Virtual Machine ====================
    VM_AGENT                      = "AZ-SEC-VM-001"
    VM_UPDATES                    = "AZ-SEC-VM-002"
    VM_DISK_ENCRYPTION            = "AZ-SEC-VM-003"
    VM_MANAGED_DISK               = "AZ-SEC-VM-004"
    VM_ACCELERATED_NETWORKING     = "AZ-SEC-VM-005"
    VM_BOOT_DIAGNOSTICS           = "AZ-SEC-VM-006"
    VM_IDENTITY                   = "AZ-SEC-VM-007"
    VM_PUBLIC_IP                  = "AZ-SEC-VM-008"
    VM_AADLOGIN                   = "AZ-SEC-VM-009"
    VM_BASTION                    = "AZ-SEC-VM-010"
    VM_PROMO_SKU                  = "AZ-SEC-VM-011"
    VM_AVAILABILITY_ZONE          = "AZ-SEC-VM-012"

    # ==================== Networking ====================
    VNET_PEER_STATE               = "AZ-SEC-NET-001"
    VNET_DNS_SERVER               = "AZ-SEC-NET-002"
    VNET_LOCAL_DNS                = "AZ-SEC-NET-003"
    NSG_ANY_INBOUND_SSH           = "AZ-SEC-NET-004"
    NSG_ANY_INBOUND_RDP           = "AZ-SEC-NET-005"
    NSG_LATERAL_TRAVERSAL         = "AZ-SEC-NET-006"
    NSG_DENIED_ALL                = "AZ-SEC-NET-007"
    NSG_RULE_DESCRIPTION          = "AZ-SEC-NET-008"
    LB_PROBE                      = "AZ-SEC-NET-009"
    PIP_DNS_LABEL                 = "AZ-SEC-NET-010"
    PIP_AVAILABILITY_ZONE         = "AZ-SEC-NET-011"
    ROUTE_NEXT_HOP_TYPE           = "AZ-SEC-NET-012"
    FRONT_DOOR_WAF                = "AZ-SEC-NET-013"
    FRONT_DOOR_HTTPS              = "AZ-SEC-NET-014"
    FRONT_DOOR_MIN_TLS            = "AZ-SEC-NET-015"
    APP_GATEWAY_WAF               = "AZ-SEC-NET-016"
    APP_GATEWAY_HTTPS_REDIRECT    = "AZ-SEC-NET-017"
    APP_GATEWAY_MIN_TLS           = "AZ-SEC-NET-018"
    FIREWALL_POLICY_DNS_PROXY     = "AZ-SEC-NET-019"
    FIREWALL_MODE                 = "AZ-SEC-NET-020"

    # ==================== App Service / Functions ====================
    APPSERVICE_HTTPS_ONLY         = "AZ-SEC-APP-001"
    APPSERVICE_MIN_TLS            = "AZ-SEC-APP-002"
    APPSERVICE_MANAGED_IDENTITY   = "AZ-SEC-APP-003"
    APPSERVICE_VNET_INTEGRATION   = "AZ-SEC-APP-004"
    APPSERVICE_AUTHENTICATION     = "AZ-SEC-APP-005"
    APPSERVICE_HTTP2              = "AZ-SEC-APP-006"
    APPSERVICE_FTPS_STATE         = "AZ-SEC-APP-007"
    APPSERVICE_REMOTE_DEBUG       = "AZ-SEC-APP-008"
    APPSERVICE_ALWAYS_ON          = "AZ-SEC-APP-009"
    APPSERVICE_CLIENT_CERT        = "AZ-SEC-APP-010"
    APPSERVICE_PHP_VERSION        = "AZ-SEC-APP-011"
    APPSERVICE_PYTHON_VERSION     = "AZ-SEC-APP-012"
    APPSERVICE_NODE_VERSION       = "AZ-SEC-APP-013"
    APPSERVICE_JAVA_VERSION       = "AZ-SEC-APP-014"
    FUNCAPP_HTTPS_ONLY            = "AZ-SEC-APP-015"
    FUNCAPP_MIN_TLS               = "AZ-SEC-APP-016"
    FUNCAPP_MANAGED_IDENTITY      = "AZ-SEC-APP-017"

    # ==================== SQL Database ====================
    SQL_AUDITING                  = "AZ-SEC-SQL-001"
    SQL_AAD_ADMIN                 = "AZ-SEC-SQL-002"
    SQL_TDE                       = "AZ-SEC-SQL-003"
    SQL_FIREWALL_AZURE_SERVICES   = "AZ-SEC-SQL-004"
    SQL_FIREWALL_IPV4_RANGE       = "AZ-SEC-SQL-005"
    SQL_DEFENDER                  = "AZ-SEC-SQL-006"
    SQL_TDE_KEY                   = "AZ-SEC-SQL-007"
    SQLMI_AAD_ADMIN               = "AZ-SEC-SQL-008"
    SQLMI_TDE                     = "AZ-SEC-SQL-009"

    # ==================== AKS ====================
    AKS_PRIVATE_CLUSTER           = "AZ-SEC-AKS-001"
    AKS_RBAC                      = "AZ-SEC-AKS-002"
    AKS_AAD_RBAC                  = "AZ-SEC-AKS-003"
    AKS_MANAGED_IDENTITY          = "AZ-SEC-AKS-004"
    AKS_NETWORK_POLICY            = "AZ-SEC-AKS-005"
    AKS_AZURE_POLICY              = "AZ-SEC-AKS-006"
    AKS_NODE_AUTO_UPGRADE         = "AZ-SEC-AKS-007"
    AKS_AUTO_SCALING              = "AZ-SEC-AKS-008"
    AKS_AVAILABILITY_ZONE         = "AZ-SEC-AKS-009"
    AKS_HTTP_APP_ROUTING          = "AZ-SEC-AKS-010"
    AKS_CONTAINER_INSIGHTS        = "AZ-SEC-AKS-011"
    AKS_API_SERVER_AUTHORIZED     = "AZ-SEC-AKS-012"
    AKS_DEFENDER                  = "AZ-SEC-AKS-013"
    AKS_LOCAL_ACCOUNTS            = "AZ-SEC-AKS-014"

    # ==================== Container Registry ====================
    ACR_ADMIN_USER                = "AZ-SEC-ACR-001"
    ACR_FIREWALL                  = "AZ-SEC-ACR-002"
    ACR_QUARANTINE                = "AZ-SEC-ACR-003"
    ACR_CONTENT_TRUST             = "AZ-SEC-ACR-004"
    ACR_RETENTION_POLICY          = "AZ-SEC-ACR-005"
    ACR_MANAGED_IDENTITY          = "AZ-SEC-ACR-006"
    ACR_SKU                       = "AZ-SEC-ACR-007"
    ACR_SOFT_DELETE               = "AZ-SEC-ACR-008"

    # ==================== API Management ====================
    APIM_HTTPS_ONLY               = "AZ-SEC-APIM-001"
    APIM_MIN_TLS                  = "AZ-SEC-APIM-002"
    APIM_MANAGED_IDENTITY         = "AZ-SEC-APIM-003"
    APIM_CIPHERS                  = "AZ-SEC-APIM-004"
    APIM_CERTIFICATES             = "AZ-SEC-APIM-005"

    # ==================== Cosmos DB ====================
    COSMOS_DEFENDER               = "AZ-SEC-COSMOS-001"
    COSMOS_DISABLE_KEY_AUTH       = "AZ-SEC-COSMOS-002"
    COSMOS_PRIVATE_ENDPOINT       = "AZ-SEC-COSMOS-003"
    COSMOS_FIREWALL               = "AZ-SEC-COSMOS-004"

    # ==================== Redis Cache ====================
    REDIS_HTTPS_ONLY              = "AZ-SEC-REDIS-001"
    REDIS_MIN_TLS                 = "AZ-SEC-REDIS-002"
    REDIS_PRIVATE_ENDPOINT        = "AZ-SEC-REDIS-003"
    REDIS_FIREWALL                = "AZ-SEC-REDIS-004"
    REDIS_NON_SSL_PORT            = "AZ-SEC-REDIS-005"

    # ==================== Service Bus ====================
    SERVICEBUS_USAGE_MIN_TLS      = "AZ-SEC-SB-001"
    SERVICEBUS_DISABLE_PUBLIC     = "AZ-SEC-SB-002"
    SERVICEBUS_MANAGED_IDENTITY   = "AZ-SEC-SB-003"

    # ==================== Event Hub ====================
    EVENTHUB_USAGE_MIN_TLS        = "AZ-SEC-EH-001"
    EVENTHUB_DISABLE_PUBLIC       = "AZ-SEC-EH-002"
    EVENTHUB_MANAGED_IDENTITY     = "AZ-SEC-EH-003"

    # ==================== Monitor / Diagnostics ====================
    MONITOR_LOG_ACTIVITY          = "AZ-SEC-MON-001"
    MONITOR_LOG_RETENTION         = "AZ-SEC-MON-002"
    MONITOR_ALERT_POLICY_DELETE   = "AZ-SEC-MON-003"
    MONITOR_ALERT_NSG             = "AZ-SEC-MON-004"
    DIAGNOSTIC_LOGS               = "AZ-SEC-MON-005"

    # ==================== Identity ====================
    RBAC_WILDCARD_ACTION          = "AZ-SEC-IAM-001"
    RBAC_WILDCARD_RESOURCE        = "AZ-SEC-IAM-002"
    RBAC_NOT_ASSIGNABLE           = "AZ-SEC-IAM-003"
    RBAC_LIMITED_SCOPE            = "AZ-SEC-IAM-004"

    # ==================== Naming / Tagging ====================
    RESOURCE_TAGS                 = "AZ-SEC-TAG-001"

    # ==================== ARM Template ====================
    TEMPLATE_TEMPLATE_FILE        = "AZ-SEC-TPL-001"
    TEMPLATE_TEMPLATE_SCHEMA      = "AZ-SEC-TPL-002"
    TEMPLATE_TEMPLATE_SCHEME      = "AZ-SEC-TPL-003"
    TEMPLATE_PARAMETER_METADATA   = "AZ-SEC-TPL-004"
    TEMPLATE_RESOURCES            = "AZ-SEC-TPL-005"
    TEMPLATE_LOCATION_DEFAULT     = "AZ-SEC-TPL-006"
    TEMPLATE_LOCATION_TYPE        = "AZ-SEC-TPL-007"
    TEMPLATE_RESOURCE_LOCATION    = "AZ-SEC-TPL-008"
    TEMPLATE_USE_LOCATION_PARAM   = "AZ-SEC-TPL-009"
    TEMPLATE_PARAM_MIN_MAX        = "AZ-SEC-TPL-010"
    TEMPLATE_DEBUG_DEPLOYMENT     = "AZ-SEC-TPL-011"
    TEMPLATE_PARAM_DATA_TYPES     = "AZ-SEC-TPL-012"
    TEMPLATE_PARAM_STRONG_TYPE    = "AZ-SEC-TPL-013"
    TEMPLATE_EXPRESSION_LENGTH    = "AZ-SEC-TPL-014"
    TEMPLATE_PARAM_FILE           = "AZ-SEC-TPL-015"
    TEMPLATE_PARAM_SCHEME         = "AZ-SEC-TPL-016"
    TEMPLATE_METADATA_LINK        = "AZ-SEC-TPL-017"
    TEMPLATE_PARAM_VALUE          = "AZ-SEC-TPL-018"
    TEMPLATE_USE_COMMENTS         = "AZ-SEC-TPL-019"
    TEMPLATE_USE_DESCRIPTIONS     = "AZ-SEC-TPL-020"

    # ==================== Deployment (Secrets / Security) ====================
    DEPLOYMENT_OUTPUT_SECRET      = "AZ-SEC-DEP-001"
    DEPLOYMENT_ADMIN_USERNAME     = "AZ-SEC-DEP-002"
    DEPLOYMENT_SECURE_VALUE       = "AZ-SEC-DEP-003"
    DEPLOYMENT_OUTER_SECRET       = "AZ-SEC-DEP-004"
    DEPLOYMENT_SECURE_PARAMETER   = "AZ-SEC-DEP-005"
    DEPLOYMENT_NAME               = "AZ-SEC-DEP-006"
    DEPLOYMENT_SECRET_LEAK        = "AZ-SEC-DEP-007"
    DEPLOYMENT_SCRIPT_PINNED      = "AZ-SEC-DEP-008"



class AzurePSRulePolicyMetadata:
    """
    Full metadata for every PSRule Azure rule, keyed by the PSRule ruleName.
    Provides fast O(1) lookup at scan-finding-enrichment time.
    """

    # Keyed by the exact PSRule ruleName string.
    METADATA: Dict[str, AzurePSRulePolicy] = {

        # ── Storage ──────────────────────────────────────────────────────────
        "Azure.Storage.SecureTransfer": AzurePSRulePolicy(
            rule_name="Azure.Storage.SecureTransfer",
            policy_id=AzurePSRulePolicyIDs.STORAGE_SECURE_TRANSFER,
            title="Storage Secure Transfer",
            category="Storage",
            resource_type="Microsoft.Storage/storageAccounts",
            severity="HIGH",
            description="Storage accounts must require HTTPS (secure transfer enabled).",
        ),
        "Azure.Storage.UseHTTPS": AzurePSRulePolicy(
            rule_name="Azure.Storage.UseHTTPS",
            policy_id=AzurePSRulePolicyIDs.STORAGE_HTTPS_ONLY,
            title="Storage HTTPS Only",
            category="Storage",
            resource_type="Microsoft.Storage/storageAccounts",
            severity="HIGH",
            description="Storage accounts must enforce HTTPS-only access.",
        ),
        "Azure.Storage.MinTLS": AzurePSRulePolicy(
            rule_name="Azure.Storage.MinTLS",
            policy_id=AzurePSRulePolicyIDs.STORAGE_MIN_TLS,
            title="Storage Minimum TLS Version",
            category="Storage",
            resource_type="Microsoft.Storage/storageAccounts",
            severity="HIGH",
            description="Storage accounts must use TLS 1.2 or later.",
        ),
        "Azure.Storage.BlobPublicAccess": AzurePSRulePolicy(
            rule_name="Azure.Storage.BlobPublicAccess",
            policy_id=AzurePSRulePolicyIDs.STORAGE_BLOB_PUBLIC_ACCESS,
            title="Storage Blob Public Access Disabled",
            category="Storage",
            resource_type="Microsoft.Storage/storageAccounts",
            severity="HIGH",
            description="Storage accounts must not allow anonymous blob public access.",
        ),
        "Azure.Storage.Firewall": AzurePSRulePolicy(
            rule_name="Azure.Storage.Firewall",
            policy_id=AzurePSRulePolicyIDs.STORAGE_FIREWALL,
            title="Storage Firewall Enabled",
            category="Storage",
            resource_type="Microsoft.Storage/storageAccounts",
            severity="HIGH",
            description="Storage accounts should restrict network access using a firewall.",
        ),
        "Azure.Storage.SoftDelete": AzurePSRulePolicy(
            rule_name="Azure.Storage.SoftDelete",
            policy_id=AzurePSRulePolicyIDs.STORAGE_SOFT_DELETE,
            title="Storage Blob Soft Delete",
            category="Storage",
            resource_type="Microsoft.Storage/storageAccounts",
            severity="MEDIUM",
            description="Storage accounts should have blob soft delete enabled for data recovery.",
        ),
        "Azure.Storage.Versioning": AzurePSRulePolicy(
            rule_name="Azure.Storage.Versioning",
            policy_id=AzurePSRulePolicyIDs.STORAGE_VERSIONING,
            title="Storage Blob Versioning",
            category="Storage",
            resource_type="Microsoft.Storage/storageAccounts",
            severity="MEDIUM",
            description="Storage accounts should enable blob versioning.",
        ),
        "Azure.Storage.DefenderCloud": AzurePSRulePolicy(
            rule_name="Azure.Storage.DefenderCloud",
            policy_id=AzurePSRulePolicyIDs.STORAGE_DEFENDER,
            title="Storage Defender for Cloud",
            category="Storage",
            resource_type="Microsoft.Storage/storageAccounts",
            severity="MEDIUM",
            description="Storage accounts should have Microsoft Defender for Cloud enabled.",
        ),
        "Azure.Storage.BlobRetention": AzurePSRulePolicy(
            rule_name="Azure.Storage.BlobRetention",
            policy_id=AzurePSRulePolicyIDs.STORAGE_BLOB_RETENTION,
            title="Storage Blob Retention Policy",
            category="Storage",
            resource_type="Microsoft.Storage/storageAccounts",
            severity="MEDIUM",
            description="Storage accounts should configure a blob retention policy.",
        ),
        "Azure.Storage.ContainerSoftDelete": AzurePSRulePolicy(
            rule_name="Azure.Storage.ContainerSoftDelete",
            policy_id=AzurePSRulePolicyIDs.STORAGE_CONTAINER_SOFT_DELETE,
            title="Storage Container Soft Delete",
            category="Storage",
            resource_type="Microsoft.Storage/storageAccounts",
            severity="MEDIUM",
            description="Storage accounts should enable container soft delete.",
        ),

        # ── Key Vault ─────────────────────────────────────────────────────────
        "Azure.KeyVault.SoftDelete": AzurePSRulePolicy(
            rule_name="Azure.KeyVault.SoftDelete",
            policy_id=AzurePSRulePolicyIDs.KEYVAULT_SOFT_DELETE,
            title="Key Vault Soft Delete",
            category="Key Vault",
            resource_type="Microsoft.KeyVault/vaults",
            severity="HIGH",
            description="Key vaults must have soft delete enabled to protect against accidental deletion.",
        ),
        "Azure.KeyVault.PurgeProtect": AzurePSRulePolicy(
            rule_name="Azure.KeyVault.PurgeProtect",
            policy_id=AzurePSRulePolicyIDs.KEYVAULT_PURGE_PROTECT,
            title="Key Vault Purge Protection",
            category="Key Vault",
            resource_type="Microsoft.KeyVault/vaults",
            severity="HIGH",
            description="Key vaults must have purge protection enabled.",
        ),
        "Azure.KeyVault.RBAC": AzurePSRulePolicy(
            rule_name="Azure.KeyVault.RBAC",
            policy_id=AzurePSRulePolicyIDs.KEYVAULT_RBAC,
            title="Key Vault RBAC Authorization",
            category="Key Vault",
            resource_type="Microsoft.KeyVault/vaults",
            severity="HIGH",
            description="Key vaults should use Azure RBAC for authorization instead of access policies.",
        ),
        "Azure.KeyVault.Firewall": AzurePSRulePolicy(
            rule_name="Azure.KeyVault.Firewall",
            policy_id=AzurePSRulePolicyIDs.KEYVAULT_FIREWALL,
            title="Key Vault Firewall Enabled",
            category="Key Vault",
            resource_type="Microsoft.KeyVault/vaults",
            severity="HIGH",
            description="Key vaults should restrict network access using a firewall.",
        ),
        "Azure.KeyVault.Logging": AzurePSRulePolicy(
            rule_name="Azure.KeyVault.Logging",
            policy_id=AzurePSRulePolicyIDs.KEYVAULT_LOGGING,
            title="Key Vault Diagnostic Logging",
            category="Key Vault",
            resource_type="Microsoft.KeyVault/vaults",
            severity="MEDIUM",
            description="Key vaults must have diagnostic logging enabled.",
        ),
        "Azure.KeyVault.SecretExpiry": AzurePSRulePolicy(
            rule_name="Azure.KeyVault.SecretExpiry",
            policy_id=AzurePSRulePolicyIDs.KEYVAULT_SECRET_EXPIRY,
            title="Key Vault Secret Expiry",
            category="Key Vault",
            resource_type="Microsoft.KeyVault/vaults/secrets",
            severity="MEDIUM",
            description="Key vault secrets must have an expiry date configured.",
        ),
        "Azure.KeyVault.KeyExpiry": AzurePSRulePolicy(
            rule_name="Azure.KeyVault.KeyExpiry",
            policy_id=AzurePSRulePolicyIDs.KEYVAULT_KEY_EXPIRY,
            title="Key Vault Key Expiry",
            category="Key Vault",
            resource_type="Microsoft.KeyVault/vaults/keys",
            severity="MEDIUM",
            description="Key vault keys must have an expiry date configured.",
        ),
        "Azure.KeyVault.CertificateExpiry": AzurePSRulePolicy(
            rule_name="Azure.KeyVault.CertificateExpiry",
            policy_id=AzurePSRulePolicyIDs.KEYVAULT_CERT_EXPIRY,
            title="Key Vault Certificate Expiry",
            category="Key Vault",
            resource_type="Microsoft.KeyVault/vaults/certificates",
            severity="MEDIUM",
            description="Key vault certificates must have a validity period configured.",
        ),

        # ── Virtual Machine ───────────────────────────────────────────────────
        "Azure.VM.Agent": AzurePSRulePolicy(
            rule_name="Azure.VM.Agent",
            policy_id=AzurePSRulePolicyIDs.VM_AGENT,
            title="VM Agent Enabled",
            category="Virtual Machine",
            resource_type="Microsoft.Compute/virtualMachines",
            severity="MEDIUM",
            description="Virtual machines must have the VM agent enabled.",
        ),
        "Azure.VM.Updates": AzurePSRulePolicy(
            rule_name="Azure.VM.Updates",
            policy_id=AzurePSRulePolicyIDs.VM_UPDATES,
            title="VM Automatic Updates",
            category="Virtual Machine",
            resource_type="Microsoft.Compute/virtualMachines",
            severity="MEDIUM",
            description="Virtual machines should have automatic updates enabled.",
        ),
        "Azure.VM.DiskEncryption": AzurePSRulePolicy(
            rule_name="Azure.VM.DiskEncryption",
            policy_id=AzurePSRulePolicyIDs.VM_DISK_ENCRYPTION,
            title="VM Disk Encryption",
            category="Virtual Machine",
            resource_type="Microsoft.Compute/virtualMachines",
            severity="HIGH",
            description="Virtual machine disks must be encrypted at rest.",
        ),
        "Azure.VM.UseManagedDisks": AzurePSRulePolicy(
            rule_name="Azure.VM.UseManagedDisks",
            policy_id=AzurePSRulePolicyIDs.VM_MANAGED_DISK,
            title="VM Managed Disks",
            category="Virtual Machine",
            resource_type="Microsoft.Compute/virtualMachines",
            severity="HIGH",
            description="Virtual machines must use managed disks.",
        ),
        "Azure.VM.AcceleratedNetworking": AzurePSRulePolicy(
            rule_name="Azure.VM.AcceleratedNetworking",
            policy_id=AzurePSRulePolicyIDs.VM_ACCELERATED_NETWORKING,
            title="VM Accelerated Networking",
            category="Virtual Machine",
            resource_type="Microsoft.Compute/virtualMachines",
            severity="LOW",
            description="Virtual machines should use accelerated networking for improved performance.",
        ),
        "Azure.VM.BootDiagnostics": AzurePSRulePolicy(
            rule_name="Azure.VM.BootDiagnostics",
            policy_id=AzurePSRulePolicyIDs.VM_BOOT_DIAGNOSTICS,
            title="VM Boot Diagnostics",
            category="Virtual Machine",
            resource_type="Microsoft.Compute/virtualMachines",
            severity="MEDIUM",
            description="Virtual machines should have boot diagnostics enabled.",
        ),
        "Azure.VM.Identity": AzurePSRulePolicy(
            rule_name="Azure.VM.Identity",
            policy_id=AzurePSRulePolicyIDs.VM_IDENTITY,
            title="VM Managed Identity",
            category="Virtual Machine",
            resource_type="Microsoft.Compute/virtualMachines",
            severity="MEDIUM",
            description="Virtual machines should use a managed identity.",
        ),
        "Azure.VM.PublicKey": AzurePSRulePolicy(
            rule_name="Azure.VM.PublicKey",
            policy_id=AzurePSRulePolicyIDs.VM_PUBLIC_IP,
            title="VM SSH Public Key Authentication",
            category="Virtual Machine",
            resource_type="Microsoft.Compute/virtualMachines",
            severity="HIGH",
            description="Linux virtual machines must use SSH public key authentication.",
        ),
        "Azure.VM.AMAAgent": AzurePSRulePolicy(
            rule_name="Azure.VM.AMAAgent",
            policy_id=AzurePSRulePolicyIDs.VM_AGENT,
            title="VM Azure Monitor Agent",
            category="Virtual Machine",
            resource_type="Microsoft.Compute/virtualMachines",
            severity="MEDIUM",
            description="Virtual machines should use the Azure Monitor Agent.",
        ),

        # ── Networking ────────────────────────────────────────────────────────
        "Azure.NSG.AnyInboundSource": AzurePSRulePolicy(
            rule_name="Azure.NSG.AnyInboundSource",
            policy_id=AzurePSRulePolicyIDs.NSG_ANY_INBOUND_SSH,
            title="NSG Any Inbound Source",
            category="Networking",
            resource_type="Microsoft.Network/networkSecurityGroups",
            severity="CRITICAL",
            description="NSG rules must not allow inbound traffic from any source (0.0.0.0/0).",
        ),
        "Azure.NSG.DenyAllInbound": AzurePSRulePolicy(
            rule_name="Azure.NSG.DenyAllInbound",
            policy_id=AzurePSRulePolicyIDs.NSG_DENIED_ALL,
            title="NSG Deny All Inbound",
            category="Networking",
            resource_type="Microsoft.Network/networkSecurityGroups",
            severity="HIGH",
            description="NSG should have a deny-all inbound rule as the last rule.",
        ),
        "Azure.NSG.LateralTraversal": AzurePSRulePolicy(
            rule_name="Azure.NSG.LateralTraversal",
            policy_id=AzurePSRulePolicyIDs.NSG_LATERAL_TRAVERSAL,
            title="NSG Lateral Traversal",
            category="Networking",
            resource_type="Microsoft.Network/networkSecurityGroups",
            severity="HIGH",
            description="NSG rules must not permit unrestricted lateral traversal between subnets.",
        ),
        "Azure.NSG.Associated": AzurePSRulePolicy(
            rule_name="Azure.NSG.Associated",
            policy_id=AzurePSRulePolicyIDs.NSG_RULE_DESCRIPTION,
            title="NSG Associated",
            category="Networking",
            resource_type="Microsoft.Network/networkSecurityGroups",
            severity="LOW",
            description="NSGs should be associated with a subnet or network interface.",
        ),
        "Azure.VNET.PeerState": AzurePSRulePolicy(
            rule_name="Azure.VNET.PeerState",
            policy_id=AzurePSRulePolicyIDs.VNET_PEER_STATE,
            title="VNet Peering State",
            category="Networking",
            resource_type="Microsoft.Network/virtualNetworks",
            severity="MEDIUM",
            description="VNet peering connections must be in a connected state.",
        ),
        "Azure.VNET.UseNSGs": AzurePSRulePolicy(
            rule_name="Azure.VNET.UseNSGs",
            policy_id=AzurePSRulePolicyIDs.NSG_DENIED_ALL,
            title="VNet Use NSGs",
            category="Networking",
            resource_type="Microsoft.Network/virtualNetworks",
            severity="HIGH",
            description="VNet subnets must use Network Security Groups.",
        ),
        "Azure.VNET.LocalDNS": AzurePSRulePolicy(
            rule_name="Azure.VNET.LocalDNS",
            policy_id=AzurePSRulePolicyIDs.VNET_LOCAL_DNS,
            title="VNet Local DNS",
            category="Networking",
            resource_type="Microsoft.Network/virtualNetworks",
            severity="MEDIUM",
            description="VNets should use custom DNS servers instead of Azure default DNS.",
        ),
        "Azure.LB.Probe": AzurePSRulePolicy(
            rule_name="Azure.LB.Probe",
            policy_id=AzurePSRulePolicyIDs.LB_PROBE,
            title="Load Balancer Health Probe",
            category="Networking",
            resource_type="Microsoft.Network/loadBalancers",
            severity="MEDIUM",
            description="Load balancers should use HTTP or HTTPS health probes.",
        ),
        "Azure.FrontDoor.WAF": AzurePSRulePolicy(
            rule_name="Azure.FrontDoor.WAF",
            policy_id=AzurePSRulePolicyIDs.FRONT_DOOR_WAF,
            title="Front Door WAF Policy",
            category="Networking",
            resource_type="Microsoft.Network/frontDoors",
            severity="HIGH",
            description="Azure Front Door must have a Web Application Firewall policy configured.",
        ),
        "Azure.FrontDoor.UseWAF": AzurePSRulePolicy(
            rule_name="Azure.FrontDoor.UseWAF",
            policy_id=AzurePSRulePolicyIDs.FRONT_DOOR_WAF,
            title="Front Door Use WAF",
            category="Networking",
            resource_type="Microsoft.Network/frontDoors",
            severity="HIGH",
            description="Azure Front Door should enforce WAF policy in prevention mode.",
        ),
        "Azure.FrontDoor.MinTLS": AzurePSRulePolicy(
            rule_name="Azure.FrontDoor.MinTLS",
            policy_id=AzurePSRulePolicyIDs.FRONT_DOOR_MIN_TLS,
            title="Front Door Minimum TLS",
            category="Networking",
            resource_type="Microsoft.Network/frontDoors",
            severity="HIGH",
            description="Azure Front Door must use TLS 1.2 or later.",
        ),
        "Azure.AppGw.WAFEnabled": AzurePSRulePolicy(
            rule_name="Azure.AppGw.WAFEnabled",
            policy_id=AzurePSRulePolicyIDs.APP_GATEWAY_WAF,
            title="Application Gateway WAF Enabled",
            category="Networking",
            resource_type="Microsoft.Network/applicationGateways",
            severity="HIGH",
            description="Application gateways must have WAF enabled.",
        ),
        "Azure.AppGw.UseWAF": AzurePSRulePolicy(
            rule_name="Azure.AppGw.UseWAF",
            policy_id=AzurePSRulePolicyIDs.APP_GATEWAY_WAF,
            title="Application Gateway Use WAF",
            category="Networking",
            resource_type="Microsoft.Network/applicationGateways",
            severity="HIGH",
            description="Application gateways must be deployed with a WAF policy.",
        ),
        "Azure.AppGw.WAFRules": AzurePSRulePolicy(
            rule_name="Azure.AppGw.WAFRules",
            policy_id=AzurePSRulePolicyIDs.APP_GATEWAY_WAF,
            title="Application Gateway WAF Rules",
            category="Networking",
            resource_type="Microsoft.Network/applicationGateways",
            severity="HIGH",
            description="Application gateway WAF must have all core rule groups enabled.",
        ),
        "Azure.AppGw.OWASP": AzurePSRulePolicy(
            rule_name="Azure.AppGw.OWASP",
            policy_id=AzurePSRulePolicyIDs.APP_GATEWAY_WAF,
            title="Application Gateway OWASP Rule Set",
            category="Networking",
            resource_type="Microsoft.Network/applicationGateways",
            severity="HIGH",
            description="Application gateway WAF must use OWASP 3.x or later rule set.",
        ),
        "Azure.AppGw.Prevention": AzurePSRulePolicy(
            rule_name="Azure.AppGw.Prevention",
            policy_id=AzurePSRulePolicyIDs.APP_GATEWAY_WAF,
            title="Application Gateway Prevention Mode",
            category="Networking",
            resource_type="Microsoft.Network/applicationGateways",
            severity="HIGH",
            description="Application gateway WAF must be in prevention mode.",
        ),
        "Azure.AppGw.MinTLS": AzurePSRulePolicy(
            rule_name="Azure.AppGw.MinTLS",
            policy_id=AzurePSRulePolicyIDs.APP_GATEWAY_MIN_TLS,
            title="Application Gateway Minimum TLS",
            category="Networking",
            resource_type="Microsoft.Network/applicationGateways",
            severity="HIGH",
            description="Application gateways must use TLS 1.2 or later.",
        ),
        "Azure.AppGw.SSLPolicy": AzurePSRulePolicy(
            rule_name="Azure.AppGw.SSLPolicy",
            policy_id=AzurePSRulePolicyIDs.APP_GATEWAY_MIN_TLS,
            title="Application Gateway SSL Policy",
            category="Networking",
            resource_type="Microsoft.Network/applicationGateways",
            severity="HIGH",
            description="Application gateways must use a predefined or custom SSL policy.",
        ),
        "Azure.AppGw.HTTPSRedirect": AzurePSRulePolicy(
            rule_name="Azure.AppGw.HTTPSRedirect",
            policy_id=AzurePSRulePolicyIDs.APP_GATEWAY_HTTPS_REDIRECT,
            title="Application Gateway HTTPS Redirect",
            category="Networking",
            resource_type="Microsoft.Network/applicationGateways",
            severity="MEDIUM",
            description="Application gateways should redirect HTTP traffic to HTTPS.",
        ),

        # ── App Service / Functions ───────────────────────────────────────────
        "Azure.AppService.UseHTTPS": AzurePSRulePolicy(
            rule_name="Azure.AppService.UseHTTPS",
            policy_id=AzurePSRulePolicyIDs.APPSERVICE_HTTPS_ONLY,
            title="App Service HTTPS Only",
            category="App Service",
            resource_type="Microsoft.Web/sites",
            severity="HIGH",
            description="App Service web apps must enforce HTTPS-only access.",
        ),
        "Azure.AppService.MinTLS": AzurePSRulePolicy(
            rule_name="Azure.AppService.MinTLS",
            policy_id=AzurePSRulePolicyIDs.APPSERVICE_MIN_TLS,
            title="App Service Minimum TLS",
            category="App Service",
            resource_type="Microsoft.Web/sites",
            severity="HIGH",
            description="App Service must use TLS 1.2 or later.",
        ),
        "Azure.AppService.ManagedIdentity": AzurePSRulePolicy(
            rule_name="Azure.AppService.ManagedIdentity",
            policy_id=AzurePSRulePolicyIDs.APPSERVICE_MANAGED_IDENTITY,
            title="App Service Managed Identity",
            category="App Service",
            resource_type="Microsoft.Web/sites",
            severity="MEDIUM",
            description="App Service web apps should use a managed identity.",
        ),
        "Azure.AppService.NETVersion": AzurePSRulePolicy(
            rule_name="Azure.AppService.NETVersion",
            policy_id=AzurePSRulePolicyIDs.APPSERVICE_NODE_VERSION,
            title="App Service .NET Version",
            category="App Service",
            resource_type="Microsoft.Web/sites",
            severity="MEDIUM",
            description="App Service should use a supported .NET version.",
        ),
        "Azure.AppService.PHPVersion": AzurePSRulePolicy(
            rule_name="Azure.AppService.PHPVersion",
            policy_id=AzurePSRulePolicyIDs.APPSERVICE_PHP_VERSION,
            title="App Service PHP Version",
            category="App Service",
            resource_type="Microsoft.Web/sites",
            severity="MEDIUM",
            description="App Service should use a supported PHP version.",
        ),
        "Azure.AppService.NodeVersion": AzurePSRulePolicy(
            rule_name="Azure.AppService.NodeVersion",
            policy_id=AzurePSRulePolicyIDs.APPSERVICE_NODE_VERSION,
            title="App Service Node.js Version",
            category="App Service",
            resource_type="Microsoft.Web/sites",
            severity="MEDIUM",
            description="App Service should use a supported Node.js version.",
        ),
        "Azure.AppService.PythonVersion": AzurePSRulePolicy(
            rule_name="Azure.AppService.PythonVersion",
            policy_id=AzurePSRulePolicyIDs.APPSERVICE_PYTHON_VERSION,
            title="App Service Python Version",
            category="App Service",
            resource_type="Microsoft.Web/sites",
            severity="MEDIUM",
            description="App Service should use a supported Python version.",
        ),
        "Azure.AppService.AlwaysOn": AzurePSRulePolicy(
            rule_name="Azure.AppService.AlwaysOn",
            policy_id=AzurePSRulePolicyIDs.APPSERVICE_ALWAYS_ON,
            title="App Service Always On",
            category="App Service",
            resource_type="Microsoft.Web/sites",
            severity="MEDIUM",
            description="App Service should have Always On enabled.",
        ),
        "Azure.AppService.ARRAffinity": AzurePSRulePolicy(
            rule_name="Azure.AppService.ARRAffinity",
            policy_id=AzurePSRulePolicyIDs.APPSERVICE_CLIENT_CERT,
            title="App Service ARR Affinity",
            category="App Service",
            resource_type="Microsoft.Web/sites",
            severity="LOW",
            description="App Service should disable ARR affinity for stateless apps.",
        ),
        "Azure.AppService.WebSecHeaders": AzurePSRulePolicy(
            rule_name="Azure.AppService.WebSecHeaders",
            policy_id=AzurePSRulePolicyIDs.APPSERVICE_HTTPS_ONLY,
            title="App Service Security Headers",
            category="App Service",
            resource_type="Microsoft.Web/sites",
            severity="MEDIUM",
            description="App Service should configure security response headers.",
        ),
        "Azure.AppService.RemoteDebug": AzurePSRulePolicy(
            rule_name="Azure.AppService.RemoteDebug",
            policy_id=AzurePSRulePolicyIDs.APPSERVICE_REMOTE_DEBUG,
            title="App Service Remote Debugging Disabled",
            category="App Service",
            resource_type="Microsoft.Web/sites",
            severity="HIGH",
            description="App Service remote debugging must be disabled in production.",
        ),
        "Azure.AppService.HTTP2": AzurePSRulePolicy(
            rule_name="Azure.AppService.HTTP2",
            policy_id=AzurePSRulePolicyIDs.APPSERVICE_HTTP2,
            title="App Service HTTP/2",
            category="App Service",
            resource_type="Microsoft.Web/sites",
            severity="LOW",
            description="App Service should use HTTP/2.",
        ),

        # ── SQL Database ──────────────────────────────────────────────────────
        "Azure.SQL.Auditing": AzurePSRulePolicy(
            rule_name="Azure.SQL.Auditing",
            policy_id=AzurePSRulePolicyIDs.SQL_AUDITING,
            title="SQL Server Auditing",
            category="SQL Database",
            resource_type="Microsoft.Sql/servers",
            severity="HIGH",
            description="SQL servers must have auditing enabled.",
        ),
        "Azure.SQL.AADOnly": AzurePSRulePolicy(
            rule_name="Azure.SQL.AADOnly",
            policy_id=AzurePSRulePolicyIDs.SQL_AAD_ADMIN,
            title="SQL Server Azure AD Only Authentication",
            category="SQL Database",
            resource_type="Microsoft.Sql/servers",
            severity="HIGH",
            description="SQL servers should enforce Azure AD-only authentication.",
        ),
        "Azure.SQL.AAD": AzurePSRulePolicy(
            rule_name="Azure.SQL.AAD",
            policy_id=AzurePSRulePolicyIDs.SQL_AAD_ADMIN,
            title="SQL Server Azure AD Admin",
            category="SQL Database",
            resource_type="Microsoft.Sql/servers",
            severity="HIGH",
            description="SQL servers must have an Azure AD admin configured.",
        ),
        "Azure.SQL.TDE": AzurePSRulePolicy(
            rule_name="Azure.SQL.TDE",
            policy_id=AzurePSRulePolicyIDs.SQL_TDE,
            title="SQL Database Transparent Data Encryption",
            category="SQL Database",
            resource_type="Microsoft.Sql/servers/databases",
            severity="HIGH",
            description="SQL databases must have Transparent Data Encryption enabled.",
        ),
        "Azure.SQL.AllowAzureAccess": AzurePSRulePolicy(
            rule_name="Azure.SQL.AllowAzureAccess",
            policy_id=AzurePSRulePolicyIDs.SQL_FIREWALL_AZURE_SERVICES,
            title="SQL Server Allow Azure Services",
            category="SQL Database",
            resource_type="Microsoft.Sql/servers",
            severity="MEDIUM",
            description="SQL server firewall should not allow unrestricted access from Azure services.",
        ),
        "Azure.SQL.FirewallIPRange": AzurePSRulePolicy(
            rule_name="Azure.SQL.FirewallIPRange",
            policy_id=AzurePSRulePolicyIDs.SQL_FIREWALL_IPV4_RANGE,
            title="SQL Server Firewall IP Range",
            category="SQL Database",
            resource_type="Microsoft.Sql/servers",
            severity="MEDIUM",
            description="SQL server firewall rules should not have overly broad IP ranges.",
        ),
        "Azure.SQL.DefenderCloud": AzurePSRulePolicy(
            rule_name="Azure.SQL.DefenderCloud",
            policy_id=AzurePSRulePolicyIDs.SQL_DEFENDER,
            title="SQL Server Defender for Cloud",
            category="SQL Database",
            resource_type="Microsoft.Sql/servers",
            severity="MEDIUM",
            description="SQL servers should have Microsoft Defender for Cloud enabled.",
        ),

        # ── AKS ───────────────────────────────────────────────────────────────
        "Azure.AKS.NetworkPolicy": AzurePSRulePolicy(
            rule_name="Azure.AKS.NetworkPolicy",
            policy_id=AzurePSRulePolicyIDs.AKS_NETWORK_POLICY,
            title="AKS Network Policy",
            category="AKS",
            resource_type="Microsoft.ContainerService/managedClusters",
            severity="HIGH",
            description="AKS clusters must enforce a network policy (Azure or Calico).",
        ),
        "Azure.AKS.RBAC": AzurePSRulePolicy(
            rule_name="Azure.AKS.RBAC",
            policy_id=AzurePSRulePolicyIDs.AKS_RBAC,
            title="AKS RBAC Enabled",
            category="AKS",
            resource_type="Microsoft.ContainerService/managedClusters",
            severity="HIGH",
            description="AKS clusters must have Kubernetes RBAC enabled.",
        ),
        "Azure.AKS.UseRBAC": AzurePSRulePolicy(
            rule_name="Azure.AKS.UseRBAC",
            policy_id=AzurePSRulePolicyIDs.AKS_RBAC,
            title="AKS Use RBAC",
            category="AKS",
            resource_type="Microsoft.ContainerService/managedClusters",
            severity="HIGH",
            description="AKS clusters should use Azure RBAC.",
        ),
        "Azure.AKS.ManagedIdentity": AzurePSRulePolicy(
            rule_name="Azure.AKS.ManagedIdentity",
            policy_id=AzurePSRulePolicyIDs.AKS_MANAGED_IDENTITY,
            title="AKS Managed Identity",
            category="AKS",
            resource_type="Microsoft.ContainerService/managedClusters",
            severity="HIGH",
            description="AKS clusters should use a managed identity instead of a service principal.",
        ),
        "Azure.AKS.AzurePolicy": AzurePSRulePolicy(
            rule_name="Azure.AKS.AzurePolicy",
            policy_id=AzurePSRulePolicyIDs.AKS_AZURE_POLICY,
            title="AKS Azure Policy Add-on",
            category="AKS",
            resource_type="Microsoft.ContainerService/managedClusters",
            severity="MEDIUM",
            description="AKS clusters should have the Azure Policy add-on enabled.",
        ),
        "Azure.AKS.AutoUpgrade": AzurePSRulePolicy(
            rule_name="Azure.AKS.AutoUpgrade",
            policy_id=AzurePSRulePolicyIDs.AKS_NODE_AUTO_UPGRADE,
            title="AKS Auto-Upgrade Channel",
            category="AKS",
            resource_type="Microsoft.ContainerService/managedClusters",
            severity="MEDIUM",
            description="AKS clusters should configure an automatic upgrade channel.",
        ),
        "Azure.AKS.AutoScaling": AzurePSRulePolicy(
            rule_name="Azure.AKS.AutoScaling",
            policy_id=AzurePSRulePolicyIDs.AKS_AUTO_SCALING,
            title="AKS Cluster Auto Scaling",
            category="AKS",
            resource_type="Microsoft.ContainerService/managedClusters",
            severity="LOW",
            description="AKS node pools should have auto-scaling enabled.",
        ),
        "Azure.AKS.AvailabilityZone": AzurePSRulePolicy(
            rule_name="Azure.AKS.AvailabilityZone",
            policy_id=AzurePSRulePolicyIDs.AKS_AVAILABILITY_ZONE,
            title="AKS Availability Zones",
            category="AKS",
            resource_type="Microsoft.ContainerService/managedClusters",
            severity="MEDIUM",
            description="AKS node pools should span multiple availability zones.",
        ),
        "Azure.AKS.HttpAppRouting": AzurePSRulePolicy(
            rule_name="Azure.AKS.HttpAppRouting",
            policy_id=AzurePSRulePolicyIDs.AKS_HTTP_APP_ROUTING,
            title="AKS HTTP Application Routing",
            category="AKS",
            resource_type="Microsoft.ContainerService/managedClusters",
            severity="HIGH",
            description="AKS clusters must not use the HTTP application routing add-on in production.",
        ),
        "Azure.AKS.ContainerInsights": AzurePSRulePolicy(
            rule_name="Azure.AKS.ContainerInsights",
            policy_id=AzurePSRulePolicyIDs.AKS_CONTAINER_INSIGHTS,
            title="AKS Container Insights",
            category="AKS",
            resource_type="Microsoft.ContainerService/managedClusters",
            severity="MEDIUM",
            description="AKS clusters should have Container Insights enabled.",
        ),
        "Azure.AKS.AuthorizedIPs": AzurePSRulePolicy(
            rule_name="Azure.AKS.AuthorizedIPs",
            policy_id=AzurePSRulePolicyIDs.AKS_API_SERVER_AUTHORIZED,
            title="AKS API Server Authorized IPs",
            category="AKS",
            resource_type="Microsoft.ContainerService/managedClusters",
            severity="HIGH",
            description="AKS clusters should restrict access to the API server with authorized IP ranges.",
        ),
        "Azure.AKS.DefenderCloud": AzurePSRulePolicy(
            rule_name="Azure.AKS.DefenderCloud",
            policy_id=AzurePSRulePolicyIDs.AKS_DEFENDER,
            title="AKS Defender for Cloud",
            category="AKS",
            resource_type="Microsoft.ContainerService/managedClusters",
            severity="MEDIUM",
            description="AKS clusters should have Microsoft Defender for Cloud enabled.",
        ),
        "Azure.AKS.LocalAccounts": AzurePSRulePolicy(
            rule_name="Azure.AKS.LocalAccounts",
            policy_id=AzurePSRulePolicyIDs.AKS_LOCAL_ACCOUNTS,
            title="AKS Local Accounts Disabled",
            category="AKS",
            resource_type="Microsoft.ContainerService/managedClusters",
            severity="HIGH",
            description="AKS clusters should disable local Kubernetes accounts.",
        ),
        "Azure.AKS.PrivateCluster": AzurePSRulePolicy(
            rule_name="Azure.AKS.PrivateCluster",
            policy_id=AzurePSRulePolicyIDs.AKS_PRIVATE_CLUSTER,
            title="AKS Private Cluster",
            category="AKS",
            resource_type="Microsoft.ContainerService/managedClusters",
            severity="HIGH",
            description="AKS clusters should be deployed as a private cluster.",
        ),

        # ── Container Registry ────────────────────────────────────────────────
        "Azure.ACR.AdminUser": AzurePSRulePolicy(
            rule_name="Azure.ACR.AdminUser",
            policy_id=AzurePSRulePolicyIDs.ACR_ADMIN_USER,
            title="ACR Admin User Disabled",
            category="Container Registry",
            resource_type="Microsoft.ContainerRegistry/registries",
            severity="HIGH",
            description="Container registries must have the admin user account disabled.",
        ),
        "Azure.ACR.Firewall": AzurePSRulePolicy(
            rule_name="Azure.ACR.Firewall",
            policy_id=AzurePSRulePolicyIDs.ACR_FIREWALL,
            title="ACR Firewall Enabled",
            category="Container Registry",
            resource_type="Microsoft.ContainerRegistry/registries",
            severity="HIGH",
            description="Container registries should restrict network access using a firewall.",
        ),
        "Azure.ACR.Quarantine": AzurePSRulePolicy(
            rule_name="Azure.ACR.Quarantine",
            policy_id=AzurePSRulePolicyIDs.ACR_QUARANTINE,
            title="ACR Image Quarantine",
            category="Container Registry",
            resource_type="Microsoft.ContainerRegistry/registries",
            severity="MEDIUM",
            description="Container registries should enable the quarantine policy.",
        ),
        "Azure.ACR.ContentTrust": AzurePSRulePolicy(
            rule_name="Azure.ACR.ContentTrust",
            policy_id=AzurePSRulePolicyIDs.ACR_CONTENT_TRUST,
            title="ACR Content Trust",
            category="Container Registry",
            resource_type="Microsoft.ContainerRegistry/registries",
            severity="HIGH",
            description="Container registries should enable content trust for image signing.",
        ),
        "Azure.ACR.Retention": AzurePSRulePolicy(
            rule_name="Azure.ACR.Retention",
            policy_id=AzurePSRulePolicyIDs.ACR_RETENTION_POLICY,
            title="ACR Retention Policy",
            category="Container Registry",
            resource_type="Microsoft.ContainerRegistry/registries",
            severity="LOW",
            description="Container registries should have a retention policy configured.",
        ),
        "Azure.ACR.SoftDelete": AzurePSRulePolicy(
            rule_name="Azure.ACR.SoftDelete",
            policy_id=AzurePSRulePolicyIDs.ACR_SOFT_DELETE,
            title="ACR Soft Delete",
            category="Container Registry",
            resource_type="Microsoft.ContainerRegistry/registries",
            severity="MEDIUM",
            description="Container registries should have soft delete enabled.",
        ),

        # ── API Management ────────────────────────────────────────────────────
        "Azure.APIM.HTTPEndpoint": AzurePSRulePolicy(
            rule_name="Azure.APIM.HTTPEndpoint",
            policy_id=AzurePSRulePolicyIDs.APIM_HTTPS_ONLY,
            title="APIM HTTPS Endpoint",
            category="API Management",
            resource_type="Microsoft.ApiManagement/service",
            severity="HIGH",
            description="API Management must only accept HTTPS requests.",
        ),
        "Azure.APIM.Protocols": AzurePSRulePolicy(
            rule_name="Azure.APIM.Protocols",
            policy_id=AzurePSRulePolicyIDs.APIM_MIN_TLS,
            title="APIM Protocols",
            category="API Management",
            resource_type="Microsoft.ApiManagement/service",
            severity="HIGH",
            description="API Management must use TLS 1.2 or later.",
        ),
        "Azure.APIM.ManagedIdentity": AzurePSRulePolicy(
            rule_name="Azure.APIM.ManagedIdentity",
            policy_id=AzurePSRulePolicyIDs.APIM_MANAGED_IDENTITY,
            title="APIM Managed Identity",
            category="API Management",
            resource_type="Microsoft.ApiManagement/service",
            severity="MEDIUM",
            description="API Management should use a managed identity.",
        ),
        "Azure.APIM.Ciphers": AzurePSRulePolicy(
            rule_name="Azure.APIM.Ciphers",
            policy_id=AzurePSRulePolicyIDs.APIM_CIPHERS,
            title="APIM Cipher Suites",
            category="API Management",
            resource_type="Microsoft.ApiManagement/service",
            severity="HIGH",
            description="API Management must disable weak or deprecated cipher suites.",
        ),
        "Azure.APIM.CertificateExpiry": AzurePSRulePolicy(
            rule_name="Azure.APIM.CertificateExpiry",
            policy_id=AzurePSRulePolicyIDs.APIM_CERTIFICATES,
            title="APIM Certificate Expiry",
            category="API Management",
            resource_type="Microsoft.ApiManagement/service",
            severity="HIGH",
            description="API Management certificates must not be expired or near expiry.",
        ),
        "Azure.APIM.HTTPBackend": AzurePSRulePolicy(
            rule_name="Azure.APIM.HTTPBackend",
            policy_id=AzurePSRulePolicyIDs.APIM_HTTPS_ONLY,
            title="APIM HTTP Backend",
            category="API Management",
            resource_type="Microsoft.ApiManagement/service",
            severity="HIGH",
            description="API Management backends must use HTTPS.",
        ),

        # ── Cosmos DB ─────────────────────────────────────────────────────────
        "Azure.Cosmos.DefenderCloud": AzurePSRulePolicy(
            rule_name="Azure.Cosmos.DefenderCloud",
            policy_id=AzurePSRulePolicyIDs.COSMOS_DEFENDER,
            title="Cosmos DB Defender for Cloud",
            category="Cosmos DB",
            resource_type="Microsoft.DocumentDB/databaseAccounts",
            severity="MEDIUM",
            description="Cosmos DB accounts should have Microsoft Defender for Cloud enabled.",
        ),
        "Azure.Cosmos.DisableLocalAuth": AzurePSRulePolicy(
            rule_name="Azure.Cosmos.DisableLocalAuth",
            policy_id=AzurePSRulePolicyIDs.COSMOS_DISABLE_KEY_AUTH,
            title="Cosmos DB Disable Local Auth",
            category="Cosmos DB",
            resource_type="Microsoft.DocumentDB/databaseAccounts",
            severity="HIGH",
            description="Cosmos DB accounts should disable local key-based authentication.",
        ),
        "Azure.Cosmos.PrivateEndpoint": AzurePSRulePolicy(
            rule_name="Azure.Cosmos.PrivateEndpoint",
            policy_id=AzurePSRulePolicyIDs.COSMOS_PRIVATE_ENDPOINT,
            title="Cosmos DB Private Endpoint",
            category="Cosmos DB",
            resource_type="Microsoft.DocumentDB/databaseAccounts",
            severity="HIGH",
            description="Cosmos DB accounts should use private endpoints.",
        ),

        # ── Redis Cache ───────────────────────────────────────────────────────
        "Azure.Redis.NonSslPort": AzurePSRulePolicy(
            rule_name="Azure.Redis.NonSslPort",
            policy_id=AzurePSRulePolicyIDs.REDIS_NON_SSL_PORT,
            title="Redis Non-SSL Port Disabled",
            category="Redis Cache",
            resource_type="Microsoft.Cache/Redis",
            severity="HIGH",
            description="Redis Cache must not have the non-SSL port (6379) enabled.",
        ),
        "Azure.Redis.MinTLS": AzurePSRulePolicy(
            rule_name="Azure.Redis.MinTLS",
            policy_id=AzurePSRulePolicyIDs.REDIS_MIN_TLS,
            title="Redis Minimum TLS Version",
            category="Redis Cache",
            resource_type="Microsoft.Cache/Redis",
            severity="HIGH",
            description="Redis Cache must use TLS 1.2 or later.",
        ),
        "Azure.Redis.MaxMemoryReserved": AzurePSRulePolicy(
            rule_name="Azure.Redis.MaxMemoryReserved",
            policy_id=AzurePSRulePolicyIDs.REDIS_HTTPS_ONLY,
            title="Redis Max Memory Reserved",
            category="Redis Cache",
            resource_type="Microsoft.Cache/Redis",
            severity="LOW",
            description="Redis Cache should have maxmemory-reserved configured.",
        ),

        # ── Service Bus ───────────────────────────────────────────────────────
        "Azure.ServiceBus.Usage": AzurePSRulePolicy(
            rule_name="Azure.ServiceBus.Usage",
            policy_id=AzurePSRulePolicyIDs.SERVICEBUS_DISABLE_PUBLIC,
            title="Service Bus Usage",
            category="Service Bus",
            resource_type="Microsoft.ServiceBus/namespaces",
            severity="LOW",
            description="Service Bus namespaces without queues or topics may be orphaned.",
        ),
        "Azure.ServiceBus.DisableLocalAuth": AzurePSRulePolicy(
            rule_name="Azure.ServiceBus.DisableLocalAuth",
            policy_id=AzurePSRulePolicyIDs.SERVICEBUS_MANAGED_IDENTITY,
            title="Service Bus Disable Local Auth",
            category="Service Bus",
            resource_type="Microsoft.ServiceBus/namespaces",
            severity="HIGH",
            description="Service Bus namespaces should disable local SAS key authentication.",
        ),
        "Azure.ServiceBus.MinTLS": AzurePSRulePolicy(
            rule_name="Azure.ServiceBus.MinTLS",
            policy_id=AzurePSRulePolicyIDs.SERVICEBUS_USAGE_MIN_TLS,
            title="Service Bus Minimum TLS",
            category="Service Bus",
            resource_type="Microsoft.ServiceBus/namespaces",
            severity="HIGH",
            description="Service Bus namespaces must use TLS 1.2 or later.",
        ),

        # ── Event Hub ─────────────────────────────────────────────────────────
        "Azure.EventHub.Usage": AzurePSRulePolicy(
            rule_name="Azure.EventHub.Usage",
            policy_id=AzurePSRulePolicyIDs.EVENTHUB_DISABLE_PUBLIC,
            title="Event Hub Usage",
            category="Event Hub",
            resource_type="Microsoft.EventHub/namespaces",
            severity="LOW",
            description="Event Hub namespaces without event hubs may be orphaned.",
        ),
        "Azure.EventHub.DisableLocalAuth": AzurePSRulePolicy(
            rule_name="Azure.EventHub.DisableLocalAuth",
            policy_id=AzurePSRulePolicyIDs.EVENTHUB_MANAGED_IDENTITY,
            title="Event Hub Disable Local Auth",
            category="Event Hub",
            resource_type="Microsoft.EventHub/namespaces",
            severity="HIGH",
            description="Event Hub namespaces should disable local SAS key authentication.",
        ),
        "Azure.EventHub.MinTLS": AzurePSRulePolicy(
            rule_name="Azure.EventHub.MinTLS",
            policy_id=AzurePSRulePolicyIDs.EVENTHUB_USAGE_MIN_TLS,
            title="Event Hub Minimum TLS",
            category="Event Hub",
            resource_type="Microsoft.EventHub/namespaces",
            severity="HIGH",
            description="Event Hub namespaces must use TLS 1.2 or later.",
        ),

        # ── Monitor / Diagnostics ─────────────────────────────────────────────
        "Azure.Monitor.ActivityRetention": AzurePSRulePolicy(
            rule_name="Azure.Monitor.ActivityRetention",
            policy_id=AzurePSRulePolicyIDs.MONITOR_LOG_RETENTION,
            title="Monitor Activity Log Retention",
            category="Monitor",
            resource_type="Microsoft.Insights/diagnosticSettings",
            severity="MEDIUM",
            description="Azure Monitor activity logs must be retained for at least one year.",
        ),
        "Azure.Monitor.AlertSummary": AzurePSRulePolicy(
            rule_name="Azure.Monitor.AlertSummary",
            policy_id=AzurePSRulePolicyIDs.MONITOR_ALERT_POLICY_DELETE,
            title="Monitor Alert Summary",
            category="Monitor",
            resource_type="Microsoft.Insights/metricAlerts",
            severity="LOW",
            description="Azure Monitor alerts should have meaningful descriptions.",
        ),

        # ── RBAC / Identity ───────────────────────────────────────────────────
        "Azure.RBAC.UseGroups": AzurePSRulePolicy(
            rule_name="Azure.RBAC.UseGroups",
            policy_id=AzurePSRulePolicyIDs.RBAC_LIMITED_SCOPE,
            title="RBAC Use Groups",
            category="Identity",
            resource_type="Microsoft.Authorization/roleAssignments",
            severity="MEDIUM",
            description="RBAC assignments should use groups rather than individual users.",
        ),
        "Azure.RBAC.LimitOwner": AzurePSRulePolicy(
            rule_name="Azure.RBAC.LimitOwner",
            policy_id=AzurePSRulePolicyIDs.RBAC_WILDCARD_ACTION,
            title="RBAC Limit Owner Role",
            category="Identity",
            resource_type="Microsoft.Authorization/roleAssignments",
            severity="HIGH",
            description="The number of Owner role assignments must be limited.",
        ),
        "Azure.RBAC.LimitMGDelegation": AzurePSRulePolicy(
            rule_name="Azure.RBAC.LimitMGDelegation",
            policy_id=AzurePSRulePolicyIDs.RBAC_NOT_ASSIGNABLE,
            title="RBAC Limit Management Group Delegation",
            category="Identity",
            resource_type="Microsoft.Authorization/roleAssignments",
            severity="HIGH",
            description="Role assignments must not be delegated at the management group scope without justification.",
        ),
        "Azure.RBAC.CoAdministrator": AzurePSRulePolicy(
            rule_name="Azure.RBAC.CoAdministrator",
            policy_id=AzurePSRulePolicyIDs.RBAC_WILDCARD_RESOURCE,
            title="RBAC Co-Administrator",
            category="Identity",
            resource_type="Microsoft.Authorization/roleAssignments",
            severity="HIGH",
            description="Classic co-administrator role assignments must not be used.",
        ),

        # ── Resource Tagging ──────────────────────────────────────────────────
        "Azure.Resource.UseTags": AzurePSRulePolicy(
            rule_name="Azure.Resource.UseTags",
            policy_id=AzurePSRulePolicyIDs.RESOURCE_TAGS,
            title="Resource Tags",
            category="Governance",
            resource_type="Microsoft.Resources/resourceGroups",
            severity="LOW",
            description="Azure resources should have tags applied for management and cost tracking.",
        ),
        "Azure.Resource.AllowedRegions": AzurePSRulePolicy(
            rule_name="Azure.Resource.AllowedRegions",
            policy_id=AzurePSRulePolicyIDs.RESOURCE_TAGS,
            title="Resource Allowed Regions",
            category="Governance",
            resource_type="Microsoft.Resources/resourceGroups",
            severity="LOW",
            description="Azure resources should be deployed in allowed regions.",
        ),

        # ── ARM Template ──────────────────────────────────────────────────────
        "Azure.Template.TemplateFile": AzurePSRulePolicy(
            rule_name="Azure.Template.TemplateFile",
            policy_id=AzurePSRulePolicyIDs.TEMPLATE_TEMPLATE_FILE,
            title="ARM Template File Valid",
            category="ARM Template",
            resource_type="Microsoft.Resources/deployments",
            severity="HIGH",
            description="Use ARM template files that are valid.",
        ),
        "Azure.Template.TemplateSchema": AzurePSRulePolicy(
            rule_name="Azure.Template.TemplateSchema",
            policy_id=AzurePSRulePolicyIDs.TEMPLATE_TEMPLATE_SCHEMA,
            title="ARM Template Schema Version",
            category="ARM Template",
            resource_type="Microsoft.Resources/deployments",
            severity="MEDIUM",
            description="Use a more recent version of the Azure template schema.",
        ),
        "Azure.Template.TemplateScheme": AzurePSRulePolicy(
            rule_name="Azure.Template.TemplateScheme",
            policy_id=AzurePSRulePolicyIDs.TEMPLATE_TEMPLATE_SCHEME,
            title="ARM Template Schema HTTPS Scheme",
            category="ARM Template",
            resource_type="Microsoft.Resources/deployments",
            severity="MEDIUM",
            description="Use an Azure template file schema with the https scheme.",
        ),
        "Azure.Template.ParameterMetadata": AzurePSRulePolicy(
            rule_name="Azure.Template.ParameterMetadata",
            policy_id=AzurePSRulePolicyIDs.TEMPLATE_PARAMETER_METADATA,
            title="ARM Template Parameter Metadata",
            category="ARM Template",
            resource_type="Microsoft.Resources/deployments",
            severity="LOW",
            description="Set metadata descriptions in ARM template for each parameter.",
        ),
        "Azure.Template.Resources": AzurePSRulePolicy(
            rule_name="Azure.Template.Resources",
            policy_id=AzurePSRulePolicyIDs.TEMPLATE_RESOURCES,
            title="ARM Template Has Resources",
            category="ARM Template",
            resource_type="Microsoft.Resources/deployments",
            severity="MEDIUM",
            description="Each ARM template file should deploy at least one resource.",
        ),
        "Azure.Template.LocationDefault": AzurePSRulePolicy(
            rule_name="Azure.Template.LocationDefault",
            policy_id=AzurePSRulePolicyIDs.TEMPLATE_LOCATION_DEFAULT,
            title="ARM Template Location Default",
            category="ARM Template",
            resource_type="Microsoft.Resources/deployments",
            severity="LOW",
            description="Set the default value for the location parameter to resource group location.",
        ),
        "Azure.Template.LocationType": AzurePSRulePolicy(
            rule_name="Azure.Template.LocationType",
            policy_id=AzurePSRulePolicyIDs.TEMPLATE_LOCATION_TYPE,
            title="ARM Template Location Parameter Type",
            category="ARM Template",
            resource_type="Microsoft.Resources/deployments",
            severity="LOW",
            description="Location parameters should use a string value.",
        ),
        "Azure.Template.ResourceLocation": AzurePSRulePolicy(
            rule_name="Azure.Template.ResourceLocation",
            policy_id=AzurePSRulePolicyIDs.TEMPLATE_RESOURCE_LOCATION,
            title="ARM Template Resource Location Expression",
            category="ARM Template",
            resource_type="Microsoft.Resources/deployments",
            severity="LOW",
            description="Resource locations should be an expression or global.",
        ),
        "Azure.Template.UseLocationParameter": AzurePSRulePolicy(
            rule_name="Azure.Template.UseLocationParameter",
            policy_id=AzurePSRulePolicyIDs.TEMPLATE_USE_LOCATION_PARAM,
            title="ARM Template Use Location Parameter",
            category="ARM Template",
            resource_type="Microsoft.Resources/deployments",
            severity="LOW",
            description="Template should reference a location parameter to specify resource location.",
        ),
        "Azure.Template.ParameterMinMaxValue": AzurePSRulePolicy(
            rule_name="Azure.Template.ParameterMinMaxValue",
            policy_id=AzurePSRulePolicyIDs.TEMPLATE_PARAM_MIN_MAX,
            title="ARM Template Parameter Min/Max Values",
            category="ARM Template",
            resource_type="Microsoft.Resources/deployments",
            severity="MEDIUM",
            description="Template parameters minValue and maxValue constraints must be valid.",
        ),
        "Azure.Template.DebugDeployment": AzurePSRulePolicy(
            rule_name="Azure.Template.DebugDeployment",
            policy_id=AzurePSRulePolicyIDs.TEMPLATE_DEBUG_DEPLOYMENT,
            title="ARM Template Debug Deployment",
            category="ARM Template",
            resource_type="Microsoft.Resources/deployments",
            severity="MEDIUM",
            description="Use default deployment detail level for nested deployments.",
        ),
        "Azure.Template.ParameterDataTypes": AzurePSRulePolicy(
            rule_name="Azure.Template.ParameterDataTypes",
            policy_id=AzurePSRulePolicyIDs.TEMPLATE_PARAM_DATA_TYPES,
            title="ARM Template Parameter Data Types",
            category="ARM Template",
            resource_type="Microsoft.Resources/deployments",
            severity="MEDIUM",
            description="Set the parameter default value to a value of the same type.",
        ),
        "Azure.Template.ParameterStrongType": AzurePSRulePolicy(
            rule_name="Azure.Template.ParameterStrongType",
            policy_id=AzurePSRulePolicyIDs.TEMPLATE_PARAM_STRONG_TYPE,
            title="ARM Template Parameter Strong Type",
            category="ARM Template",
            resource_type="Microsoft.Resources/deployments",
            severity="LOW",
            description="Set the parameter value to a value that matches the specified strong type.",
        ),
        "Azure.Template.ExpressionLength": AzurePSRulePolicy(
            rule_name="Azure.Template.ExpressionLength",
            policy_id=AzurePSRulePolicyIDs.TEMPLATE_EXPRESSION_LENGTH,
            title="ARM Template Expression Length",
            category="ARM Template",
            resource_type="Microsoft.Resources/deployments",
            severity="LOW",
            description="Template expressions should not exceed the maximum length.",
        ),
        "Azure.Template.ParameterFile": AzurePSRulePolicy(
            rule_name="Azure.Template.ParameterFile",
            policy_id=AzurePSRulePolicyIDs.TEMPLATE_PARAM_FILE,
            title="ARM Template Parameter File Valid",
            category="ARM Template",
            resource_type="Microsoft.Resources/deployments",
            severity="HIGH",
            description="Use ARM template parameter files that are valid.",
        ),
        "Azure.Template.ParameterScheme": AzurePSRulePolicy(
            rule_name="Azure.Template.ParameterScheme",
            policy_id=AzurePSRulePolicyIDs.TEMPLATE_PARAM_SCHEME,
            title="ARM Template Parameter File HTTPS Scheme",
            category="ARM Template",
            resource_type="Microsoft.Resources/deployments",
            severity="MEDIUM",
            description="Use an Azure template parameter file schema with the https scheme.",
        ),
        "Azure.Template.MetadataLink": AzurePSRulePolicy(
            rule_name="Azure.Template.MetadataLink",
            policy_id=AzurePSRulePolicyIDs.TEMPLATE_METADATA_LINK,
            title="ARM Template Metadata Link",
            category="ARM Template",
            resource_type="Microsoft.Resources/deployments",
            severity="LOW",
            description="Configure a metadata link for each parameter file.",
        ),
        "Azure.Template.ParameterValue": AzurePSRulePolicy(
            rule_name="Azure.Template.ParameterValue",
            policy_id=AzurePSRulePolicyIDs.TEMPLATE_PARAM_VALUE,
            title="ARM Template Parameter Value Set",
            category="ARM Template",
            resource_type="Microsoft.Resources/deployments",
            severity="MEDIUM",
            description="Specify a value for each parameter in template parameter files.",
        ),
        "Azure.Template.UseComments": AzurePSRulePolicy(
            rule_name="Azure.Template.UseComments",
            policy_id=AzurePSRulePolicyIDs.TEMPLATE_USE_COMMENTS,
            title="ARM Template Use Comments",
            category="ARM Template",
            resource_type="Microsoft.Resources/deployments",
            severity="LOW",
            description="Use comments for each resource in ARM template to communicate purpose.",
        ),
        "Azure.Template.UseDescriptions": AzurePSRulePolicy(
            rule_name="Azure.Template.UseDescriptions",
            policy_id=AzurePSRulePolicyIDs.TEMPLATE_USE_DESCRIPTIONS,
            title="ARM Template Use Descriptions",
            category="ARM Template",
            resource_type="Microsoft.Resources/deployments",
            severity="LOW",
            description="Use descriptions for each resource in generated template (Bicep, PSArm, AzOps) to communicate purpose.",
        ),

        # ── Deployment (Secrets / Security) ───────────────────────────────────
        "Azure.Deployment.OutputSecretValue": AzurePSRulePolicy(
            rule_name="Azure.Deployment.OutputSecretValue",
            policy_id=AzurePSRulePolicyIDs.DEPLOYMENT_OUTPUT_SECRET,
            title="Deployment Output Secret Value",
            category="Deployment",
            resource_type="Microsoft.Resources/deployments",
            severity="CRITICAL",
            description="Outputting a sensitive value from deployment may leak secrets into deployment history or logs.",
        ),
        "Azure.Deployment.AdminUsername": AzurePSRulePolicy(
            rule_name="Azure.Deployment.AdminUsername",
            policy_id=AzurePSRulePolicyIDs.DEPLOYMENT_ADMIN_USERNAME,
            title="Deployment Admin Username Hardcoded",
            category="Deployment",
            resource_type="Microsoft.Resources/deployments",
            severity="HIGH",
            description="A sensitive property set from deterministic or hardcoded values is not secure.",
        ),
        "Azure.Deployment.SecureValue": AzurePSRulePolicy(
            rule_name="Azure.Deployment.SecureValue",
            policy_id=AzurePSRulePolicyIDs.DEPLOYMENT_SECURE_VALUE,
            title="Deployment Secure Value",
            category="Deployment",
            resource_type="Microsoft.Resources/deployments",
            severity="CRITICAL",
            description="A secret property set from a non-secure value may leak the secret into deployment history or logs.",
        ),
        "Azure.Deployment.OuterSecret": AzurePSRulePolicy(
            rule_name="Azure.Deployment.OuterSecret",
            policy_id=AzurePSRulePolicyIDs.DEPLOYMENT_OUTER_SECRET,
            title="Deployment Outer Secret Leak",
            category="Deployment",
            resource_type="Microsoft.Resources/deployments",
            severity="CRITICAL",
            description="Outer evaluation deployments may leak secrets exposed as secure parameters into logs and nested deployments.",
        ),
        "Azure.Deployment.SecureParameter": AzurePSRulePolicy(
            rule_name="Azure.Deployment.SecureParameter",
            policy_id=AzurePSRulePolicyIDs.DEPLOYMENT_SECURE_PARAMETER,
            title="Deployment Secure Parameter",
            category="Deployment",
            resource_type="Microsoft.Resources/deployments",
            severity="HIGH",
            description="Sensitive parameters that have not been marked as secure may leak the secret into deployment history or logs.",
        ),
        "Azure.Deployment.Name": AzurePSRulePolicy(
            rule_name="Azure.Deployment.Name",
            policy_id=AzurePSRulePolicyIDs.DEPLOYMENT_NAME,
            title="Deployment Naming Requirements",
            category="Deployment",
            resource_type="Microsoft.Resources/deployments",
            severity="LOW",
            description="Nested deployments should meet naming requirements.",
        ),
        "Azure.Deployment.SecretLeak": AzurePSRulePolicy(
            rule_name="Azure.Deployment.SecretLeak",
            policy_id=AzurePSRulePolicyIDs.DEPLOYMENT_SECRET_LEAK,
            title="Deployment Secret Leak",
            category="Deployment",
            resource_type="Microsoft.Resources/deployments",
            severity="CRITICAL",
            description="Sensitive parameters that have not been marked as secure may leak the secret into deployment history or logs.",
        ),
        "Azure.DeploymentScript.Pinned": AzurePSRulePolicy(
            rule_name="Azure.DeploymentScript.Pinned",
            policy_id=AzurePSRulePolicyIDs.DEPLOYMENT_SCRIPT_PINNED,
            title="Deployment Script Pinned URL",
            category="Deployment",
            resource_type="Microsoft.Resources/deploymentScripts",
            severity="HIGH",
            description="Deployment scripts that use external scripts from an unpinned URL may be modified to execute malicious code.",
        ),

        # ── Storage (Extended) ───────────────────────────────────────────────
    }

    @classmethod
    def lookup(cls, rule_name: str) -> Optional[AzurePSRulePolicy]:
        """
        Return the AzurePSRulePolicy for the given PSRule ruleName,
        or None if the rule is not in the registry.
        """
        return cls.METADATA.get(rule_name)

    @classmethod
    def get_severity(cls, rule_name: str, default: str = "MEDIUM") -> str:
        """Return the severity string for the given rule, or default."""
        policy = cls.lookup(rule_name)
        return policy.severity if policy else default

    @classmethod
    def get_category(cls, rule_name: str, default: str = "Azure") -> str:
        """Return the category string for the given rule, or default."""
        policy = cls.lookup(rule_name)
        return policy.category if policy else default
