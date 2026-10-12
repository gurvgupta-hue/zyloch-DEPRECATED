"""
AWS Policy IDs and Messages

Centralized repository of AWS security policy details with fast lookup.
Organized by resource type for easy management and reusability.

Policy Naming Convention:
AWS-SEC-{SERVICE}-{NUMBER}
Examples:
- AWS-SEC-IAM-001: IAM policy
- AWS-SEC-EC2-001: EC2 policy
- AWS-SEC-S3-001: S3 policy
"""

from typing import Optional, Dict, List
from dataclasses import dataclass


@dataclass(frozen=True)
class Policy:
    """Represents a single AWS security policy record."""
    policy_id: str
    resource_type: str
    security_level: str
    message: str
    guide: str = "https://aws.amazon.com/security/best-practices"


class AWSPolicyIDs:
    """Central registry of AWS security policy IDs."""

    # ==================== S3 Policies ====================
    S3_PUBLIC_ACCESS = "AWS-SEC-S3-001"
    S3_VERSIONING = "AWS-SEC-S3-002"
    S3_SERVER_SIDE_ENCRYPTION = "AWS-SEC-S3-003"
    S3_LOGGING = "AWS-SEC-S3-004"
    S3_BUCKET_ENCRYPTION = "AWS-SEC-S3-005"
    S3_ACCESS_LOGGING = "AWS-SEC-S3-006"
    S3_MFA_DELETE = "AWS-SEC-S3-007"
    S3_SECURE_TRANSPORT = "AWS-SEC-S3-008"
    S3_BUCKET_ACL = "AWS-SEC-S3-009"
    S3_BUCKET_POLICY = "AWS-SEC-S3-010"

    # ==================== IAM Policies ====================
    IAM_ADMIN_ROLES = "AWS-SEC-IAM-001"
    IAM_KEY_ROTATION = "AWS-SEC-IAM-002"
    IAM_MFA_ENFORCEMENT = "AWS-SEC-IAM-003"
    IAM_ROOT_ACCOUNT = "AWS-SEC-IAM-004"
    IAM_WILDCARD_PRINCIPAL = "AWS-SEC-IAM-005"
    IAM_WILDCARD_ACTION = "AWS-SEC-IAM-006"
    IAM_EXCESSIVE_PERMISSIONS = "AWS-SEC-IAM-007"
    IAM_ACCESS_KEY_SECURITY = "AWS-SEC-IAM-008"

    # ==================== EC2 Policies ====================
    EC2_PUBLIC_IP = "AWS-SEC-EC2-001"
    EC2_SECURITY_GROUPS = "AWS-SEC-EC2-002"
    EC2_EBS_ENCRYPTION = "AWS-SEC-EC2-003"
    EC2_DETAILED_MONITORING = "AWS-SEC-EC2-004"
    EC2_NO_DEFAULT_VPC = "AWS-SEC-EC2-005"
    EC2_SECURITY_GROUP_RESTRICTED = "AWS-SEC-EC2-006"
    EC2_SSH_RESTRICTED = "AWS-SEC-EC2-007"
    EC2_RDP_RESTRICTED = "AWS-SEC-EC2-008"
    EC2_PUBLIC_SNAPSHOT = "AWS-SEC-EC2-009"
    EC2_INSTANCE_PROFILE = "AWS-SEC-EC2-010"

    # ==================== RDS Policies ====================
    RDS_PUBLIC_ACCESSIBLE = "AWS-SEC-RDS-001"
    RDS_ENCRYPTION = "AWS-SEC-RDS-002"
    RDS_BACKUP_RETENTION = "AWS-SEC-RDS-003"
    RDS_ENHANCED_MONITORING = "AWS-SEC-RDS-004"
    RDS_DELETION_PROTECTION = "AWS-SEC-RDS-005"
    RDS_MULTI_AZ = "AWS-SEC-RDS-006"
    RDS_SECURITY_GROUP = "AWS-SEC-RDS-007"
    RDS_DB_SUBNET_GROUP = "AWS-SEC-RDS-008"
    RDS_PARAMETER_ENCRYPTION = "AWS-SEC-RDS-009"
    RDS_LOG_RETENTION = "AWS-SEC-RDS-010"

    # ==================== Lambda Policies ====================
    LAMBDA_FUNCTION_PUBLIC = "AWS-SEC-LAMBDA-001"
    LAMBDA_VPC_CONFIGURED = "AWS-SEC-LAMBDA-002"
    LAMBDA_ENVIRONMENT_ENCRYPTION = "AWS-SEC-LAMBDA-003"
    LAMBDA_TIMEOUT_CONFIGURED = "AWS-SEC-LAMBDA-004"
    LAMBDA_MEMORY_CONFIGURED = "AWS-SEC-LAMBDA-005"
    LAMBDA_LOGGING_ENABLED = "AWS-SEC-LAMBDA-006"
    LAMBDA_PERMISSION_WILDCARD = "AWS-SEC-LAMBDA-007"
    LAMBDA_EXECUTION_ROLE = "AWS-SEC-LAMBDA-008"
    LAMBDA_RESERVED_CONCURRENT = "AWS-SEC-LAMBDA-009"
    LAMBDA_LAYER_SOURCE = "AWS-SEC-LAMBDA-010"

    # ==================== KMS Policies ====================
    KMS_KEY_ROTATION = "AWS-SEC-KMS-001"
    KMS_DELETION_PROTECTION = "AWS-SEC-KMS-002"
    KMS_KEY_POLICY = "AWS-SEC-KMS-003"
    KMS_MULTI_REGION = "AWS-SEC-KMS-004"
    KMS_KEY_DESCRIPTION = "AWS-SEC-KMS-005"
    KMS_KEY_TAGS = "AWS-SEC-KMS-006"
    KMS_ALIAS_NAMING = "AWS-SEC-KMS-007"
    KMS_GRANT_OPERATIONS = "AWS-SEC-KMS-008"
    KMS_KEY_USAGE = "AWS-SEC-KMS-009"
    KMS_CLOUDTRAIL_INTEGRATION = "AWS-SEC-KMS-010"
    KMS_KEY_POLICY_DELETION = "AWS-SEC-KMS-011"
    KMS_KEY_DISABLED = "AWS-SEC-KMS-012"
    KMS_MULTI_REGION_REPLICATION = "AWS-SEC-KMS-013"
    KMS_ALIAS_NAMING_CONVENTION = "AWS-SEC-KMS-014"
    KMS_ALIAS_AWS_RESERVED = "AWS-SEC-KMS-015"
    KMS_GRANT_RETIRING_PRINCIPAL = "AWS-SEC-KMS-016"

    # ==================== VPC Policies ====================
    VPC_FLOW_LOGS = "AWS-SEC-VPC-001"
    VPC_SECURITY_GROUP_RULES = "AWS-SEC-VPC-002"
    VPC_NACL = "AWS-SEC-VPC-003"
    VPC_SUBNET_PRIVATE = "AWS-SEC-VPC-004"
    VPC_ROUTE_TABLE = "AWS-SEC-VPC-005"
    VPC_PEERING_SECURITY = "AWS-SEC-VPC-006"
    VPC_ENDPOINT_SECURITY = "AWS-SEC-VPC-007"
    VPC_DNS_CONFIGURATION = "AWS-SEC-VPC-008"
    VPC_NETWORK_ACL = "AWS-SEC-VPC-009"
    VPC_DEFAULT_SECURITY = "AWS-SEC-VPC-010"
    SUBNET_PUBLIC_IP_AUTO_ASSIGN = "AWS-SEC-VPC-011"
    SUBNET_AVAILABILITY_ZONE = "AWS-SEC-VPC-012"
    NACL_ALLOW_ALL_INGRESS = "AWS-SEC-VPC-013"
    NACL_EXPLICIT_DENY = "AWS-SEC-VPC-014"
    NACL_RULE_NUMBER = "AWS-SEC-VPC-015"
    ROUTE_TABLE_TAGS = "AWS-SEC-VPC-016"
    ROUTE_TABLE_DEFAULT_ROUTES = "AWS-SEC-VPC-017"
    ROUTE_DEFAULT_DESTINATION = "AWS-SEC-VPC-018"

    # ==================== CloudTrail Policies ====================
    CLOUDTRAIL_ENABLED = "AWS-SEC-CT-001"
    CLOUDTRAIL_LOG_FILE_VALIDATION = "AWS-SEC-CT-002"
    CLOUDTRAIL_S3_ENCRYPTION = "AWS-SEC-CT-003"
    CLOUDTRAIL_MULTI_REGION = "AWS-SEC-CT-004"
    CLOUDTRAIL_CLOUDWATCH_INTEGRATION = "AWS-SEC-CT-005"
    CLOUDTRAIL_KMS_ENCRYPTION = "AWS-SEC-CT-006"
    CLOUDTRAIL_MANAGEMENT_EVENTS = "AWS-SEC-CT-007"
    CLOUDTRAIL_DATA_EVENTS = "AWS-SEC-CT-008"
    CLOUDTRAIL_S3_BUCKET_LOGGING = "AWS-SEC-CT-009"
    CLOUDTRAIL_LOG_RETENTION = "AWS-SEC-CT-010"

    # ==================== CloudFormation Policies ====================
    CFN_TERMINATION_PROTECTION = "AWS-SEC-CFN-001"
    CFN_CAPABILITIES = "AWS-SEC-CFN-002"
    CFN_NOTIFICATIONS = "AWS-SEC-CFN-003"
    CFN_TAGGING = "AWS-SEC-CFN-004"

    # ==================== SNS Policies ====================
    SNS_ENCRYPTION = "AWS-SEC-SNS-001"
    SNS_PUBLIC_ACCESS = "AWS-SEC-SNS-002"
    SNS_TAGGING = "AWS-SEC-SNS-003"
    SNS_DEAD_LETTER_QUEUE = "AWS-SEC-SNS-004"

    # ==================== SQS Policies ====================
    SQS_ENCRYPTION = "AWS-SEC-SQS-001"
    SQS_MESSAGE_RETENTION = "AWS-SEC-SQS-002"
    SQS_DEAD_LETTER_QUEUE = "AWS-SEC-SQS-003"
    SQS_PUBLIC_ACCESS = "AWS-SEC-SQS-004"

    # ==================== DynamoDB Policies ====================
    DYNAMODB_ENCRYPTION = "AWS-SEC-DDB-001"
    DYNAMODB_POINT_IN_TIME_RECOVERY = "AWS-SEC-DDB-002"
    DYNAMODB_TTL = "AWS-SEC-DDB-003"
    DYNAMODB_TAGGING = "AWS-SEC-DDB-004"
    DYNAMODB_BACKUP = "AWS-SEC-DDB-005"
    DYNAMODB_BILLING_MODE = "AWS-SEC-DDB-006"

    # ==================== ElastiCache Policies ====================
    ELASTICACHE_ENCRYPTION_AT_REST = "AWS-SEC-EC-001"
    ELASTICACHE_ENCRYPTION_IN_TRANSIT = "AWS-SEC-EC-002"
    ELASTICACHE_VPC = "AWS-SEC-EC-003"
    ELASTICACHE_FAILOVER = "AWS-SEC-EC-004"

    # ==================== API Gateway Policies ====================
    APIGW_ENDPOINT_TYPE = "AWS-SEC-APIGW-001"
    APIGW_CLOUDWATCH_LOGGING = "AWS-SEC-APIGW-002"
    APIGW_XRAY_TRACING = "AWS-SEC-APIGW-003"
    APIGW_WAF = "AWS-SEC-APIGW-004"
    APIGW_RESOURCE_POLICY = "AWS-SEC-APIGW-005"
    APIGW_THROTTLING = "AWS-SEC-APIGW-006"

    # ==================== Secrets Manager Policies ====================
    SECRETS_KMS_ENCRYPTION = "AWS-SEC-SM-001"
    SECRETS_ROTATION = "AWS-SEC-SM-002"
    SECRETS_PUBLIC_ACCESS = "AWS-SEC-SM-003"
    SECRETS_TAGGING = "AWS-SEC-SM-004"
    SECRETS_REPLICA = "AWS-SEC-SM-005"


class AWSPolicyMetadata:
    """Metadata for AWS security policies organized by service."""

    METADATA = {
        # S3 Metadata
        AWSPolicyIDs.S3_PUBLIC_ACCESS: {
            'title': 'S3 Public Access',
            'description': 'S3 buckets must not allow public access',
            'severity': 'CRITICAL',
            'category': 'Data Protection',
            'standards': ['CIS AWS v1.4.0 2.1.5', 'NIST 800-53 AC-2', 'PCI-DSS 1.2']
        },
        AWSPolicyIDs.S3_VERSIONING: {
            'title': 'S3 Versioning',
            'description': 'S3 buckets should have versioning enabled',
            'severity': 'MEDIUM',
            'category': 'Data Protection',
            'standards': ['AWS Best Practices']
        },
        AWSPolicyIDs.S3_SERVER_SIDE_ENCRYPTION: {
            'title': 'S3 Server-Side Encryption',
            'description': 'S3 buckets must have encryption enabled',
            'severity': 'HIGH',
            'category': 'Encryption',
            'standards': ['CIS AWS v1.4.0 2.1.3', 'PCI-DSS 3.4']
        },
        
        # IAM Metadata
        AWSPolicyIDs.IAM_ADMIN_ROLES: {
            'title': 'IAM Admin Roles',
            'description': 'IAM users must not have admin roles directly assigned',
            'severity': 'CRITICAL',
            'category': 'Access Control',
            'standards': ['CIS AWS v1.4.0 1.16', 'NIST 800-53 AC-6', 'PCI-DSS 2.2']
        },
        AWSPolicyIDs.IAM_WILDCARD_PRINCIPAL: {
            'title': 'IAM Wildcard Principal',
            'description': 'IAM policies must not use wildcard principals',
            'severity': 'CRITICAL',
            'category': 'Access Control',
            'standards': ['CIS AWS v1.4.0 1.19', 'NIST 800-53 AC-2']
        },
        
        # EC2 Metadata
        AWSPolicyIDs.EC2_PUBLIC_IP: {
            'title': 'EC2 Public IP',
            'description': 'EC2 instances must not have public IPs',
            'severity': 'HIGH',
            'category': 'Network Security',
            'standards': ['AWS Best Practices', 'CIS AWS v1.4.0 4.1']
        },
        AWSPolicyIDs.EC2_SSH_RESTRICTED: {
            'title': 'EC2 SSH Restricted',
            'description': 'SSH access must not be open to 0.0.0.0/0',
            'severity': 'CRITICAL',
            'category': 'Network Security',
            'standards': ['CIS AWS v1.4.0 4.2', 'PCI-DSS 1.2']
        },
        
        # RDS Metadata
        AWSPolicyIDs.RDS_PUBLIC_ACCESSIBLE: {
            'title': 'RDS Public Accessible',
            'description': 'RDS databases must not be publicly accessible',
            'severity': 'CRITICAL',
            'category': 'Database Security',
            'standards': ['CIS AWS v1.4.0 2.2.2', 'PCI-DSS 1.2']
        },
        AWSPolicyIDs.RDS_ENCRYPTION: {
            'title': 'RDS Encryption',
            'description': 'RDS databases must have encryption enabled',
            'severity': 'HIGH',
            'category': 'Encryption',
            'standards': ['CIS AWS v1.4.0 2.2.1', 'PCI-DSS 3.4']
        },
        
        # CloudTrail Metadata
        AWSPolicyIDs.CLOUDTRAIL_ENABLED: {
            'title': 'CloudTrail Enabled',
            'description': 'CloudTrail must be enabled for all regions',
            'severity': 'CRITICAL',
            'category': 'Logging',
            'standards': ['CIS AWS v1.4.0 2.1', 'NIST 800-53 AU-2']
        },
        AWSPolicyIDs.CLOUDTRAIL_LOG_FILE_VALIDATION: {
            'title': 'CloudTrail Log File Validation',
            'description': 'CloudTrail log file validation must be enabled',
            'severity': 'HIGH',
            'category': 'Logging',
            'standards': ['CIS AWS v1.4.0 2.1.3', 'NIST 800-53 SI-7']
        },
    }
    
    @classmethod
    def get_policy_info(cls, policy_id: str) -> Dict:
        """Get metadata for a specific policy."""
        return cls.METADATA.get(policy_id, {
            'title': 'Unknown Policy',
            'description': 'No description available',
            'severity': 'MEDIUM',
            'category': 'Uncategorized',
            'standards': []
        })
