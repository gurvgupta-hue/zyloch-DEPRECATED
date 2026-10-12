from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class CfnPolicy:
    """Represents a single CloudFormation security policy record."""
    policy_id: str       # CFN-SEC-{CATEGORY}-{NNN} identifier
    title: str           # Short human-readable title
    category: str        # Domain category (e.g. IAM, S3, Encryption)
    resource_type: str   # Primary CFN resource type this rule targets
    severity: str        # CRITICAL | HIGH | MEDIUM | LOW
    description: str     # What the rule checks
    remediation: str     # How to fix the violation


class CfnPolicyIDs:
    """
    Internal policy ID constants for the CloudFormation scanner.
    Use CfnPolicyMetadata.lookup(policy_id) to get the full record.
    """

    # ==================== IAM ====================
    IAM_NO_INLINE_POLICY              = "CFN-SEC-IAM-001"
    IAM_ROLE_WILDCARD_ACTION          = "CFN-SEC-IAM-002"
    IAM_ROLE_WILDCARD_RESOURCE        = "CFN-SEC-IAM-003"
    IAM_POLICY_WILDCARD_ACTION        = "CFN-SEC-IAM-004"
    IAM_POLICY_WILDCARD_RESOURCE      = "CFN-SEC-IAM-005"
    IAM_USER_ATTACHED_POLICIES        = "CFN-SEC-IAM-006"
    IAM_ROLE_ASSUME_ALL_PRINCIPALS    = "CFN-SEC-IAM-007"
    IAM_ACCESS_KEY_ROTATION           = "CFN-SEC-IAM-008"
    IAM_PASSWORD_POLICY_MIN_LENGTH    = "CFN-SEC-IAM-009"
    IAM_PASSWORD_POLICY_REUSE         = "CFN-SEC-IAM-010"

    # ==================== S3 ====================
    S3_BUCKET_PUBLIC_ACL              = "CFN-SEC-S3-001"
    S3_BUCKET_PUBLIC_POLICY           = "CFN-SEC-S3-002"
    S3_BUCKET_VERSIONING              = "CFN-SEC-S3-003"
    S3_BUCKET_ENCRYPTION              = "CFN-SEC-S3-004"
    S3_BUCKET_LOGGING                 = "CFN-SEC-S3-005"
    S3_BUCKET_BLOCK_PUBLIC_ACCESS     = "CFN-SEC-S3-006"
    S3_BUCKET_HTTPS_ONLY              = "CFN-SEC-S3-007"
    S3_BUCKET_MFA_DELETE              = "CFN-SEC-S3-008"

    # ==================== EC2 ====================
    EC2_SECURITY_GROUP_OPEN_SSH       = "CFN-SEC-EC2-001"
    EC2_SECURITY_GROUP_OPEN_RDP       = "CFN-SEC-EC2-002"
    EC2_SECURITY_GROUP_OPEN_ALL       = "CFN-SEC-EC2-003"
    EC2_INSTANCE_NO_PUBLIC_IP         = "CFN-SEC-EC2-004"
    EC2_INSTANCE_IMDSv2               = "CFN-SEC-EC2-005"
    EC2_EBS_VOLUME_ENCRYPTION         = "CFN-SEC-EC2-006"
    EC2_INSTANCE_DETAILED_MONITORING  = "CFN-SEC-EC2-007"

    # ==================== RDS ====================
    RDS_ENCRYPTION_AT_REST            = "CFN-SEC-RDS-001"
    RDS_NO_PUBLIC_ACCESS              = "CFN-SEC-RDS-002"
    RDS_MULTI_AZ                      = "CFN-SEC-RDS-003"
    RDS_DELETION_PROTECTION           = "CFN-SEC-RDS-004"
    RDS_AUTO_MINOR_VERSION_UPGRADE    = "CFN-SEC-RDS-005"
    RDS_BACKUP_RETENTION              = "CFN-SEC-RDS-006"

    # ==================== KMS ====================
    KMS_KEY_ROTATION                  = "CFN-SEC-KMS-001"

    # ==================== CloudTrail ====================
    CLOUDTRAIL_ENABLED                = "CFN-SEC-CT-001"
    CLOUDTRAIL_ENCRYPTION             = "CFN-SEC-CT-002"
    CLOUDTRAIL_LOG_FILE_VALIDATION    = "CFN-SEC-CT-003"
    CLOUDTRAIL_MULTI_REGION           = "CFN-SEC-CT-004"

    # ==================== Lambda ====================
    LAMBDA_FUNCTION_POLICY_WILDCARD   = "CFN-SEC-LAM-001"
    LAMBDA_TRACING_ENABLED            = "CFN-SEC-LAM-002"

    # ==================== ELB / ALB ====================
    ELB_ACCESS_LOGS_ENABLED           = "CFN-SEC-ELB-001"
    ELB_HTTPS_LISTENER                = "CFN-SEC-ELB-002"
    ELBV2_DROP_HTTP_HEADERS           = "CFN-SEC-ELB-003"

    # ==================== CloudFront ====================
    CF_DISTRIBUTION_HTTPS_ONLY        = "CFN-SEC-CFT-001"
    CF_DISTRIBUTION_LOGGING           = "CFN-SEC-CFT-002"
    CF_DISTRIBUTION_ORIGIN_HTTPS      = "CFN-SEC-CFT-003"

    # ==================== SQS ====================
    SQS_QUEUE_ENCRYPTION              = "CFN-SEC-SQS-001"

    # ==================== SNS ====================
    SNS_TOPIC_ENCRYPTION              = "CFN-SEC-SNS-001"

    # ==================== Secrets Management ====================
    CFN_NO_HARDCODED_CREDENTIALS      = "CFN-SEC-SEC-001"

    # ==================== EKS ====================
    EKS_CLUSTER_PRIVATE_ENDPOINT      = "CFN-SEC-EKS-001"
    EKS_CLUSTER_LOGGING               = "CFN-SEC-EKS-002"

    # ==================== DynamoDB ====================
    DYNAMODB_PITR_ENABLED             = "CFN-SEC-DYN-001"
    DYNAMODB_ENCRYPTION               = "CFN-SEC-DYN-002"

    # ==================== ElastiCache ====================
    ELASTICACHE_ENCRYPTION_AT_REST    = "CFN-SEC-ELC-001"
    ELASTICACHE_ENCRYPTION_IN_TRANSIT = "CFN-SEC-ELC-002"


class CfnPolicyMetadata:
    """
    Full metadata for every CloudFormation scanner policy, keyed by policy_id.
    Provides fast O(1) lookup at scan-finding-enrichment time.
    """

    METADATA: Dict[str, CfnPolicy] = {

        # ── IAM ───────────────────────────────────────────────────────────────
        CfnPolicyIDs.IAM_NO_INLINE_POLICY: CfnPolicy(
            policy_id=CfnPolicyIDs.IAM_NO_INLINE_POLICY,
            title="IAM: No Inline Policies on Roles or Users",
            category="IAM",
            resource_type="AWS::IAM::Role / AWS::IAM::User / AWS::IAM::Group",
            severity="MEDIUM",
            description=(
                "Inline IAM policies are embedded directly in a principal and "
                "cannot be reused, versioned, or centrally reviewed. They make "
                "auditing complex and violate the principle of least privilege "
                "by hiding permissions from policy-level reviews."
            ),
            remediation=(
                "Replace inline policies (Policies property on the IAM resource) "
                "with managed IAM policies (AWS::IAM::ManagedPolicy) attached "
                "via ManagedPolicyArns."
            ),
        ),
        CfnPolicyIDs.IAM_ROLE_WILDCARD_ACTION: CfnPolicy(
            policy_id=CfnPolicyIDs.IAM_ROLE_WILDCARD_ACTION,
            title="IAM Role: No Wildcard Actions",
            category="IAM",
            resource_type="AWS::IAM::Role",
            severity="HIGH",
            description=(
                "Using '*' as an Action in an IAM role's inline or assume-role "
                "policy grants all AWS service permissions to the principal. "
                "This violates the principle of least privilege and can allow "
                "privilege escalation or lateral movement if the role is compromised."
            ),
            remediation=(
                "Replace Action: '*' with the specific set of actions the role "
                "requires. Use IAM Access Analyzer to discover the minimum "
                "required permissions."
            ),
        ),
        CfnPolicyIDs.IAM_ROLE_WILDCARD_RESOURCE: CfnPolicy(
            policy_id=CfnPolicyIDs.IAM_ROLE_WILDCARD_RESOURCE,
            title="IAM Role: No Wildcard Resource",
            category="IAM",
            resource_type="AWS::IAM::Role",
            severity="HIGH",
            description=(
                "Using '*' as a Resource in an IAM role policy grants access to "
                "every resource of the given service. This exceeds the minimum "
                "required permissions and can allow unintended access to sensitive "
                "or production resources."
            ),
            remediation=(
                "Restrict the Resource to specific ARNs. Where dynamic ARNs are "
                "needed, use ARN conditions (aws:ResourceTag, aws:RequestedRegion) "
                "to limit scope."
            ),
        ),
        CfnPolicyIDs.IAM_POLICY_WILDCARD_ACTION: CfnPolicy(
            policy_id=CfnPolicyIDs.IAM_POLICY_WILDCARD_ACTION,
            title="IAM ManagedPolicy: No Wildcard Actions",
            category="IAM",
            resource_type="AWS::IAM::ManagedPolicy",
            severity="HIGH",
            description=(
                "An AWS::IAM::ManagedPolicy with Action: '*' in any statement "
                "grants unrestricted API access to all services. This is a "
                "critical overpermission that can be used for data exfiltration "
                "or infrastructure takeover."
            ),
            remediation=(
                "Enumerate only the specific IAM actions required by the "
                "workload. Use SCPs to prevent wildcard policies in production "
                "accounts."
            ),
        ),
        CfnPolicyIDs.IAM_POLICY_WILDCARD_RESOURCE: CfnPolicy(
            policy_id=CfnPolicyIDs.IAM_POLICY_WILDCARD_RESOURCE,
            title="IAM ManagedPolicy: No Wildcard Resource",
            category="IAM",
            resource_type="AWS::IAM::ManagedPolicy",
            severity="HIGH",
            description=(
                "An AWS::IAM::ManagedPolicy with Resource: '*' in any statement "
                "applies the allowed actions to every resource across the account. "
                "Combined with broad actions this is a common attack vector in "
                "privilege escalation scenarios."
            ),
            remediation=(
                "Replace Resource: '*' with the specific ARNs that the policy "
                "should cover. Use condition keys to further restrict access "
                "by tags, VPC, or source IP."
            ),
        ),
        CfnPolicyIDs.IAM_USER_ATTACHED_POLICIES: CfnPolicy(
            policy_id=CfnPolicyIDs.IAM_USER_ATTACHED_POLICIES,
            title="IAM: Do Not Attach Policies Directly to Users",
            category="IAM",
            resource_type="AWS::IAM::User",
            severity="LOW",
            description=(
                "Attaching IAM policies directly to users is an anti-pattern "
                "that makes permission management difficult to audit and maintain. "
                "It bypasses group-based access control and makes offboarding "
                "error-prone."
            ),
            remediation=(
                "Attach permissions to IAM Groups or Roles and add users to "
                "the appropriate group. Use AWS SSO / IAM Identity Center for "
                "human access patterns."
            ),
        ),
        CfnPolicyIDs.IAM_ROLE_ASSUME_ALL_PRINCIPALS: CfnPolicy(
            policy_id=CfnPolicyIDs.IAM_ROLE_ASSUME_ALL_PRINCIPALS,
            title="IAM Role: AssumeRolePolicyDocument Must Not Allow All Principals",
            category="IAM",
            resource_type="AWS::IAM::Role",
            severity="CRITICAL",
            description=(
                "Setting Principal: '*' in a role's AssumeRolePolicyDocument "
                "allows any AWS principal — including external accounts and "
                "anonymous users — to assume the role. This is a critical "
                "misconfiguration that can lead to full account compromise."
            ),
            remediation=(
                "Replace Principal: '*' with the specific AWS account IDs, "
                "service principals, or IAM ARNs that should be permitted to "
                "assume the role. Add Condition keys (aws:PrincipalOrgID, "
                "aws:PrincipalAccount) where broader trust is necessary."
            ),
        ),
        CfnPolicyIDs.IAM_ACCESS_KEY_ROTATION: CfnPolicy(
            policy_id=CfnPolicyIDs.IAM_ACCESS_KEY_ROTATION,
            title="IAM: Access Keys Must Not Be Embedded in Templates",
            category="IAM",
            resource_type="AWS::IAM::AccessKey",
            severity="CRITICAL",
            description=(
                "Provisioning IAM access keys via AWS::IAM::AccessKey in a "
                "CloudFormation template embeds long-lived credentials in the "
                "stack. Secret values are stored in plain text in CloudFormation "
                "stack outputs and can be exposed through CloudTrail logs, "
                "S3 bucket exports, or source control."
            ),
            remediation=(
                "Avoid generating IAM access keys in CloudFormation. Use IAM "
                "Roles with instance profiles, IRSA (IAM Roles for Service "
                "Accounts), or OIDC federation instead of static credentials."
            ),
        ),
        CfnPolicyIDs.IAM_PASSWORD_POLICY_MIN_LENGTH: CfnPolicy(
            policy_id=CfnPolicyIDs.IAM_PASSWORD_POLICY_MIN_LENGTH,
            title="IAM Account Password Policy: Minimum Length Must Be >= 14",
            category="IAM",
            resource_type="AWS::IAM::AccountPasswordPolicy",
            severity="MEDIUM",
            description=(
                "An IAM account password policy with MinimumPasswordLength < 14 "
                "increases the risk of brute-force attacks against the AWS Console "
                "and IAM user credentials."
            ),
            remediation=(
                "Set MinimumPasswordLength to at least 14 in the "
                "AWS::IAM::AccountPasswordPolicy resource."
            ),
        ),
        CfnPolicyIDs.IAM_PASSWORD_POLICY_REUSE: CfnPolicy(
            policy_id=CfnPolicyIDs.IAM_PASSWORD_POLICY_REUSE,
            title="IAM Account Password Policy: Password Reuse Prevention",
            category="IAM",
            resource_type="AWS::IAM::AccountPasswordPolicy",
            severity="MEDIUM",
            description=(
                "Not configuring PasswordReusePrevention allows users to cycle "
                "between a small set of passwords, reducing the effectiveness "
                "of mandatory password rotation."
            ),
            remediation=(
                "Set PasswordReusePrevention to at least 24 in the "
                "AWS::IAM::AccountPasswordPolicy resource."
            ),
        ),

        # ── S3 ────────────────────────────────────────────────────────────────
        CfnPolicyIDs.S3_BUCKET_PUBLIC_ACL: CfnPolicy(
            policy_id=CfnPolicyIDs.S3_BUCKET_PUBLIC_ACL,
            title="S3: Bucket Must Not Have Public ACL",
            category="S3",
            resource_type="AWS::S3::Bucket",
            severity="HIGH",
            description=(
                "Setting AccessControl to PublicRead, PublicReadWrite, "
                "AuthenticatedRead, or similar canned ACLs on an S3 bucket "
                "exposes objects to unauthenticated access, risking data "
                "exfiltration or content injection."
            ),
            remediation=(
                "Remove the AccessControl property or set it to 'Private'. "
                "Control access via bucket policies and IAM instead of ACLs. "
                "Enable S3 Block Public Access settings to prevent accidental "
                "public exposure."
            ),
        ),
        CfnPolicyIDs.S3_BUCKET_PUBLIC_POLICY: CfnPolicy(
            policy_id=CfnPolicyIDs.S3_BUCKET_PUBLIC_POLICY,
            title="S3: Bucket Policy Must Not Grant Public Access",
            category="S3",
            resource_type="AWS::S3::BucketPolicy",
            severity="HIGH",
            description=(
                "An AWS::S3::BucketPolicy with Principal: '*' in an Allow "
                "statement without a restrictive Condition makes the bucket "
                "publicly accessible. This is a common misconfiguration "
                "responsible for large-scale data breaches."
            ),
            remediation=(
                "Remove the wildcard Principal or add a restrictive Condition "
                "(e.g. aws:PrincipalOrgID, aws:SourceVpc) to limit access. "
                "Enable S3 Block Public Access to prevent public bucket policies."
            ),
        ),
        CfnPolicyIDs.S3_BUCKET_VERSIONING: CfnPolicy(
            policy_id=CfnPolicyIDs.S3_BUCKET_VERSIONING,
            title="S3: Bucket Versioning Must Be Enabled",
            category="S3",
            resource_type="AWS::S3::Bucket",
            severity="MEDIUM",
            description=(
                "S3 versioning protects against accidental deletion, ransomware, "
                "and overwrites by maintaining a history of object versions. "
                "Without versioning, data loss is unrecoverable."
            ),
            remediation=(
                "Set VersioningConfiguration.Status to 'Enabled' in the "
                "AWS::S3::Bucket resource."
            ),
        ),
        CfnPolicyIDs.S3_BUCKET_ENCRYPTION: CfnPolicy(
            policy_id=CfnPolicyIDs.S3_BUCKET_ENCRYPTION,
            title="S3: Bucket Server-Side Encryption Must Be Enabled",
            category="S3",
            resource_type="AWS::S3::Bucket",
            severity="HIGH",
            description=(
                "Storing data in S3 without server-side encryption (SSE) "
                "risks exposing sensitive data if physical storage media is "
                "not properly decommissioned, or in the event of an unauthorized "
                "access to the underlying data store."
            ),
            remediation=(
                "Add a BucketEncryption property with "
                "ServerSideEncryptionConfiguration using SSE-S3 (AES256) or "
                "SSE-KMS (aws:kms). Prefer SSE-KMS with a CMK for fine-grained "
                "key access control."
            ),
        ),
        CfnPolicyIDs.S3_BUCKET_LOGGING: CfnPolicy(
            policy_id=CfnPolicyIDs.S3_BUCKET_LOGGING,
            title="S3: Access Logging Must Be Enabled",
            category="S3",
            resource_type="AWS::S3::Bucket",
            severity="LOW",
            description=(
                "S3 server access logging records detailed information about "
                "every request made to the bucket. Without logging, security "
                "investigations and compliance audits cannot be completed."
            ),
            remediation=(
                "Add a LoggingConfiguration property to the AWS::S3::Bucket "
                "resource pointing to a dedicated logging bucket."
            ),
        ),
        CfnPolicyIDs.S3_BUCKET_BLOCK_PUBLIC_ACCESS: CfnPolicy(
            policy_id=CfnPolicyIDs.S3_BUCKET_BLOCK_PUBLIC_ACCESS,
            title="S3: Block Public Access Settings Must Be Enabled",
            category="S3",
            resource_type="AWS::S3::Bucket",
            severity="HIGH",
            description=(
                "S3 Block Public Access provides an account-level or bucket-level "
                "guardrail that prevents public ACLs and public bucket policies "
                "from taking effect. Without it, a single misconfigured policy "
                "can expose all objects."
            ),
            remediation=(
                "Add a PublicAccessBlockConfiguration property to the "
                "AWS::S3::Bucket resource with all four settings set to true: "
                "BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, "
                "RestrictPublicBuckets."
            ),
        ),
        CfnPolicyIDs.S3_BUCKET_HTTPS_ONLY: CfnPolicy(
            policy_id=CfnPolicyIDs.S3_BUCKET_HTTPS_ONLY,
            title="S3: Bucket Policy Must Enforce HTTPS",
            category="S3",
            resource_type="AWS::S3::BucketPolicy",
            severity="MEDIUM",
            description=(
                "Without a bucket policy that denies requests over plain HTTP "
                "(aws:SecureTransport: false), objects can be accessed and "
                "transferred over unencrypted connections, enabling "
                "eavesdropping and content tampering."
            ),
            remediation=(
                "Add a Deny statement to the bucket policy with Condition "
                "'aws:SecureTransport': 'false' to enforce HTTPS-only access."
            ),
        ),
        CfnPolicyIDs.S3_BUCKET_MFA_DELETE: CfnPolicy(
            policy_id=CfnPolicyIDs.S3_BUCKET_MFA_DELETE,
            title="S3: MFA Delete Should Be Enabled",
            category="S3",
            resource_type="AWS::S3::Bucket",
            severity="LOW",
            description=(
                "MFA Delete requires additional authentication before permanently "
                "deleting an object version or disabling versioning. Without it, "
                "a compromised IAM credential can irreversibly destroy data."
            ),
            remediation=(
                "Enable MFA Delete on the bucket versioning configuration. Note "
                "that MFA Delete can only be enabled via the CLI/SDK using root "
                "credentials, not directly in CloudFormation."
            ),
        ),

        # ── EC2 ───────────────────────────────────────────────────────────────
        CfnPolicyIDs.EC2_SECURITY_GROUP_OPEN_SSH: CfnPolicy(
            policy_id=CfnPolicyIDs.EC2_SECURITY_GROUP_OPEN_SSH,
            title="EC2 Security Group: Port 22 (SSH) Must Not Be Open to the World",
            category="Network Security",
            resource_type="AWS::EC2::SecurityGroup",
            severity="HIGH",
            description=(
                "Allowing inbound SSH access (port 22) from 0.0.0.0/0 or ::/0 "
                "exposes instances to brute-force attacks, credential stuffing, "
                "and exploitation of SSH service vulnerabilities from any source "
                "on the internet."
            ),
            remediation=(
                "Restrict the SSH ingress rule's CidrIp / CidrIpv6 to specific "
                "trusted IP ranges (e.g. VPN exit IPs). For EC2 instances, prefer "
                "AWS Systems Manager Session Manager over SSH to eliminate the "
                "need for inbound port 22 entirely."
            ),
        ),
        CfnPolicyIDs.EC2_SECURITY_GROUP_OPEN_RDP: CfnPolicy(
            policy_id=CfnPolicyIDs.EC2_SECURITY_GROUP_OPEN_RDP,
            title="EC2 Security Group: Port 3389 (RDP) Must Not Be Open to the World",
            category="Network Security",
            resource_type="AWS::EC2::SecurityGroup",
            severity="HIGH",
            description=(
                "Allowing inbound RDP access (port 3389) from 0.0.0.0/0 or ::/0 "
                "exposes Windows instances to brute-force attacks, BlueKeep-style "
                "vulnerabilities, and credential attacks from any source on the "
                "internet."
            ),
            remediation=(
                "Restrict the RDP ingress rule's CidrIp / CidrIpv6 to specific "
                "trusted IP ranges. Use AWS Systems Manager Fleet Manager for "
                "browser-based RDP access without opening port 3389."
            ),
        ),
        CfnPolicyIDs.EC2_SECURITY_GROUP_OPEN_ALL: CfnPolicy(
            policy_id=CfnPolicyIDs.EC2_SECURITY_GROUP_OPEN_ALL,
            title="EC2 Security Group: All Ports Must Not Be Open to the World",
            category="Network Security",
            resource_type="AWS::EC2::SecurityGroup",
            severity="CRITICAL",
            description=(
                "A security group ingress rule with protocol '-1' (all traffic) "
                "or port range 0–65535 with CidrIp 0.0.0.0/0 or ::/0 allows any "
                "internet host to reach all ports on the associated instances, "
                "eliminating network perimeter controls entirely."
            ),
            remediation=(
                "Remove the open-world ingress rule and replace it with specific "
                "port/protocol rules restricted to required source CIDRs or "
                "security group references."
            ),
        ),
        CfnPolicyIDs.EC2_INSTANCE_NO_PUBLIC_IP: CfnPolicy(
            policy_id=CfnPolicyIDs.EC2_INSTANCE_NO_PUBLIC_IP,
            title="EC2: Instances Must Not Have a Public IP Address",
            category="Network Security",
            resource_type="AWS::EC2::Instance",
            severity="HIGH",
            description=(
                "Setting NetworkInterfaces[].AssociatePublicIpAddress: true or "
                "using a public subnet without explicitly disabling public IP "
                "assignment exposes instances directly to the internet, increasing "
                "the attack surface."
            ),
            remediation=(
                "Set AssociatePublicIpAddress to false in the network interface "
                "configuration. Route external traffic through an ALB or NAT "
                "gateway in a public subnet while keeping instances in private "
                "subnets."
            ),
        ),
        CfnPolicyIDs.EC2_INSTANCE_IMDSv2: CfnPolicy(
            policy_id=CfnPolicyIDs.EC2_INSTANCE_IMDSv2,
            title="EC2: IMDSv2 Must Be Required",
            category="Compute Security",
            resource_type="AWS::EC2::Instance / AWS::EC2::LaunchTemplate",
            severity="HIGH",
            description=(
                "The Instance Metadata Service v1 (IMDSv1) is vulnerable to "
                "SSRF attacks that allow unauthorized code or web applications "
                "running on the instance to retrieve IAM credentials and other "
                "sensitive metadata. IMDSv2 enforces session-oriented requests "
                "that are not exploitable via SSRF."
            ),
            remediation=(
                "Set MetadataOptions.HttpTokens to 'required' in the "
                "AWS::EC2::Instance or AWS::EC2::LaunchTemplate resource to "
                "enforce IMDSv2."
            ),
        ),
        CfnPolicyIDs.EC2_EBS_VOLUME_ENCRYPTION: CfnPolicy(
            policy_id=CfnPolicyIDs.EC2_EBS_VOLUME_ENCRYPTION,
            title="EC2: EBS Volumes Must Be Encrypted",
            category="Encryption",
            resource_type="AWS::EC2::Volume / AWS::EC2::Instance",
            severity="HIGH",
            description=(
                "Unencrypted EBS volumes may expose data at rest if the underlying "
                "storage media is not properly secured. Encryption with a KMS key "
                "ensures data is protected and provides audit trails for key usage."
            ),
            remediation=(
                "Set Encrypted: true in AWS::EC2::Volume. For instance root "
                "volumes, set Encrypted: true in the BlockDeviceMappings "
                "EbsBlockDevice property."
            ),
        ),
        CfnPolicyIDs.EC2_INSTANCE_DETAILED_MONITORING: CfnPolicy(
            policy_id=CfnPolicyIDs.EC2_INSTANCE_DETAILED_MONITORING,
            title="EC2: Detailed Monitoring Must Be Enabled",
            category="Logging & Monitoring",
            resource_type="AWS::EC2::Instance",
            severity="LOW",
            description=(
                "Detailed monitoring provides one-minute metric granularity in "
                "CloudWatch, enabling faster detection of anomalous behavior. "
                "Without it, the default five-minute interval delays alerting "
                "on security events."
            ),
            remediation=(
                "Set Monitoring: true in the AWS::EC2::Instance resource."
            ),
        ),

        # ── RDS ───────────────────────────────────────────────────────────────
        CfnPolicyIDs.RDS_ENCRYPTION_AT_REST: CfnPolicy(
            policy_id=CfnPolicyIDs.RDS_ENCRYPTION_AT_REST,
            title="RDS: Storage Encryption Must Be Enabled",
            category="Encryption",
            resource_type="AWS::RDS::DBInstance",
            severity="HIGH",
            description=(
                "Unencrypted RDS instances store database files, logs, and "
                "automated backups in plaintext. If underlying storage is "
                "compromised, data is immediately readable without access controls."
            ),
            remediation=(
                "Set StorageEncrypted: true in the AWS::RDS::DBInstance resource. "
                "Optionally specify a KmsKeyId to use a customer-managed KMS key "
                "for fine-grained access control."
            ),
        ),
        CfnPolicyIDs.RDS_NO_PUBLIC_ACCESS: CfnPolicy(
            policy_id=CfnPolicyIDs.RDS_NO_PUBLIC_ACCESS,
            title="RDS: Database Must Not Be Publicly Accessible",
            category="Network Security",
            resource_type="AWS::RDS::DBInstance",
            severity="CRITICAL",
            description=(
                "Setting PubliclyAccessible: true on an RDS instance assigns a "
                "public DNS endpoint and enables direct internet access to the "
                "database port. This bypasses VPC network controls and exposes "
                "the database to internet-facing attacks."
            ),
            remediation=(
                "Set PubliclyAccessible: false in the AWS::RDS::DBInstance "
                "resource. Place the database in a private subnet and access it "
                "through an application tier or a VPN/Direct Connect connection."
            ),
        ),
        CfnPolicyIDs.RDS_MULTI_AZ: CfnPolicy(
            policy_id=CfnPolicyIDs.RDS_MULTI_AZ,
            title="RDS: Multi-AZ Must Be Enabled for Production Instances",
            category="Resilience",
            resource_type="AWS::RDS::DBInstance",
            severity="MEDIUM",
            description=(
                "Single-AZ RDS instances have no automatic failover capability. "
                "A hardware failure or AZ outage will cause downtime that disrupts "
                "application availability and may result in data loss if the "
                "instance is not recovered promptly."
            ),
            remediation=(
                "Set MultiAZ: true in the AWS::RDS::DBInstance resource for "
                "production workloads."
            ),
        ),
        CfnPolicyIDs.RDS_DELETION_PROTECTION: CfnPolicy(
            policy_id=CfnPolicyIDs.RDS_DELETION_PROTECTION,
            title="RDS: Deletion Protection Must Be Enabled",
            category="Data Protection",
            resource_type="AWS::RDS::DBInstance",
            severity="MEDIUM",
            description=(
                "Without deletion protection, an RDS instance can be deleted "
                "with a single API call by any principal with the "
                "rds:DeleteDBInstance permission. Enabling this setting prevents "
                "accidental or malicious deletion."
            ),
            remediation=(
                "Set DeletionProtection: true in the AWS::RDS::DBInstance "
                "resource."
            ),
        ),
        CfnPolicyIDs.RDS_AUTO_MINOR_VERSION_UPGRADE: CfnPolicy(
            policy_id=CfnPolicyIDs.RDS_AUTO_MINOR_VERSION_UPGRADE,
            title="RDS: Auto Minor Version Upgrade Must Be Enabled",
            category="Patch Management",
            resource_type="AWS::RDS::DBInstance",
            severity="LOW",
            description=(
                "Disabling automatic minor version upgrades leaves the database "
                "engine unpatched against known CVEs. Minor version upgrades "
                "include critical security patches that fix vulnerabilities in "
                "the underlying database engine."
            ),
            remediation=(
                "Set AutoMinorVersionUpgrade: true (the default) in the "
                "AWS::RDS::DBInstance resource. Schedule the maintenance window "
                "during off-peak hours to minimise disruption."
            ),
        ),
        CfnPolicyIDs.RDS_BACKUP_RETENTION: CfnPolicy(
            policy_id=CfnPolicyIDs.RDS_BACKUP_RETENTION,
            title="RDS: Backup Retention Must Be >= 7 Days",
            category="Data Protection",
            resource_type="AWS::RDS::DBInstance",
            severity="MEDIUM",
            description=(
                "A BackupRetentionPeriod of fewer than 7 days limits the recovery "
                "point objective (RPO) window and may violate compliance requirements "
                "(PCI-DSS, HIPAA). Setting it to 0 disables automated backups "
                "entirely, making point-in-time recovery impossible."
            ),
            remediation=(
                "Set BackupRetentionPeriod to at least 7 in the "
                "AWS::RDS::DBInstance resource."
            ),
        ),

        # ── KMS ───────────────────────────────────────────────────────────────
        CfnPolicyIDs.KMS_KEY_ROTATION: CfnPolicy(
            policy_id=CfnPolicyIDs.KMS_KEY_ROTATION,
            title="KMS: Annual Key Rotation Must Be Enabled",
            category="Cryptography",
            resource_type="AWS::KMS::Key",
            severity="MEDIUM",
            description=(
                "Disabling automatic key rotation for a KMS CMK means the same "
                "key material is used indefinitely. If the key material is ever "
                "exposed or compromised, all data it protects is at risk without "
                "a rotation event to limit the exposure window."
            ),
            remediation=(
                "Set EnableKeyRotation: true in the AWS::KMS::Key resource to "
                "enable annual automatic rotation of key material."
            ),
        ),

        # ── CloudTrail ────────────────────────────────────────────────────────
        CfnPolicyIDs.CLOUDTRAIL_ENABLED: CfnPolicy(
            policy_id=CfnPolicyIDs.CLOUDTRAIL_ENABLED,
            title="CloudTrail: Trail Must Be Enabled",
            category="Logging & Monitoring",
            resource_type="AWS::CloudTrail::Trail",
            severity="HIGH",
            description=(
                "CloudTrail provides the audit log of all AWS API calls in the "
                "account. Without an enabled trail, security investigations, "
                "compliance audits, and incident response are severely impaired."
            ),
            remediation=(
                "Set IsLogging: true in the AWS::CloudTrail::Trail resource."
            ),
        ),
        CfnPolicyIDs.CLOUDTRAIL_ENCRYPTION: CfnPolicy(
            policy_id=CfnPolicyIDs.CLOUDTRAIL_ENCRYPTION,
            title="CloudTrail: Log Files Must Be Encrypted with KMS",
            category="Logging & Monitoring",
            resource_type="AWS::CloudTrail::Trail",
            severity="MEDIUM",
            description=(
                "CloudTrail log files written to S3 without KMS encryption "
                "may be readable by any principal with S3 read access on the "
                "logging bucket. Encrypting with a KMS CMK enforces key-level "
                "access controls on who can read audit logs."
            ),
            remediation=(
                "Set KMSKeyId to a KMS CMK ARN in the "
                "AWS::CloudTrail::Trail resource."
            ),
        ),
        CfnPolicyIDs.CLOUDTRAIL_LOG_FILE_VALIDATION: CfnPolicy(
            policy_id=CfnPolicyIDs.CLOUDTRAIL_LOG_FILE_VALIDATION,
            title="CloudTrail: Log File Integrity Validation Must Be Enabled",
            category="Logging & Monitoring",
            resource_type="AWS::CloudTrail::Trail",
            severity="MEDIUM",
            description=(
                "Without log file integrity validation, CloudTrail log files "
                "can be silently deleted or tampered with after they are written. "
                "This undermines the evidentiary value of logs in forensic "
                "investigations."
            ),
            remediation=(
                "Set EnableLogFileValidation: true in the "
                "AWS::CloudTrail::Trail resource."
            ),
        ),
        CfnPolicyIDs.CLOUDTRAIL_MULTI_REGION: CfnPolicy(
            policy_id=CfnPolicyIDs.CLOUDTRAIL_MULTI_REGION,
            title="CloudTrail: Multi-Region Trail Must Be Enabled",
            category="Logging & Monitoring",
            resource_type="AWS::CloudTrail::Trail",
            severity="MEDIUM",
            description=(
                "A single-region CloudTrail trail does not capture API calls "
                "made in other AWS regions. An attacker operating in a region "
                "without a trail can perform actions without any audit record."
            ),
            remediation=(
                "Set IsMultiRegionTrail: true in the AWS::CloudTrail::Trail "
                "resource to capture events from all regions."
            ),
        ),

        # ── Lambda ────────────────────────────────────────────────────────────
        CfnPolicyIDs.LAMBDA_FUNCTION_POLICY_WILDCARD: CfnPolicy(
            policy_id=CfnPolicyIDs.LAMBDA_FUNCTION_POLICY_WILDCARD,
            title="Lambda: Resource-Based Policy Must Not Grant Invoke to All Principals",
            category="IAM",
            resource_type="AWS::Lambda::Permission",
            severity="HIGH",
            description=(
                "Granting lambda:InvokeFunction to Principal: '*' in a Lambda "
                "resource-based policy (AWS::Lambda::Permission) allows any AWS "
                "principal or anonymous caller to trigger the function. This can "
                "lead to unauthorised code execution and associated cost abuse."
            ),
            remediation=(
                "Restrict the Principal to a specific service ARN or AWS account "
                "ID. Add SourceArn and SourceAccount conditions to prevent "
                "confused deputy attacks."
            ),
        ),
        CfnPolicyIDs.LAMBDA_TRACING_ENABLED: CfnPolicy(
            policy_id=CfnPolicyIDs.LAMBDA_TRACING_ENABLED,
            title="Lambda: X-Ray Tracing Must Be Enabled",
            category="Logging & Monitoring",
            resource_type="AWS::Lambda::Function",
            severity="LOW",
            description=(
                "Enabling X-Ray active tracing on Lambda functions provides "
                "distributed tracing data that helps detect anomalous invocation "
                "patterns and aids in security incident investigations."
            ),
            remediation=(
                "Set TracingConfig.Mode to 'Active' in the "
                "AWS::Lambda::Function resource."
            ),
        ),

        # ── ELB / ALB ─────────────────────────────────────────────────────────
        CfnPolicyIDs.ELB_ACCESS_LOGS_ENABLED: CfnPolicy(
            policy_id=CfnPolicyIDs.ELB_ACCESS_LOGS_ENABLED,
            title="ELB/ALB: Access Logging Must Be Enabled",
            category="Logging & Monitoring",
            resource_type="AWS::ElasticLoadBalancingV2::LoadBalancer",
            severity="MEDIUM",
            description=(
                "Load balancer access logs record detailed information about "
                "every request, including client IP, request path, and response "
                "code. Without this data, detecting and investigating attacks "
                "such as DDoS, web scraping, or targeted exploitation is "
                "significantly impaired."
            ),
            remediation=(
                "Add a LoadBalancerAttribute with Key: 'access_logs.s3.enabled' "
                "and Value: 'true', and configure the S3 bucket destination in "
                "the AWS::ElasticLoadBalancingV2::LoadBalancer resource."
            ),
        ),
        CfnPolicyIDs.ELB_HTTPS_LISTENER: CfnPolicy(
            policy_id=CfnPolicyIDs.ELB_HTTPS_LISTENER,
            title="ELB/ALB: Listeners Must Use HTTPS or TLS",
            category="Network Security",
            resource_type="AWS::ElasticLoadBalancingV2::Listener",
            severity="HIGH",
            description=(
                "An ALB or NLB listener configured with protocol HTTP or TCP "
                "transmits data between clients and the load balancer in "
                "cleartext. This enables eavesdropping and content injection on "
                "traffic traversing untrusted networks."
            ),
            remediation=(
                "Change the Protocol to HTTPS (for ALBs) or TLS (for NLBs) in "
                "the AWS::ElasticLoadBalancingV2::Listener resource and attach a "
                "valid SSL certificate via the Certificates property."
            ),
        ),
        CfnPolicyIDs.ELBV2_DROP_HTTP_HEADERS: CfnPolicy(
            policy_id=CfnPolicyIDs.ELBV2_DROP_HTTP_HEADERS,
            title="ALB: HTTP Header Dropping Must Be Enabled",
            category="Network Security",
            resource_type="AWS::ElasticLoadBalancingV2::LoadBalancer",
            severity="MEDIUM",
            description=(
                "Application Load Balancers can drop invalid HTTP headers that "
                "are forwarded to backend targets. Headers with invalid characters "
                "can be used for HTTP desync / request smuggling attacks that "
                "bypass security controls."
            ),
            remediation=(
                "Add a LoadBalancerAttribute with Key: "
                "'routing.http.drop_invalid_header_fields.enabled' and "
                "Value: 'true' in the AWS::ElasticLoadBalancingV2::LoadBalancer "
                "resource."
            ),
        ),

        # ── CloudFront ────────────────────────────────────────────────────────
        CfnPolicyIDs.CF_DISTRIBUTION_HTTPS_ONLY: CfnPolicy(
            policy_id=CfnPolicyIDs.CF_DISTRIBUTION_HTTPS_ONLY,
            title="CloudFront: Distribution Must Redirect HTTP to HTTPS",
            category="Network Security",
            resource_type="AWS::CloudFront::Distribution",
            severity="MEDIUM",
            description=(
                "A CloudFront distribution that allows plain HTTP requests "
                "transmits content and cookies over unencrypted connections. "
                "ViewerProtocolPolicy should enforce HTTPS to prevent "
                "eavesdropping and session hijacking."
            ),
            remediation=(
                "Set ViewerProtocolPolicy to 'https-only' or "
                "'redirect-to-https' in all CacheBehaviors and the "
                "DefaultCacheBehavior of the AWS::CloudFront::Distribution "
                "resource."
            ),
        ),
        CfnPolicyIDs.CF_DISTRIBUTION_LOGGING: CfnPolicy(
            policy_id=CfnPolicyIDs.CF_DISTRIBUTION_LOGGING,
            title="CloudFront: Access Logging Must Be Enabled",
            category="Logging & Monitoring",
            resource_type="AWS::CloudFront::Distribution",
            severity="LOW",
            description=(
                "CloudFront access logs provide visibility into viewer request "
                "details including IP addresses, URIs, and status codes. Without "
                "logging, detecting content delivery attacks or data exfiltration "
                "via CDN is not possible."
            ),
            remediation=(
                "Configure the Logging property in the DistributionConfig to "
                "point to an S3 bucket with proper permissions."
            ),
        ),
        CfnPolicyIDs.CF_DISTRIBUTION_ORIGIN_HTTPS: CfnPolicy(
            policy_id=CfnPolicyIDs.CF_DISTRIBUTION_ORIGIN_HTTPS,
            title="CloudFront: Origin Protocol Policy Must Enforce HTTPS",
            category="Network Security",
            resource_type="AWS::CloudFront::Distribution",
            severity="MEDIUM",
            description=(
                "A CloudFront distribution that connects to its origin over "
                "HTTP (OriginProtocolPolicy: http-only or match-viewer with HTTP "
                "allowed) transmits data between CloudFront and the origin in "
                "cleartext within AWS infrastructure, risking data leakage on "
                "the origin fetch path."
            ),
            remediation=(
                "Set OriginProtocolPolicy to 'https-only' in the CustomOriginConfig "
                "of the AWS::CloudFront::Distribution resource."
            ),
        ),

        # ── SQS ───────────────────────────────────────────────────────────────
        CfnPolicyIDs.SQS_QUEUE_ENCRYPTION: CfnPolicy(
            policy_id=CfnPolicyIDs.SQS_QUEUE_ENCRYPTION,
            title="SQS: Queue Server-Side Encryption Must Be Enabled",
            category="Encryption",
            resource_type="AWS::SQS::Queue",
            severity="MEDIUM",
            description=(
                "SQS queues without server-side encryption store message bodies "
                "in plaintext. Sensitive data in queue messages is exposed if "
                "queue access controls are misconfigured or an insider threat "
                "accesses the underlying storage."
            ),
            remediation=(
                "Set KmsMasterKeyId to 'alias/aws/sqs' or a CMK ARN in the "
                "AWS::SQS::Queue resource to enable SSE."
            ),
        ),

        # ── SNS ───────────────────────────────────────────────────────────────
        CfnPolicyIDs.SNS_TOPIC_ENCRYPTION: CfnPolicy(
            policy_id=CfnPolicyIDs.SNS_TOPIC_ENCRYPTION,
            title="SNS: Topic Server-Side Encryption Must Be Enabled",
            category="Encryption",
            resource_type="AWS::SNS::Topic",
            severity="MEDIUM",
            description=(
                "SNS topics without server-side encryption store message "
                "payloads in plaintext at rest. If the SNS service is used to "
                "transport sensitive data (PII, financial records), encryption "
                "is required for regulatory compliance."
            ),
            remediation=(
                "Set KmsMasterKeyId to 'alias/aws/sns' or a CMK ARN in the "
                "AWS::SNS::Topic resource to enable SSE."
            ),
        ),

        # ── Secrets Management ────────────────────────────────────────────────
        CfnPolicyIDs.CFN_NO_HARDCODED_CREDENTIALS: CfnPolicy(
            policy_id=CfnPolicyIDs.CFN_NO_HARDCODED_CREDENTIALS,
            title="CloudFormation: No Hardcoded Credentials or Secrets",
            category="Secrets Management",
            resource_type="All resources",
            severity="CRITICAL",
            description=(
                "Hardcoded passwords, API keys, access key IDs, private keys, "
                "or connection strings in CloudFormation templates are committed "
                "to source control and stored in CloudFormation stack outputs in "
                "plaintext. Any principal with CloudFormation read access or "
                "repository access can retrieve these secrets."
            ),
            remediation=(
                "Remove all plaintext credentials from the template. Use "
                "AWS Secrets Manager (secretsmanager:SecretValue dynamic "
                "reference) or AWS Systems Manager Parameter Store (SSM secure "
                "string) to inject secrets at deployment time via dynamic "
                "references: '{{resolve:secretsmanager:...}}'."
            ),
        ),

        # ── EKS ───────────────────────────────────────────────────────────────
        CfnPolicyIDs.EKS_CLUSTER_PRIVATE_ENDPOINT: CfnPolicy(
            policy_id=CfnPolicyIDs.EKS_CLUSTER_PRIVATE_ENDPOINT,
            title="EKS: Cluster API Endpoint Should Be Private",
            category="Network Security",
            resource_type="AWS::EKS::Cluster",
            severity="HIGH",
            description=(
                "Enabling the public Kubernetes API endpoint exposes the cluster "
                "control plane to the internet. If Kubernetes RBAC is misconfigured "
                "or a vulnerability exists in the API server, the cluster is "
                "directly reachable by attackers."
            ),
            remediation=(
                "Set ResourcesVpcConfig.EndpointPublicAccess: false and "
                "EndpointPrivateAccess: true in the AWS::EKS::Cluster resource. "
                "Access the API server through a VPN or AWS Direct Connect."
            ),
        ),
        CfnPolicyIDs.EKS_CLUSTER_LOGGING: CfnPolicy(
            policy_id=CfnPolicyIDs.EKS_CLUSTER_LOGGING,
            title="EKS: Control Plane Logging Must Be Enabled",
            category="Logging & Monitoring",
            resource_type="AWS::EKS::Cluster",
            severity="MEDIUM",
            description=(
                "EKS control plane logs (audit, authenticator, scheduler, "
                "controller-manager, api) capture Kubernetes API activity. "
                "Without these logs, detecting privilege escalation, lateral "
                "movement, or unauthorised resource creation is not possible."
            ),
            remediation=(
                "Configure Logging.ClusterLogging with Enabled: true types "
                "for at least 'api', 'audit', and 'authenticator' in the "
                "AWS::EKS::Cluster resource."
            ),
        ),

        # ── DynamoDB ──────────────────────────────────────────────────────────
        CfnPolicyIDs.DYNAMODB_PITR_ENABLED: CfnPolicy(
            policy_id=CfnPolicyIDs.DYNAMODB_PITR_ENABLED,
            title="DynamoDB: Point-in-Time Recovery Must Be Enabled",
            category="Data Protection",
            resource_type="AWS::DynamoDB::Table",
            severity="MEDIUM",
            description=(
                "Without point-in-time recovery (PITR), accidental table "
                "deletions or corrupted data cannot be restored to a previous "
                "consistent state. PITR provides continuous backups for the "
                "last 35 days."
            ),
            remediation=(
                "Set PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled: "
                "true in the AWS::DynamoDB::Table resource."
            ),
        ),
        CfnPolicyIDs.DYNAMODB_ENCRYPTION: CfnPolicy(
            policy_id=CfnPolicyIDs.DYNAMODB_ENCRYPTION,
            title="DynamoDB: Table Must Use Customer-Managed KMS Key",
            category="Encryption",
            resource_type="AWS::DynamoDB::Table",
            severity="MEDIUM",
            description=(
                "DynamoDB tables encrypted with the default AWS-owned key (SSE_DEFAULT) "
                "do not provide customer control over the key lifecycle or access "
                "policy. Using a customer-managed key (SSE_KMS) allows key rotation, "
                "usage auditing, and cross-account access controls."
            ),
            remediation=(
                "Set SSESpecification.SSEEnabled: true and SSEType: 'KMS' with "
                "a KMSMasterKeyId in the AWS::DynamoDB::Table resource."
            ),
        ),

        # ── ElastiCache ───────────────────────────────────────────────────────
        CfnPolicyIDs.ELASTICACHE_ENCRYPTION_AT_REST: CfnPolicy(
            policy_id=CfnPolicyIDs.ELASTICACHE_ENCRYPTION_AT_REST,
            title="ElastiCache: Encryption at Rest Must Be Enabled",
            category="Encryption",
            resource_type="AWS::ElastiCache::ReplicationGroup",
            severity="HIGH",
            description=(
                "ElastiCache (Redis) data stored without at-rest encryption is "
                "vulnerable to data exposure if the cache nodes are accessed "
                "through other means or if snapshots are copied to a less "
                "secure location."
            ),
            remediation=(
                "Set AtRestEncryptionEnabled: true in the "
                "AWS::ElastiCache::ReplicationGroup resource."
            ),
        ),
        CfnPolicyIDs.ELASTICACHE_ENCRYPTION_IN_TRANSIT: CfnPolicy(
            policy_id=CfnPolicyIDs.ELASTICACHE_ENCRYPTION_IN_TRANSIT,
            title="ElastiCache: Encryption in Transit Must Be Enabled",
            category="Encryption",
            resource_type="AWS::ElastiCache::ReplicationGroup",
            severity="HIGH",
            description=(
                "ElastiCache (Redis) without in-transit encryption transmits "
                "all data between clients and cache nodes in cleartext. In shared "
                "VPC environments or if an attacker achieves network-level access, "
                "all cache traffic can be intercepted."
            ),
            remediation=(
                "Set TransitEncryptionEnabled: true in the "
                "AWS::ElastiCache::ReplicationGroup resource."
            ),
        ),
    }

    @classmethod
    def lookup(cls, policy_id: str) -> Optional[CfnPolicy]:
        """Return the CfnPolicy for *policy_id*, or None if not found."""
        return cls.METADATA.get(policy_id)
