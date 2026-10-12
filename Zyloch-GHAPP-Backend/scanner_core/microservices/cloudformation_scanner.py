from __future__ import annotations

import json
import os
import re
import sys
import time
from typing import Any, Dict, Generator, List, Optional, Tuple

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner_core.base_scanner import (
    BaseScanner,
    ScanFinding,
    ScanRequest,
    ScanResponse,
    ScanResult,
    ScanSeverity,
    ScanStatus,
)
from scanner_core.helpers.scoring_engine import OPABasedScoreAdapter
from scanner_core.logging_config import get_scanner_logger
from scanner_core.constants.cfn_policy_ids import CfnPolicyIDs, CfnPolicyMetadata

logger = get_scanner_logger()

# ── Severity map ───────────────────────────────────────────────────────────────
_SEVERITY_MAP: Dict[str, ScanSeverity] = {
    "CRITICAL": ScanSeverity.CRITICAL,
    "HIGH":     ScanSeverity.HIGH,
    "MEDIUM":   ScanSeverity.MEDIUM,
    "LOW":      ScanSeverity.LOW,
    "INFO":     ScanSeverity.INFO,
}

# ── Helpers ────────────────────────────────────────────────────────────────────

def _prop(resource_props: dict, *keys: str, default: Any = None) -> Any:
    """Walk a nested path inside a CFN resource Properties dict."""
    val: Any = resource_props
    for k in keys:
        if not isinstance(val, dict):
            return default
        val = val.get(k, default)
        if val is None:
            return default
    return val


def _is_false(val: Any) -> bool:
    if isinstance(val, bool):
        return not val
    if isinstance(val, str):
        return val.lower() in ("false", "no", "0")
    return val == 0


def _is_true(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ("true", "yes", "1")
    return val == 1


def _open_world_cidr(cidr: Any) -> bool:
    """Return True if a CIDR represents unrestricted internet access."""
    if not isinstance(cidr, str):
        return False
    return cidr.strip() in ("0.0.0.0/0", "::/0")


def _has_wildcard_action(statements: Any) -> bool:
    """Return True if any statement grants Action '*'."""
    if not isinstance(statements, list):
        return False
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        effect = stmt.get("Effect", "Allow")
        if effect != "Allow":
            continue
        action = stmt.get("Action", [])
        if action == "*" or (isinstance(action, list) and "*" in action):
            return True
    return False


def _has_wildcard_resource(statements: Any) -> bool:
    """Return True if any Allow statement has Resource '*'."""
    if not isinstance(statements, list):
        return False
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect", "Allow") != "Allow":
            continue
        resource = stmt.get("Resource", [])
        if resource == "*" or (isinstance(resource, list) and "*" in resource):
            return True
    return False


def _principal_is_world(principal: Any) -> bool:
    """Return True if Principal is '*' or contains '*'."""
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for v in principal.values():
            if v == "*" or (isinstance(v, list) and "*" in v):
                return True
    if isinstance(principal, list) and "*" in principal:
        return True
    return False


def _public_allow_without_condition(statements: Any) -> bool:
    """
    Return True if any Allow statement has Principal '*' without a restricting
    Condition (e.g. aws:SecureTransport or aws:PrincipalOrgID).
    """
    if not isinstance(statements, list):
        return False
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect", "Allow") != "Allow":
            continue
        principal = stmt.get("Principal", None)
        if principal is None:
            continue
        if _principal_is_world(principal):
            # If there is no condition at all, this is an unrestricted grant.
            if not stmt.get("Condition"):
                return True
    return False


# ── Credential detection ───────────────────────────────────────────────────────
_CFN_DYNAMIC_REF_RE = re.compile(
    r"\{\{resolve:(ssm-secure|secretsmanager):", re.IGNORECASE
)
_CREDENTIAL_KEY_PATTERNS = re.compile(
    r"(password|passwd|secret|apikey|api_key|access_key|private_key|token|credentials)",
    re.IGNORECASE,
)
# Regex that recognises likely secret *values* — high-entropy or known formats.
_SECRET_VALUE_PATTERNS = (
    re.compile(r"(?i)^[A-Za-z0-9/+=]{20,}$"),         # Base64 / AWS key material
    re.compile(r"(?i)AKIA[0-9A-Z]{16}"),               # AWS access key ID
    re.compile(r"(?i)[0-9a-f]{32,}"),                  # Hex secrets / tokens
)


def _looks_like_secret_value(val: str) -> bool:
    """Heuristically determine whether *val* looks like a raw secret."""
    if not val or len(val) < 8:
        return False
    # Dynamic references are safe — they are resolved at deploy time.
    if _CFN_DYNAMIC_REF_RE.search(val):
        return False
    # Common placeholder patterns
    if val.lower() in ("changeme", "placeholder", "example", "todo", "yourpassword"):
        return False
    for pattern in _SECRET_VALUE_PATTERNS:
        if pattern.search(val):
            return True
    return False


def _scan_for_credentials(
    obj: Any, path: str, findings_out: List[Tuple[str, str]]
) -> None:
    """
    Recursively walk *obj* (a parsed CFN template fragment) looking for
    parameter keys whose names suggest they hold credentials and whose values
    look like raw secrets.  Appends (path, evidence) tuples to *findings_out*.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_path = f"{path}.{k}" if path else k
            if isinstance(v, str) and _CREDENTIAL_KEY_PATTERNS.search(k):
                if _looks_like_secret_value(v):
                    findings_out.append((full_path, f"{k}: <redacted>"))
            _scan_for_credentials(v, full_path, findings_out)
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            _scan_for_credentials(item, f"{path}[{idx}]", findings_out)


# ── CFN-aware YAML loader ─────────────────────────────────────────────────────
# CloudFormation templates use YAML intrinsic function tags (!Ref, !Sub,
# !GetAtt, !Join, etc.) that are not understood by yaml.SafeLoader.  We
# register constructors for every known CFN tag so that tag values are
# returned as plain Python scalars / lists / dicts and the rest of the
# parsing continues normally.

_CFN_INTRINSIC_TAGS: Tuple[str, ...] = (
    "!And", "!Base64", "!Cidr", "!Condition", "!Equals",
    "!FindInMap", "!GetAtt", "!GetAZs", "!If", "!ImportValue",
    "!Join", "!Length", "!Not", "!Or", "!Ref", "!Select",
    "!Split", "!Sub", "!Transform", "!ValueOf", "!ValueOfAll",
)


def _cfn_tag_constructor(loader: yaml.SafeLoader, node: yaml.Node) -> Any:
    """Return the underlying node value, stripping the CFN-specific tag."""
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    return None


class _CfnSafeLoader(yaml.SafeLoader):
    """
    yaml.SafeLoader extended with constructors for all CloudFormation
    intrinsic function tags.  Using this loader allows parsing CFN YAML
    templates that contain !Ref, !Sub, !GetAtt, etc. without errors.
    """


for _tag in _CFN_INTRINSIC_TAGS:
    _CfnSafeLoader.add_constructor(_tag, _cfn_tag_constructor)


# ── CFN template loading ───────────────────────────────────────────────────────

def _load_template(
    file_path: str, *, _for_detection: bool = False
) -> Optional[Dict[str, Any]]:
    """
    Parse a CloudFormation template file (JSON or YAML).
    Returns the parsed dict or None on failure.

    *_for_detection* — when True the function is being called during the
    file-discovery walk (``_is_cfn_template``).  Parse errors in that context
    are expected for non-CFN YAML files and are logged at DEBUG level to
    avoid flooding the log with noise from Ansible playbooks, K8s charts, etc.
    When False (scanning a confirmed CFN template) errors are logged at WARNING.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            content = fh.read()
    except OSError as exc:
        logger.warning(f"[CFN] Cannot read {file_path}: {exc}")
        return None

    # ── 1. Try strict JSON first ───────────────────────────────────────────────
    try:
        return json.loads(content)
    except (json.JSONDecodeError, ValueError):
        pass

    # ── 2. Try CFN-aware YAML loader ──────────────────────────────────────────
    # Use load_all so that multi-document YAML files (e.g. Helm charts with
    # '---' separators) don't raise an error — we simply take the first
    # document that parses as a dict.
    log_parse_err = logger.debug if _for_detection else logger.warning
    try:
        for doc in yaml.load_all(content, Loader=_CfnSafeLoader):
            if isinstance(doc, dict):
                return doc
    except yaml.YAMLError as exc:
        log_parse_err(f"[CFN] YAML parse error in {file_path}: {exc}")

    return None


def _is_cfn_template(file_path: str) -> bool:
    """
    Determine whether a file is a CloudFormation template.

    Detection strategy:
    1. File extension must be .json, .yaml, or .yml.
    2. Parsed top-level dict must contain either:
       a. A 'AWSTemplateFormatVersion' key, or
       b. A 'Resources' key whose value is a non-empty dict containing at least
          one sub-key with a 'Type' sub-key (the canonical CFN resource shape).
    """
    lower = file_path.lower()
    if not (lower.endswith(".json") or lower.endswith(".yaml") or lower.endswith(".yml")):
        return False

    doc = _load_template(file_path, _for_detection=True)
    if not isinstance(doc, dict):
        return False

    if "AWSTemplateFormatVersion" in doc:
        return True

    resources = doc.get("Resources")
    if isinstance(resources, dict) and resources:
        # Accept the file if at least one resource has a 'Type' key
        for v in resources.values():
            if isinstance(v, dict) and "Type" in v:
                return True

    return False


def _iter_resources(
    template: Dict[str, Any]
) -> Generator[Tuple[str, str, Dict[str, Any]], None, None]:
    """
    Yield (logical_id, resource_type, properties_dict) for every resource.
    """
    resources = template.get("Resources", {})
    if not isinstance(resources, dict):
        return
    for logical_id, resource_def in resources.items():
        if not isinstance(resource_def, dict):
            continue
        rtype = resource_def.get("Type", "")
        props = resource_def.get("Properties", {})
        if not isinstance(props, dict):
            props = {}
        yield logical_id, rtype, props


# ── Per-resource check functions ───────────────────────────────────────────────

def _check_iam_no_inline_policy(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype not in ("AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group"):
        return None
    if props.get("Policies"):
        return "Inline 'Policies' property is present"
    return None


def _check_iam_role_wildcard_action(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::IAM::Role":
        return None
    for policy in props.get("Policies", []):
        doc = policy.get("PolicyDocument", {})
        if _has_wildcard_action(doc.get("Statement", [])):
            return f"Inline policy '{policy.get('PolicyName', '')}' uses Action: '*'"
    return None


def _check_iam_role_wildcard_resource(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::IAM::Role":
        return None
    for policy in props.get("Policies", []):
        doc = policy.get("PolicyDocument", {})
        if _has_wildcard_resource(doc.get("Statement", [])):
            return f"Inline policy '{policy.get('PolicyName', '')}' uses Resource: '*'"
    return None


def _check_iam_managed_policy_wildcard_action(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::IAM::ManagedPolicy":
        return None
    doc = props.get("PolicyDocument", {})
    if _has_wildcard_action(doc.get("Statement", [])):
        return "ManagedPolicy contains Action: '*'"
    return None


def _check_iam_managed_policy_wildcard_resource(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::IAM::ManagedPolicy":
        return None
    doc = props.get("PolicyDocument", {})
    if _has_wildcard_resource(doc.get("Statement", [])):
        return "ManagedPolicy contains Resource: '*'"
    return None


def _check_iam_user_attached_policies(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::IAM::User":
        return None
    if props.get("ManagedPolicyArns") or props.get("Policies"):
        return "Policies attached directly to IAM user"
    return None


def _check_iam_role_assume_all(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::IAM::Role":
        return None
    assume_doc = props.get("AssumeRolePolicyDocument", {})
    for stmt in assume_doc.get("Statement", []):
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect", "Allow") == "Allow":
            if _principal_is_world(stmt.get("Principal", "")):
                return "AssumeRolePolicyDocument has Principal: '*'"
    return None


def _check_iam_access_key(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype == "AWS::IAM::AccessKey":
        return (
            "AWS::IAM::AccessKey resource provisions long-lived IAM credentials. "
            "Use IAM Roles or OIDC federation instead."
        )
    return None


def _check_iam_password_min_length(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::IAM::AccountPasswordPolicy":
        return None
    min_len = props.get("MinimumPasswordLength", 6)
    try:
        if int(min_len) < 14:
            return f"MinimumPasswordLength is {min_len} (must be >= 14)"
    except (TypeError, ValueError):
        pass
    return None


def _check_iam_password_reuse(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::IAM::AccountPasswordPolicy":
        return None
    reuse = props.get("PasswordReusePrevention")
    if reuse is None:
        return "PasswordReusePrevention not configured"
    try:
        if int(reuse) < 24:
            return f"PasswordReusePrevention is {reuse} (recommended >= 24)"
    except (TypeError, ValueError):
        pass
    return None


# ── S3 checks ──────────────────────────────────────────────────────────────────
_S3_PUBLIC_ACLS = frozenset({
    "PublicRead", "PublicReadWrite", "AuthenticatedRead",
    "BucketOwnerRead",  # technically not public, but non-owner read access
})


def _check_s3_public_acl(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::S3::Bucket":
        return None
    acl = props.get("AccessControl", "Private")
    if isinstance(acl, str) and acl in _S3_PUBLIC_ACLS:
        return f"AccessControl: {acl!r} grants public read access"
    return None


def _check_s3_public_policy(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::S3::BucketPolicy":
        return None
    doc = props.get("PolicyDocument", {})
    stmts = doc.get("Statement", []) if isinstance(doc, dict) else []
    if _public_allow_without_condition(stmts):
        return "BucketPolicy grants Allow to Principal: '*' without conditions"
    return None


def _check_s3_versioning(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::S3::Bucket":
        return None
    vc = props.get("VersioningConfiguration", {})
    if not isinstance(vc, dict) or vc.get("Status", "Suspended") != "Enabled":
        return "VersioningConfiguration.Status is not 'Enabled'"
    return None


def _check_s3_encryption(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::S3::Bucket":
        return None
    enc = props.get("BucketEncryption")
    if not enc:
        return "BucketEncryption is not configured"
    rules = _prop(enc, "ServerSideEncryptionConfiguration") if isinstance(enc, dict) else None
    if not rules:
        return "BucketEncryption.ServerSideEncryptionConfiguration is empty"
    return None


def _check_s3_logging(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::S3::Bucket":
        return None
    if not props.get("LoggingConfiguration"):
        return "LoggingConfiguration is not configured"
    return None


def _check_s3_block_public_access(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::S3::Bucket":
        return None
    bpa = props.get("PublicAccessBlockConfiguration")
    if not isinstance(bpa, dict):
        return "PublicAccessBlockConfiguration is not configured"
    required_keys = (
        "BlockPublicAcls", "BlockPublicPolicy",
        "IgnorePublicAcls", "RestrictPublicBuckets",
    )
    disabled = [k for k in required_keys if not _is_true(bpa.get(k, False))]
    if disabled:
        return f"PublicAccessBlockConfiguration: {', '.join(disabled)} not set to true"
    return None


def _check_s3_https_only(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    """Check that the bucket policy has a Deny on non-HTTPS requests."""
    if rtype != "AWS::S3::BucketPolicy":
        return None
    doc = props.get("PolicyDocument", {})
    stmts = doc.get("Statement", []) if isinstance(doc, dict) else []
    for stmt in stmts:
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect") == "Deny":
            cond = stmt.get("Condition", {})
            if isinstance(cond, dict):
                # Look for Condition: {Bool: {"aws:SecureTransport": "false"}}
                for op_val in cond.values():
                    if isinstance(op_val, dict):
                        st = op_val.get("aws:SecureTransport")
                        if st in (False, "false", "False"):
                            return None
    return "No Deny statement for aws:SecureTransport: false (HTTPS not enforced)"


def _check_s3_mfa_delete(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::S3::Bucket":
        return None
    vc = props.get("VersioningConfiguration", {})
    if not isinstance(vc, dict):
        return None  # Versioning not configured — separate check handles that.
    if vc.get("Status") == "Enabled":
        # MFA Delete can only be enabled via CLI with root credentials, so we
        # flag a LOW finding if versioning is on but MFADelete key is absent/disabled.
        mfa = vc.get("MFADelete", "Disabled")
        if mfa != "Enabled":
            return "VersioningConfiguration.MFADelete is not 'Enabled'"
    return None


# ── EC2 / Security Group checks ────────────────────────────────────────────────

def _check_sg_open_ssh(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::EC2::SecurityGroup":
        return None
    for rule in props.get("SecurityGroupIngress", []):
        if not isinstance(rule, dict):
            continue
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 65535)
        cidr = rule.get("CidrIp", "") or rule.get("CidrIpv6", "")
        try:
            if (
                _open_world_cidr(cidr)
                and int(from_port) <= 22 <= int(to_port)
            ):
                return f"Port 22 (SSH) is open to {cidr}"
        except (TypeError, ValueError):
            pass
    return None


def _check_sg_open_rdp(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::EC2::SecurityGroup":
        return None
    for rule in props.get("SecurityGroupIngress", []):
        if not isinstance(rule, dict):
            continue
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 65535)
        cidr = rule.get("CidrIp", "") or rule.get("CidrIpv6", "")
        try:
            if (
                _open_world_cidr(cidr)
                and int(from_port) <= 3389 <= int(to_port)
            ):
                return f"Port 3389 (RDP) is open to {cidr}"
        except (TypeError, ValueError):
            pass
    return None


def _check_sg_open_all(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::EC2::SecurityGroup":
        return None
    for rule in props.get("SecurityGroupIngress", []):
        if not isinstance(rule, dict):
            continue
        cidr = rule.get("CidrIp", "") or rule.get("CidrIpv6", "")
        if not _open_world_cidr(cidr):
            continue
        protocol = str(rule.get("IpProtocol", ""))
        if protocol in ("-1", "all"):
            return f"All traffic is open to {cidr} (IpProtocol: {protocol})"
        from_port = rule.get("FromPort", -1)
        to_port = rule.get("ToPort", -1)
        try:
            if int(from_port) == 0 and int(to_port) == 65535:
                return f"All ports (0-65535) are open to {cidr}"
        except (TypeError, ValueError):
            pass
    return None


def _check_ec2_public_ip(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::EC2::Instance":
        return None
    for iface in props.get("NetworkInterfaces", []):
        if isinstance(iface, dict) and _is_true(iface.get("AssociatePublicIpAddress", False)):
            return "NetworkInterfaces[].AssociatePublicIpAddress: true"
    return None


def _check_ec2_imdsv2(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype == "AWS::EC2::Instance":
        opts = props.get("MetadataOptions", {})
        if not isinstance(opts, dict) or opts.get("HttpTokens", "optional") != "required":
            return "MetadataOptions.HttpTokens is not 'required' (IMDSv2 not enforced)"
    elif rtype == "AWS::EC2::LaunchTemplate":
        lt_data = props.get("LaunchTemplateData", {})
        if isinstance(lt_data, dict):
            opts = lt_data.get("MetadataOptions", {})
            if not isinstance(opts, dict) or opts.get("HttpTokens", "optional") != "required":
                return "LaunchTemplateData.MetadataOptions.HttpTokens is not 'required'"
    return None


def _check_ebs_encryption(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype == "AWS::EC2::Volume":
        if not _is_true(props.get("Encrypted", False)):
            return "EBS Volume Encrypted is not true"
    elif rtype == "AWS::EC2::Instance":
        for bdm in props.get("BlockDeviceMappings", []):
            if not isinstance(bdm, dict):
                continue
            ebs = bdm.get("Ebs", {})
            if isinstance(ebs, dict) and not _is_true(ebs.get("Encrypted", False)):
                return f"BlockDeviceMapping '{bdm.get('DeviceName', '')}' Ebs.Encrypted is not true"
    return None


def _check_ec2_monitoring(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::EC2::Instance":
        return None
    if not _is_true(props.get("Monitoring", False)):
        return "Monitoring (detailed monitoring) is not enabled"
    return None


# ── RDS checks ─────────────────────────────────────────────────────────────────

def _check_rds_encryption(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::RDS::DBInstance":
        return None
    if not _is_true(props.get("StorageEncrypted", False)):
        return "StorageEncrypted is not true"
    return None


def _check_rds_public_access(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::RDS::DBInstance":
        return None
    if _is_true(props.get("PubliclyAccessible", False)):
        return "PubliclyAccessible: true"
    return None


def _check_rds_multi_az(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::RDS::DBInstance":
        return None
    if not _is_true(props.get("MultiAZ", False)):
        return "MultiAZ is not enabled"
    return None


def _check_rds_deletion_protection(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::RDS::DBInstance":
        return None
    if not _is_true(props.get("DeletionProtection", False)):
        return "DeletionProtection is not enabled"
    return None


def _check_rds_auto_minor_upgrade(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::RDS::DBInstance":
        return None
    # Default is True; flag only explicit False.
    if _is_false(props.get("AutoMinorVersionUpgrade", True)):
        return "AutoMinorVersionUpgrade: false"
    return None


def _check_rds_backup_retention(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::RDS::DBInstance":
        return None
    retention = props.get("BackupRetentionPeriod", 1)
    try:
        if int(retention) < 7:
            return f"BackupRetentionPeriod is {retention} (minimum 7 recommended)"
    except (TypeError, ValueError):
        pass
    return None


# ── KMS checks ─────────────────────────────────────────────────────────────────

def _check_kms_rotation(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::KMS::Key":
        return None
    if not _is_true(props.get("EnableKeyRotation", False)):
        return "EnableKeyRotation is not true"
    return None


# ── CloudTrail checks ──────────────────────────────────────────────────────────

def _check_cloudtrail_logging(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::CloudTrail::Trail":
        return None
    if not _is_true(props.get("IsLogging", False)):
        return "IsLogging: false — trail is not capturing events"
    return None


def _check_cloudtrail_encryption(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::CloudTrail::Trail":
        return None
    if not props.get("KMSKeyId"):
        return "KMSKeyId not set — log files are not encrypted with KMS"
    return None


def _check_cloudtrail_log_validation(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::CloudTrail::Trail":
        return None
    if not _is_true(props.get("EnableLogFileValidation", False)):
        return "EnableLogFileValidation is not true"
    return None


def _check_cloudtrail_multi_region(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::CloudTrail::Trail":
        return None
    if not _is_true(props.get("IsMultiRegionTrail", False)):
        return "IsMultiRegionTrail is not true"
    return None


# ── Lambda checks ──────────────────────────────────────────────────────────────

def _check_lambda_permission_wildcard(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::Lambda::Permission":
        return None
    if _principal_is_world(props.get("Principal", "")):
        return "Lambda Permission Principal: '*' grants invoke to all principals"
    return None


def _check_lambda_tracing(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::Lambda::Function":
        return None
    tracing = props.get("TracingConfig", {})
    if not isinstance(tracing, dict) or tracing.get("Mode", "PassThrough") != "Active":
        return "TracingConfig.Mode is not 'Active'"
    return None


# ── ELB / ALB checks ──────────────────────────────────────────────────────────

def _check_elb_access_logs(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::ElasticLoadBalancingV2::LoadBalancer":
        return None
    for attr in props.get("LoadBalancerAttributes", []):
        if not isinstance(attr, dict):
            continue
        if (
            attr.get("Key") == "access_logs.s3.enabled"
            and attr.get("Value", "").lower() == "true"
        ):
            return None
    return "access_logs.s3.enabled is not set to 'true'"


def _check_elb_https_listener(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::ElasticLoadBalancingV2::Listener":
        return None
    protocol = props.get("Protocol", "HTTP")
    if isinstance(protocol, str) and protocol.upper() in ("HTTP", "TCP"):
        return f"Listener Protocol is {protocol!r} — use HTTPS or TLS"
    return None


def _check_elb_drop_http_headers(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::ElasticLoadBalancingV2::LoadBalancer":
        return None
    for attr in props.get("LoadBalancerAttributes", []):
        if not isinstance(attr, dict):
            continue
        if (
            attr.get("Key") == "routing.http.drop_invalid_header_fields.enabled"
            and attr.get("Value", "").lower() == "true"
        ):
            return None
    return "routing.http.drop_invalid_header_fields.enabled is not set to 'true'"


# ── CloudFront checks ──────────────────────────────────────────────────────────

def _check_cf_https_only(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::CloudFront::Distribution":
        return None
    dist_config = props.get("DistributionConfig", {})
    if not isinstance(dist_config, dict):
        return None

    allowed_http = ("allow-all",)

    # Check DefaultCacheBehavior
    dcb = dist_config.get("DefaultCacheBehavior", {})
    if isinstance(dcb, dict):
        vpp = dcb.get("ViewerProtocolPolicy", "allow-all")
        if vpp.lower() in allowed_http:
            return f"DefaultCacheBehavior.ViewerProtocolPolicy: {vpp!r} allows HTTP"

    # Check all CacheBehaviors
    for cb in dist_config.get("CacheBehaviors", []):
        if not isinstance(cb, dict):
            continue
        vpp = cb.get("ViewerProtocolPolicy", "allow-all")
        if vpp.lower() in allowed_http:
            path = cb.get("PathPattern", "?")
            return f"CacheBehavior ('{path}').ViewerProtocolPolicy: {vpp!r} allows HTTP"

    return None


def _check_cf_logging(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::CloudFront::Distribution":
        return None
    dist_config = props.get("DistributionConfig", {})
    if not isinstance(dist_config, dict):
        return None
    if not dist_config.get("Logging"):
        return "DistributionConfig.Logging is not configured"
    return None


def _check_cf_origin_https(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::CloudFront::Distribution":
        return None
    dist_config = props.get("DistributionConfig", {})
    if not isinstance(dist_config, dict):
        return None
    for origin in dist_config.get("Origins", []):
        if not isinstance(origin, dict):
            continue
        custom = origin.get("CustomOriginConfig", {})
        if isinstance(custom, dict):
            opp = custom.get("OriginProtocolPolicy", "http-only")
            if opp.lower() != "https-only":
                oid = origin.get("Id", "?")
                return f"Origin '{oid}' OriginProtocolPolicy: {opp!r} allows HTTP"
    return None


# ── SQS / SNS checks ──────────────────────────────────────────────────────────

def _check_sqs_encryption(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::SQS::Queue":
        return None
    if not props.get("KmsMasterKeyId") and not props.get("SqsManagedSseEnabled"):
        return "Neither KmsMasterKeyId nor SqsManagedSseEnabled is configured"
    return None


def _check_sns_encryption(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::SNS::Topic":
        return None
    if not props.get("KmsMasterKeyId"):
        return "KmsMasterKeyId is not set — SNS topic is not encrypted"
    return None


# ── EKS checks ─────────────────────────────────────────────────────────────────

def _check_eks_private_endpoint(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::EKS::Cluster":
        return None
    vpc_config = props.get("ResourcesVpcConfig", {})
    if not isinstance(vpc_config, dict):
        return None
    if _is_true(vpc_config.get("EndpointPublicAccess", True)):
        return "ResourcesVpcConfig.EndpointPublicAccess is true"
    return None


def _check_eks_logging(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::EKS::Cluster":
        return None
    logging_cfg = props.get("Logging", {})
    if not isinstance(logging_cfg, dict):
        return "Logging property not configured"
    cluster_logging = logging_cfg.get("ClusterLogging", {})
    if not isinstance(cluster_logging, dict):
        return "Logging.ClusterLogging not configured"
    enabled_types = cluster_logging.get("EnabledTypes", [])
    if not enabled_types:
        return "Logging.ClusterLogging.EnabledTypes is empty"
    type_names = {t.get("Type", "") for t in enabled_types if isinstance(t, dict)}
    required = {"api", "audit", "authenticator"}
    missing = required - {t.lower() for t in type_names}
    if missing:
        return f"Control plane log types missing: {', '.join(sorted(missing))}"
    return None


# ── DynamoDB checks ────────────────────────────────────────────────────────────

def _check_dynamodb_pitr(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::DynamoDB::Table":
        return None
    pitr = props.get("PointInTimeRecoverySpecification", {})
    if not isinstance(pitr, dict) or not _is_true(pitr.get("PointInTimeRecoveryEnabled", False)):
        return "PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled is not true"
    return None


def _check_dynamodb_encryption(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::DynamoDB::Table":
        return None
    sse = props.get("SSESpecification", {})
    if not isinstance(sse, dict):
        return "SSESpecification not configured"
    if not _is_true(sse.get("SSEEnabled", False)):
        return "SSESpecification.SSEEnabled is not true"
    if sse.get("SSEType", "AES256").upper() != "KMS":
        return f"SSESpecification.SSEType is {sse.get('SSEType')!r} — prefer 'KMS'"
    return None


# ── ElastiCache checks ─────────────────────────────────────────────────────────

def _check_elasticache_at_rest(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::ElastiCache::ReplicationGroup":
        return None
    if not _is_true(props.get("AtRestEncryptionEnabled", False)):
        return "AtRestEncryptionEnabled is not true"
    return None


def _check_elasticache_in_transit(
    logical_id: str, rtype: str, props: dict
) -> Optional[str]:
    if rtype != "AWS::ElastiCache::ReplicationGroup":
        return None
    if not _is_true(props.get("TransitEncryptionEnabled", False)):
        return "TransitEncryptionEnabled is not true"
    return None


# ── Policy table ───────────────────────────────────────────────────────────────
# (policy_id, check_fn)

_RESOURCE_POLICIES: List[Tuple[str, Any]] = [
    (CfnPolicyIDs.IAM_NO_INLINE_POLICY,           _check_iam_no_inline_policy),
    (CfnPolicyIDs.IAM_ROLE_WILDCARD_ACTION,        _check_iam_role_wildcard_action),
    (CfnPolicyIDs.IAM_ROLE_WILDCARD_RESOURCE,      _check_iam_role_wildcard_resource),
    (CfnPolicyIDs.IAM_POLICY_WILDCARD_ACTION,      _check_iam_managed_policy_wildcard_action),
    (CfnPolicyIDs.IAM_POLICY_WILDCARD_RESOURCE,    _check_iam_managed_policy_wildcard_resource),
    (CfnPolicyIDs.IAM_USER_ATTACHED_POLICIES,      _check_iam_user_attached_policies),
    (CfnPolicyIDs.IAM_ROLE_ASSUME_ALL_PRINCIPALS,  _check_iam_role_assume_all),
    (CfnPolicyIDs.IAM_ACCESS_KEY_ROTATION,         _check_iam_access_key),
    (CfnPolicyIDs.IAM_PASSWORD_POLICY_MIN_LENGTH,  _check_iam_password_min_length),
    (CfnPolicyIDs.IAM_PASSWORD_POLICY_REUSE,       _check_iam_password_reuse),
    (CfnPolicyIDs.S3_BUCKET_PUBLIC_ACL,            _check_s3_public_acl),
    (CfnPolicyIDs.S3_BUCKET_PUBLIC_POLICY,         _check_s3_public_policy),
    (CfnPolicyIDs.S3_BUCKET_VERSIONING,            _check_s3_versioning),
    (CfnPolicyIDs.S3_BUCKET_ENCRYPTION,            _check_s3_encryption),
    (CfnPolicyIDs.S3_BUCKET_LOGGING,               _check_s3_logging),
    (CfnPolicyIDs.S3_BUCKET_BLOCK_PUBLIC_ACCESS,   _check_s3_block_public_access),
    (CfnPolicyIDs.S3_BUCKET_HTTPS_ONLY,            _check_s3_https_only),
    (CfnPolicyIDs.S3_BUCKET_MFA_DELETE,            _check_s3_mfa_delete),
    (CfnPolicyIDs.EC2_SECURITY_GROUP_OPEN_SSH,     _check_sg_open_ssh),
    (CfnPolicyIDs.EC2_SECURITY_GROUP_OPEN_RDP,     _check_sg_open_rdp),
    (CfnPolicyIDs.EC2_SECURITY_GROUP_OPEN_ALL,     _check_sg_open_all),
    (CfnPolicyIDs.EC2_INSTANCE_NO_PUBLIC_IP,       _check_ec2_public_ip),
    (CfnPolicyIDs.EC2_INSTANCE_IMDSv2,             _check_ec2_imdsv2),
    (CfnPolicyIDs.EC2_EBS_VOLUME_ENCRYPTION,       _check_ebs_encryption),
    (CfnPolicyIDs.EC2_INSTANCE_DETAILED_MONITORING, _check_ec2_monitoring),
    (CfnPolicyIDs.RDS_ENCRYPTION_AT_REST,          _check_rds_encryption),
    (CfnPolicyIDs.RDS_NO_PUBLIC_ACCESS,            _check_rds_public_access),
    (CfnPolicyIDs.RDS_MULTI_AZ,                   _check_rds_multi_az),
    (CfnPolicyIDs.RDS_DELETION_PROTECTION,        _check_rds_deletion_protection),
    (CfnPolicyIDs.RDS_AUTO_MINOR_VERSION_UPGRADE, _check_rds_auto_minor_upgrade),
    (CfnPolicyIDs.RDS_BACKUP_RETENTION,           _check_rds_backup_retention),
    (CfnPolicyIDs.KMS_KEY_ROTATION,               _check_kms_rotation),
    (CfnPolicyIDs.CLOUDTRAIL_ENABLED,             _check_cloudtrail_logging),
    (CfnPolicyIDs.CLOUDTRAIL_ENCRYPTION,          _check_cloudtrail_encryption),
    (CfnPolicyIDs.CLOUDTRAIL_LOG_FILE_VALIDATION, _check_cloudtrail_log_validation),
    (CfnPolicyIDs.CLOUDTRAIL_MULTI_REGION,        _check_cloudtrail_multi_region),
    (CfnPolicyIDs.LAMBDA_FUNCTION_POLICY_WILDCARD, _check_lambda_permission_wildcard),
    (CfnPolicyIDs.LAMBDA_TRACING_ENABLED,         _check_lambda_tracing),
    (CfnPolicyIDs.ELB_ACCESS_LOGS_ENABLED,        _check_elb_access_logs),
    (CfnPolicyIDs.ELB_HTTPS_LISTENER,             _check_elb_https_listener),
    (CfnPolicyIDs.ELBV2_DROP_HTTP_HEADERS,        _check_elb_drop_http_headers),
    (CfnPolicyIDs.CF_DISTRIBUTION_HTTPS_ONLY,     _check_cf_https_only),
    (CfnPolicyIDs.CF_DISTRIBUTION_LOGGING,        _check_cf_logging),
    (CfnPolicyIDs.CF_DISTRIBUTION_ORIGIN_HTTPS,   _check_cf_origin_https),
    (CfnPolicyIDs.SQS_QUEUE_ENCRYPTION,           _check_sqs_encryption),
    (CfnPolicyIDs.SNS_TOPIC_ENCRYPTION,           _check_sns_encryption),
    (CfnPolicyIDs.EKS_CLUSTER_PRIVATE_ENDPOINT,  _check_eks_private_endpoint),
    (CfnPolicyIDs.EKS_CLUSTER_LOGGING,           _check_eks_logging),
    (CfnPolicyIDs.DYNAMODB_PITR_ENABLED,         _check_dynamodb_pitr),
    (CfnPolicyIDs.DYNAMODB_ENCRYPTION,           _check_dynamodb_encryption),
    (CfnPolicyIDs.ELASTICACHE_ENCRYPTION_AT_REST,    _check_elasticache_at_rest),
    (CfnPolicyIDs.ELASTICACHE_ENCRYPTION_IN_TRANSIT, _check_elasticache_in_transit),
]


# ── cfn-lint integration ───────────────────────────────────────────────────────

def _run_cfn_lint(file_path: str) -> List[Dict[str, Any]]:
    """
    Run cfn-lint on a single CloudFormation template file and return a list of
    normalised finding dicts.

    Returns an empty list if cfn-lint is not installed or the file has no
    findings; callers treat this as a graceful no-op.
    """
    try:
        from cfnlint import decode, runner as cfnlint_runner
        from cfnlint.rules import CloudFormationLintRule  # noqa: F401 – import probe
        import cfnlint.core as cfnlint_core
    except ImportError:
        logger.debug("[CFN] cfn-lint is not installed — skipping structural validation")
        return []

    findings: List[Dict[str, Any]] = []
    try:
        (template, matches) = cfnlint_core.get_matches([file_path], include_checks=[])
        for match in matches:
            sev_str = str(getattr(match, "rule", None) and getattr(match.rule, "severity", "MEDIUM") or "MEDIUM")
            findings.append({
                "policy_id": getattr(getattr(match, "rule", None), "id", "CFN-LINT"),
                "severity": sev_str.upper(),
                "description": str(match.message),
                "line": str(match.linenumber) if hasattr(match, "linenumber") else None,
            })
    except Exception as exc:
        logger.debug(f"[CFN] cfn-lint execution error on {file_path}: {exc}")

    return findings


# ── Scanner class ──────────────────────────────────────────────────────────────

class CloudFormationScanner(BaseScanner):
    """CloudFormation template security scanner microservice."""

    def __init__(self) -> None:
        super().__init__("cloudformation")

    # ── Public scan entry point ────────────────────────────────────────────────

    def scan(self, request: ScanRequest) -> ScanResponse:
        start_time = time.time()
        try:
            logger.info(
                f"[CFN] Scan started | scan_id={request.scan_id} | repo={request.repo_path}"
            )

            cfn_files = self._find_cfn_files(request.repo_path)

            if not cfn_files:
                logger.info("[CFN] No CloudFormation templates found – skipping scan")
                return self._create_success_response(
                    request.scan_id,
                    ScanResult(
                        scanner_type=self.scanner_type,
                        status=ScanStatus.COMPLETED,
                        findings=[],
                        scanned_files=[],
                        scan_duration=time.time() - start_time,
                    ),
                )

            logger.info(f"[CFN] Found {len(cfn_files)} template(s)")

            disabled_policies: Dict[str, Any] = {}
            if request.metadata:
                disabled_policies = request.metadata.get("disabled_policies", {})

            findings: List[ScanFinding] = []
            scanned_files: List[str] = []

            for file_path in cfn_files:
                try:
                    file_findings = self._scan_file(file_path, disabled_policies)
                    findings.extend(file_findings)
                    scanned_files.append(file_path)
                    if file_findings:
                        logger.info(f"[CFN] {len(file_findings)} finding(s) in {file_path}")
                except Exception as exc:
                    logger.error(f"[CFN] Error scanning {file_path}: {exc}", exc_info=True)

            # ── Artifact writing ───────────────────────────────────────────────
            write_artifacts = os.getenv("WRITE_ARTIFACTS", "false").lower() == "true"
            if findings and request.output_dir and write_artifacts:
                report_path = os.path.join(
                    request.output_dir, "CloudFormation-Security-Scan-Result.md"
                )
                self._write_findings_report(
                    findings, report_path, "CloudFormation Security Scan Results"
                )

            # ── Scoring ────────────────────────────────────────────────────────
            overall_score = 100.0
            file_scores: Dict[str, Any] = {}
            try:
                findings_dicts = [
                    {
                        "policy": f.policy or "",
                        "severity": (
                            f.severity.value
                            if hasattr(f.severity, "value")
                            else str(f.severity)
                        ),
                        "description": f.description,
                        "code": f.code,
                        "file": f.file,
                        "line": f.line,
                    }
                    for f in findings
                ]
                adapter = OPABasedScoreAdapter()
                overall_score, file_scores = adapter.calculate_score(
                    findings=findings_dicts,
                    scanned_files=scanned_files,
                )
                logger.info(f"[CFN] Security score: {overall_score:.2f}")
            except Exception as score_err:
                logger.warning(f"[CFN] Scoring failed: {score_err}", exc_info=True)

            if findings:
                logger.warning(f"[CFN] Scan complete — {len(findings)} finding(s)")
            else:
                logger.info("[CFN] Scan complete — no violations found")

            return self._create_success_response(
                request.scan_id,
                ScanResult(
                    scanner_type=self.scanner_type,
                    status=ScanStatus.COMPLETED,
                    findings=findings,
                    scanned_files=scanned_files,
                    scan_duration=time.time() - start_time,
                    metadata={
                        "total_findings": len(findings),
                        "overall_score": overall_score,
                        "file_scores": file_scores,
                    },
                ),
            )

        except Exception as exc:
            logger.error(f"[CFN] Scan failed: {exc}", exc_info=True)
            return self._create_error_response(request.scan_id, str(exc))

    # ── File discovery ─────────────────────────────────────────────────────────

    def _find_cfn_files(self, repo_path: str) -> List[str]:
        """Walk *repo_path* and return paths of CloudFormation template files."""
        cfn_files: List[str] = []
        for root, dirs, files in os.walk(repo_path):
            # Skip common non-template directories to reduce false positives.
            dirs[:] = [
                d for d in dirs
                if d not in (
                    ".git", ".github", "node_modules", "__pycache__",
                    ".tox", ".venv", "venv", "dist", "build",
                )
            ]
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    if _is_cfn_template(fpath):
                        cfn_files.append(fpath)
                except Exception:
                    pass
        return cfn_files

    # ── Per-file scan ──────────────────────────────────────────────────────────

    def _scan_file(
        self,
        file_path: str,
        disabled_policies: Dict[str, Any],
    ) -> List[ScanFinding]:
        template = _load_template(file_path)
        if not template:
            return []

        findings: List[ScanFinding] = []

        # ── 1. cfn-lint structural checks ─────────────────────────────────────
        lint_hits = _run_cfn_lint(file_path)
        for hit in lint_hits:
            pid = hit.get("policy_id", "CFN-LINT")
            if disabled_policies.get(pid) is False:
                continue
            sev = _SEVERITY_MAP.get(hit.get("severity", "MEDIUM"), ScanSeverity.MEDIUM)
            findings.append(ScanFinding(
                policy=pid,
                severity=sev,
                description=hit.get("description", "cfn-lint finding"),
                code=pid,
                file=file_path,
                line=hit.get("line"),
                match=None,
            ))

        # ── 2. Custom resource-level policy checks ────────────────────────────
        for logical_id, rtype, props in _iter_resources(template):
            for policy_id, check_fn in _RESOURCE_POLICIES:
                if disabled_policies.get(policy_id) is False:
                    continue
                try:
                    evidence = check_fn(logical_id, rtype, props)
                except Exception as exc:
                    logger.debug(
                        f"[CFN] Check {policy_id} raised on {logical_id}: {exc}"
                    )
                    continue
                if evidence is None:
                    continue

                meta = CfnPolicyMetadata.lookup(policy_id)
                severity = _SEVERITY_MAP.get(
                    meta.severity if meta else "MEDIUM", ScanSeverity.MEDIUM
                )
                description = (
                    f"[{logical_id}] ({rtype}) {meta.description}"
                    if meta
                    else f"[{logical_id}] ({rtype}) {evidence}"
                )
                findings.append(ScanFinding(
                    policy=meta.title if meta else policy_id,
                    severity=severity,
                    description=description,
                    code=policy_id,
                    file=file_path,
                    line=None,
                    match=f"{logical_id}: {evidence}",
                ))

        # ── 3. Hardcoded credential scan (whole template) ─────────────────────
        if disabled_policies.get(CfnPolicyIDs.CFN_NO_HARDCODED_CREDENTIALS) is not False:
            cred_hits: List[Tuple[str, str]] = []
            _scan_for_credentials(template, "", cred_hits)
            meta = CfnPolicyMetadata.lookup(CfnPolicyIDs.CFN_NO_HARDCODED_CREDENTIALS)
            for path, evidence in cred_hits:
                findings.append(ScanFinding(
                    policy=meta.title if meta else CfnPolicyIDs.CFN_NO_HARDCODED_CREDENTIALS,
                    severity=ScanSeverity.CRITICAL,
                    description=(
                        meta.description
                        if meta
                        else "Hardcoded credentials detected in CloudFormation template"
                    ),
                    code=CfnPolicyIDs.CFN_NO_HARDCODED_CREDENTIALS,
                    file=file_path,
                    line=None,
                    match=f"{path}: {evidence}",
                ))

        return findings

    # ── Report writing ─────────────────────────────────────────────────────────

    def _write_findings_report(
        self,
        findings: List[ScanFinding],
        output_path: str,
        title: str,
    ) -> None:
        try:
            from scanner_core.policy_scanner_common.utils import write_markdown_report
            formatted = [{"file": f.file, "deny": [f.description]} for f in findings]
            write_markdown_report(formatted, output_path, title)
        except Exception as exc:
            logger.warning(f"[CFN] Could not write markdown report: {exc}")


# ── Module-level entry point ───────────────────────────────────────────────────

def scan_cloudformation(request: ScanRequest) -> ScanResponse:
    """CloudFormation scanner microservice entry point."""
    scanner = CloudFormationScanner()
    return scanner.scan(request)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="CloudFormation Scanner Microservice")
    parser.add_argument("--repo-path", required=True, help="Repository path to scan")
    parser.add_argument("--output-dir", required=True, help="Output directory for results")
    parser.add_argument("--scan-id", required=True, help="Unique scan ID")
    args = parser.parse_args()

    _request = ScanRequest(
        repo_path=args.repo_path,
        output_dir=args.output_dir,
        scan_id=args.scan_id,
    )
    _response = scan_cloudformation(_request)
    print(_response.json())
