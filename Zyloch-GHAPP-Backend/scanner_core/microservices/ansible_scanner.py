"""
Ansible Playbook Security Scanner Microservice

Implements Checkov-equivalent policy checks for Ansible YAML playbooks:

  ANS-SEC-TLS-001  uri / ansible.builtin.uri          — validate_certs: false
  ANS-SEC-TLS-002  get_url / ansible.builtin.get_url  — validate_certs: false
  ANS-SEC-TLS-003  yum / ansible.builtin.yum          — validate_certs: false
  ANS-SEC-TLS-004  yum / ansible.builtin.yum          — sslverify: false
  ANS-SEC-PKG-001  apt / ansible.builtin.apt           — allow_unauthenticated: true
  ANS-SEC-PKG-002  apt / ansible.builtin.apt           — force / force_yes: true
  ANS-SEC-NET-001  uri / ansible.builtin.uri           — non-HTTPS url
  ANS-SEC-NET-002  get_url / ansible.builtin.get_url   — non-HTTPS url
  ANS-SEC-ERR-001  block                               — missing rescue section
  ANS-SEC-PKG-003  dnf / ansible.builtin.dnf           — disable_gpg_check: true
  ANS-SEC-TLS-005  dnf / ansible.builtin.dnf           — sslverify: false
  ANS-SEC-TLS-006  dnf / ansible.builtin.dnf           — validate_certs: false
  ANS-SEC-NET-003  ec2_instance / amazon.aws.ec2_instance — public IP assigned
"""

from __future__ import annotations

import os
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

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
from scanner_core.constants.ansible_policy_ids import AnsiblePolicyMetadata

logger = get_scanner_logger()


# ── YAML Line-Tracking Loader ──────────────────────────────────────────────────

class _LineTrackingLoader(yaml.SafeLoader):
    """YAML loader that injects ``__line__`` (1-indexed) into every mapping node."""


def _construct_mapping_with_line(loader: yaml.SafeLoader, node: yaml.MappingNode) -> dict:
    mapping = loader.construct_mapping(node, deep=True)
    mapping["__line__"] = node.start_mark.line + 1
    return mapping


_LineTrackingLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping_with_line,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _get_arg(task: dict, module: str, *keys: str, default: Any = None) -> Any:
    """Return a nested value from a task's module args dict."""
    args = task.get(module, {})
    if not isinstance(args, dict):
        return default
    val: Any = args
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


# ── Per-module check functions ─────────────────────────────────────────────────

def _check_validate_certs(task: dict, module: str) -> Optional[str]:
    v = _get_arg(task, module, "validate_certs", default=True)
    if _is_false(v):
        return f"validate_certs: {v!r}"
    return None


def _check_ssl_verify(task: dict, module: str) -> Optional[str]:
    v = _get_arg(task, module, "sslverify", default=True)
    if _is_false(v):
        return f"sslverify: {v!r}"
    return None


def _check_allow_unauthenticated(task: dict, module: str) -> Optional[str]:
    v = _get_arg(task, module, "allow_unauthenticated", default=False)
    if _is_true(v):
        return f"allow_unauthenticated: {v!r}"
    return None


def _check_apt_force(task: dict, module: str) -> Optional[str]:
    if _is_true(_get_arg(task, module, "force", default=False)):
        return "force: true"
    if _is_true(_get_arg(task, module, "force_yes", default=False)):
        return "force_yes: true"
    return None


def _check_http_url(task: dict, module: str) -> Optional[str]:
    url = _get_arg(task, module, "url", default="")
    if isinstance(url, str) and url.strip() and not url.strip().lower().startswith("https://"):
        return f"url: {url!r} (not HTTPS)"
    return None


def _check_dnf_gpg(task: dict, module: str) -> Optional[str]:
    v = _get_arg(task, module, "disable_gpg_check", default=False)
    if _is_true(v):
        return f"disable_gpg_check: {v!r}"
    return None


def _check_ec2_public_ip(task: dict, module: str) -> Optional[str]:
    network = _get_arg(task, module, "network", default={})
    if isinstance(network, dict) and _is_true(network.get("assign_public_ip", False)):
        return "network.assign_public_ip: true"
    if _is_true(_get_arg(task, module, "assign_public_ip", default=False)):
        return "assign_public_ip: true"
    return None


def _check_ec2_ebs_optimized(task: dict, module: str) -> Optional[str]:
    v = _get_arg(task, module, "ebs_optimized", default=None)
    if v is None or _is_false(v):
        return f"ebs_optimized: {v!r} (should be true)"
    return None


# ── Palo Alto Networks check functions ────────────────────────────────────────

def _check_pan_no_http(task: dict, module: str) -> Optional[str]:
    if _is_true(_get_arg(task, module, "http", default=False)):
        return "http: true (plain-text HTTP management enabled)"
    return None


def _check_pan_no_telnet(task: dict, module: str) -> Optional[str]:
    if _is_true(_get_arg(task, module, "telnet", default=False)):
        return "telnet: true (Telnet management enabled)"
    return None


def _check_pan_no_dsri(task: dict, module: str) -> Optional[str]:
    if _is_true(_get_arg(task, module, "disable_server_response_inspection", default=False)):
        return "disable_server_response_inspection: true"
    return None


def _check_pan_no_app_any(task: dict, module: str) -> Optional[str]:
    app = _get_arg(task, module, "application", default=None)
    if app == "any":
        return "application: any"
    if isinstance(app, list) and "any" in app:
        return "application list contains 'any'"
    return None


def _check_pan_no_service_any(task: dict, module: str) -> Optional[str]:
    svc = _get_arg(task, module, "service", default=None)
    if svc == "any":
        return "service: any"
    if isinstance(svc, list) and "any" in svc:
        return "service list contains 'any'"
    return None


def _check_pan_no_src_dst_any(task: dict, module: str) -> Optional[str]:
    src = _get_arg(task, module, "source_ip", default=None)
    dst = _get_arg(task, module, "destination_ip", default=None)
    src_any = src == "any" or (isinstance(src, list) and "any" in src)
    dst_any = dst == "any" or (isinstance(dst, list) and "any" in dst)
    if src_any and dst_any:
        return "source_ip and destination_ip are both 'any'"
    return None


def _check_pan_policy_description(task: dict, module: str) -> Optional[str]:
    desc = _get_arg(task, module, "description", default=None)
    if not desc or (isinstance(desc, str) and not desc.strip()):
        return "description is missing or empty"
    return None


def _check_pan_log_forwarding(task: dict, module: str) -> Optional[str]:
    v = _get_arg(task, module, "log_forwarding", default=None)
    if not v:
        return "log_forwarding profile not set"
    return None


def _check_pan_log_session_end(task: dict, module: str) -> Optional[str]:
    v = _get_arg(task, module, "log_end", default=None)
    if v is None or _is_false(v):
        return f"log_end: {v!r} (session-end logging disabled)"
    return None


_INSECURE_AUTH_ALGORITHMS = frozenset({"md5", "sha1"})
_INSECURE_ENCRYPTION_PROTOCOLS = frozenset({"des", "3des", "null"})


def _check_pan_ipsec_auth(task: dict, module: str) -> Optional[str]:
    auth = _get_arg(task, module, "authentication", default=None)
    if isinstance(auth, str):
        if auth.lower() in _INSECURE_AUTH_ALGORITHMS:
            return f"authentication: {auth!r} (insecure algorithm)"
    elif isinstance(auth, list):
        bad = [a for a in auth if isinstance(a, str) and a.lower() in _INSECURE_AUTH_ALGORITHMS]
        if bad:
            return f"insecure authentication algorithms: {bad}"
    return None


def _check_pan_ipsec_protocols(task: dict, module: str) -> Optional[str]:
    enc = _get_arg(task, module, "encryption", default=None)
    if isinstance(enc, str):
        if enc.lower() in _INSECURE_ENCRYPTION_PROTOCOLS:
            return f"encryption: {enc!r} (insecure protocol)"
    elif isinstance(enc, list):
        bad = [e for e in enc if isinstance(e, str) and e.lower() in _INSECURE_ENCRYPTION_PROTOCOLS]
        if bad:
            return f"insecure encryption protocols: {bad}"
    return None


def _check_pan_zone_protection(task: dict, module: str) -> Optional[str]:
    v = _get_arg(task, module, "zone_profile", default=None)
    if not v:
        return "zone_profile (Zone Protection Profile) not defined"
    return None


def _check_pan_userid_acl(task: dict, module: str) -> Optional[str]:
    uid = _get_arg(task, module, "enable_userid", default=False)
    if _is_true(uid):
        acl = _get_arg(task, module, "include_acl", default=None)
        if not acl:
            return "enable_userid: true but include_acl not set"
    return None


def _check_pan_no_log_session_start(task: dict, module: str) -> Optional[str]:
    if _is_true(_get_arg(task, module, "log_start", default=False)):
        return "log_start: true (session-start logging enabled)"
    return None


def _check_pan_no_zone_any(task: dict, module: str) -> Optional[str]:
    src_z = _get_arg(task, module, "source_zone", default=None)
    dst_z = _get_arg(task, module, "destination_zone", default=None)
    src_any = src_z == "any" or (isinstance(src_z, list) and "any" in src_z)
    dst_any = dst_z == "any" or (isinstance(dst_z, list) and "any" in dst_z)
    if src_any and dst_any:
        return "source_zone and destination_zone are both 'any'"
    return None


# ── Policy Table ───────────────────────────────────────────────────────────────
# (check_id, severity_str, [modules], check_fn, description)

_TASK_POLICIES: List[Tuple[str, str, List[str], Callable, str]] = [
    (
        "ANS-SEC-TLS-001", "HIGH",
        ["uri", "ansible.builtin.uri"],
        _check_validate_certs,
        "Ensure certificate validation isn't disabled with uri",
    ),
    (
        "ANS-SEC-TLS-002", "HIGH",
        ["get_url", "ansible.builtin.get_url"],
        _check_validate_certs,
        "Ensure certificate validation isn't disabled with get_url",
    ),
    (
        "ANS-SEC-TLS-003", "MEDIUM",
        ["yum", "ansible.builtin.yum"],
        _check_validate_certs,
        "Ensure certificate validation isn't disabled with yum",
    ),
    (
        "ANS-SEC-TLS-004", "MEDIUM",
        ["yum", "ansible.builtin.yum"],
        _check_ssl_verify,
        "Ensure SSL validation isn't disabled with yum",
    ),
    (
        "ANS-SEC-PKG-001", "HIGH",
        ["apt", "ansible.builtin.apt"],
        _check_allow_unauthenticated,
        "Ensure packages with untrusted signatures are not installed via apt",
    ),
    (
        "ANS-SEC-PKG-002", "HIGH",
        ["apt", "ansible.builtin.apt"],
        _check_apt_force,
        "Ensure force/force_yes is not used with apt (disables signature validation)",
    ),
    (
        "ANS-SEC-NET-001", "MEDIUM",
        ["uri", "ansible.builtin.uri"],
        _check_http_url,
        "Ensure HTTPS URL is used with uri",
    ),
    (
        "ANS-SEC-NET-002", "MEDIUM",
        ["get_url", "ansible.builtin.get_url"],
        _check_http_url,
        "Ensure HTTPS URL is used with get_url",
    ),
    (
        "ANS-SEC-PKG-003", "HIGH",
        ["dnf", "ansible.builtin.dnf"],
        _check_dnf_gpg,
        "Ensure packages without GPG signatures are not used by dnf",
    ),
    (
        "ANS-SEC-TLS-005", "MEDIUM",
        ["dnf", "ansible.builtin.dnf"],
        _check_ssl_verify,
        "Ensure SSL validation isn't disabled with dnf",
    ),
    (
        "ANS-SEC-TLS-006", "HIGH",
        ["dnf", "ansible.builtin.dnf"],
        _check_validate_certs,
        "Ensure certificate validation isn't disabled with dnf",
    ),
    (
        "ANS-SEC-NET-003", "HIGH",
        ["ec2_instance", "amazon.aws.ec2_instance"],
        _check_ec2_public_ip,
        "EC2 instance should not have a public IP",
    ),
    (
        "ANS-SEC-EC2-001", "LOW",
        ["ec2_instance", "amazon.aws.ec2_instance"],
        _check_ec2_ebs_optimized,
        "Ensure EBS optimization is enabled for EC2 instances",
    ),
    # ── Palo Alto Networks ──────────────────────────────────────────────────
    (
        "ANS-SEC-PAN-001", "HIGH",
        ["paloaltonetworks.panos.panos_management_profile"],
        _check_pan_no_http,
        "PANOS Management Profile must not allow HTTP",
    ),
    (
        "ANS-SEC-PAN-002", "HIGH",
        ["paloaltonetworks.panos.panos_management_profile"],
        _check_pan_no_telnet,
        "PANOS Management Profile must not allow Telnet",
    ),
    (
        "ANS-SEC-PAN-003", "MEDIUM",
        ["paloaltonetworks.panos.panos_security_rule"],
        _check_pan_no_dsri,
        "PANOS security rules must not have DSRI enabled",
    ),
    (
        "ANS-SEC-PAN-004", "HIGH",
        ["paloaltonetworks.panos.panos_security_rule"],
        _check_pan_no_app_any,
        "PANOS security rules must not use application 'any'",
    ),
    (
        "ANS-SEC-PAN-005", "HIGH",
        ["paloaltonetworks.panos.panos_security_rule"],
        _check_pan_no_service_any,
        "PANOS security rules must not use service 'any'",
    ),
    (
        "ANS-SEC-PAN-006", "HIGH",
        ["paloaltonetworks.panos.panos_security_rule"],
        _check_pan_no_src_dst_any,
        "PANOS security rules must not have both source and destination IP as 'any'",
    ),
    (
        "ANS-SEC-PAN-007", "LOW",
        ["paloaltonetworks.panos.panos_security_rule"],
        _check_pan_policy_description,
        "PANOS security policies must include a description",
    ),
    (
        "ANS-SEC-PAN-008", "MEDIUM",
        ["paloaltonetworks.panos.panos_security_rule"],
        _check_pan_log_forwarding,
        "PANOS security policies must have a Log Forwarding profile",
    ),
    (
        "ANS-SEC-PAN-009", "MEDIUM",
        ["paloaltonetworks.panos.panos_security_rule"],
        _check_pan_log_session_end,
        "PANOS security policies must log at session end",
    ),
    (
        "ANS-SEC-PAN-010", "HIGH",
        ["paloaltonetworks.panos.panos_ipsec_profile"],
        _check_pan_ipsec_auth,
        "PANOS IPsec profiles must not use insecure authentication algorithms",
    ),
    (
        "ANS-SEC-PAN-011", "HIGH",
        ["paloaltonetworks.panos.panos_ipsec_profile"],
        _check_pan_ipsec_protocols,
        "PANOS IPsec profiles must not use insecure encryption protocols",
    ),
    (
        "ANS-SEC-PAN-012", "MEDIUM",
        ["paloaltonetworks.panos.panos_zone"],
        _check_pan_zone_protection,
        "PANOS security zones must have a Zone Protection Profile",
    ),
    (
        "ANS-SEC-PAN-013", "MEDIUM",
        ["paloaltonetworks.panos.panos_zone"],
        _check_pan_userid_acl,
        "PANOS zones with User-ID enabled must define an Include ACL",
    ),
    (
        "ANS-SEC-PAN-014", "LOW",
        ["paloaltonetworks.panos.panos_security_rule"],
        _check_pan_no_log_session_start,
        "PANOS security policies must not enable session-start logging",
    ),
    (
        "ANS-SEC-PAN-015", "HIGH",
        ["paloaltonetworks.panos.panos_security_rule"],
        _check_pan_no_zone_any,
        "PANOS security rules must not have both source and destination zone as 'any'",
    ),
]

# Module → list of (check_id, severity_str, check_fn, description) tuples
_MODULE_INDEX: Dict[str, List[Tuple]] = {}
for _policy in _TASK_POLICIES:
    _cid, _sev, _mods, _fn, _desc = _policy
    for _mod in _mods:
        _MODULE_INDEX.setdefault(_mod, []).append((_cid, _sev, _fn, _desc))

_SEVERITY_MAP = {
    "CRITICAL": ScanSeverity.CRITICAL,
    "HIGH": ScanSeverity.HIGH,
    "MEDIUM": ScanSeverity.MEDIUM,
    "LOW": ScanSeverity.LOW,
    "INFO": ScanSeverity.INFO,
}

# ── Inventory security constants ───────────────────────────────────────────────
# Exact key names that are definitively cloud/service credentials.
_CREDENTIAL_KEYS = frozenset((
    "aws_access_key", "aws_access_key_id",
    "aws_secret_key", "aws_secret_access_key", "aws_session_token",
    "azure_client_secret", "azure_ad_password",
    "gcp_service_account_key",
    "api_key", "api_secret", "api_token", "access_token",
    "db_root_pass", "db_password", "db_pass", "database_password",
    "vault_token", "vault_password",
))
# Substrings that suggest a key holds a secret value.
_CREDENTIAL_SUBSTRINGS = (
    "_secret", "_password", "_passwd", "_pass",
    "secret_key", "access_key", "api_key", "api_token",
)
# Ansible connection variables that carry SSH/sudo passwords.
_SSH_PASS_KEYS = frozenset((
    "ansible_ssh_pass", "ansible_become_pass",
    "ansible_password", "ansible_sudo_pass",
))
# Structural keys found in every Ansible inventory group.
_INVENTORY_GROUP_KEYS = frozenset(("hosts", "vars", "children"))


def _is_jinja2(val: Any) -> bool:
    """Return True if *val* is a Jinja2 template reference, not a plain secret."""
    return isinstance(val, str) and val.strip().startswith("{{")


def _check_vars_dict(
    vars_dict: Dict[str, Any],
    context: str,
    file_path: str,
    findings: List["ScanFinding"],
) -> None:
    """
    Inspect a single vars / host-vars dict and append any security findings.

    Policies checked:
      ANS-SEC-INV-001  Hardcoded cloud / service credentials
      ANS-SEC-INV-002  Plain-text SSH / become passwords
      ANS-SEC-INV-003  ansible_user: root
      ANS-SEC-INV-004  StrictHostKeyChecking disabled
    """
    if not isinstance(vars_dict, dict):
        return
    _line: Optional[str] = str(vars_dict["__line__"]) if vars_dict.get("__line__") else None
    for key, val in vars_dict.items():
        if key == "__line__":
            continue
        key_lower = key.lower()

        # ANS-SEC-INV-002: SSH / sudo passwords in plain text (check first so
        # they are not also flagged as generic credential violations).
        if key in _SSH_PASS_KEYS:
            if isinstance(val, str) and val.strip() and not _is_jinja2(val):
                findings.append(ScanFinding(
                    policy="ANS-SEC-INV-002",
                    severity=ScanSeverity.HIGH,
                    description=(
                        f"Plain-text SSH/become password in inventory "
                        f"({context}): '{key}'"
                    ),
                    code="ANS-SEC-INV-002",
                    file=file_path,
                    line=_line,
                    match=f"{key}: <redacted>",
                ))
            continue  # Do not double-count as INV-001.

        # ANS-SEC-INV-001: Hardcoded credentials.
        is_cred = (
            key_lower in _CREDENTIAL_KEYS
            or any(sub in key_lower for sub in _CREDENTIAL_SUBSTRINGS)
        )
        if is_cred and isinstance(val, str) and val.strip() and not _is_jinja2(val):
            findings.append(ScanFinding(
                policy="ANS-SEC-INV-001",
                severity=ScanSeverity.HIGH,
                description=(
                    f"Hardcoded credential in inventory ({context}): '{key}'"
                ),
                code="ANS-SEC-INV-001",
                file=file_path,
                line=_line,
                match=f"{key}: <redacted>",
            ))

        # ANS-SEC-INV-003: Connecting as root.
        if key == "ansible_user" and val == "root":
            findings.append(ScanFinding(
                policy="ANS-SEC-INV-003",
                severity=ScanSeverity.HIGH,
                description=(
                    f"Connection as root in inventory ({context}): "
                    "ansible_user: root. Use a non-privileged user with sudo."
                ),
                code="ANS-SEC-INV-003",
                file=file_path,
                line=_line,
                match="ansible_user: root",
            ))

        # ANS-SEC-INV-004: StrictHostKeyChecking disabled.
        if key == "ansible_ssh_common_args" and isinstance(val, str):
            if "StrictHostKeyChecking=no" in val or "stricthostkeychecking=no" in val.lower():
                findings.append(ScanFinding(
                    policy="ANS-SEC-INV-004",
                    severity=ScanSeverity.MEDIUM,
                    description=(
                        f"StrictHostKeyChecking disabled in inventory ({context}). "
                        "This exposes SSH connections to MITM attacks."
                    ),
                    code="ANS-SEC-INV-004",
                    file=file_path,
                    line=_line,
                    match=f"ansible_ssh_common_args: {val!r}",
                ))


def _check_inventory_security(
    data: Dict[str, Any],
    file_path: str,
) -> List["ScanFinding"]:
    """
    Recursively walk an Ansible inventory dict and collect security findings.
    Handles nested groups via the standard ``vars`` / ``hosts`` / ``children``
    structure.
    """
    findings: List[ScanFinding] = []

    def _walk_group(group_data: Any, path: str) -> None:
        if not isinstance(group_data, dict):
            return
        # Group-level vars apply to every host in the group.
        gvars = group_data.get("vars")
        if isinstance(gvars, dict):
            _check_vars_dict(gvars, f"{path}.vars", file_path, findings)
        # Host-specific vars.
        hosts = group_data.get("hosts")
        if isinstance(hosts, dict):
            for host_name, host_vars in hosts.items():
                if isinstance(host_vars, dict):
                    _check_vars_dict(
                        host_vars,
                        f"{path}.hosts.{host_name}",
                        file_path,
                        findings,
                    )
        # Recurse into child groups.
        children = group_data.get("children")
        if isinstance(children, dict):
            for child_name, child_data in children.items():
                _walk_group(child_data, f"{path}.children.{child_name}")

    for group_name, group_data in data.items():
        _walk_group(group_data, group_name)

    return findings


# ── Task Extraction ────────────────────────────────────────────────────────────

def _extract_tasks(obj: Any) -> List[dict]:
    """
    Recursively collect all task dicts from a playbook structure.
    Handles: tasks, pre_tasks, post_tasks, handlers, block, rescue, always.
    """
    tasks: List[dict] = []
    if isinstance(obj, list):
        for item in obj:
            tasks.extend(_extract_tasks(item))
    elif isinstance(obj, dict):
        for key in ("tasks", "pre_tasks", "post_tasks", "handlers"):
            if key in obj:
                tasks.extend(_extract_tasks(obj[key]))
        for key in ("rescue", "always"):
            if key in obj:
                tasks.extend(_extract_tasks(obj[key]))
        # If this dict itself contains a known module key, it is a task
        if any(mod in obj for mod in _MODULE_INDEX):
            tasks.append(obj)
    return tasks


# ── Block Error-Handling Check (ANS-SEC-ERR-001) ─────────────────────────────

def _check_block_error_handling(plays: List[Any]) -> List[Dict[str, Any]]:
    """
    ANS-SEC-ERR-001 — every `block` list must have an adjacent `rescue`.
    Returns list of dicts: {task_name, evidence}.
    """
    hits: List[Dict[str, Any]] = []

    def _walk(obj: Any) -> None:
        if isinstance(obj, list):
            for item in obj:
                _walk(item)
        elif isinstance(obj, dict):
            if "block" in obj and "rescue" not in obj:
                hits.append({
                    "task_name": obj.get("name"),
                    "line": obj.get("__line__"),
                    "evidence": (
                        f"block without rescue (name: {obj.get('name')!r})"
                        if obj.get("name") else "unnamed block without rescue"
                    ),
                })
            for v in obj.values():
                if isinstance(v, (dict, list)):
                    _walk(v)

    for play in plays:
        _walk(play)
    return hits


# ── Ansible Playbook Detection ─────────────────────────────────────────────────
_ANSIBLE_PLAY_KEYS = frozenset((
    "tasks", "roles", "pre_tasks", "post_tasks", "handlers",
    "become", "become_user", "gather_facts", "vars", "vars_files",
    "vars_prompt", "connection", "any_errors_fatal", "max_fail_percentage",
    "include_tasks", "import_tasks", "import_playbook",
    "serial", "strategy", "environment", "module_defaults",
))

# Path fragments that are canonical Ansible directory conventions
_ANSIBLE_PATH_HINTS = (
    "/playbooks/", "/tasks/", "/roles/", "/handlers/",
    "/plays/", "/ansible/",
)


def _is_ansible_playbook(file_path: str) -> bool:
    """
    Decide whether a YAML file is an Ansible playbook or task file.

    Detection strategy (ordered by confidence):

    1. Classic playbook play: top-level list item that has BOTH 'hosts' AND at
       least one of tasks/roles/pre_tasks/post_tasks/handlers.  Requiring
       co-presence avoids mis-identifying generic config files that happen to
       have a 'hosts' key.

    2. Bare task file: top-level list item that has no 'hosts' key but lives
       inside a canonical Ansible directory (tasks/, roles/, handlers/, etc.)
       AND contains at least one known Ansible module key.  The path hint
       prevents false positives in unrelated YAML files.

    3. Full-FQCN module detection: a task dict whose key is a fully-qualified
       Ansible module name (e.g. 'ansible.builtin.apt') is considered Ansible
       regardless of directory — FQCN names are virtually Ansible-exclusive.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            docs = list(yaml.safe_load_all(fh))
    except Exception:
        return False

    # Normalise path separators for hint matching
    normalised_path = file_path.replace("\\", "/").lower()
    in_ansible_dir = any(hint in normalised_path for hint in _ANSIBLE_PATH_HINTS)

    for doc in docs:
        if not isinstance(doc, list):
            continue
        for item in doc:
            if not isinstance(item, dict):
                continue

            # 1. Classic play: 'hosts' + any recognised Ansible play-level key.
            #    'hosts' alone in a list-of-dicts is Ansible-exclusive in
            #    practice, so we only need one additional corroborating key to
            #    avoid false positives on e.g. inventory files.
            if "hosts" in item and item["hosts"] is not None:
                if any(k in item for k in _ANSIBLE_PLAY_KEYS):
                    return True
                # If no other play key is found, still accept it — a minimal
                # play like `- hosts: all` with only `name:` is valid Ansible.
                if set(item.keys()) <= {"hosts", "name", "gather_facts", "become",
                                        "become_user", "connection", "vars",
                                        "vars_files", "serial", "strategy"}:
                    return True

            # 2. Bare task file inside a known Ansible directory
            if in_ansible_dir and any(mod in item for mod in _MODULE_INDEX):
                return True

            # 3. Fully-qualified collection module names are Ansible-exclusive
            if any(
                mod in item
                for mod in _MODULE_INDEX
                if "." in mod  # e.g. ansible.builtin.apt, amazon.aws.ec2_instance
            ):
                return True

    return False


def _is_ansible_inventory(file_path: str) -> bool:
    """
    Decide whether a YAML file is an Ansible **inventory** file.

    Ansible inventory YAML is a top-level *dict* where keys are group names
    (``all``, ``webservers``, …) and values are dicts that may contain
    ``hosts``, ``vars``, and/or ``children`` sub-keys.

    Detection criteria (any one is sufficient):
      1. Top-level key ``all`` whose value contains ``hosts``, ``vars``, or
         ``children`` — this is the canonical YAML inventory structure.
      2. Any other group whose ``hosts`` dict has at least one host entry with
         ``ansible_*`` connection variables, OR whose ``vars`` dict contains
         ``ansible_*`` keys.
      3. Any group whose ``hosts`` dict has bare entries (value is None), which
         is the minimal valid inventory format.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    except Exception:
        return False

    if not isinstance(doc, dict):
        return False

    for group_name, group_data in doc.items():
        if not isinstance(group_data, dict):
            continue
        if not any(k in group_data for k in _INVENTORY_GROUP_KEYS):
            continue

        # Criterion 1: canonical 'all' top-level group.
        if group_name == "all":
            return True

        # Criterion 2 & 3: other groups with ansible_ vars or bare hosts.
        hosts = group_data.get("hosts") or {}
        gvars = group_data.get("vars") or {}
        if isinstance(hosts, dict):
            for hv in hosts.values():
                if isinstance(hv, dict) and any(k.startswith("ansible_") for k in hv):
                    return True
                if hv is None:  # bare hostname entry — valid minimal inventory
                    return True
        if isinstance(gvars, dict) and any(k.startswith("ansible_") for k in gvars):
            return True

    return False


# ── Scanner Class ──────────────────────────────────────────────────────────────

class AnsibleScanner(BaseScanner):
    """Ansible playbook security scanner microservice (Checkov-equivalent checks)."""

    def __init__(self) -> None:
        super().__init__("ansible")

    def scan(self, request: ScanRequest) -> ScanResponse:
        """Execute Ansible security scan across all playbook/task YAML files."""
        start_time = time.time()

        try:
            logger.info(f"[Ansible] Scan started | scan_id={request.scan_id} | repo={request.repo_path}")

            # ── Step 1: Discover Ansible YAML files ───────────────────────────
            playbook_files = self._find_ansible_files(request.repo_path)

            if not playbook_files:
                logger.info("[Ansible] No Ansible YAML files found – skipping scan")
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

            logger.info(f"[Ansible] Found {len(playbook_files)} Ansible file(s)")
            for f in playbook_files:
                logger.info(f"[Ansible]   -> {f}")

            # ── Step 2: Scan each file ─────────────────────────────────────────
            findings: List[ScanFinding] = []
            scanned_files: List[str] = []

            for file_path in playbook_files:
                try:
                    file_findings = self._scan_file(file_path)
                    findings.extend(file_findings)
                    scanned_files.append(file_path)
                    if file_findings:
                        logger.info(f"[Ansible] {len(file_findings)} finding(s) in {file_path}")
                except Exception as exc:
                    logger.error(f"[Ansible] Error scanning {file_path}: {exc}", exc_info=True)

            # ── Step 3: Artifact writing ───────────────────────────────────────
            write_artifacts = os.getenv("WRITE_ARTIFACTS", "false").lower() == "true"
            if findings and request.output_dir and write_artifacts:
                report_path = os.path.join(request.output_dir, "Ansible-Security-Scan-Result.md")
                self._write_findings_report(findings, report_path, "Ansible Security Scan Results")

            # ── Step 4: Scoring ────────────────────────────────────────────────
            overall_score = 100.0
            file_scores: Dict[str, Any] = {}
            try:
                findings_dicts = [
                    {
                        "policy": f.policy or "",
                        "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
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
                logger.info(f"[Ansible] Security score: {overall_score:.2f}")
            except Exception as score_err:
                logger.warning(f"[Ansible] Scoring failed: {score_err}", exc_info=True)

            if findings:
                logger.warning(f"[Ansible] Scan complete — {len(findings)} finding(s)")
            else:
                logger.info("[Ansible] Scan complete — no violations found")

            return self._create_success_response(
                request.scan_id,
                ScanResult(
                    scanner_type=self.scanner_type,
                    status=ScanStatus.COMPLETED,
                    findings=findings,
                    scanned_files=scanned_files,
                    scan_duration=time.time() - start_time,
                    metadata={
                        "ansible_files_found": len(playbook_files),
                        "overall_score": overall_score,
                        "file_scores": file_scores,
                    },
                ),
            )

        except Exception as exc:
            logger.error(f"[Ansible] Scan failed: {exc}", exc_info=True)
            return self._create_error_response(
                request.scan_id,
                f"Ansible scan failed: {str(exc)}",
            )

    # ── File discovery ─────────────────────────────────────────────────────────

    def _find_ansible_files(self, root_dir: str) -> List[str]:
        """Find all Ansible playbook, task, and inventory YAML files under root_dir."""
        matched: List[str] = []
        for dirpath, dirnames, filenames in os.walk(root_dir):
            # Skip hidden dirs and common non-Ansible dirs
            dirnames[:] = [
                d for d in dirnames
                if not d.startswith(".")
                and d not in ("node_modules", ".git", "__pycache__", ".terraform")
            ]
            for fname in filenames:
                if not fname.lower().endswith((".yaml", ".yml")):
                    continue
                full_path = os.path.join(dirpath, fname)
                if _is_ansible_playbook(full_path) or _is_ansible_inventory(full_path):
                    matched.append(full_path)
        return matched

    # ── Per-file scanning ──────────────────────────────────────────────────────

    def _scan_file(self, file_path: str) -> List[ScanFinding]:
        """Parse a single YAML file and run all policy checks against it."""
        with open(file_path, "r", encoding="utf-8") as fh:
            try:
                data = yaml.load(fh, Loader=_LineTrackingLoader)
            except yaml.YAMLError as exc:
                logger.warning(f"[Ansible] YAML parse error in {file_path}: {exc}")
                return [
                    ScanFinding(
                        policy="ANSIBLE_PARSE_ERROR",
                        severity=ScanSeverity.LOW,
                        description=f"YAML parse error: {exc}",
                        code="ANSIBLE_PARSE_ERROR",
                        file=file_path,
                        line=None,
                    )
                ]

        if data is None:
            return []

        # ── Inventory file: top-level dict with group/host structure ──────────
        if isinstance(data, dict):
            return _check_inventory_security(data, file_path)

        # ── Playbook / task file: top-level list of plays ─────────────────────
        plays = data if isinstance(data, list) else []

        findings: List[ScanFinding] = []

        # Task-level policy checks
        all_tasks = _extract_tasks(plays)
        for task in all_tasks:
            if not isinstance(task, dict):
                continue
            task_name: Optional[str] = task.get("name")
            for module, policies in _MODULE_INDEX.items():
                if module not in task:
                    continue
                for check_id, severity_str, check_fn, description in policies:
                    evidence = check_fn(task, module)
                    if evidence is None:
                        continue
                    full_desc = description
                    if task_name:
                        full_desc = f"[task: {task_name}] {description}"
                    findings.append(
                        ScanFinding(
                            policy=check_id,
                            severity=_SEVERITY_MAP.get(severity_str, ScanSeverity.MEDIUM),
                            description=full_desc,
                            code=check_id,
                            file=file_path,
                            line=str(task["__line__"]) if task.get("__line__") else None,
                            match=evidence,
                        )
                    )

        # Structural: block without rescue (ANS-SEC-ERR-001)
        for hit in _check_block_error_handling(plays):
            task_name = hit.get("task_name")
            desc = "Ensure block is handling task errors properly (missing rescue)"
            if task_name:
                desc = f"[task: {task_name}] {desc}"
            findings.append(
                ScanFinding(
                    policy="ANS-SEC-ERR-001",
                    severity=ScanSeverity.LOW,
                    description=desc,
                    code="ANS-SEC-ERR-001",
                    file=file_path,
                    line=str(hit["line"]) if hit.get("line") else None,
                    match=hit.get("evidence"),
                )
            )

        return findings

    # ── Markdown report ────────────────────────────────────────────────────────

    def _write_findings_report(
        self, findings: List[ScanFinding], output_path: str, title: str
    ) -> None:
        try:
            from scanner_core.policy_scanner_common.utils import write_markdown_report
            formatted = [{"file": f.file, "deny": [f.description]} for f in findings]
            write_markdown_report(formatted, output_path, title)
        except Exception as exc:
            logger.warning(f"[Ansible] Could not write markdown report: {exc}")


# ── Module-level entry point ───────────────────────────────────────────────────

def scan_ansible(request: ScanRequest) -> ScanResponse:
    """Ansible scanner microservice entry point."""
    scanner = AnsibleScanner()
    return scanner.scan(request)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Ansible Scanner Microservice")
    parser.add_argument("--repo-path", required=True, help="Repository path to scan")
    parser.add_argument("--output-dir", required=True, help="Output directory for results")
    parser.add_argument("--scan-id", required=True, help="Unique scan ID")

    args = parser.parse_args()

    _request = ScanRequest(
        repo_path=args.repo_path,
        output_dir=args.output_dir,
        scan_id=args.scan_id,
    )

    _response = scan_ansible(_request)
    print(_response.json())
