from typing import Optional
from dataclasses import dataclass

@dataclass(frozen=True)
class CVE:
    """Represents a single Kubernetes CVE record."""
    cveId: str
    security: str
    message: str


class K8SCVEIDs:
    """Centralized repository of Kubernetes CVE details with fast lookup."""

    # ==================== AppArmor Policies ====================
    APPARMOR_PROFILE_MISSING = "K8S-SEC-APPARMOR-001"

    # ==================== Capabilities Policies ====================
    DISALLOWED_CAPABILITIES = "K8S-SEC-CAP-001"

    # ==================== Host Isolation Policies ====================
    HOST_NETWORK_USAGE = "K8S-SEC-HOST-001"
    HOST_PATH_VOLUMES = "K8S-SEC-HOST-002"
    HOST_PORT_USAGE = "K8S-SEC-HOST-003"
    HOST_PROCESS_USAGE = "K8S-SEC-HOST-004"
    HOST_IPC_USAGE = "K8S-SEC-HOST-005"
    HOST_PID_USAGE = "K8S-SEC-HOST-006"

    # ==================== Image Policies ====================
    IMAGE_PULL_POLICY = "K8S-SEC-IMG-001"
    LATEST_IMAGE_TAG = "K8S-SEC-IMG-002"

    # ==================== Privilege Policies ====================
    PRIVILEGED_MODE = "K8S-SEC-PRIV-001"

    # ==================== Probe Policies ====================
    MISSING_READINESS_PROBE = "K8S-SEC-PROBE-001"
    MISSING_LIVENESS_PROBE = "K8S-SEC-PROBE-002"

    # ==================== Seccomp Policies ====================
    DISALLOWED_SECCOMP = "K8S-SEC-SECCOMP-001"

    # ==================== SELinux Policies ====================
    SELINUX_USER_POD = "K8S-SEC-SELINUX-001"
    SELINUX_ROLE_POD = "K8S-SEC-SELINUX-002"
    SELINUX_TYPE_POD = "K8S-SEC-SELINUX-003"
    SELINUX_USER_CONTAINER = "K8S-SEC-SELINUX-004"
    SELINUX_ROLE_CONTAINER = "K8S-SEC-SELINUX-005"
    SELINUX_TYPE_CONTAINER = "K8S-SEC-SELINUX-006"

    # ==================== Sysctl Policies ====================
    DISALLOWED_SYSCTLS = "K8S-SEC-SYSCTL-001"

    # ==================== Proc Mount Policies ====================
    DISALLOWED_PROC_MOUNT = "K8S-SEC-PROC-001"

    # ==================== Resource Policies ====================
    MISSING_RESOURCE_LIMITS = "K8S-SEC-RES-001"

    _vulnerabilities = [
        CVE("K8S-SEC-APPARMOR-001", "High", "Container must use AppArmor profile"),
        CVE("K8S-SEC-CAP-001", "High", "Container uses disallowed Linux capabilities"),
        CVE("K8S-SEC-HOST-001", "High", "Pod uses hostNetwork which is not allowed"),
        CVE("K8S-SEC-HOST-002", "High", "Pod uses hostPath volumes which are restricted"),
        CVE("K8S-SEC-HOST-003", "High", "Container uses hostPort which is not allowed"),
        CVE("K8S-SEC-HOST-004", "High", "Container uses HostProcess which is restricted"),
        CVE("K8S-SEC-HOST-005", "High", "Pod uses hostIPC which is not allowed"),
        CVE("K8S-SEC-HOST-006", "High", "Pod uses hostPID which is not allowed"),
        CVE("K8S-SEC-IMG-001", "Medium", "Container imagePullPolicy should be Always"),
        CVE("K8S-SEC-IMG-002", "Medium", "Container uses latest or untagged image"),
        CVE("K8S-SEC-PRIV-001", "Critical", "Container runs in privileged mode"),
        CVE("K8S-SEC-PROBE-001", "Medium", "Container missing readinessProbe"),
        CVE("K8S-SEC-PROBE-002", "Medium", "Container missing livenessProbe"),
        CVE("K8S-SEC-SECCOMP-001", "High", "Container uses disallowed seccomp profile"),
        CVE("K8S-SEC-SELINUX-001", "High", "SELinux user violation at pod level"),
        CVE("K8S-SEC-SELINUX-002", "High", "SELinux role violation at pod level"),
        CVE("K8S-SEC-SELINUX-003", "High", "SELinux type violation at pod level"),
        CVE("K8S-SEC-SELINUX-004", "High", "SELinux user violation at container level"),
        CVE("K8S-SEC-SELINUX-005", "High", "SELinux role violation at container level"),
        CVE("K8S-SEC-SELINUX-006", "High", "SELinux type violation at container level"),
        CVE("K8S-SEC-SYSCTL-001", "High", "Container uses disallowed sysctl settings"),
        CVE("K8S-SEC-PROC-001", "High", "Container uses disallowed /proc mount"),
        CVE("K8S-SEC-RES-001", "Medium", "Container missing resource limits/requests"),
    ]

    # ✅ Pre-index CVEs for O(1) lookup
    _index = {v.cveId: v for v in _vulnerabilities}

    @classmethod
    def get(cls, cve_id: str) -> Optional[CVE]:
        """
        Returns the CVE object matching the given ID.

        Args:
            cve_id (str): CVE identifier (e.g. 'K8S-SEC-001').

        Returns:
            CVE | None: The CVE object if found, otherwise None.
        """
        return cls._index.get(cve_id)
