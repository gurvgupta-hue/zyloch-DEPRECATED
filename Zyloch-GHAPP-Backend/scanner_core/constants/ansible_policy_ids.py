from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class AnsiblePolicy:
    """Represents a single Ansible security policy record."""
    policy_id: str       # ANS-SEC-{CATEGORY}-{NNN} identifier
    title: str           # Short human-readable title
    category: str        # Domain category (e.g. TLS, Package Management)
    module: str          # Primary Ansible module this rule targets
    severity: str        # CRITICAL | HIGH | MEDIUM | LOW
    description: str     # What the rule checks
    remediation: str     # How to fix the violation


class AnsiblePolicyIDs:
    """
    Internal policy ID constants for the Ansible scanner.
    Use AnsiblePolicyMetadata.lookup(policy_id) to get the full record.
    """

    # ==================== TLS / Certificate Validation ====================
    URI_VALIDATE_CERTS            = "ANS-SEC-TLS-001"
    GET_URL_VALIDATE_CERTS        = "ANS-SEC-TLS-002"
    YUM_VALIDATE_CERTS            = "ANS-SEC-TLS-003"
    YUM_SSL_VERIFY                = "ANS-SEC-TLS-004"

    # ==================== Package Management (apt) ====================
    APT_ALLOW_UNAUTHENTICATED     = "ANS-SEC-PKG-001"
    APT_FORCE                     = "ANS-SEC-PKG-002"

    # ==================== HTTPS URL Enforcement ====================
    URI_HTTPS_URL                 = "ANS-SEC-NET-001"
    GET_URL_HTTPS_URL             = "ANS-SEC-NET-002"

    # ==================== Error Handling ====================
    BLOCK_ERROR_HANDLING          = "ANS-SEC-ERR-001"

    # ==================== Package Management (dnf) ====================
    DNF_GPG_CHECK                 = "ANS-SEC-PKG-003"
    DNF_SSL_VERIFY                = "ANS-SEC-TLS-005"
    DNF_VALIDATE_CERTS            = "ANS-SEC-TLS-006"

    # ==================== AWS EC2 ====================
    EC2_NO_PUBLIC_IP              = "ANS-SEC-NET-003"
    EC2_EBS_OPTIMIZED             = "ANS-SEC-EC2-001"

    # ==================== Palo Alto Networks (PANOS) ====================
    PAN_MGMT_NO_HTTP              = "ANS-SEC-PAN-001"
    PAN_MGMT_NO_TELNET            = "ANS-SEC-PAN-002"
    PAN_POLICY_NO_DSRI            = "ANS-SEC-PAN-003"
    PAN_POLICY_NO_APP_ANY         = "ANS-SEC-PAN-004"
    PAN_POLICY_NO_SERVICE_ANY     = "ANS-SEC-PAN-005"
    PAN_POLICY_NO_SRC_DST_ANY     = "ANS-SEC-PAN-006"
    PAN_POLICY_DESCRIPTION        = "ANS-SEC-PAN-007"
    PAN_POLICY_LOG_FORWARDING     = "ANS-SEC-PAN-008"
    PAN_POLICY_LOG_SESSION_END    = "ANS-SEC-PAN-009"
    PAN_IPSEC_AUTH_ALGORITHMS     = "ANS-SEC-PAN-010"
    PAN_IPSEC_PROTOCOLS           = "ANS-SEC-PAN-011"
    PAN_ZONE_PROTECTION_PROFILE   = "ANS-SEC-PAN-012"
    PAN_ZONE_USERID_INCLUDE_ACL   = "ANS-SEC-PAN-013"
    PAN_POLICY_NO_LOG_SESSION_START = "ANS-SEC-PAN-014"
    PAN_POLICY_NO_ZONE_ANY        = "ANS-SEC-PAN-015"

    # ==================== Inventory Security ====================
    INV_HARDCODED_CREDENTIALS     = "ANS-SEC-INV-001"
    INV_PLAINTEXT_SSH_PASS        = "ANS-SEC-INV-002"
    INV_ROOT_USER                 = "ANS-SEC-INV-003"
    INV_STRICT_HOST_KEY_CHECKING  = "ANS-SEC-INV-004"


class AnsiblePolicyMetadata:
    """
    Full metadata for every Ansible scanner policy, keyed by policy_id.
    Provides fast O(1) lookup at scan-finding-enrichment time.
    """

    METADATA: Dict[str, AnsiblePolicy] = {

        # ── TLS / Certificate Validation ─────────────────────────────────────
        AnsiblePolicyIDs.URI_VALIDATE_CERTS: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.URI_VALIDATE_CERTS,
            title="uri: Certificate Validation Enabled",
            category="TLS",
            module="uri / ansible.builtin.uri",
            severity="HIGH",
            description=(
                "Ensure that the 'uri' module does not disable certificate "
                "validation. Setting validate_certs: false bypasses TLS "
                "verification, exposing the connection to MITM attacks."
            ),
            remediation=(
                "Remove 'validate_certs: false' or set it to 'true'. "
                "If using a self-signed cert, add it to the system trust store "
                "and keep certificate validation enabled."
            ),
        ),
        AnsiblePolicyIDs.GET_URL_VALIDATE_CERTS: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.GET_URL_VALIDATE_CERTS,
            title="get_url: Certificate Validation Enabled",
            category="TLS",
            module="get_url / ansible.builtin.get_url",
            severity="HIGH",
            description=(
                "Ensure that the 'get_url' module does not disable certificate "
                "validation. Disabling it allows downloading from forged endpoints."
            ),
            remediation=(
                "Remove 'validate_certs: false' or set it to 'true'. "
                "Supply a valid CA bundle via 'ca_path' if needed."
            ),
        ),
        AnsiblePolicyIDs.YUM_VALIDATE_CERTS: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.YUM_VALIDATE_CERTS,
            title="yum: Certificate Validation Enabled",
            category="TLS",
            module="yum / ansible.builtin.yum",
            severity="MEDIUM",
            description=(
                "Ensure that the 'yum' module does not disable certificate "
                "validation, which would allow installation from untrusted repos."
            ),
            remediation=(
                "Remove 'validate_certs: false' or set it to 'true'. "
                "Configure the repo with a valid SSL certificate."
            ),
        ),
        AnsiblePolicyIDs.YUM_SSL_VERIFY: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.YUM_SSL_VERIFY,
            title="yum: SSL Verification Enabled",
            category="TLS",
            module="yum / ansible.builtin.yum",
            severity="MEDIUM",
            description=(
                "Ensure that 'sslverify' is not disabled in the yum module. "
                "Disabling SSL verification exposes package downloads to tampering."
            ),
            remediation=(
                "Remove 'sslverify: false' or set it to 'true'. "
                "Ensure the repository SSL certificate is valid and trusted."
            ),
        ),

        # ── Package Management (apt) ──────────────────────────────────────────
        AnsiblePolicyIDs.APT_ALLOW_UNAUTHENTICATED: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.APT_ALLOW_UNAUTHENTICATED,
            title="apt: Reject Unauthenticated Packages",
            category="Package Management",
            module="apt / ansible.builtin.apt",
            severity="HIGH",
            description=(
                "Ensure 'allow_unauthenticated: true' is not set in the apt module. "
                "This option bypasses GPG signature validation, allowing installation "
                "of unsigned or tampered packages."
            ),
            remediation=(
                "Remove 'allow_unauthenticated: true'. "
                "Import the repository GPG key with the 'apt_key' module instead."
            ),
        ),
        AnsiblePolicyIDs.APT_FORCE: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.APT_FORCE,
            title="apt: force/force_yes Must Not Be Used",
            category="Package Management",
            module="apt / ansible.builtin.apt",
            severity="HIGH",
            description=(
                "Ensure 'force: true' or 'force_yes: true' is not used with the "
                "apt module. These flags disable signature validation checks and "
                "may install broken or insecure packages."
            ),
            remediation=(
                "Remove 'force: true' / 'force_yes: true'. "
                "Resolve dependency conflicts explicitly or use "
                "'allow_downgrade: true' only when downgrading is intentional."
            ),
        ),

        # ── HTTPS URL Enforcement ─────────────────────────────────────────────
        AnsiblePolicyIDs.URI_HTTPS_URL: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.URI_HTTPS_URL,
            title="uri: Use HTTPS URL",
            category="Network Security",
            module="uri / ansible.builtin.uri",
            severity="MEDIUM",
            description=(
                "Ensure all URLs passed to the 'uri' module use the HTTPS scheme. "
                "Plain HTTP transmits data in cleartext, enabling eavesdropping "
                "and content injection."
            ),
            remediation=(
                "Replace 'http://' with 'https://' in the 'url' parameter. "
                "If the server does not support HTTPS, enable it or use a "
                "secure proxy."
            ),
        ),
        AnsiblePolicyIDs.GET_URL_HTTPS_URL: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.GET_URL_HTTPS_URL,
            title="get_url: Use HTTPS URL",
            category="Network Security",
            module="get_url / ansible.builtin.get_url",
            severity="MEDIUM",
            description=(
                "Ensure all URLs passed to the 'get_url' module use the HTTPS "
                "scheme. HTTP downloads can be intercepted and the file replaced "
                "with malicious content."
            ),
            remediation=(
                "Replace 'http://' with 'https://' in the 'url' parameter. "
                "Combine with 'checksum:' to verify file integrity."
            ),
        ),

        # ── Error Handling ────────────────────────────────────────────────────
        AnsiblePolicyIDs.BLOCK_ERROR_HANDLING: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.BLOCK_ERROR_HANDLING,
            title="Block: Rescue Section Required",
            category="Error Handling",
            module="block",
            severity="LOW",
            description=(
                "Every Ansible 'block' statement should include a 'rescue' section. "
                "Without rescue, failures inside the block propagate unhandled, "
                "potentially leaving the system in an inconsistent state."
            ),
            remediation=(
                "Add a 'rescue:' section to the block to handle errors gracefully. "
                "Use 'always:' for cleanup tasks that must run regardless of outcome."
            ),
        ),

        # ── Package Management (dnf) ──────────────────────────────────────────
        AnsiblePolicyIDs.DNF_GPG_CHECK: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.DNF_GPG_CHECK,
            title="dnf: GPG Check Must Not Be Disabled",
            category="Package Management",
            module="dnf / ansible.builtin.dnf",
            severity="HIGH",
            description=(
                "Ensure 'disable_gpg_check: true' is not set in the dnf module. "
                "Disabling GPG checks allows installation of unsigned or tampered "
                "packages from any source."
            ),
            remediation=(
                "Remove 'disable_gpg_check: true'. "
                "Import the GPG key for the repository using 'rpm_key' module."
            ),
        ),
        AnsiblePolicyIDs.DNF_SSL_VERIFY: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.DNF_SSL_VERIFY,
            title="dnf: SSL Verification Enabled",
            category="TLS",
            module="dnf / ansible.builtin.dnf",
            severity="MEDIUM",
            description=(
                "Ensure 'sslverify' is not disabled in the dnf module. "
                "Disabling it exposes package repo traffic to MITM attacks."
            ),
            remediation=(
                "Remove 'sslverify: false' or set it to 'true'. "
                "Ensure the repository uses a valid, trusted SSL certificate."
            ),
        ),
        AnsiblePolicyIDs.DNF_VALIDATE_CERTS: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.DNF_VALIDATE_CERTS,
            title="dnf: Certificate Validation Enabled",
            category="TLS",
            module="dnf / ansible.builtin.dnf",
            severity="HIGH",
            description=(
                "Ensure 'validate_certs: false' is not set in the dnf module. "
                "Certificate validation ensures the package source is authentic."
            ),
            remediation=(
                "Remove 'validate_certs: false' or set it to 'true'. "
                "Configure the correct CA certificates on the target host."
            ),
        ),

        # ── Inventory Security ────────────────────────────────────────────────
        AnsiblePolicyIDs.INV_HARDCODED_CREDENTIALS: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.INV_HARDCODED_CREDENTIALS,
            title="Inventory: No Hardcoded Cloud Credentials",
            category="Secrets Management",
            module="inventory vars",
            severity="HIGH",
            description=(
                "Ansible inventory files must not contain hard-coded cloud provider "
                "credentials (AWS access/secret keys, Azure client secrets, GCP "
                "service account keys, API tokens, etc.). Committing these values "
                "to source control exposes them to anyone with repository access."
            ),
            remediation=(
                "Remove the credential values from the inventory file and reference "
                "them via Ansible Vault, environment variables, or a dedicated "
                "secrets manager such as HashiCorp Vault or AWS Secrets Manager. "
                "Use Jinja2 lookups (env, hashi_vault, aws_ssm) to inject values "
                "at runtime without committing them to source control."
            ),
        ),
        AnsiblePolicyIDs.INV_PLAINTEXT_SSH_PASS: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.INV_PLAINTEXT_SSH_PASS,
            title="Inventory: No Plain-Text SSH / Become Passwords",
            category="Secrets Management",
            module="inventory host vars",
            severity="HIGH",
            description=(
                "Storing SSH passwords (ansible_ssh_pass, ansible_become_pass, "
                "ansible_password, ansible_sudo_pass) as plain text in inventory "
                "files is a critical security risk. These values are visible to "
                "anyone with access to the repository or the filesystem."
            ),
            remediation=(
                "Encrypt the inventory file with Ansible Vault "
                "(ansible-vault encrypt inventory.yml) or use SSH key-based "
                "authentication instead of password-based auth."
            ),
        ),
        AnsiblePolicyIDs.INV_ROOT_USER: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.INV_ROOT_USER,
            title="Inventory: Do Not Connect as root",
            category="Least Privilege",
            module="inventory host vars",
            severity="HIGH",
            description=(
                "Setting ansible_user: root in inventory causes every task to run "
                "with full root privileges on the managed host. A single misconfigured "
                "task or compromised control node can cause irreversible damage."
            ),
            remediation=(
                "Use a non-privileged service account and escalate only where "
                "required via 'become: yes' on individual tasks or plays. "
                "Grant only the minimum sudo rules needed."
            ),
        ),
        AnsiblePolicyIDs.INV_STRICT_HOST_KEY_CHECKING: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.INV_STRICT_HOST_KEY_CHECKING,
            title="Inventory: StrictHostKeyChecking Must Not Be Disabled",
            category="Network Security",
            module="inventory host vars",
            severity="MEDIUM",
            description=(
                "Setting -o StrictHostKeyChecking=no in ansible_ssh_common_args "
                "disables SSH host key verification, making connections vulnerable "
                "to man-in-the-middle (MITM) attacks where an attacker can intercept "
                "and alter the communication."
            ),
            remediation=(
                "Remove StrictHostKeyChecking=no. Pre-populate the control node's "
                "known_hosts file with the target host keys using ssh-keyscan, "
                "or set ANSIBLE_HOST_KEY_CHECKING=True in ansible.cfg."
            ),
        ),

        # ── AWS EC2 ───────────────────────────────────────────────────────────
        AnsiblePolicyIDs.EC2_NO_PUBLIC_IP: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.EC2_NO_PUBLIC_IP,
            title="EC2: No Public IP Assignment",
            category="Network Security",
            module="ec2_instance / amazon.aws.ec2_instance",
            severity="HIGH",
            description=(
                "Ensure EC2 instances are not assigned a public IP address directly "
                "via 'network.assign_public_ip: true' or 'assign_public_ip: true'. "
                "Public IPs increase the attack surface; use a load balancer or "
                "NAT gateway instead."
            ),
            remediation=(
                "Set 'assign_public_ip: false' (or remove the parameter, as false "
                "is the default for instances launched in a VPC subnet without "
                "auto-assign enabled). Route external traffic through an ELB/ALB."
            ),
        ),
        AnsiblePolicyIDs.EC2_EBS_OPTIMIZED: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.EC2_EBS_OPTIMIZED,
            title="EC2: EBS Optimization Enabled",
            category="Compute Security",
            module="ec2_instance / amazon.aws.ec2_instance",
            severity="LOW",
            description=(
                "Ensure EC2 instances have EBS optimization enabled. EBS-optimized "
                "instances provide dedicated bandwidth to Amazon EBS, improving I/O "
                "performance and preventing resource contention that could be "
                "exploited by a noisy-neighbour attack vector."
            ),
            remediation=(
                "Set 'ebs_optimized: true' in the ec2_instance task. Verify that "
                "the chosen instance type supports EBS optimization."
            ),
        ),

        # ── Palo Alto Networks (PANOS) ────────────────────────────────────────
        AnsiblePolicyIDs.PAN_MGMT_NO_HTTP: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.PAN_MGMT_NO_HTTP,
            title="PANOS: Management Profile Must Not Allow HTTP",
            category="Network Security",
            module="paloaltonetworks.panos.panos_management_profile",
            severity="HIGH",
            description=(
                "Ensure plain-text HTTP management is not enabled on a Palo Alto "
                "Networks Interface Management Profile. HTTP transmits credentials "
                "and management traffic in cleartext, enabling eavesdropping and "
                "session hijacking."
            ),
            remediation=(
                "Set 'http: false' (or omit the key) in the "
                "panos_management_profile task. Use HTTPS for all management access."
            ),
        ),
        AnsiblePolicyIDs.PAN_MGMT_NO_TELNET: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.PAN_MGMT_NO_TELNET,
            title="PANOS: Management Profile Must Not Allow Telnet",
            category="Network Security",
            module="paloaltonetworks.panos.panos_management_profile",
            severity="HIGH",
            description=(
                "Ensure Telnet management is not enabled on a Palo Alto Networks "
                "Interface Management Profile. Telnet sends all data including "
                "credentials in plaintext over the network."
            ),
            remediation=(
                "Set 'telnet: false' (or omit the key) in the "
                "panos_management_profile task. Use SSH for CLI access instead."
            ),
        ),
        AnsiblePolicyIDs.PAN_POLICY_NO_DSRI: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.PAN_POLICY_NO_DSRI,
            title="PANOS: DSRI Must Not Be Enabled in Security Policies",
            category="Firewall Policy",
            module="paloaltonetworks.panos.panos_security_rule",
            severity="MEDIUM",
            description=(
                "Ensure Disable Server Response Inspection (DSRI) is not enabled "
                "within Palo Alto security policies. DSRI prevents the firewall from "
                "inspecting server-to-client traffic, hiding malicious payloads "
                "in responses."
            ),
            remediation=(
                "Set 'disable_server_response_inspection: false' (or omit it, "
                "as false is the default) in all panos_security_rule tasks."
            ),
        ),
        AnsiblePolicyIDs.PAN_POLICY_NO_APP_ANY: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.PAN_POLICY_NO_APP_ANY,
            title="PANOS: Security Rules Must Not Use Application 'any'",
            category="Firewall Policy",
            module="paloaltonetworks.panos.panos_security_rule",
            severity="HIGH",
            description=(
                "Ensure Palo Alto security rules do not have 'application' set to "
                "'any'. Allowing any application bypasses App-ID inspection and "
                "permits unapproved or malicious applications to traverse the firewall."
            ),
            remediation=(
                "Replace 'application: any' with a specific list of approved "
                "application identifiers in the panos_security_rule task."
            ),
        ),
        AnsiblePolicyIDs.PAN_POLICY_NO_SERVICE_ANY: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.PAN_POLICY_NO_SERVICE_ANY,
            title="PANOS: Security Rules Must Not Use Service 'any'",
            category="Firewall Policy",
            module="paloaltonetworks.panos.panos_security_rule",
            severity="HIGH",
            description=(
                "Ensure Palo Alto security rules do not have 'service' set to 'any'. "
                "Permitting any service allows traffic on all ports and protocols, "
                "significantly widening the attack surface."
            ),
            remediation=(
                "Replace 'service: any' with specific service objects or "
                "'application-default' in the panos_security_rule task."
            ),
        ),
        AnsiblePolicyIDs.PAN_POLICY_NO_SRC_DST_ANY: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.PAN_POLICY_NO_SRC_DST_ANY,
            title="PANOS: Security Rules Must Not Have Both Source and Destination IP 'any'",
            category="Firewall Policy",
            module="paloaltonetworks.panos.panos_security_rule",
            severity="HIGH",
            description=(
                "Ensure Palo Alto security rules do not have both 'source_ip' and "
                "'destination_ip' set to 'any'. This creates an unrestricted "
                "allow-all rule that defeats the purpose of having a firewall."
            ),
            remediation=(
                "Restrict at least one of 'source_ip' or 'destination_ip' to "
                "specific IP addresses, address objects, or address groups."
            ),
        ),
        AnsiblePolicyIDs.PAN_POLICY_DESCRIPTION: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.PAN_POLICY_DESCRIPTION,
            title="PANOS: Security Policies Must Have a Description",
            category="Firewall Policy",
            module="paloaltonetworks.panos.panos_security_rule",
            severity="LOW",
            description=(
                "Ensure every Palo Alto security policy rule includes a description. "
                "Undocumented rules make auditing difficult, increase the risk of "
                "accidental misconfigurations going unnoticed, and complicate "
                "compliance reporting."
            ),
            remediation=(
                "Add a meaningful 'description:' field to each panos_security_rule "
                "task explaining the business justification for the rule."
            ),
        ),
        AnsiblePolicyIDs.PAN_POLICY_LOG_FORWARDING: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.PAN_POLICY_LOG_FORWARDING,
            title="PANOS: Security Policies Must Have a Log Forwarding Profile",
            category="Logging & Monitoring",
            module="paloaltonetworks.panos.panos_security_rule",
            severity="MEDIUM",
            description=(
                "Ensure a Log Forwarding Profile is selected for each Palo Alto "
                "security policy rule. Without log forwarding, security events are "
                "stored only on the device and may be lost or unavailable for "
                "centralised SIEM analysis."
            ),
            remediation=(
                "Set 'log_forwarding: <profile_name>' in each panos_security_rule "
                "task to forward logs to a Panorama log collector or external syslog."
            ),
        ),
        AnsiblePolicyIDs.PAN_POLICY_LOG_SESSION_END: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.PAN_POLICY_LOG_SESSION_END,
            title="PANOS: Logging at Session End Must Be Enabled",
            category="Logging & Monitoring",
            module="paloaltonetworks.panos.panos_security_rule",
            severity="MEDIUM",
            description=(
                "Ensure logging at session end is enabled within Palo Alto security "
                "policies. Session-end logs capture the full traffic summary including "
                "bytes transferred and application, which is essential for incident "
                "investigation and compliance."
            ),
            remediation=(
                "Set 'log_end: true' in each panos_security_rule task. "
                "This is the PAN-OS default; verify it is not explicitly disabled."
            ),
        ),
        AnsiblePolicyIDs.PAN_IPSEC_AUTH_ALGORITHMS: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.PAN_IPSEC_AUTH_ALGORITHMS,
            title="PANOS: IPsec Profiles Must Not Use Insecure Authentication Algorithms",
            category="Cryptography",
            module="paloaltonetworks.panos.panos_ipsec_profile",
            severity="HIGH",
            description=(
                "Ensure Palo Alto IPsec profiles do not specify insecure "
                "authentication algorithms such as MD5 or SHA-1. These algorithms "
                "are cryptographically broken and susceptible to collision attacks."
            ),
            remediation=(
                "Replace MD5 and SHA-1 with SHA-256, SHA-384, or SHA-512 in the "
                "'authentication' list of the panos_ipsec_profile task."
            ),
        ),
        AnsiblePolicyIDs.PAN_IPSEC_PROTOCOLS: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.PAN_IPSEC_PROTOCOLS,
            title="PANOS: IPsec Profiles Must Not Use Insecure Protocols",
            category="Cryptography",
            module="paloaltonetworks.panos.panos_ipsec_profile",
            severity="HIGH",
            description=(
                "Ensure Palo Alto IPsec profiles do not specify insecure protocols "
                "or encryption algorithms (e.g. DES, 3DES, NULL encryption). "
                "These algorithms provide inadequate or no confidentiality for VPN "
                "traffic."
            ),
            remediation=(
                "Replace DES/3DES with AES-128-CBC, AES-256-CBC, AES-128-GCM, "
                "or AES-256-GCM. Remove any NULL encryption entries from the "
                "'encryption' list in the panos_ipsec_profile task."
            ),
        ),
        AnsiblePolicyIDs.PAN_ZONE_PROTECTION_PROFILE: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.PAN_ZONE_PROTECTION_PROFILE,
            title="PANOS: Security Zones Must Have a Zone Protection Profile",
            category="Firewall Policy",
            module="paloaltonetworks.panos.panos_zone",
            severity="MEDIUM",
            description=(
                "Ensure a Zone Protection Profile is defined for every Palo Alto "
                "security zone. Without it, the zone is unprotected against "
                "reconnaissance, flood, and packet-based attacks."
            ),
            remediation=(
                "Set 'zone_profile: <profile_name>' in each panos_zone task. "
                "Create a Zone Protection Profile in Panorama/PAN-OS that enables "
                "flood protection, reconnaissance detection, and packet-based "
                "attack protection."
            ),
        ),
        AnsiblePolicyIDs.PAN_ZONE_USERID_INCLUDE_ACL: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.PAN_ZONE_USERID_INCLUDE_ACL,
            title="PANOS: Zone User-ID Must Define an Include ACL",
            category="Firewall Policy",
            module="paloaltonetworks.panos.panos_zone",
            severity="MEDIUM",
            description=(
                "Ensure an Include ACL is defined for a Palo Alto security zone "
                "when User-ID is enabled. Without an Include ACL, User-ID collects "
                "identity information from all subnets in the zone, which may "
                "inadvertently expose sensitive authentication data."
            ),
            remediation=(
                "Set 'include_acl: [<subnet>]' when 'enable_userid: true' is "
                "configured in the panos_zone task. Limit User-ID to only the "
                "subnets that require identity-based policy."
            ),
        ),
        AnsiblePolicyIDs.PAN_POLICY_NO_LOG_SESSION_START: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.PAN_POLICY_NO_LOG_SESSION_START,
            title="PANOS: Session-Start Logging Must Be Disabled Except for Troubleshooting",
            category="Logging & Monitoring",
            module="paloaltonetworks.panos.panos_security_rule",
            severity="LOW",
            description=(
                "Ensure logging at session start is disabled within Palo Alto "
                "security policies except for intentional troubleshooting or "
                "long-lived GRE tunnels. Session-start logging doubles log volume "
                "and can overwhelm log collectors, causing log-loss events that "
                "hide genuine security incidents."
            ),
            remediation=(
                "Set 'log_start: false' in panos_security_rule tasks. "
                "Enable it only temporarily for specific troubleshooting rules "
                "and remove it once the investigation is complete."
            ),
        ),
        AnsiblePolicyIDs.PAN_POLICY_NO_ZONE_ANY: AnsiblePolicy(
            policy_id=AnsiblePolicyIDs.PAN_POLICY_NO_ZONE_ANY,
            title="PANOS: Security Rules Must Not Have Both Source and Destination Zone 'any'",
            category="Firewall Policy",
            module="paloaltonetworks.panos.panos_security_rule",
            severity="HIGH",
            description=(
                "Ensure Palo Alto security rules do not have both 'source_zone' and "
                "'destination_zone' set to 'any'. A rule with both zones as 'any' "
                "matches all inter-zone and intra-zone traffic, effectively creating "
                "a universal allow rule."
            ),
            remediation=(
                "Restrict at least one of 'source_zone' or 'destination_zone' to "
                "a specific zone. Follow the principle of least privilege and only "
                "permit traffic between zones that have a documented business need."
            ),
        ),
    }

    @classmethod
    def lookup(cls, policy_id: str) -> Optional[AnsiblePolicy]:
        """Return the AnsiblePolicy for *policy_id*, or None if not found."""
        return cls.METADATA.get(policy_id)
