from typing import Set, Dict, List


class DockerSecurityConstants:
    """Constants for Docker security validation"""
    
    # Severity levels
    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_LOW = "LOW"
    SEVERITY_INFO = "INFO"
    
    # File types
    FILE_TYPE_DOCKERFILE = "Dockerfile"
    FILE_TYPE_DOCKER_COMPOSE = "docker-compose"
    
    # Dangerous capabilities that should be avoided
    DANGEROUS_CAPABILITIES: Set[str] = {
        "SYS_ADMIN",
        "SYS_MODULE",
        "SYS_RAWIO",
        "SYS_BOOT",
        "SYS_TIME",
        "SYS_PTRACE",
        "NET_ADMIN",
        "NET_RAW",
        "SYS_RESOURCE",
        "MKNOD",
        "AUDIT_CONTROL",
        "AUDIT_READ",
        "BLOCK_SUSPEND",
        "BPF",
        "CHECKPOINT_RESTORE",
        "DAC_READ_SEARCH",
        "IPC_LOCK",
        "IPC_OWNER",
        "LEASE",
        "LINUX_IMMUTABLE",
        "MAC_ADMIN",
        "MAC_OVERRIDE",
        "PERFMON",
        "SETPCAP",
        "SYSLOG",
        "WAKE_ALARM"
    }
    
    # Suspicious environment variable keys that might contain secrets
    SUSPICIOUS_ENV_KEYS: List[str] = [
        "password", "passwd", "pwd",
        "secret", "key", "token", "auth",
        "api_key", "apikey", "api_secret",
        "database_url", "db_password", "db_pass",
        "private_key", "priv_key", "ssl_key",
        "access_key", "secret_key", "session_key",
        "jwt_secret", "oauth", "credential", "cred"
    ]
    
    # Forbidden image tags
    FORBIDDEN_IMAGE_TAGS: List[str] = [
        "latest", "master", "main", "dev", "development"
    ]
    
    # Allowed/safe capabilities
    SAFE_CAPABILITIES: Set[str] = {
        "AUDIT_WRITE",
        "CHOWN",
        "DAC_OVERRIDE",
        "FOWNER",
        "FSETID",
        "KILL",
        "NET_BIND_SERVICE",
        "SETFCAP",
        "SETGID",
        "SETUID",
        "SYS_CHROOT"
    }
    
    # Insecure base images
    INSECURE_BASE_IMAGES: Set[str] = {
        "ubuntu:latest",
        "debian:latest",
        "centos:latest",
        "alpine:latest",
        "node:latest",
        "python:latest",
        "nginx:latest"
    }
    
    # Insecure ports (commonly targeted)
    INSECURE_PORTS: Set[int] = {
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        53,    # DNS
        80,    # HTTP
        110,   # POP3
        135,   # RPC
        139,   # NetBIOS
        143,   # IMAP
        443,   # HTTPS
        445,   # SMB
        993,   # IMAPS
        995,   # POP3S
        1433,  # SQL Server
        1521,  # Oracle
        2049,  # NFS
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        5900,  # VNC
        6379,  # Redis
        8080,  # HTTP Alt
        8443,  # HTTPS Alt
        9200,  # Elasticsearch
        27017  # MongoDB
    }
    
    # Privileged ports (0-1023)
    PRIVILEGED_PORTS = set(range(0, 1024))
    
    # Insecure environment variable patterns
    INSECURE_ENV_PATTERNS: Set[str] = {
        "PASSWORD",
        "PASS",
        "SECRET",
        "TOKEN",
        "KEY",
        "API_KEY",
        "PRIVATE_KEY",
        "DB_PASSWORD",
        "DATABASE_PASSWORD",
        "MYSQL_PASSWORD",
        "POSTGRES_PASSWORD",
        "REDIS_PASSWORD",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "SLACK_TOKEN"
    }
    
    # Dockerfile instructions that require security review
    SECURITY_SENSITIVE_INSTRUCTIONS: Set[str] = {
        "USER",
        "RUN",
        "COPY",
        "ADD",
        "EXPOSE",
        "ENV",
        "ENTRYPOINT",
        "CMD",
        "WORKDIR",
        "VOLUME"
    }
    
    # Package managers and their update commands
    PACKAGE_MANAGERS: Dict[str, str] = {
        "apt": "apt-get update",
        "apt-get": "apt-get update",
        "yum": "yum update",
        "dnf": "dnf update",
        "apk": "apk update",
        "zypper": "zypper refresh",
        "pacman": "pacman -Sy"
    }
    
    # Package upgrade commands that make builds non-reproducible
    PACKAGE_UPGRADE_COMMANDS: List[str] = [
        "apt-get upgrade",
        "apt upgrade",
        "apt-get dist-upgrade",
        "apt dist-upgrade",
        "yum update",
        "yum upgrade",
        "dnf upgrade",
        "apk upgrade",
        "zypper update",
        "pacman -Syu",
        "pip install --upgrade",
        "pip install -U"
    ]

    # Common secret file paths
    SECRET_FILE_PATHS: Set[str] = {
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/root/.ssh/",
        "/home/*/.ssh/",
        "*.pem",
        "*.key",
        "*.p12",
        "*.pfx",
        "*.jks",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        ".env",
        "config.json",
        "secrets.json"
    }
    
    # Insecure network modes
    INSECURE_NETWORK_MODES: Set[str] = {
        "host",
        "container"
    }
    
    # Reference table of policy codes -> description, kept in sync with the
    # cve_id literal each checker actually passes to add_violation(). This is
    # documentation only (nothing in the codebase looks values up from this
    # dict), but it previously drifted badly out of sync with the real
    # checkers: the "Additional mappings for new checkers" section below used
    # to list a completely different, never-emitted "CVE-2023-*" code for
    # every one of those checkers (e.g. it claimed env_secrets_checker.py
    # emitted "CVE-2023-ENV-SECRETS", while the checker has always emitted
    # "DOCKER-SEC-006") - a stale block that was never wired to anything.
    # Verify against the checker source (grep for `cve_id=`) before editing.
    CVE_MAPPINGS = {
        "DOCKER-SEC-001": "Use of latest tag in FROM instruction",
        "DOCKER-SEC-002": "Running as root user",
        "DOCKER-SEC-003": "Privileged mode enabled",
        "DOCKER-SEC-004": "Adding dangerous capabilities",
        "DOCKER-SEC-005": "(unused - reserved) Exposing insecure ports",
        "DOCKER-SEC-006": "Hardcoded secrets in environment variables",
        "DOCKER-SEC-007": "Using ADD instead of COPY for local files",
        "DOCKER-SEC-008": "Running a full system package upgrade",
        "DOCKER-SEC-009": "Copying sensitive files",
        "DOCKER-SEC-010": "Using insecure network mode",
        "DOCKER-SEC-011": "Missing health checks",
        "DOCKER-SEC-012": "Overly permissive volume mounts",
        "DOCKER-SEC-013": "Using deprecated or insecure base images",
        "DOCKER-SEC-014": "Missing resource limits",
        "DOCKER-SEC-015": "Insecure restart policy",
        "DOCKER-SEC-016": "(unused - reserved) Using default ports for services",
        "DOCKER-SEC-017": "Missing security options",
        "DOCKER-SEC-018": "Dockerfile not following multi-stage build",
        "DOCKER-SEC-019": "Disabling TLS certificate verification in curl",
        "DOCKER-SEC-020": "Installing/enabling a non-essential background service",
        "DOCKER-SEC-021": "Potential crypto-mining/malware indicator detected",
        "DOCKER-SEC-022": "Dockerfile missing required metadata labels",
        "DOCKER-SEC-023": "Container publishes a privileged host port",
        "DOCKER-SEC-024": "Dockerfile uses sudo",
        "DOCKER-SEC-025": "Dockerfile uses a disallowed command",
        "DOCKER-SEC-026": "Dockerfile uses an unapproved base image",
    }

class SecurityConstants:
    """Constants for Kubernetes security validation"""
    
    # Allowed Seccomp profile types
    ALLOWED_SECCOMP_TYPES: Set[str] = {
        "RuntimeDefault",
        "Localhost"
    }
    
    # Allowed SELinux types
    ALLOWED_SELINUX_TYPES: Set[str] = {
        "container_t",
        "container_init_t",
        "container_kvm_t"
    }
    
    # Allowed Linux capabilities
    ALLOWED_CAPABILITIES: Set[str] = {
        "AUDIT_WRITE",
        "CHOWN",
        "DAC_OVERRIDE",
        "FOWNER",
        "FSETID",
        "KILL",
        "MKNOD",
        "NET_BIND_SERVICE",
        "SETFCAP",
        "SETGID",
        "SETPCAP",
        "SETUID",
        "SYS_CHROOT"
    }
    
    # Allowed sysctls
    ALLOWED_SYSCTLS: Set[str] = {
        "kernel.shm_rmid_forced",
        "net.ipv4.ip_local_port_range",
        "net.ipv4.ip_unprivileged_port_start",
        "net.ipv4.tcp_syncookies",
        "net.ipv4.ping_group_range"
    }
    
    # Container types to check
    CONTAINER_TYPES: list = [
        "containers",
        "initContainers",
        "ephemeralContainers"
    ]
    
    # Supported resource kinds
    SUPPORTED_KINDS: Set[str] = {
        "Pod",
        "Deployment",
        "DaemonSet",
        "StatefulSet",
        "ReplicaSet"
    }
    
    # Severity levels
    SEVERITY_CRITICAL = "Critical"
    SEVERITY_HIGH = "High"
    SEVERITY_MEDIUM = "Medium"
    SEVERITY_LOW = "Low"
    SEVERITY_INFO = "Info"

