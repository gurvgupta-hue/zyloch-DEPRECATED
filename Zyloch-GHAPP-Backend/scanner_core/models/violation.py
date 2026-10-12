from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from datetime import datetime

@dataclass
class DockerSecurityViolation:
    """Represents a Docker security policy violation"""
    
    cve_id: str
    severity: str
    resource_name: str  # Dockerfile name or docker-compose service name
    resource_type: str  # "dockerfile" or "docker-compose"
    instruction: str    # Docker instruction (FROM, RUN, ENV, etc.)
    line_number: Optional[int]
    message: str
    remediation_url: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __str__(self) -> str:
        """String representation of violation"""
        return (
            f"[{self.severity}] {self.cve_id} - "
            f"{self.resource_name}:{self.line_number} ({self.instruction}): {self.message}"
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "cve_id": self.cve_id,
            "severity": self.severity,
            "resource_name": self.resource_name,
            "resource_type": self.resource_type,
            "line_number": self.line_number,
            "instruction": self.instruction,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata
        }


@dataclass
class DockerFileContext:
    """Context information for a Docker file being analyzed"""
    
    file_path: str
    file_type: str  # 'Dockerfile' or 'docker-compose'
    content: str
    lines: list = field(default_factory=list)
    parsed_instructions: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Initialize lines from content if not provided"""
        if not self.lines and self.content:
            self.lines = self.content.strip().split('\n')


@dataclass
class PolicyViolation:
    """Represents a security policy violation"""
    
    cve_id: str
    severity: str
    resource_name: str
    resource_kind: str
    key_path: str
    message: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __str__(self) -> str:
        """String representation of violation"""
        return (
            f"[{self.severity}] {self.cve_id} - "
            f"{self.resource_kind}/{self.resource_name}: {self.message}"
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "cve_id": self.cve_id,
            "severity": self.severity,
            "resource_name": self.resource_name,
            "resource_kind": self.resource_kind,
            "key_path": self.key_path,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata
        }


@dataclass
class GCPPolicyViolation:
    """Represents a GCP security policy violation"""

    policy_id: str
    severity: str
    resource_name: str
    resource_type: str
    message: str
    guide: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        """String representation of violation"""
        return (
            f"[{self.severity}] {self.policy_id} - "
            f"{self.resource_type}/{self.resource_name}: {self.message}"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "policy_id": self.policy_id,
            "severity": self.severity,
            "resource_name": self.resource_name,
            "resource_type": self.resource_type,
            "message": self.message,
            "guide": self.guide,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata
        }

@dataclass
class AWSPolicyViolation:
    """Represents an AWS security policy violation"""

    policy_id: str
    severity: str
    resource_name: str
    resource_type: str
    message: str
    guide: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        """String representation of violation"""
        return (
            f"[{self.severity}] {self.policy_id} - "
            f"{self.resource_type}/{self.resource_name}: {self.message}"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "policy_id": self.policy_id,
            "severity": self.severity,
            "resource_name": self.resource_name,
            "resource_type": self.resource_type,
            "message": self.message,
            "guide": self.guide,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata
        }
