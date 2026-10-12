from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Literal, Optional

from pydantic import BaseModel, Field

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
Confidence = Literal["LOW", "MEDIUM", "HIGH"]
HarmCategory = Literal[
    "MANIPULATION",
    "EXFILTRATION",
    "PRIVILEGE_ESCALATION",
    "JAILBREAK",
    "SOCIAL_ENGINEERING",
    "SUPPLY_CHAIN",
]

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Layer1Finding(BaseModel):
    layer: int = 1
    detector: str
    type: str
    owasp_id: Optional[str] = None
    severity: Severity
    line: Optional[int] = None
    matched_snippet: Optional[str] = None
    decoded_payload: Optional[str] = None
    harm_category: Optional[HarmCategory] = None
    recommended_action: str


class Layer2Finding(BaseModel):
    layer: int = 2
    type: str
    owasp_id: Optional[str] = None
    severity: Severity
    confidence: Confidence
    description: str
    location: Optional[str] = None
    harm_category: Optional[HarmCategory] = None
    recommended_action: str


class ScanWarning(BaseModel):
    step: str
    error: str


class BundledScan(BaseModel):
    """Sibling file referenced by a SKILL.md and scanned alongside it."""
    file: str
    relation: str  # how the SKILL.md referred to it (e.g. "python helper.py")
    scan_id: str
    overall_severity: str
    total_findings: int


class ScanReport(BaseModel):
    scan_id: str
    file: str
    scanned_at: str = Field(default_factory=utcnow_iso)
    overall_severity: str = "CLEAN"
    total_findings: int = 0
    elapsed_ms: float = 0.0
    layer1_findings: List[Layer1Finding] = Field(default_factory=list)
    layer2_findings: List[Layer2Finding] = Field(default_factory=list)
    warnings: List[ScanWarning] = Field(default_factory=list)
    bundled_scans: List[BundledScan] = Field(default_factory=list)


def aggregate_severity(report: ScanReport) -> str:
    sevs = [f.severity for f in report.layer1_findings] + [
        f.severity for f in report.layer2_findings
    ]
    if not sevs:
        return "CLEAN"
    return max(sevs, key=lambda s: SEVERITY_RANK.get(s, 0))
