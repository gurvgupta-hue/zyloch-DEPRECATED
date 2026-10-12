import strawberry
from typing import Optional, List
from datetime import datetime
from .common import Severity

@strawberry.type
class Finding:
    policy: str
    severity: Severity
    description: str
    file: str
    code: Optional[str] = None
    url: Optional[str] = None
    match: Optional[str] = None
    line: Optional[str] = None
    column: Optional[str] = None
    deny: Optional[List[str]] = None
    
    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        severity_str = data.get("severity", "info")
        if isinstance(severity_str, str):
            severity_str = severity_str.lower()
            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO
            }
            severity = severity_map.get(severity_str, Severity.INFO)
        else:
            severity = Severity.INFO
            
        return cls(
            policy=data.get("policy", ""),
            severity=severity,
            description=data.get("description", ""),
            file=data.get("file", ""),
            code=data.get("code"),
            url=data.get("url"),
            match=data.get("match"),
            line=data.get("line"),
            column=data.get("column"),
            deny=data.get("deny")
        )
