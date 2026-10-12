"""Base policy interfaces and common types."""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class IssueType(Enum):
    IncorrectValue = "IncorrectValue"
    MissingValue = "MissingValue"
    Security = "Security"
    Deprecated = "Deprecated"


class Severity(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass
class Violation:
    policy: str
    message: str
    resource: Dict[str, Any]
    issue_type: IssueType = IssueType.IncorrectValue
    severity: Severity = Severity.MEDIUM
    code: str = ""
    params: Dict[str, Any] = field(default_factory=dict)


class BasePolicy:
    """Abstract base for policies. Subclass and implement `check`.

    Following SOLID: single responsibility (one policy per class),
    open/closed (extend by subclassing), dependency injection friendly.
    """

    name: str = "base"

    def check(self, resource: Dict[str, Any], metadata: Dict[str, Any] = None) -> List[Violation]:
        """Return list of `Violation` objects when resource violates policy."""
        raise NotImplementedError()
