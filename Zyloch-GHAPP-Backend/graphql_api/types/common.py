import strawberry
from enum import Enum

@strawberry.enum
class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@strawberry.enum
class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

@strawberry.enum
class ScannerType(Enum):
    DOCKER = "docker"
    KUBERNETES = "kubernetes"
    WORKFLOW = "workflow"
    SECRET_SCANNER = "secret_scanner"
    TERRAFORM_AZURE = "terraform_azure"

@strawberry.enum
class ScanSortField(Enum):
    CREATED_AT = "created_at"
    COMPLETED_AT = "completed_at"
    OVERALL_SCORE = "overall_score"
    TOTAL_ISSUES = "total_issues"

@strawberry.enum
class SortOrder(Enum):
    ASC = 1
    DESC = -1
