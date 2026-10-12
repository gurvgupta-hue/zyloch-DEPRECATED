import strawberry
from typing import Optional, List
from datetime import datetime
from .common import ScanStatus, ScannerType, Severity
from .finding import Finding
from .score import IssueSummary, ScoreSummary, ScoreDetails
from pymongo.database import Database

@strawberry.type
class ScanMetadata:
    scan_id: str
    organization: str
    repository: str
    branch: str
    commit_hash: str
    scan_type: str
    scan_timestamp: datetime
    repository_url: str
    commit_message: Optional[str] = None
    commit_author: Optional[str] = None
    commit_date: Optional[datetime] = None
    event_type: Optional[str] = None

@strawberry.type
class ScannerResult:
    scanner: str
    status: str
    findings_count: int
    files_scanned: int
    duration: float
    findings: List[Finding]
    scanned_files: List[str]
    
    @classmethod
    async def from_db(cls, db: Database, scan_id: str, scanner_type: str) -> Optional["ScannerResult"]:
        collection_name = f"scan_results_{scanner_type}"
        doc = db[collection_name].find_one({"scan_id": scan_id, "scanner": scanner_type})
        
        if not doc:
            return None
            
        findings_data = doc.get("findings", [])
        findings = [Finding.from_dict(f) for f in findings_data]
        
        return cls(
            scanner=scanner_type,
            status="completed",
            findings_count=len(findings),
            files_scanned=len(doc.get("scanned_files", [])),
            duration=0.0,
            findings=findings,
            scanned_files=doc.get("scanned_files", [])
        )

@strawberry.type
class ScanSummary:
    file_scanned: int
    issues_summary: IssueSummary
    score_summary: ScoreSummary
    scanners_executed: List[str]

@strawberry.type
class Scan:
    scan_id: str
    scan_status: ScanStatus
    created_at: datetime
    installation_id: str
    metadata: ScanMetadata
    summary: ScanSummary
    overall_duration: float
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    
    _db: strawberry.Private[Database] = None
    
    @strawberry.field
    async def docker_results(self) -> Optional[ScannerResult]:
        return await ScannerResult.from_db(self._db, self.scan_id, "docker")
    
    @strawberry.field
    async def kubernetes_results(self) -> Optional[ScannerResult]:
        return await ScannerResult.from_db(self._db, self.scan_id, "kubernetes")
    
    @strawberry.field
    async def workflow_results(self) -> Optional[ScannerResult]:
        return await ScannerResult.from_db(self._db, self.scan_id, "workflow")
    
    @strawberry.field
    async def secret_scanner_results(self) -> Optional[ScannerResult]:
        return await ScannerResult.from_db(self._db, self.scan_id, "secret_scanner")

    @strawberry.field
    async def terraform_azure_results(self) -> Optional[ScannerResult]:
        return await ScannerResult.from_db(self._db, self.scan_id, "terraform_azure")
    
    @strawberry.field
    async def all_findings(
        self,
        scanner: Optional[ScannerType] = None,
        severity: Optional[Severity] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Finding]:
        findings = []
        scanners_to_check = [scanner.value] if scanner else ["docker", "kubernetes", "workflow", "secret_scanner", "terraform_azure"]
        
        for scanner_type in scanners_to_check:
            result = await ScannerResult.from_db(self._db, self.scan_id, scanner_type)
            if result:
                findings.extend(result.findings)
        
        if severity:
            findings = [f for f in findings if f.severity == severity]
        
        return findings[offset:offset + limit]
    
    @strawberry.field
    async def scores(self) -> Optional[ScoreDetails]:
        scan_doc = self._db.scan_summary.find_one({"scan_id": self.scan_id}, {"scores": 1})
        if not scan_doc or not scan_doc.get("scores"):
            return None
        score_payload = {"scan_id": self.scan_id, **scan_doc["scores"]}
        return ScoreDetails.from_dict(score_payload)
    
    @classmethod
    def from_dict(cls, data: dict, db: Database) -> "Scan":
        metadata = data.get("scan_metadata", {})
        scan_results = data.get("scan_results", {}).get("scan_results", {})
        summary_data = scan_results.get("summary", {})
        
        issues = summary_data.get("issues_summary", {})
        severity_counts = issues.get("total_issue_counts_by_severity", {})
        
        scores = summary_data.get("score_summary", {})
        score_by_subscan = scores.get("score_by_subscan", {})
        
        scan_status_str = data.get("scan_status", "completed")
        status_map = {
            "pending": ScanStatus.PENDING,
            "running": ScanStatus.RUNNING,
            "completed": ScanStatus.COMPLETED,
            "failed": ScanStatus.FAILED
        }
        
        return cls(
            scan_id=data.get("scan_id", ""),
            scan_status=status_map.get(scan_status_str, ScanStatus.COMPLETED),
            created_at=data.get("created_at", datetime.now()),
            completed_at=data.get("completed_at"),
            installation_id=data.get("installation_id", ""),
            metadata=ScanMetadata(
                scan_id=metadata.get("scan_id", ""),
                organization=metadata.get("organization", ""),
                repository=metadata.get("repository", ""),
                branch=metadata.get("branch", ""),
                commit_hash=metadata.get("commit_hash", ""),
                commit_message=metadata.get("commit_message"),
                commit_author=metadata.get("commit_author"),
                scan_type=metadata.get("scan_type", ""),
                scan_timestamp=metadata.get("scan_timestamp", datetime.now()),
                commit_date=metadata.get("commit_date"),
                repository_url=metadata.get("repository_url", ""),
                event_type=metadata.get("event_type")
            ),
            summary=ScanSummary(
                file_scanned=summary_data.get("file_scanned", 0),
                issues_summary=IssueSummary(
                    total_issues=issues.get("total_issues", 0),
                    critical=severity_counts.get("critical", 0),
                    high=severity_counts.get("high", 0),
                    medium=severity_counts.get("medium", 0),
                    low=severity_counts.get("low", 0)
                ),
                score_summary=ScoreSummary(
                    overall_score=scores.get("overall_score", 0.0),
                    docker=score_by_subscan.get("docker", 0.0),
                    kubernetes=score_by_subscan.get("kubernetes", 0.0),
                    workflow=score_by_subscan.get("workflow", 0.0),
                    secret_scanner=score_by_subscan.get("secret_scanner", 0.0),
                    terraform_azure=score_by_subscan.get("terraform_azure", 0.0)
                ),
                scanners_executed=summary_data.get("scanners_executed", [])
            ),
            overall_duration=scan_results.get("overall_duration", 0.0),
            error=data.get("error"),
            _db=db
        )
