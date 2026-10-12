import strawberry
from typing import Optional

@strawberry.type
class IssueSummary:
    total_issues: int
    critical: int
    high: int
    medium: int
    low: int

@strawberry.type
class ScoreSummary:
    overall_score: float
    docker: float
    kubernetes: float
    workflow: float
    secret_scanner: float
    terraform_azure: float

@strawberry.type
class FileScore:
    file_name: str
    score: float
    scanner: str

@strawberry.type
class ScoreDetails:
    scan_id: str
    overall_score: float
    score_by_scanner: ScoreSummary
    file_wise_scores: list[FileScore]
    scanners_executed: list[str]
    
    @classmethod
    def from_dict(cls, data: dict) -> "ScoreDetails":
        score_by_scanner = data.get("score_by_scanner", {})
        file_wise = data.get("file_wise_scores", {})
        
        file_scores = []
        for scanner, files in file_wise.items():
            if isinstance(files, list):
                for file_data in files:
                    file_scores.append(FileScore(
                        file_name=file_data.get("file_name", ""),
                        score=file_data.get("score", 0.0),
                        scanner=scanner
                    ))
        
        return cls(
            scan_id=data.get("scan_id", ""),
            overall_score=data.get("overall_score", 0.0),
            score_by_scanner=ScoreSummary(
                overall_score=data.get("overall_score", 0.0),
                docker=score_by_scanner.get("docker", 0.0),
                kubernetes=score_by_scanner.get("kubernetes", 0.0),
                workflow=score_by_scanner.get("workflow", 0.0),
                secret_scanner=score_by_scanner.get("secret_scanner", 0.0),
            ),
            file_wise_scores=file_scores,
            scanners_executed=data.get("scanners_executed", [])
        )
