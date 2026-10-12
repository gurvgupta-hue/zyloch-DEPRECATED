"""
Base Scanner Interface and Common Data Models
Defines the contract for all scanner microservices
"""

import os
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from pydantic import BaseModel
from datetime import datetime
from enum import Enum


class ScanStatus(str, Enum):
    """Scan status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanSeverity(str, Enum):
    """Scan severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanFinding(BaseModel):
    """Individual scan finding"""
    policy: str
    severity: ScanSeverity
    description: str
    code: Optional[str] = None
    url: Optional[str] = None
    match: Optional[str] = None
    file: str
    line: Optional[str] = None
    column: Optional[str] = None
    deny: Optional[List[str]] = None
    code_block: Optional[str] = None
    provider: Optional[str] = None
    # Spec-scanner: `file` holds the endpoint ("POST /api/order"); real path here.
    source_file: Optional[str] = None


class ScanResult(BaseModel):
    """Complete scan result for a single scanner"""
    scanner_type: str
    status: ScanStatus
    findings: List[ScanFinding]
    scanned_files: List[str]
    scan_duration: Optional[float] = None
    error: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class ScanRequest(BaseModel):
    """Scan request payload"""
    repo_path: str
    output_dir: str
    scan_id: str
    metadata: Optional[Dict[str, Any]] = None


class ScanResponse(BaseModel):
    """Scan response payload"""
    scan_id: str
    scanner_type: str
    status: ScanStatus
    result: Optional[ScanResult] = None
    error: Optional[str] = None
    timestamp: datetime = datetime.now()


class BaseScanner(ABC):
    """
    Abstract base class for all scanner microservices
    Each scanner must implement the scan method
    """
    
    def __init__(self, scanner_type: str):
        self.scanner_type = scanner_type
    
    @abstractmethod
    def scan(self, request: ScanRequest) -> ScanResponse:
        """
        Execute the scan and return results
        
        Args:
            request: ScanRequest containing scan parameters
            
        Returns:
            ScanResponse with scan results or error
        """
        pass
    
    def _create_error_response(self, scan_id: str, error: str) -> ScanResponse:
        """Helper method to create error response"""
        return ScanResponse(
            scan_id=scan_id,
            scanner_type=self.scanner_type,
            status=ScanStatus.FAILED,
            error=error
        )
    
    def _create_success_response(
        self,
        scan_id: str,
        result: ScanResult,
        base_path: Optional[str] = None,
    ) -> ScanResponse:
        """Helper method to create success response"""
        self._populate_code_blocks(result.findings, base_path=base_path)
        return ScanResponse(
            scan_id=scan_id,
            scanner_type=self.scanner_type,
            status=ScanStatus.COMPLETED,
            result=result
        )

    def _resolve_source_path(
        self, path_key: str, base_path: Optional[str] = None
    ) -> Optional[str]:
        """Return an openable filesystem path for a finding source reference."""
        candidates = []
        if path_key:
            candidates.append(path_key)
            if base_path and not os.path.isabs(path_key):
                candidates.insert(0, os.path.join(base_path, path_key))
        for candidate in candidates:
            if candidate and os.path.isfile(candidate):
                return candidate
        return None

    def _populate_code_blocks(
        self,
        findings: List[ScanFinding],
        base_path: Optional[str] = None,
    ) -> None:
        """
        For each finding with a valid file path and line number, populate
        code_block with up to 2 surrounding lines of source context:
          - lines (x-2) to (x+2), clamped to the actual file bounds.
        Prefers ``source_file`` (e.g. Spec Scanner) over ``file`` when set.
        Files are read once per path and cached for the duration of the call.
        """
        file_lines_cache: Dict[str, List[str]] = {}

        for finding in findings:
            if finding.code_block:
                continue

            path_key = finding.source_file or finding.file
            if not path_key or not finding.line:
                continue
            try:
                line_num = int(finding.line)
            except (ValueError, TypeError):
                continue
            if line_num <= 0:
                continue

            resolved = self._resolve_source_path(path_key, base_path=base_path)
            if not resolved:
                continue

            if resolved not in file_lines_cache:
                try:
                    with open(resolved, "r", encoding="utf-8") as fh:
                        file_lines_cache[resolved] = fh.readlines()
                except Exception:
                    continue

            lines = file_lines_cache[resolved]
            total = len(lines)
            if total == 0:
                continue

            # Clamp window to file bounds (line_num is 1-indexed)
            # start: max line 1  (x-2), end: min last line (x+2)
            start_idx = max(0, line_num - 3)       # 0-indexed inclusive
            end_idx   = min(total, line_num + 2)   # 0-indexed exclusive

            finding.code_block = "\n".join(
                line.rstrip() for line in lines[start_idx:end_idx]
            )
