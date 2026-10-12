import os
import sys
import time
from typing import List, Dict, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner_core.base_scanner import (
    BaseScanner, ScanRequest, ScanResponse, ScanResult, 
    ScanFinding, ScanStatus, ScanSeverity
)
from scanner_core.logging_config import get_scanner_logger

from core.validator import DockerSecurityValidator

logger = get_scanner_logger()

class DockerScanner(BaseScanner):
    """Docker security scanner microservice using DockerSecurityValidator engine"""
    
    def __init__(self):
        super().__init__("docker")
        self.validator = DockerSecurityValidator()
    
    def scan(self, request: ScanRequest) -> ScanResponse:
        """Execute Docker security scan using the new internal checkers"""
        start_time = time.time()
        
        try:
            logger.info(f"Starting Docker security scan for: {request.repo_path}")
            
            target_files = self._find_relevant_files(request.repo_path)
            
            if not target_files:
                logger.info("No Docker-related files found")
                return self._create_success_response(
                    request.scan_id,
                    ScanResult(
                        scanner_type=self.scanner_type,
                        status=ScanStatus.COMPLETED,
                        findings=[],
                        scanned_files=[],
                        scan_duration=time.time() - start_time
                    )
                )
            
            logger.info(f"Found {len(target_files)} relevant file(s)")
            
            raw_violations = self.validator.validate_files(target_files)
            disabled_policies = (request.metadata or {}).get("disabled_policies", {})
            findings = []
            unique_violations = self._deduplicate_violations(raw_violations)
            for v in unique_violations:
                # Skip findings whose code or policy name is disabled in the org config.
                code = getattr(v, 'cve_id', None) or ''
                violation_metadata = getattr(v, 'metadata', None) or {}
                policy_name = (
                    violation_metadata.get('checker')
                    or getattr(v, 'checker', None)
                    or ''
                )
                if disabled_policies.get(code) is False or disabled_policies.get(policy_name) is False:
                    continue
                finding = ScanFinding(
                    policy=policy_name if policy_name else 'docker_policy',
                    code=code,
                    severity=v.severity.lower() if hasattr(v.severity, 'lower') else ScanSeverity.MEDIUM,
                    description=v.message,
                    file=v.resource_name,
                    line=str(v.line_number),
                    # deny=[v.remediation_url]
                )
                findings.append(finding)

            write_artifacts = os.getenv("WRITE_ARTIFACTS", "false").lower() == "true"
            if findings and request.output_dir and write_artifacts:
                result_md_path = os.path.join(request.output_dir, "Docker-Security-Scan-Result.md")
                self._write_findings_report(findings, result_md_path, "Docker Security Scan Results")
            
            scan_duration = time.time() - start_time
            
            overall_score = 100.0
            if hasattr(self.validator, 'get_risk_score'):
                try:
                    risk_score = self.validator.get_risk_score()
                    overall_score = max(0.0, 100.0 - float(risk_score))
                except Exception:
                    overall_score = 0.0

            return self._create_success_response(
                request.scan_id,
                ScanResult(
                    scanner_type=self.scanner_type,
                    status=ScanStatus.COMPLETED,
                    findings=findings,
                    scanned_files=target_files,
                    scan_duration=scan_duration,
                    metadata={
                        "files_found": len(target_files),
                        "overall_score": overall_score,
                        "checkers_used": [c.__class__.__name__ for c in self.validator.checkers]
                    }
                )
            )
            
        except Exception as e:
            logger.error(f"Docker scan failed: {e}", exc_info=True)
            return self._create_error_response(
                request.scan_id,
                f"Docker scan failed: {str(e)}"
            )

    @staticmethod
    def _deduplicate_violations(violations: List[Any]) -> List[Any]:
        """Remove repeated reports without merging distinct Docker violations."""
        seen = set()
        unique_violations = []

        for violation in violations:
            metadata = getattr(violation, 'metadata', None) or {}
            policy = metadata.get('checker') or getattr(violation, 'checker', None) or ''
            resource_name = getattr(violation, 'resource_name', '') or ''
            normalized_resource = os.path.normcase(os.path.normpath(str(resource_name)))
            line_number = getattr(violation, 'line_number', None)
            instruction = ' '.join(str(getattr(violation, 'instruction', '') or '').split())
            message = ' '.join(str(getattr(violation, 'message', '') or '').split())
            identity = (
                policy,
                getattr(violation, 'cve_id', None),
                getattr(violation, 'severity', None),
                getattr(violation, 'resource_type', None),
                normalized_resource,
                line_number or 0,
                instruction,
                message,
            )
            if identity in seen:
                continue
            seen.add(identity)
            unique_violations.append(violation)

        return unique_violations

    def _find_relevant_files(self, search_path: str) -> List[str]:
        """Find Dockerfiles and Docker Compose files"""
        relevant_files = []
        for root, dirs, files in os.walk(search_path):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for file in files:
                fname = file.lower()
                if fname == 'dockerfile' or fname.startswith('dockerfile.') or fname.endswith('.dockerfile'):
                    relevant_files.append(os.path.join(root, file))
                elif fname in ['docker-compose.yml', 'docker-compose.yaml']:
                    relevant_files.append(os.path.join(root, file))
        return relevant_files

    def _write_findings_report(self, findings: List[ScanFinding], output_path: str, title: str):
        """Standard reporting logic"""
        try:
            from scanner_core.policy_scanner_common.utils import write_markdown_report
            formatted_findings = [{'file': f.file, 'deny': f.deny} for f in findings]
            write_markdown_report(formatted_findings, output_path, title)
        except Exception as e:
            logger.warning(f"Could not write markdown report: {e}")

def scan_docker(request: ScanRequest) -> ScanResponse:
    scanner = DockerScanner()
    return scanner.scan(request)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Docker Scanner Microservice")
    parser.add_argument("--repo-path", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--scan-id", required=True)
    
    args = parser.parse_args()
    req = ScanRequest(repo_path=args.repo_path, output_dir=args.output_dir, scan_id=args.scan_id)
    response = scan_docker(req)
    print(response.json())