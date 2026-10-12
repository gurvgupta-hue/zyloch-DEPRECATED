"""
Scan Controller Service
Central service that orchestrates scanner microservices and combines their results
"""

import os
import sys
import json
import time
from typing import List, Dict, Any, Optional
from datetime import datetime

# Add current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner_core.base_scanner import ScanRequest, ScanResponse, ScanResult, ScanStatus, ScanSeverity
from scanner_core.microservices.docker_scanner import scan_docker
from scanner_core.microservices.kubernetes_scanner import scan_kubernetes
from scanner_core.microservices.workflow_scanner import scan_workflow
from scanner_core.microservices.secrets_detection import scan_repository
from scanner_core.microservices.sbom_scanner import scan_sbom
from scanner_core.helpers.output_formatter import ScanOutputFormatter
from scanner_core.microservices.terraform_azure_scanner import scan_terraform_azure
from scanner_core.microservices.terraform_gcp_scanner import scan_terraform_gcp
from scanner_core.microservices.terraform_aws_scanner import scan_terraform_aws
from scanner_core.microservices.bicep_scanner import scan_bicep_azure
from scanner_core.microservices.spec_scanner import scan_spec
from scanner_core.microservices.ansible_scanner import scan_ansible
from scanner_core.microservices.cloudformation_scanner import scan_cloudformation
from scanner_core.microservices.skill_scanner import scan_skill
from scanner_core.microservices.cis_agent_scanner import scan_cis_agent


class ScanControllerService:
    """
    Central Scan Controller Service that orchestrates scanner microservices
    """
    
    def __init__(self):
        self.scanners = {
            "docker": scan_docker,
            "kubernetes": scan_kubernetes,
            "workflow": scan_workflow,
            "secret_scanner": scan_repository,
            "terraform_azure": scan_terraform_azure,
            "terraform_gcp": scan_terraform_gcp,
            "terraform_aws": scan_terraform_aws,
            "sbom": scan_sbom,
            "bicep": scan_bicep_azure,
            "spec-scanner": scan_spec,
            "ansible": scan_ansible,
            "cloudformation": scan_cloudformation,
            "skill-scanner": scan_skill,
            "cis-agent": scan_cis_agent,
        }
        self.output_formatter = ScanOutputFormatter()
        
    def scan(self, repo_path: str, output_dir: str, scan_types: List[str] = None, scan_id: str = None, policy_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Execute scans using the specified scanner microservices
        
        Args:
            repo_path: Path to the repository to scan
            output_dir: Directory to save scan results
            scan_types: List of scanner types to run (default: all)
            scan_id: Unique scan identifier (default: auto-generated)
            policy_config: Organization policy configuration.  Scanners whose
                           ``enabled`` flag is ``False`` are skipped entirely.
                           Disabled policy IDs are injected into each
                           ScanRequest so individual scanners can skip them.
            
        Returns:
            Combined scan results from all scanners
        """
        if scan_types is None:
            scan_types = ["docker", "kubernetes", "workflow", "secret_scanner", "terraform_azure", "terraform_gcp", "sbom", "terraform_aws", "bicep", "spec-scanner", "ansible", "cloudformation", "skill-scanner", "cis-agent"]
        
        if scan_id is None:
            scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        # ── Pre-scan policy gating ──────────────────────────────────────────
        # Build a per-scanner map of disabled policy IDs from the org config.
        # Scanners with enabled=False are dropped from scan_types entirely.
        from scanner_core.policy_filter import SCANNER_KEY_MAP
        scanners_cfg: Dict[str, Any] = {}
        if policy_config:
            scanners_cfg = policy_config.get("scanners", {})

        active_scan_types = []
        for st in scan_types:
            cfg_key = SCANNER_KEY_MAP.get(st, st)
            scanner_policy = scanners_cfg.get(cfg_key, {})
            if scanner_policy.get("enabled") is False:
                print(f"  [Policy] Skipping disabled scanner: {st}")
            else:
                active_scan_types.append(st)

        scan_types = active_scan_types
        # ───────────────────────────────────────────────────────────────────
        
        print(f"Scan Controller: Starting scan {scan_id}")
        print(f"  Repository: {repo_path}")
        print(f"  Output Directory: {output_dir}")
        print(f"  Scan Types: {', '.join(scan_types)}")
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Prepare base scan request metadata
        base_metadata = {
            "scan_types": scan_types,
            "start_time": datetime.now().isoformat(),
        }
        
        # Execute scans
        scan_results = {}
        overall_start_time = time.time()
        
        for scan_type in scan_types:
            if scan_type not in self.scanners:
                print(f"Unknown scanner type: {scan_type}")
                continue
            
            print(f"\nExecuting {scan_type} scan...")
            scanner_start_time = time.time()

            # Build per-scanner disabled-policy list for injection into metadata
            cfg_key = SCANNER_KEY_MAP.get(scan_type, scan_type)
            scanner_policy = scanners_cfg.get(cfg_key, {})
            disabled_policies: Dict[str, bool] = (
                scanner_policy.get("policies")
                or scanner_policy.get("detectors")
                or {}
            )
            
            try:
                # Build a per-scanner request with disabled_policies in metadata
                # so individual scanners can skip those checks at the source.
                scanner_metadata = {
                    **base_metadata,
                    "disabled_policies": disabled_policies,
                }
                request = ScanRequest(
                    repo_path=repo_path,
                    output_dir=output_dir,
                    scan_id=scan_id,
                    metadata=scanner_metadata,
                )
                scanner_func = self.scanners[scan_type]
                response = scanner_func(request)

                # Convert result to dict
                result_dict = None
                if response.result:
                    try:
                        result_dict = response.result.dict()
                    except Exception as e:
                        print(f"Error converting {scan_type} result to dict: {e}")
                        # Try fallback conversion
                        if response.result:
                            try:
                                result_dict = response.result.dict() if hasattr(response.result, 'dict') else (response.result.model_dump() if hasattr(response.result, 'model_dump') else {})
                            except:
                                result_dict = {}
                
                scan_results[scan_type] = {
                    "status": response.status,
                    "result": result_dict if result_dict is not None else (response.result.dict() if response.result and hasattr(response.result, 'dict') else (response.result.model_dump() if response.result and hasattr(response.result, 'model_dump') else {})),
                    "error": response.error,
                    "duration": time.time() - scanner_start_time
                }
                
                if response.status == ScanStatus.COMPLETED:
                    print(f"{scan_type} scan completed successfully")
                else:
                    print(f"{scan_type} scan failed: {response.error}")
                    
            except Exception as e:
                print(f"{scan_type} scan failed with exception: {e}")
                scan_results[scan_type] = {
                    "status": ScanStatus.FAILED,
                    "result": None,
                    "error": str(e),
                    "duration": time.time() - scanner_start_time
                }
        
        overall_duration = time.time() - overall_start_time
        
        # Combine results
        combined_result = self._combine_results(scan_results, scan_id, overall_duration)
        
        # Save combined results
        self._save_combined_results(combined_result, output_dir)
        
        print(f"\nScan Controller: All scans completed in {overall_duration:.2f}s")
        
        return combined_result
    
    def generate_formatted_output(self, 
                                scan_id: str,
                                scan_status: str,
                                installation_id: str,
                                scan_metadata: Dict[str, Any],
                                scan_results: Dict[str, Any],
                                error: str = "",
                                completed_at: Optional[datetime] = None,
                                is_update: bool = False,
                                tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate formatted output in the new MongoDB-style structure
        
        Args:
            scan_id: Unique scan identifier
            scan_status: Status of the scan
            installation_id: GitHub App installation ID
            scan_metadata: Metadata about the scan
            scan_results: Raw scan results from scanners
            error: Error message if any
            completed_at: Completion timestamp
            is_update: If True, exclude _id and created_at for updates
            
        Returns:
            Formatted scan result in new structure
        """
        return self.output_formatter.format_scan_result(
            scan_id=scan_id,
            scan_status=scan_status,
            installation_id=installation_id,
            scan_metadata=scan_metadata,
            scan_results=scan_results,
            error=error,
            completed_at=completed_at,
            is_update=is_update,
            tenant_id=tenant_id,
        )
    
    def _combine_results(self, scan_results: Dict[str, Any], scan_id: str, overall_duration: float) -> Dict[str, Any]:
        """Combine results from all scanners"""
        all_findings = []
        all_scanned_files = []
        scanner_summaries = {}
        
        # Collect findings and files from all scanners
        for scanner_type, result in scan_results.items():
            if result["status"] == ScanStatus.COMPLETED:
                scanner_result = result.get("result") or {}
                
                # Convert ScanFinding objects to dictionaries
                findings_list = scanner_result.get("findings", []) if scanner_result else []
                findings_dicts = []
                for finding in findings_list:
                    # Handle both Pydantic models and dictionaries
                    if hasattr(finding, 'dict'):
                        # Pydantic v1
                        finding_dict = finding.dict()
                    elif hasattr(finding, 'model_dump'):
                        # Pydantic v2
                        finding_dict = finding.model_dump()
                    elif isinstance(finding, dict):
                        # Already a dictionary
                        finding_dict = finding
                    else:
                        # Fallback: convert object attributes to dict
                        finding_dict = {
                            "policy": getattr(finding, 'policy', ''),
                            "severity": str(getattr(finding, 'severity', 'unknown')),
                            "description": getattr(finding, 'description', ''),
                            "code": getattr(finding, 'code', None),
                            "url": getattr(finding, 'url', None),
                            "match": getattr(finding, 'match', None),
                            "file": getattr(finding, 'file', ''),
                            "line": getattr(finding, 'line', None),
                            "deny": getattr(finding, 'deny', None)
                        }
                    
                    findings_dicts.append(finding_dict)
                
                all_findings.extend(findings_dicts)
                all_scanned_files.extend(scanner_result.get("scanned_files", []) if scanner_result else [])
                
                scanner_summaries[scanner_type] = {
                    "status": "completed",
                    "findings_count": len(findings_dicts),
                    "files_scanned": len(scanner_result.get("scanned_files", []) if scanner_result else []),
                    "duration": result["duration"],
                    "metadata": scanner_result.get("metadata", {}) if scanner_result else {}
                }
            else:
                scanner_summaries[scanner_type] = {
                    "status": "failed",
                    "findings_count": 0,
                    "files_scanned": 0,
                    "duration": result["duration"],
                    "error": result.get("error", "Unknown error")
                }
        
        # Calculate overall statistics
        total_findings = len(all_findings)
        total_files = len(set(all_scanned_files))  # Remove duplicates
        
        # Count findings by severity
        severity_counts = {}
        for finding in all_findings:
            # finding is now guaranteed to be a dictionary
            severity = finding.get("severity", "unknown")
            # Convert ScanSeverity enum to string if needed
            if hasattr(severity, 'value'):
                severity = severity.value
            elif isinstance(severity, str):
                severity = severity.lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Determine overall status
        overall_status = ScanStatus.COMPLETED
        if any(result["status"] == ScanStatus.FAILED for result in scan_results.values()):
            overall_status = ScanStatus.FAILED
        
        # Build per-scanner detailed results (findings and files)
        per_scanner_results = {}
        for scanner_type, result in scan_results.items():
            scanner_result = result.get("result") or {}
            findings_list = scanner_result.get("findings", []) or []
            # Normalize findings to plain dicts (some scanners may already return dicts)
            normalized = []
            for f in findings_list:
                # Handle both Pydantic models and dictionaries
                if hasattr(f, 'dict'):
                    # Pydantic v1
                    finding_dict = f.dict()
                elif hasattr(f, 'model_dump'):
                    # Pydantic v2
                    finding_dict = f.model_dump()
                elif isinstance(f, dict):
                    # Already a dictionary
                    finding_dict = f
                else:
                    # Fallback: convert object attributes to dict
                    finding_dict = {
                        "policy": getattr(f, 'policy', ''),
                        "severity": str(getattr(f, 'severity', 'unknown')),
                        "description": getattr(f, 'description', ''),
                        "code": getattr(f, 'code', None),
                        "url": getattr(f, 'url', None),
                        "match": getattr(f, 'match', None),
                        "file": getattr(f, 'file', ''),
                        "line": getattr(f, 'line', None),
                        "column": getattr(f, 'column', None),
                        "deny": getattr(f, 'deny', None)
                    }

                normalized.append(finding_dict)
            per_scanner_results[scanner_type] = {
                "findings": normalized,
                "scanned_files": scanner_result.get("scanned_files", []) or [],
                "metadata": scanner_result.get("metadata", {}) or {}
            }
        
        combined_result = {
            "scan_id": scan_id,
            "overall_status": overall_status,
            "overall_duration": overall_duration,
            "summary": {
                "total_findings": total_findings,
                "total_files_scanned": total_files,
                "severity_breakdown": severity_counts,
                "scanners_executed": list(scan_results.keys())
            },
            "scanner_results": scanner_summaries,
            "per_scanner_results": per_scanner_results,
            "all_findings": all_findings,
            "all_scanned_files": list(set(all_scanned_files)),  # Remove duplicates
            "timestamp": datetime.now().isoformat()
        }
        
        return combined_result
    
    def _save_combined_results(self, combined_result: Dict[str, Any], output_dir: str):
        """Save combined results to JSON file"""
        try:
            write_artifacts = os.getenv("WRITE_ARTIFACTS", "false").lower() == "true"
            write_md = os.getenv("WRITE_MD_REPORTS", "false").lower() == "true"
            if not write_artifacts:
                return
            # Save detailed JSON results
            json_file_path = os.path.join(output_dir, "combined_scan_results.json")
            os.makedirs(output_dir, exist_ok=True)
            with open(json_file_path, 'w', encoding='utf-8') as f:
                json.dump(combined_result, f, indent=2, default=str)
            print(f"Combined results saved to: {json_file_path}")
            # Save summary report
            if write_md:
                summary_file_path = os.path.join(output_dir, "scan_summary.md")
                self._write_summary_report(combined_result, summary_file_path)
        except Exception as e:
            print(f"Error saving combined results: {e}")
    
    def _write_summary_report(self, combined_result: Dict[str, Any], output_path: str):
        """Write a summary report in Markdown format"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("# 🔝 Combined Security Scan Results\n\n")
                f.write(f"**Scan ID:** {combined_result['scan_id']}\n")
                f.write(f"**Timestamp:** {combined_result['timestamp']}\n")
                f.write(f"**Overall Status:** {combined_result['overall_status']}\n")
                f.write(f"**Duration:** {combined_result['overall_duration']:.2f}s\n\n")
                
                # Summary statistics
                summary = combined_result['summary']
                f.write("## 📊 Summary\n\n")
                f.write(f"- **Total Findings:** {summary['total_findings']}\n")
                f.write(f"- **Files Scanned:** {summary['total_files_scanned']}\n")
                f.write(f"- **Scanners Executed:** {', '.join(summary['scanners_executed'])}\n\n")
                
                # Severity breakdown
                if summary['severity_breakdown']:
                    f.write("## 🚨 Severity Breakdown\n\n")
                    for severity, count in summary['severity_breakdown'].items():
                        f.write(f"- **{severity.upper()}:** {count}\n")
                    f.write("\n")
                
                # Scanner results
                f.write("## 🔧 Scanner Results\n\n")
                for scanner_type, result in combined_result['scanner_results'].items():
                    f.write(f"### {scanner_type.title()} Scanner\n")
                    f.write(f"- **Status:** {result['status']}\n")
                    f.write(f"- **Findings:** {result['findings_count']}\n")
                    f.write(f"- **Files Scanned:** {result['files_scanned']}\n")
                    f.write(f"- **Duration:** {result['duration']:.2f}s\n")
                    if result.get('error'):
                        f.write(f"- **Error:** {result['error']}\n")
                    f.write("\n")
                
        except Exception as e:
            print(f"Error writing summary report: {e}")


# Convenience function for easy integration
def run_combined_scan(repo_path: str, output_dir: str, scan_types: List[str] = None, scan_id: str = None, policy_config: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Convenience function to run combined scan using the Scan Controller Service
    
    Args:
        repo_path: Path to the repository to scan
        output_dir: Directory to save scan results
        scan_types: List of scanner types to run (default: all)
        scan_id: Unique scan identifier (default: auto-generated)
        policy_config: Organization policy configuration used to skip disabled
                       scanners and policies before/during scanning.
        
    Returns:
        Combined scan results from all scanners
    """
    controller = ScanControllerService()
    return controller.scan(repo_path, output_dir, scan_types, scan_id, policy_config)


if __name__ == "__main__":
    # For testing purposes
    import argparse
    
    parser = argparse.ArgumentParser(description="Scan Controller Service")
    parser.add_argument("--repo-path", required=True, help="Repository path to scan")
    parser.add_argument("--output-dir", required=True, help="Output directory for results")
    parser.add_argument("--scan-types", nargs="+", choices=["docker", "kubernetes", "workflow", "sbom"],
                       help="Scanner types to run (default: all)")
    parser.add_argument("--scan-id", help="Unique scan ID")
    
    args = parser.parse_args()
    
    result = run_combined_scan(
        repo_path=args.repo_path,
        output_dir=args.output_dir,
        scan_types=args.scan_types,
        scan_id=args.scan_id
    )
    
    print(f"\nFinal Result:")
    print(f"Status: {result['overall_status']}")
    print(f"Total Findings: {result['summary']['total_findings']}")
    print(f"Files Scanned: {result['summary']['total_files_scanned']}")
    print(f"Duration: {result['overall_duration']:.2f}s")
