
"""
Output Formatter Helper Functions
Provides utilities for transforming scan results into the new MongoDB-style format
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from collections import defaultdict
from bson import ObjectId


class ScanOutputFormatter:
    """Helper class for formatting scan results into the new structure"""
    
    def __init__(self):
        self.severity_weights = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 1
        }
    
    def format_scan_result(self, 
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
        Format scan results into the new MongoDB-style structure
        
        Args:
            scan_id: Unique scan identifier
            scan_status: Status of the scan (completed, failed, etc.)
            installation_id: GitHub App installation ID
            scan_metadata: Metadata about the scan
            scan_results: Raw scan results from scanners
            error: Error message if any
            completed_at: Completion timestamp
            is_update: If True, exclude _id and created_at for updates
            
        Returns:
            Formatted scan result in new structure
        """
        if completed_at is None:
            completed_at = datetime.now()
        
        result = {
            "scan_id": scan_id,
            "scan_status": scan_status,
            "installation_id": installation_id,
            "scan_metadata": scan_metadata,
            "scan_results": self._format_scan_results(scan_results),
            "error": error,
            "completed_at": completed_at
        }

        if tenant_id:
            result["tenantId"] = str(tenant_id)
            if "tenantId" not in result["scan_metadata"]:
                result["scan_metadata"] = {**scan_metadata, "tenantId": str(tenant_id)}
        
        # Only add _id and created_at for new documents, not updates
        if not is_update:
            result["_id"] = ObjectId()
            result["created_at"] = datetime.now()
            
        return result
    
    def _format_scan_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Format the scan_results section with proper nesting"""
        if not scan_results:
            return {"scan_results": {}}
            
        # Extract data from current format
        overall_duration = scan_results.get("overall_duration", 0.0)
        summary = scan_results.get("summary", {})
        scanner_results = scan_results.get("scanner_results", {})
        all_findings = scan_results.get("all_findings", [])
        
        # Debug: Print findings structure
        print(f"Debug: Processing {len(all_findings)} findings")
        if all_findings:
            print(f"Debug: First finding keys: {list(all_findings[0].keys()) if all_findings[0] else 'None'}")
            print(f"Debug: First finding code: {all_findings[0].get('code', 'None') if all_findings[0] else 'None'}")
        
        # Group findings by scanner type
        findings_by_scanner = self._group_findings_by_scanner(all_findings)
        
        # Calculate enhanced summary statistics
        enhanced_summary = self._calculate_enhanced_summary(summary, findings_by_scanner, scanner_results)
        
        # Format scanner results with additional metadata
        formatted_scanner_results = self._format_scanner_results(scanner_results)
        
        # Format findings by scanner type
        formatted_findings = self._format_findings_by_scanner(findings_by_scanner)
        
        return {
            "scan_results": {
                "overall_duration": overall_duration,
                "summary": enhanced_summary,
                "scanner_results": formatted_scanner_results,
                "scans_status": self._get_scans_status(scanner_results),
                "scans_findings": formatted_findings
            }
        }
    
    def _group_findings_by_scanner(self, all_findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by scanner type based on policy codes"""
        findings_by_scanner = defaultdict(list)
        
        for finding in all_findings:
            if not isinstance(finding, dict):
                continue
                
            policy_code = finding.get("code", "") or ""
            policy_name = finding.get("policy", "") or ""
            scanner_type = self._determine_scanner_type(policy_code, policy_name)
            findings_by_scanner[scanner_type].append(finding)
            
        return dict(findings_by_scanner)
    
    def _determine_scanner_type(self, policy_code: str, policy_name: str = "") -> str:
        """Determine scanner type based on policy code and policy name"""
        if isinstance(policy_code, str) and policy_code:
            if policy_code.startswith("GHA-"):
                return "workflow"
            elif policy_code.startswith("DOCK-"):
                return "docker"
            elif policy_code.startswith("KUBE-") or policy_code.startswith("kUBE-"):
                return "kubernetes"
            elif policy_code.startswith("AWS-SEC-"):
                return "terraform_aws"
            elif policy_code.startswith("GCP-SEC-") or policy_code.startswith("TF_GCP_"):
                return "terraform_gcp"
            elif policy_code.startswith("HCL_AZ_"):
                return "terraform_azure"
            elif policy_code.startswith("CFN-SEC-"):
                return "cloudformation"
            elif policy_code.startswith("ANS-SEC-"):
                return "ansible"
            elif policy_code.startswith("BICEP-") or policy_code.startswith("ARM-"):
                return "bicep"
        
        # Fallback: infer from policy name for Azure (code is often empty)
        if isinstance(policy_name, str) and policy_name:
            if policy_name.startswith("azurerm_") or policy_name.startswith("azure_"):
                return "terraform_azure"
        
        return "unknown"
    
    def _calculate_enhanced_summary(self, 
                                  summary: Dict[str, Any], 
                                  findings_by_scanner: Dict[str, List[Dict[str, Any]]],
                                  scanner_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate enhanced summary statistics"""
        total_files = summary.get("total_files_scanned", 0)
        scanners_executed = summary.get("scanners_executed", [])
        
        # Calculate total issues and breakdown by scanner
        total_issues = 0
        total_issues_by_subscan = {}
        total_issue_counts_by_severity = defaultdict(int)
        issue_counts_by_subscan_and_severity = defaultdict(lambda: defaultdict(int))
        
        for scanner_type, findings in findings_by_scanner.items():
            issue_count = len(findings)
            total_issues += issue_count
            total_issues_by_subscan[scanner_type] = issue_count
            
            # Count by severity for this scanner
            scanner_severity_counts = defaultdict(int)
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                    
                severity = str(finding.get("severity", "unknown")).lower()
                scanner_severity_counts[severity] += 1
                total_issue_counts_by_severity[severity] += 1
            
            # Store severity counts for this scanner
            issue_counts_by_subscan_and_severity[scanner_type] = dict(scanner_severity_counts)
        
        # Calculate score summary (static for now as requested)
        score_summary = self._calculate_static_score_summary(scanner_results)
        
        return {
            "file_scanned": total_files,
            "issues_summary": {
                "total_issues": total_issues,
                "total_issues_by_subscan": total_issues_by_subscan,
                "total_issue_counts_by_severity": dict(total_issue_counts_by_severity),
                "issue_counts_by_subscan_and_severity": dict(issue_counts_by_subscan_and_severity)
            },
            "score_summary": score_summary,
            "scanners_executed": scanners_executed
        }
    
    def _calculate_static_score_summary(self, scanner_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate static score summary (as requested to keep static for now)"""
        score_by_subscan = {}
        overall_score = 0.0
        scanner_count = 0
        
        for scanner_type, result in scanner_results.items():
            if result.get("status") == "completed":
                # Static scoring - will be enhanced later
                if scanner_type == "workflow":
                    score = 78.57142857142857
                elif scanner_type == "docker":
                    score = 80.0
                elif scanner_type == "kubernetes":
                    score = 90.0
                else:
                    score = 85.0
                
                score_by_subscan[scanner_type] = score
                overall_score += score
                scanner_count += 1
        
        if scanner_count > 0:
            overall_score = overall_score / scanner_count
        
        return {
            "overall_score": overall_score,
            "score_by_subscan": score_by_subscan
        }
    
    def _format_scanner_results(self, scanner_results: Dict[str, Any]) -> Dict[str, Any]:
        """Format scanner results with enhanced metadata"""
        formatted_results = {}

        # Keys that skill-scanner stores in metadata but should appear at the
        # top level of the scanner result block (alongside metadata).
        _SKILL_TOP_LEVEL_KEYS = {
            "issue_by_scanner", "eu_ai_act_mapping",
            "nist_ai_rmf_mapping", "mitre_atlas_mapping", "owasp_mapping",
        }

        for scanner_type, result in scanner_results.items():
            if scanner_type == "skill-scanner":
                raw_meta = result.get("metadata", {}) or {}
                top_level = {k: raw_meta[k] for k in _SKILL_TOP_LEVEL_KEYS if k in raw_meta}
                scan_meta = {k: v for k, v in raw_meta.items() if k not in _SKILL_TOP_LEVEL_KEYS}
                formatted_results[scanner_type] = {
                    "status":         result.get("status", "unknown"),
                    "findings_count": result.get("findings_count", 0),
                    "files_scanned":  result.get("files_scanned", 0),
                    "duration":       result.get("duration", 0.0),
                    **top_level,
                    "metadata":       scan_meta,
                }
            else:
                formatted_results[scanner_type] = {
                    "status":         result.get("status", "unknown"),
                    "findings_count": result.get("findings_count", 0),
                    "files_scanned":  result.get("files_scanned", 0),
                    "duration":       result.get("duration", 0.0),
                    "metadata":       self._enhance_scanner_metadata(scanner_type, result.get("metadata", {}))
                }

        return formatted_results
    
    def _enhance_scanner_metadata(self, scanner_type: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance scanner metadata with additional information"""
        enhanced_metadata = metadata.copy()
        
        if scanner_type == "workflow":
            enhanced_metadata.update({
                "policies_loaded": enhanced_metadata.get("policies_loaded", 14),
                "workflows_dir": enhanced_metadata.get("workflows_dir", ""),
                "actions_dir": enhanced_metadata.get("actions_dir", ""),
                "md_file_path": enhanced_metadata.get("md_file_path", ""),
                "overall_score": enhanced_metadata.get("overall_score", 0.0)
            })
        elif scanner_type == "docker":
            enhanced_metadata.update({
                "dockerfiles_found": enhanced_metadata.get("dockerfiles_found", 0),
                "policy_path": enhanced_metadata.get("policy_path", "/app/scanner_core/policies/docker")
            })
        elif scanner_type == "kubernetes":
            enhanced_metadata.update({
                "k8s_files_found": enhanced_metadata.get("k8s_files_found", 0),
                "policy_path": enhanced_metadata.get("policy_path", "/app/scanner_core/policies/kubernetes")
            })

        return enhanced_metadata
    
    def _get_scans_status(self, scanner_results: Dict[str, Any]) -> Dict[str, str]:
        """Get status of all scans"""
        return {
            scanner_type: result.get("status", "unknown")
            for scanner_type, result in scanner_results.items()
        }
    
    def _format_findings_by_scanner(self, findings_by_scanner: Dict[str, List[Dict[str, Any]]]) -> Dict[str, List[Dict[str, Any]]]:
        """Format findings grouped by scanner type"""
        formatted_findings = {}
        
        for scanner_type, findings in findings_by_scanner.items():
            if not findings:
                continue
                
            # Group findings by file
            findings_by_file = defaultdict(list)
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                    
                file_name = finding.get("file", "")
                findings_by_file[file_name].append(finding)
            
            # Format findings for this scanner
            scanner_findings = []
            for file_name, file_findings in findings_by_file.items():
                violated_policies = []
                for finding in file_findings:
                    if not isinstance(finding, dict):
                        continue
                        
                    policy_dict = {
                        "policy_code": finding.get("code", ""),
                        "policy_name": finding.get("policy", ""),
                        "description": finding.get("description", ""),
                        "severity": str(finding.get("severity", "")).lower(),
                        "Line_No": finding.get("line") or "-",
                        "Matches": finding.get("match", "-"),
                        "remediation": finding.get("url", "")
                    }

                    if finding.get("provider"):
                        policy_dict["provider"] = finding["provider"]
                    if finding.get("code_block"):
                        policy_dict["code_block"] = finding["code_block"]
                    
                    # Add code_snippet if available (for yaml-json and other scanners)
                    code_snippet = finding.get("code_snippet")
                    if code_snippet is not None:
                        # Include code_snippet if it's a list (even if empty, backend will populate it)
                        # or if it has content for non-list types
                        if isinstance(code_snippet, list):
                            policy_dict["code_snippet"] = code_snippet
                        elif code_snippet:  # For non-list types, only include if truthy
                            policy_dict["code_snippet"] = code_snippet
                    
                    # Add deny field if available (for YARA context snippets)
                    deny = finding.get("deny")
                    if deny is not None and deny:
                        # Convert deny list to string for code_snippet
                        if isinstance(deny, list) and deny:
                            policy_dict["code_snippet"] = "\n".join(str(d) for d in deny)
                        elif isinstance(deny, str):
                            policy_dict["code_snippet"] = deny
                    
                    # Add column if available (for yaml-json)
                    column = finding.get("column")
                    if column is not None:
                        policy_dict["column"] = column
                    
                    violated_policies.append(policy_dict)
                
                if violated_policies:  # Only add if there are policies
                    finding_group = {
                        "file_name": file_name,
                        "violated_policies": violated_policies
                    }
                    # Spec-scanner: file_name is endpoint; emit real path as `file`.
                    source_file = next(
                        (
                            f.get("source_file")
                            for f in file_findings
                            if isinstance(f, dict) and f.get("source_file")
                        ),
                        None,
                    )
                    if source_file:
                        finding_group["file"] = source_file
                    scanner_findings.append(finding_group)
            
            # Use proper key format
            if scanner_findings:  # Only add if there are findings
                key = f"{scanner_type.title()}-findings"
                formatted_findings[key] = scanner_findings
        
        return formatted_findings
    
    def create_scan_metadata(self, 
                           scan_id: str,
                           organization: str,
                           repository: str,
                           branch: str,
                           commit_hash: str,
                           commit_message: Optional[str],
                           commit_author: Optional[str],
                           scan_type: str,
                           scan_timestamp: Optional[str],
                           commit_date: Optional[datetime],
                           repository_url: str,
                           event_type: str,
                           tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """Create scan metadata. Includes tenantId (Zyloch org id) when provided."""
        metadata = {
            "scan_id": scan_id,
            "organization": organization,
            "repository": repository,
            "branch": branch,
            "commit_hash": commit_hash,
            "commit_message": commit_message,
            "commit_author": commit_author,
            "scan_type": scan_type,
            "scan_timestamp": scan_timestamp,
            "commit_date": commit_date,
            "repository_url": repository_url,
            "event_type": event_type,
        }
        if tenant_id:
            metadata["tenantId"] = str(tenant_id)
        return metadata


def format_scan_result(scan_id: str,
                      scan_status: str,
                      installation_id: str,
                      scan_metadata: Dict[str, Any],
                      scan_results: Dict[str, Any],
                      error: str = "",
                      completed_at: Optional[datetime] = None,
                      is_update: bool = False,
                      tenant_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Convenience function to format scan results
    
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
    formatter = ScanOutputFormatter()
    return formatter.format_scan_result(
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
