"""
Unified Scoring Engine
Handles score calculation and aggregation for all scanner types
Supports: Policy-based, OPA-based, Tool-based, and Error count-based scoring
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
import os
import yaml
import math


# Severity weights for different scoring methods
SEVERITY_WEIGHTS = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 1,
    "info": 0.5
}

# Workflow-specific weights (policy-based)
WORKFLOW_SEVERITY_WEIGHTS = {
    "low": 1,
    "medium": 3,
    "critical": 5,
}


class ScannerScoreAdapter(ABC):
    """Base adapter for extracting scores from scanner results"""
    
    @abstractmethod
    def extract_scanner_score(self, scanner_result: Dict[str, Any]) -> Optional[float]:
        """Extract overall score from scanner metadata"""
        pass
    
    @abstractmethod
    def extract_file_scores(self, scanner_result: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Extract file-wise scores from scanner metadata"""
        pass
    
    @abstractmethod
    def extract_findings(self, scanner_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract findings for cross-scanner analysis"""
        pass
    
    @abstractmethod
    def calculate_score(
        self,
        findings: List[Dict[str, Any]],
        scanned_files: List[str],
        **kwargs
    ) -> Tuple[float, Dict[str, Dict[str, Any]]]:
        """Calculate score if not available in metadata"""
        pass


class PolicyBasedScoreAdapter(ScannerScoreAdapter):
    """Adapter for policy-based scanners (Workflow)"""
    
    def extract_scanner_score(self, scanner_result: Dict[str, Any]) -> Optional[float]:
        metadata = scanner_result.get("metadata", {})
        return metadata.get("overall_score")
    
    def extract_file_scores(self, scanner_result: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        metadata = scanner_result.get("metadata", {})
        return metadata.get("file_scores", {})
    
    def extract_findings(self, scanner_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        return scanner_result.get("findings", [])
    
    def calculate_score(
        self,
        findings: List[Dict[str, Any]],
        scanned_files: List[str],
        policies: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Tuple[float, Dict[str, Dict[str, Any]]]:
        """Calculate policy-based score"""
        if not scanned_files:
            return 100.0, {}
        
        if not policies:
            # Fallback: use simple severity-based
            return self._calculate_simple_score(findings, scanned_files)
        
        # Group findings by file
        grouped_findings = defaultdict(list)
        for finding in findings:
            file_path = finding.get("file", "")
            if file_path:
                grouped_findings[file_path].append(finding)
        
        # Calculate total weight from all policies
        total_weight = sum(
            WORKFLOW_SEVERITY_WEIGHTS.get(p.get("severity", "medium").lower(), 3)
            for p in policies.values()
        )
        
        file_scores = {}
        for file_path in scanned_files:
            file_findings = grouped_findings.get(file_path, [])
            
            if not file_findings:
                file_scores[file_path] = {"score": 100.0, "violated_weight": 0}
                continue
            
            # Calculate violated weight
            violated_weight = 0
            unique_policies = {f.get("policy", "") for f in file_findings}
            
            for policy_name in unique_policies:
                if policy_name:
                    policy_details = policies.get(policy_name, {})
                    severity = policy_details.get("severity", "medium").lower()
                    weight = WORKFLOW_SEVERITY_WEIGHTS.get(severity, 3)
                    violated_weight += weight
            
            # Calculate score
            if total_weight > 0:
                score = max(0.0, 100.0 - ((violated_weight / total_weight) * 100.0))
            else:
                score = 100.0
            
            file_scores[file_path] = {
                "score": round(score, 2),
                "violated_weight": violated_weight
            }
        
        # Overall score as average
        if file_scores:
            overall_score = sum(s["score"] for s in file_scores.values()) / len(file_scores)
        else:
            overall_score = 100.0
        
        return round(overall_score, 2), file_scores
    
    def _calculate_simple_score(
        self,
        findings: List[Dict[str, Any]],
        scanned_files: List[str]
    ) -> Tuple[float, Dict[str, Dict[str, Any]]]:
        """Simple fallback calculation"""
        if not findings:
            return 100.0, {f: {"score": 100.0} for f in scanned_files}
        
        # Group by file
        grouped = defaultdict(list)
        for finding in findings:
            file_path = finding.get("file", "")
            if file_path:
                grouped[file_path].append(finding)
        
        file_scores = {}
        for file_path in scanned_files:
            file_findings = grouped.get(file_path, [])
            if not file_findings:
                file_scores[file_path] = {"score": 100.0}
                continue
            
            # Simple penalty based on finding count
            penalty = min(50, len(file_findings) * 2)
            score = max(0, 100 - penalty)
            file_scores[file_path] = {"score": round(score, 2)}
        
        overall = sum(s["score"] for s in file_scores.values()) / len(file_scores) if file_scores else 100.0
        return round(overall, 2), file_scores


class OPABasedScoreAdapter(ScannerScoreAdapter):
    """Adapter for OPA-based scanners (Kubernetes, Docker, Terraform, etc.)"""
    
    def extract_scanner_score(self, scanner_result: Dict[str, Any]) -> Optional[float]:
        metadata = scanner_result.get("metadata", {})
        return metadata.get("overall_score")
    
    def extract_file_scores(self, scanner_result: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        metadata = scanner_result.get("metadata", {})
        file_scores = metadata.get("file_scores", {})
        
        # Normalize format
        normalized = {}
        for file_path, score_data in file_scores.items():
            if isinstance(score_data, dict):
                normalized[file_path] = score_data
            elif isinstance(score_data, (int, float)):
                normalized[file_path] = {"score": score_data}
        
        return normalized
    
    def extract_findings(self, scanner_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        return scanner_result.get("findings", [])
    
    def calculate_score(
        self,
        findings: List[Dict[str, Any]],
        scanned_files: List[str],
        **kwargs
    ) -> Tuple[float, Dict[str, Dict[str, Any]]]:
        """Calculate OPA-based score using finding severity"""
        if not scanned_files:
            return 100.0, {}
        
        if not findings:
            return 100.0, {f: {"score": 100.0} for f in scanned_files}
        
        # Group findings by file
        grouped_findings = defaultdict(list)
        for finding in findings:
            file_path = finding.get("file", "")
            if file_path:
                grouped_findings[file_path].append(finding)
        
        # For OPA-based: Calculate total weight based on unique policies found
        # We use a baseline approach: assume each unique policy can have max severity weight
        all_unique_policies = set()
        for finding in findings:
            policy = finding.get("policy") or finding.get("code", "")
            if policy:
                all_unique_policies.add(policy)
        
        # Calculate baseline total weight
        # Each policy can contribute up to max severity weight (critical = 5)
        max_severity_weight = max(SEVERITY_WEIGHTS.values())
        baseline_total_weight = len(all_unique_policies) * max_severity_weight if all_unique_policies else 100
        
        # If no policies found, use a default baseline
        if baseline_total_weight == 0:
            baseline_total_weight = 100
        
        file_scores = {}
        for file_path in scanned_files:
            file_findings = grouped_findings.get(file_path, [])
            
            if not file_findings:
                file_scores[file_path] = {"score": 100.0, "violated_weight": 0}
                continue
            
            # Calculate violated weight for this file
            violated_weight = 0
            policy_severities = {}  # Track highest severity per policy
            
            for finding in file_findings:
                policy = finding.get("policy") or finding.get("code", "")
                if not policy:
                    continue
                
                severity = finding.get("severity", "medium")
                if isinstance(severity, str):
                    severity_lower = severity.lower()
                elif hasattr(severity, 'value'):
                    severity_lower = severity.value.lower()
                else:
                    severity_lower = str(severity).lower()
                
                # Keep highest severity for each policy
                if policy not in policy_severities:
                    policy_severities[policy] = severity_lower
                else:
                    # Compare severities
                    severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
                    current_order = severity_order.get(policy_severities[policy], 0)
                    new_order = severity_order.get(severity_lower, 0)
                    if new_order > current_order:
                        policy_severities[policy] = severity_lower
            
            # Calculate weight based on policy severities
            for policy, severity in policy_severities.items():
                weight = SEVERITY_WEIGHTS.get(severity, 3)
                violated_weight += weight
            
            # Calculate score for this file
            # Use file-specific baseline or overall baseline
            file_unique_policies = len(policy_severities)
            file_total_weight = file_unique_policies * max_severity_weight if file_unique_policies > 0 else baseline_total_weight
            
            if file_total_weight > 0:
                score = max(0.0, 100.0 - ((violated_weight / file_total_weight) * 100.0))
            else:
                score = 100.0
            
            file_scores[file_path] = {
                "score": round(score, 2),
                "violated_weight": violated_weight
            }
        
        # Overall score as average of file scores
        if file_scores:
            overall_score = sum(s["score"] for s in file_scores.values()) / len(file_scores)
        else:
            overall_score = 100.0
        
        return round(overall_score, 2), file_scores


class ToolBasedScoreAdapter(ScannerScoreAdapter):
    """Adapter for tool-based scanners (SBOM, Security Detection)"""
    
    def extract_scanner_score(self, scanner_result: Dict[str, Any]) -> Optional[float]:
        metadata = scanner_result.get("metadata", {})
        return metadata.get("overall_score")
    
    def extract_file_scores(self, scanner_result: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        metadata = scanner_result.get("metadata", {})
        return metadata.get("file_scores", {})
    
    def extract_findings(self, scanner_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        return scanner_result.get("findings", [])
    
    def calculate_score(
        self,
        findings: List[Dict[str, Any]],
        scanned_files: List[str],
        **kwargs
    ) -> Tuple[float, Dict[str, Dict[str, Any]]]:
        """Calculate tool-based score (similar to OPA-based)"""
        if not scanned_files:
            return 100.0, {}
        
        if not findings:
            return 100.0, {f: {"score": 100.0} for f in scanned_files}
        
        # Similar to OPA-based: use severity from findings
        # Group by file
        grouped_findings = defaultdict(list)
        for finding in findings:
            file_path = finding.get("file", "")
            if file_path:
                grouped_findings[file_path].append(finding)
        
        # Calculate baseline total weight
        all_unique_issues = set()
        for finding in findings:
            issue_id = finding.get("code") or finding.get("cve_id") or finding.get("policy", "")
            if issue_id:
                all_unique_issues.add(issue_id)
        
        max_severity_weight = max(SEVERITY_WEIGHTS.values())
        baseline_total_weight = len(all_unique_issues) * max_severity_weight if all_unique_issues else 100
        
        file_scores = {}
        for file_path in scanned_files:
            file_findings = grouped_findings.get(file_path, [])
            
            if not file_findings:
                file_scores[file_path] = {"score": 100.0, "violated_weight": 0}
                continue
            
            violated_weight = 0
            for finding in file_findings:
                severity = finding.get("severity", "medium")
                if isinstance(severity, str):
                    severity_lower = severity.lower()
                elif hasattr(severity, 'value'):
                    severity_lower = severity.value.lower()
                else:
                    severity_lower = str(severity).lower()
                
                weight = SEVERITY_WEIGHTS.get(severity_lower, 3)
                violated_weight += weight
            
            # Calculate score
            file_unique_issues = len(set(
                f.get("code") or f.get("cve_id") or f.get("policy", "")
                for f in file_findings
            ))
            file_total_weight = file_unique_issues * max_severity_weight if file_unique_issues > 0 else baseline_total_weight
            
            if file_total_weight > 0:
                score = max(0.0, 100.0 - ((violated_weight / file_total_weight) * 100.0))
            else:
                score = 100.0
            
            file_scores[file_path] = {
                "score": round(score, 2),
                "violated_weight": violated_weight
            }
        
        if file_scores:
            overall_score = sum(s["score"] for s in file_scores.values()) / len(file_scores)
        else:
            overall_score = 100.0
        
        return round(overall_score, 2), file_scores


class ErrorCountBasedScoreAdapter(ScannerScoreAdapter):
    """Adapter for error count-based scanners (Linter, Secret Scanner)"""
    
    def extract_scanner_score(self, scanner_result: Dict[str, Any]) -> Optional[float]:
        metadata = scanner_result.get("metadata", {})
        return metadata.get("overall_score")
    
    def extract_file_scores(self, scanner_result: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        metadata = scanner_result.get("metadata", {})
        return metadata.get("file_scores", {})
    
    def extract_findings(self, scanner_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        return scanner_result.get("findings", [])
    
    def _error_count_to_score(self, error_count: int) -> float:
        """
        Map error count to score.
        Formula based on examples:
        - 5 errors = 95 score
        - 16 errors = 84 score
        
        Simple linear mapping: score = 100 - error_count
        This ensures score stays between 0-100.
        """
        if error_count == 0:
            return 100.0
        
        # Linear mapping: 1 point penalty per error
        # score = 100 - error_count
        # Examples: 5 errors = 95, 16 errors = 84
        score = max(0.0, 100.0 - error_count)
        
        return round(score, 2)
    
    def calculate_score(
        self,
        findings: List[Dict[str, Any]],
        scanned_files: List[str],
        **kwargs
    ) -> Tuple[float, Dict[str, Dict[str, Any]]]:
        """Calculate error count-based score"""
        if not scanned_files:
            return 100.0, {}
        
        if not findings:
            return 100.0, {f: {"score": 100.0} for f in scanned_files}
        
        # Group findings by file
        grouped_findings = defaultdict(list)
        for finding in findings:
            file_path = finding.get("file", "")
            if file_path:
                grouped_findings[file_path].append(finding)
        
        file_scores = {}
        for file_path in scanned_files:
            file_findings = grouped_findings.get(file_path, [])
            error_count = len(file_findings)
            
            score = self._error_count_to_score(error_count)
            
            file_scores[file_path] = {
                "score": score,
                "error_count": error_count
            }
        
        # Overall score as average
        if file_scores:
            overall_score = sum(s["score"] for s in file_scores.values()) / len(file_scores)
        else:
            overall_score = 100.0
        
        return round(overall_score, 2), file_scores


class UnifiedScoringEngine:
    """
    Central engine for calculating comprehensive scores:
    - Individual scanner scores
    - File-wise scores (across all scanners)
    - Overall repository score
    """
    
    def __init__(self):
        # Map scanner types to their adapters
        self.adapters = {
            "workflow": PolicyBasedScoreAdapter(),
            "kubernetes": OPABasedScoreAdapter(),
            "docker": OPABasedScoreAdapter(),
            "terraform": OPABasedScoreAdapter(),
            "sbom": ToolBasedScoreAdapter(),
            "security_detection": ToolBasedScoreAdapter(),
            "linter": ErrorCountBasedScoreAdapter(),
            "secret_scanner": ErrorCountBasedScoreAdapter(),
        }
        self.default_adapter = OPABasedScoreAdapter()  # Default to OPA-based
    
    def get_adapter(self, scanner_type: str) -> ScannerScoreAdapter:
        """Get adapter for scanner type"""
        return self.adapters.get(scanner_type, self.default_adapter)
    
    def calculate_comprehensive_scores(
        self,
        per_scanner_results: Dict[str, Dict[str, Any]],
        scanner_policies: Optional[Dict[str, Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Calculate comprehensive scoring for entire repository scan.
        
        Args:
            per_scanner_results: Dictionary mapping scanner types to their results
                Format: {
                    "workflow": {"findings": [...], "scanned_files": [...], "metadata": {...}},
                    "kubernetes": {...},
                    ...
                }
            scanner_policies: Optional dictionary mapping scanner types to their policies
                Format: {
                    "workflow": {policy_name: {severity: "medium", ...}},
                    ...
                }
        
        Returns:
            {
                "overall_score": float,
                "score_by_scanner": {scanner_type: score},
                "file_wise_scores": {file_path: {score, scanners, findings_count, severity_counts}},
                "scoring_breakdown": {
                    "by_severity": {...},
                    "by_scanner": {...}
                }
            }
        """
        scanner_scores = {}
        all_file_scores = defaultdict(lambda: {
            "scores": [],
            "scanners": set(),
            "findings_count": 0,
            "severity_counts": defaultdict(int)
        })
        
        scanner_breakdown = {}
        
        # Process each scanner
        for scanner_type, scanner_data in per_scanner_results.items():
            adapter = self.get_adapter(scanner_type)
            
            # Extract or calculate scanner score
            scanner_score = adapter.extract_scanner_score(scanner_data)
            findings = adapter.extract_findings(scanner_data)
            scanned_files = scanner_data.get("scanned_files", [])
            
            if scanner_score is None:
                # Calculate score
                policies = scanner_policies.get(scanner_type) if scanner_policies else None
                scanner_score, file_scores = adapter.calculate_score(
                    findings=findings,
                    scanned_files=scanned_files,
                    policies=policies
                )
            else:
                # Extract file scores
                file_scores = adapter.extract_file_scores(scanner_data)
                if not file_scores:
                    # Calculate file scores
                    policies = scanner_policies.get(scanner_type) if scanner_policies else None
                    _, file_scores = adapter.calculate_score(
                        findings=findings,
                        scanned_files=scanned_files,
                        policies=policies
                    )
            
            scanner_scores[scanner_type] = round(scanner_score, 2)
            
            # Aggregate file scores across scanners
            for file_path, file_data in file_scores.items():
                score = file_data.get("score", 100.0) if isinstance(file_data, dict) else file_data
                all_file_scores[file_path]["scores"].append(score)
                all_file_scores[file_path]["scanners"].add(scanner_type)
                
                # Count findings per file
                file_findings = [f for f in findings if f.get("file") == file_path]
                all_file_scores[file_path]["findings_count"] += len(file_findings)
                
                # Aggregate severity counts
                for finding in file_findings:
                    severity = finding.get("severity", "medium")
                    if isinstance(severity, str):
                        severity = severity.lower()
                    elif hasattr(severity, 'value'):
                        severity = severity.value.lower()
                    else:
                        severity = str(severity).lower()
                    all_file_scores[file_path]["severity_counts"][severity] += 1
            
            # Build scanner breakdown
            scanner_breakdown[scanner_type] = {
                "score": round(scanner_score, 2),
                "findings_count": len(findings),
                "files_scanned": len(scanned_files),
                "severity_counts": self._count_severities(findings)
            }
        
        # Calculate aggregated file-wise scores
        aggregated_file_scores = {}
        for file_path, file_data in all_file_scores.items():
            scores = file_data["scores"]
            if scores:
                # Simple average across scanners
                avg_score = sum(scores) / len(scores)
                
                aggregated_file_scores[file_path] = {
                    "score": round(avg_score, 2),
                    "scanner_count": len(file_data["scanners"]),
                    "scanners": sorted(list(file_data["scanners"])),
                    "findings_count": file_data["findings_count"],
                    "severity_counts": dict(file_data["severity_counts"])
                }
        
        # Calculate overall repository score
        if scanner_scores:
            # Simple average of scanner scores
            overall_score = sum(scanner_scores.values()) / len(scanner_scores)
        else:
            overall_score = 100.0
        
        # Aggregate severity breakdown
        total_severity_counts = defaultdict(int)
        for scanner_break in scanner_breakdown.values():
            for severity, count in scanner_break["severity_counts"].items():
                total_severity_counts[severity] += count
        
        return {
            "overall_score": round(overall_score, 2),
            "score_by_scanner": scanner_scores,
            "file_wise_scores": aggregated_file_scores,
            "scoring_breakdown": {
                "by_severity": dict(total_severity_counts),
                "by_scanner": scanner_breakdown
            },
            "scanners_executed": list(scanner_scores.keys())
        }
    
    def _count_severities(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count findings by severity"""
        counts = defaultdict(int)
        for finding in findings:
            severity = finding.get("severity", "medium")
            if isinstance(severity, str):
                severity = severity.lower()
            elif hasattr(severity, 'value'):
                severity = severity.value.lower()
            else:
                severity = str(severity).lower()
            counts[severity] += 1
        return dict(counts)


def load_workflow_policies() -> Dict[str, Any]:
    """
    Load workflow policies from the policy directory.
    Returns policies dictionary or empty dict if not found.
    """
    try:
        # Get the directory of the scoring_engine.py file
        current_dir = os.path.realpath(os.path.dirname(__file__))
        # Navigate to policies directory: scanner_core/helpers -> scanner_core -> policies
        policy_file = os.path.join(current_dir, '..', 'policies', 'workflow.yaml')
        policy_file = os.path.abspath(policy_file)
        
        if not os.path.exists(policy_file):
            return {}
        
        with open(policy_file, 'r') as f:
            policies_data = yaml.safe_load(f)
            return policies_data.get('policies', {})
    except FileNotFoundError:
        return {}
    except yaml.YAMLError as e:
        return {}
    except Exception as e:
        return {}

