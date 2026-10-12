"""
Workflow Scanner Microservice
Handles GitHub Actions workflow security scanning as a modular microservice
"""

import os
import sys
import re
import yaml
import time
from typing import List, Dict, Any
from collections import defaultdict

# Add current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from scanner_core.base_scanner import BaseScanner, ScanRequest, ScanResponse, ScanResult, ScanFinding, ScanStatus, ScanSeverity
from scanner_core.policy_scanner_common.utils import safe_print
from scanner_core.logging_config import get_scanner_logger

logger = get_scanner_logger()

# Import unified scoring engine
from scanner_core.helpers.scoring_engine import PolicyBasedScoreAdapter


class WorkflowScanner(BaseScanner):
    """GitHub Actions workflow security scanner microservice"""
    
    def __init__(self):
        super().__init__("workflow")
    
    def scan(self, request: ScanRequest) -> ScanResponse:
        """Execute GitHub Actions workflow security scan"""
        start_time = time.time()
        
        try:
            logger.info("Starting GitHub Actions Security Policy Scanner")
            
            # Get the directory of the current script
            scanner_dir = os.path.realpath(os.path.dirname(__file__))
            policy_file = os.path.join(scanner_dir, '..', 'policies', 'workflow.yaml')
            
            # Define workflow directories
            workflows_dir = os.path.join(request.repo_path, '.github', 'workflows')
            actions_dir = os.path.join(request.repo_path, '.github', 'actions')
            
            # Load policies
            policies = self._load_policies(policy_file)
            if not policies:
                logger.error("No policies found in policy file")
                return self._create_error_response(
                    request.scan_id,
                    "No policies found in policy file"
                )
            
            logger.info(f"Loaded {len(policies)} security policies")
            logger.info(f"Scanning workflows in: {workflows_dir}, actions in: {actions_dir}")
            
            # Scan directories
            findings, scanned_files = self._scan_directory(workflows_dir, policies)
            more_findings, more_files = self._scan_directory(actions_dir, policies)
            
            findings.extend(more_findings)
            scanned_files.extend(more_files)

            # Filter out findings whose policy code is disabled in the org config.
            disabled_policies = (request.metadata or {}).get("disabled_policies", {})
            if disabled_policies:
                before = len(findings)
                findings = [
                    f for f in findings
                    if not (disabled_policies.get(getattr(f, 'code', None) or '') is False
                            or disabled_policies.get(getattr(f, 'policy', None) or '') is False)
                ]
                if len(findings) != before:
                    logger.info(f"[Workflow] Skipped {before - len(findings)} finding(s) due to disabled policies")
            
            logger.info(f"Scan Summary: Files scanned: {len(scanned_files)}, Issues found: {len(findings)}")
            
            # Convert ScanFinding objects to dictionaries for scoring
            findings_dicts = []
            for finding in findings:
                if isinstance(finding, dict):
                    # Already a dictionary
                    finding_dict = finding.copy()
                    # Ensure severity is a string
                    if 'severity' in finding_dict:
                        severity = finding_dict['severity']
                        if hasattr(severity, 'value'):
                            finding_dict['severity'] = severity.value
                        else:
                            finding_dict['severity'] = str(severity)
                    findings_dicts.append(finding_dict)
                elif hasattr(finding, 'dict'):
                    # Pydantic v1
                    finding_dict = finding.dict()
                    # Ensure severity is a string
                    if 'severity' in finding_dict:
                        severity = finding_dict['severity']
                        if hasattr(severity, 'value'):
                            finding_dict['severity'] = severity.value
                        else:
                            finding_dict['severity'] = str(severity)
                    findings_dicts.append(finding_dict)
                elif hasattr(finding, 'model_dump'):
                    # Pydantic v2
                    finding_dict = finding.model_dump()
                    # Ensure severity is a string
                    if 'severity' in finding_dict:
                        severity = finding_dict['severity']
                        if hasattr(severity, 'value'):
                            finding_dict['severity'] = severity.value
                        else:
                            finding_dict['severity'] = str(severity)
                    findings_dicts.append(finding_dict)
                else:
                    # Fallback: convert object attributes to dict
                    severity = getattr(finding, 'severity', 'unknown')
                    if hasattr(severity, 'value'):
                        severity = severity.value
                    else:
                        severity = str(severity)
                    
                    findings_dicts.append({
                        "policy": getattr(finding, 'policy', ''),
                        "severity": severity,
                        "description": getattr(finding, 'description', ''),
                        "code": getattr(finding, 'code', None),
                        "url": getattr(finding, 'url', None),
                        "match": getattr(finding, 'match', None),
                        "file": getattr(finding, 'file', ''),
                        "line": getattr(finding, 'line', None),
                        "deny": getattr(finding, 'deny', None)
                    })
            
            # Calculate scores using unified scoring engine
            overall_score = 100.0
            file_scores = {}
            try:
                # Use PolicyBasedScoreAdapter to calculate scores
                adapter = PolicyBasedScoreAdapter()
                overall_score, file_scores = adapter.calculate_score(
                    findings=findings_dicts,
                    scanned_files=scanned_files,
                    policies=policies
                )
                
                logger.info(f"Workflow security score calculated: {overall_score:.2f}")
            except Exception as score_error:
                logger.warning(f"Failed to calculate workflow scores: {score_error}", exc_info=True)
            
            # Save findings to markdown file if requested
            md_file_path = None
            write_artifacts = os.getenv("WRITE_ARTIFACTS", "false").lower() == "true"
            if request.output_dir and write_artifacts:
                md_file_path = self._save_findings_to_md(findings, scanned_files, request.output_dir)
            
            scan_duration = time.time() - start_time
            
            if findings:
                logger.warning(f"Scan completed with {len(findings)} finding(s)")
            else:
                logger.info("Scan completed successfully with no findings")
            
            logger.info(f"Workflow scan completed in {scan_duration:.2f}s")
            
            return self._create_success_response(
                request.scan_id,
                ScanResult(
                    scanner_type=self.scanner_type,
                    status=ScanStatus.COMPLETED,
                    findings=findings,
                    scanned_files=scanned_files,
                    scan_duration=scan_duration,
                    metadata={
                        "policies_loaded": len(policies),
                        "workflows_dir": workflows_dir,
                        "actions_dir": actions_dir,
                        "md_file_path": md_file_path,
                        "overall_score": overall_score,
                        "file_scores": file_scores
                    }
                )
            )
            
        except Exception as e:
            logger.error(f"Workflow scan failed: {e}", exc_info=True)
            return self._create_error_response(
                request.scan_id,
                f"Workflow scan failed: {str(e)}"
            )
    
    def _load_policies(self, policy_file: str) -> Dict[str, Any]:
        """Load security policies from YAML file"""
        try:
            with open(policy_file, 'r') as f:
                return yaml.safe_load(f)['policies']
        except FileNotFoundError:
            logger.error(f"Policy file not found at {policy_file}")
            return {}
        except yaml.YAMLError as e:
            logger.error(f"Error parsing policy file: {e}", exc_info=True)
            return {}
        except Exception as e:
            logger.error(f"Error loading policies: {e}", exc_info=True)
            return {}
    
    def _scan_file(self, filepath: str, content: str, policies: Dict[str, Any]) -> List[ScanFinding]:
        """Scan a file against security policies"""
        findings = []
        lines = content.splitlines()
        workspace = os.environ.get('GITHUB_WORKSPACE', '.')
        rel_filepath = os.path.relpath(filepath, workspace)

        for name, policy in policies.items():
            description = policy.get("description", "")
            pattern = policy.get("pattern")
            missing_block = policy.get("missing_block")
            allowlist = policy.get("allowlist", [])
            exclude_files = policy.get("exclude") or []

            if rel_filepath in exclude_files:
                continue  # Skip scanning this file for this policy

            if pattern:
                try:
                    regex = re.compile(pattern, re.MULTILINE | re.IGNORECASE)
                    for lineno, line in enumerate(lines, start=1):
                        match = regex.search(line)
                        if match:
                            if name == "unknown-actions":
                                full_action = match.group(1) if match.groups() else match.group(0)
                                org = full_action.split("/")[0] if "/" in full_action else full_action
                                if org in allowlist:
                                    continue
                            if name == "gcp-legacy-auth":
                                peek_ahead = lines[lineno:lineno + 10]  # Look at next few lines
                                if not any("credentials_json" in line for line in peek_ahead):
                                    continue
                            
                            # Map policy severity to ScanSeverity
                            severity_map = {
                                "critical": ScanSeverity.CRITICAL,
                                "high": ScanSeverity.HIGH,
                                "medium": ScanSeverity.MEDIUM,
                                "low": ScanSeverity.LOW,
                                "info": ScanSeverity.INFO
                            }
                            
                            finding = ScanFinding(
                                policy=name,
                                severity=severity_map.get(policy["severity"], ScanSeverity.MEDIUM),
                                description=description,
                                code=policy.get("code", ""),
                                url=policy.get("url", ""),
                                match=match.group(0).strip(),
                                file=filepath,
                                line=str(lineno)
                            )
                            findings.append(finding)
                except re.error as e:
                    logger.warning(f"Invalid regex pattern in policy '{name}': {e}")
                    continue

            if missing_block and missing_block not in content:
                finding = ScanFinding(
                    policy=name,
                    severity=ScanSeverity.MEDIUM,  # Default severity for missing blocks
                    description=f"'{missing_block}' block is missing",
                    code=policy.get("code", ""),
                    url=policy.get("url", ""),
                    match="-",
                    file=filepath,
                    line="-"
                )
                findings.append(finding)
        
        return findings
    
    def _scan_directory(self, directory: str, policies: Dict[str, Any]) -> tuple[List[ScanFinding], List[str]]:
        """Scan a directory for YAML files and check against policies"""
        all_findings = []
        scanned_files = []

        if not os.path.exists(directory):
            logger.debug(f"Directory {directory} does not exist")
            return all_findings, scanned_files
        
        for root, _, files in os.walk(directory):
            # Exclude scanning within the 'policy-scanner' directory itself
            if os.path.basename(os.path.dirname(__file__)) in root:
                continue
            for f in files:
                if f.endswith((".yaml", ".yml")):
                    path = os.path.join(root, f)
                    try:
                        with open(path, "r", encoding="utf-8") as file:
                            content = file.read()
                            findings = self._scan_file(path, content, policies)
                            all_findings.extend(findings)
                            scanned_files.append(path)
                    except Exception as e:
                        logger.warning(f"Could not read file {path}: {e}", exc_info=True)
                        continue
        return all_findings, scanned_files
    
    def _save_findings_to_md(self, findings: List[ScanFinding], scanned_files: List[str], output_dir: str) -> str:
        """Save findings to a Markdown file"""
        grouped = defaultdict(list)
        for finding in findings:
            grouped[finding.file].append(finding)

        md_file_path = os.path.join(output_dir, 'GHASEC_Scan_Results.md')
        try:
            with open(md_file_path, 'w', encoding='utf-8') as md_file:
                md_file.write("# 🛡🔎 GHA Security Policy Scan Results\n")
                for file_path in scanned_files:
                    if file_path in grouped:
                        md_file.write(f"\n### 📃File: `{file_path}`\n")
                        for finding in grouped[file_path]:
                            severity = finding.severity.upper()
                            prefix = f"({severity})"
                            if severity == "CRITICAL":
                                prefix = f"❌ {prefix}"
                            elif severity == "HIGH":
                                prefix = f"⚠️ {prefix}"
                            else:
                                prefix = f"ℹ️ {prefix}"
                            md_file.write(f"\n#### {prefix}: [{finding.policy}] {finding.description}\n")
                            md_file.write(f"  - **Code**: {finding.code or 'N/A'}\n")
                            md_file.write(f"  - **Learn more**: {finding.url or 'N/A'}\n")
                            md_file.write(f"  - **Line**: {finding.line}\n")
                            md_file.write(f"  - **Match**: {finding.match}\n")
                        md_file.write("\n" + "-" * 40)
                    else:
                        md_file.write(f"\n### ✅ No policy violations found in: `{file_path}`\n")
                        md_file.write("\n" + "-" * 40)
        except Exception as e:
            logger.error(f"Error writing markdown file: {e}", exc_info=True)
            return None

        return md_file_path


# Microservice endpoint function
def scan_workflow(request: ScanRequest) -> ScanResponse:
    """
    Workflow scanner microservice endpoint
    This function can be called by the Scan Controller Service
    """
    scanner = WorkflowScanner()
    return scanner.scan(request)


if __name__ == "__main__":
    # For testing purposes
    import argparse
    
    parser = argparse.ArgumentParser(description="Workflow Scanner Microservice")
    parser.add_argument("--repo-path", required=True, help="Repository path to scan")
    parser.add_argument("--output-dir", required=True, help="Output directory for results")
    parser.add_argument("--scan-id", required=True, help="Unique scan ID")
    
    args = parser.parse_args()
    
    request = ScanRequest(
        repo_path=args.repo_path,
        output_dir=args.output_dir,
        scan_id=args.scan_id
    )
    
    response = scan_workflow(request)
    print(f"Scan Response: {response.json()}")
