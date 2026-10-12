import os
import sys
import time
import re
import hcl2
from typing import List, Dict, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner_core.base_scanner import (
    BaseScanner, ScanRequest, ScanResponse, ScanResult,
    ScanFinding, ScanStatus, ScanSeverity
)
from scanner_core.logging_config import get_scanner_logger
from scanner_core.core.utils import strip_hcl2_identifier, normalize_hcl2_attrs, deduplicate_findings
from core.validator import AWSSecurityValidator

logger = get_scanner_logger()


class TerraformAwsScanner(BaseScanner):
    """
    Terraform AWS security scanner microservice.
    Scans raw .tf files using the AWSSecurityValidator.
    """

    def __init__(self):
        super().__init__("terraform_aws")
        self.validator = AWSSecurityValidator()

    def scan(self, request: ScanRequest) -> ScanResponse:
        start_time = time.time()
        logger.info(f"[AWS] Scan started | scan_id={request.scan_id} | repo={request.repo_path}")

        try:
            # --- Step 1: Discover .tf files ---
            target_files = self._find_tf_files(request.repo_path)

            if not target_files:
                logger.info("[AWS][1/5] No .tf files found – skipping AWS scan")
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

            logger.info(f"[AWS] Found {len(target_files)} .tf file(s):")

            # --- Step 2: Parse & validate each file ---
            all_findings = []
            for idx, file_path in enumerate(target_files, 1):
                file_findings = self._process_tf_file(file_path)
                all_findings.extend(file_findings)

            # --- Step 2b: Filter disabled policies ---
            disabled_policies = (request.metadata or {}).get("disabled_policies", {})
            if disabled_policies:
                all_findings = [
                    f for f in all_findings
                    if not (disabled_policies.get(getattr(f, "code", None) or "") is False)
                ]

            # --- Step 3: Deduplicate ---
            pre_dedup_count = len(all_findings)
            all_findings = deduplicate_findings(all_findings)
            if pre_dedup_count != len(all_findings):
                logger.info(f"[AWS][3/5] Removed {pre_dedup_count - len(all_findings)} duplicate(s)")

            
            # --- Step 5: Build metadata & return ---
            metadata = {"total_tf_files": len(target_files), "total_violations": len(all_findings)}
            if hasattr(self.validator, 'get_summary'):
                try:
                    summary = self.validator.get_summary()
                    metadata["validator_summary"] = summary
                except Exception as summary_err:
                    logger.warning(f"[AWS][5/5] Could not retrieve validator summary: {summary_err}")

            duration = time.time() - start_time
            logger.info(
                f"[AWS] Scan complete | scan_id={request.scan_id} | files={len(target_files)} "
                f"| findings={len(all_findings)} | duration={duration:.2f}s"
            )

            # Log severity breakdown
            sev_counts: Dict[str, int] = {}
            for f in all_findings:
                sev = str(f.severity.value) if hasattr(f.severity, 'value') else str(f.severity)
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
            if sev_counts:
                logger.info(f"[AWS] Severity breakdown: {sev_counts}")

            return self._create_success_response(
                request.scan_id,
                ScanResult(
                    scanner_type=self.scanner_type,
                    status=ScanStatus.COMPLETED,
                    findings=all_findings,
                    scanned_files=target_files,
                    scan_duration=duration,
                    metadata=metadata
                )
            )

        except Exception as e:
            logger.error(f"[AWS] Scan failed after {time.time() - start_time:.2f}s: {e}", exc_info=True)
            return self._create_error_response(request.scan_id, f"Terraform AWS scan failed: {str(e)}")

    def _process_tf_file(self, file_path: str) -> List[ScanFinding]:
        """Parses HCL into the grouped dict structure expected by AWSSecurityValidator."""
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = hcl2.load(f)

            # AWS Validator expects: resources_dict[rtype][rname] = rvalues
            resources_dict = {}
            resource_blocks = data.get('resource', [])

            for block in resource_blocks:
                for rtype, instances in block.items():
                    # hcl2 v8+ wraps identifier labels in double-quotes; strip them.
                    rtype = strip_hcl2_identifier(rtype)
                    if rtype not in resources_dict:
                        resources_dict[rtype] = {}

                    for rname, attributes in instances.items():
                        rname = strip_hcl2_identifier(rname)
                        # Normalise nested block lists and remove __is_block__ markers.
                        resources_dict[rtype][rname] = normalize_hcl2_attrs(attributes)
                        logger.debug(f"[AWS]   Parsed resource: {rtype}.{rname}")

            all_types = list(resources_dict.keys())

            # Keep only AWS resource types (aws_ prefix); skip files belonging to other providers
            resources_dict = {rtype: instances for rtype, instances in resources_dict.items()
                              if rtype.startswith('aws_')}

            # If no AWS resources were found in the file, skip validation
            if not resources_dict:
                logger.info(f"[AWS] {file_path}: no AWS resources found (types present: {all_types}) – skipping")
                return []

            aws_types = list(resources_dict.keys())
            aws_resource_count = sum(len(v) for v in resources_dict.values())
            logger.info(
                f"[AWS] {file_path}: {aws_resource_count} AWS resource(s) across "
                f"{len(aws_types)} type(s): {aws_types}"
            )

            line_map = self._build_line_number_map(file_path)
            logger.info(f"[AWS] {file_path}: line_map has {len(line_map)} entries")
            logger.debug(f"[AWS] {file_path}: running AWSSecurityValidator")
            violations = self.validator.validate(resources_dict)
            logger.info(f"[AWS] {file_path}: validator returned {len(violations)} violation(s)")

            for v in violations:
                resource_name = getattr(v, 'resource_name', 'unknown_resource')
                msg = getattr(v, 'message', str(v))
                policy_id = getattr(v, 'policy_id', 'TF_AWS_001')

                # Resolve severity to a ScanSeverity enum value
                raw_sev = getattr(v, 'severity', ScanSeverity.MEDIUM)
                if isinstance(raw_sev, ScanSeverity):
                    severity = raw_sev
                else:
                    sev_str = raw_sev.value.lower() if hasattr(raw_sev, 'value') else str(raw_sev).lower()
                    try:
                        severity = ScanSeverity(sev_str)
                    except ValueError:
                        logger.warning(f"[AWS] Unknown severity '{raw_sev}' for {policy_id}, defaulting to MEDIUM")
                        severity = ScanSeverity.MEDIUM

                # Resolve line number from raw HCL source
                resource_type = getattr(v, 'resource_type', None)
                line_num = line_map.get((resource_type, resource_name))
                if line_num is None:
                    for (rt, rn), ln in line_map.items():
                        if rn == resource_name:
                            line_num = ln
                            break
                if line_num:
                    logger.debug(f"[AWS] Resolved line {line_num} for {resource_type}.{resource_name}")
                else:
                    logger.debug(f"[AWS] No line resolved for {resource_type}.{resource_name} (resource_name='{resource_name}', map keys={list(line_map.keys())[:5]})")

                finding = ScanFinding(
                    policy=getattr(v, 'checker', getattr(v, 'resource_type', 'aws_policy')),
                    code=policy_id,
                    severity=severity,
                    description=f"[{resource_name}] {msg}",
                    file=file_path,
                    line=str(line_num) if line_num else "1"
                )
                logger.debug(
                    f"[AWS]   Finding: code={policy_id} severity={severity} "
                    f"resource={resource_name} msg={msg[:80]}"
                )
                findings.append(finding)

        except Exception as e:
            logger.warning(f"[AWS] Skipping {file_path} due to parse/validation error: {e}", exc_info=True)

        return findings

    def _build_line_number_map(self, file_path: str) -> dict:
        """Returns a dict mapping (resource_type, resource_name) -> line_number by scanning raw HCL text."""
        line_map = {}
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for lineno, line in enumerate(f, 1):
                    m = re.match(r'\s*resource\s+"([^"]+)"\s+"([^"]+)"', line)
                    if m:
                        line_map[(m.group(1), m.group(2))] = lineno
        except Exception:
            pass
        return line_map

    def _find_tf_files(self, search_path: str) -> List[str]:
        """Finds all .tf files in the target directory."""
        tf_files = []
        for root, dirs, files in os.walk(search_path):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for file in files:
                if file.endswith(".tf"):
                    tf_files.append(os.path.join(root, file))
        return tf_files

    def _write_findings_report(self, findings: List[ScanFinding], output_path: str, title: str):
        """Standard reporting logic used in other scanners."""
        try:
            from scanner_core.policy_scanner_common.utils import write_markdown_report
            formatted_findings = [{'file': f.file, 'deny': [f.description]} for f in findings]
            write_markdown_report(formatted_findings, output_path, title)
        except Exception:
            pass


def scan_terraform_aws(request: ScanRequest) -> ScanResponse:
    scanner = TerraformAwsScanner()
    return scanner.scan(request)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Terraform AWS Scanner Microservice")
    parser.add_argument("--repo-path", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--scan-id", required=True)

    args = parser.parse_args()
    req = ScanRequest(repo_path=args.repo_path, output_dir=args.output_dir, scan_id=args.scan_id)
    response = scan_terraform_aws(req)
    print(response.json())
