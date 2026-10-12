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

from scanner_core.core.engine import PolicyEngine
from scanner_core.core.utils import normalize_resource, strip_hcl2_identifier, normalize_hcl2_attrs, deduplicate_findings

logger = get_scanner_logger()

class TerraformAzureScanner(BaseScanner):
    def __init__(self):
        super().__init__("terraform_azure")
        self.engine = PolicyEngine()
    
    def scan(self, request: ScanRequest) -> ScanResponse:
        start_time = time.time()
        logger.info(f"[Azure] Scan started | scan_id={request.scan_id} | repo={request.repo_path}")
        try:
            # --- Step 1: Discover .tf files ---
            target_files = self._find_tf_files(request.repo_path)

            if not target_files:
                logger.info("[Azure][1/5] No .tf files found – skipping Azure scan")
                return self._create_success_response(request.scan_id, ScanResult(
                    scanner_type=self.scanner_type, status=ScanStatus.COMPLETED,
                    findings=[], scanned_files=[], scan_duration=time.time() - start_time
                ))

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
                logger.info(f"[Azure][3/5] Removed {pre_dedup_count - len(all_findings)} duplicate(s)")

        
            # --- Step 5: Build metadata & return ---
            duration = time.time() - start_time
            logger.info(
                f"[Azure] Scan complete | scan_id={request.scan_id} | files={len(target_files)} "
                f"| findings={len(all_findings)} | duration={duration:.2f}s"
            )

            # Log severity breakdown
            sev_counts: Dict[str, int] = {}
            for f in all_findings:
                sev = str(f.severity.value) if hasattr(f.severity, 'value') else str(f.severity)
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
            if sev_counts:
                logger.info(f"[Azure] Severity breakdown: {sev_counts}")

            return self._create_success_response(request.scan_id, ScanResult(
                scanner_type=self.scanner_type,
                status=ScanStatus.COMPLETED,
                findings=all_findings,
                scanned_files=target_files,
                scan_duration=duration,
                metadata={"total_tf_files": len(target_files), "total_violations": len(all_findings)}
            ))

        except Exception as e:
            logger.error(f"[Azure] Scan failed after {time.time() - start_time:.2f}s: {e}", exc_info=True)
            return self._create_error_response(request.scan_id, str(e))

    def _process_tf_file(self, file_path: str) -> List[ScanFinding]:
        """Parses HCL and runs policy engine"""
        findings = []
        line_map = self._build_line_number_map(file_path)
        try:
            logger.debug(f"[Azure] Parsing HCL file: {file_path}")
            with open(file_path, 'r') as f:
                data = hcl2.load(f)

            # HCL2 parses resources as a list of dicts: [{'resource_type': {'resource_name': {values}}}]
            resource_blocks = data.get('resource', [])
            logger.debug(f"[Azure] {file_path}: found {len(resource_blocks)} top-level resource block(s)")

            _AZURE_PREFIXES = ('azurerm_', 'azuread_', 'azurestack_', 'azapi_')
            azure_resource_count = 0
            skipped_types: List[str] = []

            for block in resource_blocks:
                for res_type, instances in block.items():
                    # hcl2 v8+ wraps identifier labels in double-quotes; strip them.
                    res_type = strip_hcl2_identifier(res_type)
                    # Skip resources that don't belong to an Azure provider
                    if not any(res_type.startswith(p) for p in _AZURE_PREFIXES):
                        if res_type not in skipped_types:
                            skipped_types.append(res_type)
                        logger.debug(f"[Azure]   Skipping non-Azure resource type: {res_type}")
                        continue
                    for res_name, attributes in instances.items():
                        res_name = strip_hcl2_identifier(res_name)
                        azure_resource_count += 1
                        logger.debug(f"[Azure]   Processing Azure resource: {res_type}.{res_name}")
                        # Create a structure that normalize_resource understands
                        raw_resource = {
                            "type": res_type,
                            "name": res_name,
                            # Normalise nested block lists and remove __is_block__ markers.
                            "values": normalize_hcl2_attrs(attributes)
                        }

                        normalized = normalize_resource(raw_resource)
                        violations = self.engine.run(normalized)
                        logger.debug(
                            f"[Azure]   {res_type}.{res_name}: "
                            f"{len(violations)} violation(s) from policy engine"
                        )

                        for v in violations:
                            code = v.code or 'HCL_AZ_001'
                            # Resolve severity to a ScanSeverity enum value
                            raw_sev = getattr(v, 'severity', ScanSeverity.MEDIUM)
                            if isinstance(raw_sev, ScanSeverity):
                                severity = raw_sev
                            else:
                                sev_str = raw_sev.value.lower() if hasattr(raw_sev, 'value') else str(raw_sev).lower()
                                try:
                                    severity = ScanSeverity(sev_str)
                                except ValueError:
                                    logger.warning(f"[Azure] Unknown severity '{raw_sev}' for {code}, defaulting to MEDIUM")
                                    severity = ScanSeverity.MEDIUM

                            finding = ScanFinding(
                                policy=getattr(v, 'policy', 'azure_hcl_policy'),
                                code=code,
                                severity=severity,
                                description=f"[{res_type}.{res_name}] {v.message}",
                                file=file_path,
                                line=str(line_map.get((res_type, res_name), 1))
                            )
                            logger.debug(
                                f"[Azure]   Finding: code={code} severity={severity} "
                                f"resource={res_type}.{res_name} msg={v.message[:80]}"
                            )
                            findings.append(finding)

            if skipped_types:
                logger.info(f"[Azure] {file_path}: skipped {len(skipped_types)} non-Azure resource type(s): {skipped_types}")
            logger.info(
                f"[Azure] {file_path}: processed {azure_resource_count} Azure resource(s), "
                f"produced {len(findings)} finding(s)"
            )
        except Exception as e:
            logger.warning(f"[Azure] Skipping {file_path} due to parse/validation error: {e}", exc_info=True)
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
        tf_files = []
        for root, dirs, files in os.walk(search_path):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for file in files:
                if file.endswith(".tf"):
                    tf_files.append(os.path.join(root, file))
        return tf_files

    def _write_findings_report(self, findings: List[ScanFinding], output_path: str, title: str):
        try:
            from scanner_core.policy_scanner_common.utils import write_markdown_report
            formatted = [{'file': f.file, 'deny': [f.description]} for f in findings]
            write_markdown_report(formatted, output_path, title)
        except: pass

def scan_terraform_azure(request: ScanRequest) -> ScanResponse:
    return TerraformAzureScanner().scan(request)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-path", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--scan-id", required=True)
    args = parser.parse_args()
    print(scan_terraform_azure(ScanRequest(args.repo_path, args.output_dir, args.scan_id)).json())