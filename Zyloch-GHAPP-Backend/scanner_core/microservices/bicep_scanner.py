import os
import sys
import time
import json
import shutil
import subprocess
import re as _re
import tempfile
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner_core.base_scanner import (
    BaseScanner, ScanRequest, ScanResponse, ScanResult, 
    ScanFinding, ScanStatus, ScanSeverity
)
from scanner_core.logging_config import get_scanner_logger
from scanner_core.core.utils import deduplicate_findings
from scanner_core.constants.azure_psrule_policy_ids import AzurePSRulePolicyMetadata

logger = get_scanner_logger()

ARM_SCHEMA_HINTS = (
    "deploymentTemplate.json",
    "subscriptionDeploymentTemplate.json",
    "managementGroupDeploymentTemplate.json",
    "tenantDeploymentTemplate.json",
)

_ANSI = _re.compile(r'\x1b\[[0-9;]*m')
MAX_WORKERS = max(1, int(os.environ.get("BICEP_SCAN_WORKERS", min(os.cpu_count() or 2, 4))))


class BicepAzureScanner(BaseScanner):
    def __init__(self):
        super().__init__("bicep")
    
    def scan(self, request: ScanRequest) -> ScanResponse:
        start_time = time.time()
        logger.info(f"[Bicep-Azure] Scan started | scan_id={request.scan_id} | repo={request.repo_path}")

        try:
            native_bicep_files = self._find_bicep_files(request.repo_path)
            arm_files = self._find_arm_files(request.repo_path)

            if not native_bicep_files and not arm_files:
                return self._create_success_response(request.scan_id, ScanResult(
                    scanner_type=self.scanner_type, status=ScanStatus.COMPLETED,
                    findings=[], scanned_files=[], scan_duration=time.time() - start_time
                ))

            for f in native_bicep_files:
                logger.info(f"[Bicep-Azure]   -> {f}")
            for f in arm_files:
                logger.info(f"[Bicep-Azure]   -> {f} (ARM template)")

            # All source files for the scanned_files report
            target_files = native_bicep_files + arm_files

            all_findings = self._run_psrule_scan(request.repo_path, arm_files=arm_files)

            # --- Step 2b: Filter disabled policies ---
            disabled_policies = (request.metadata or {}).get("disabled_policies", {})
            if disabled_policies:
                all_findings = [
                    f for f in all_findings
                    if not (disabled_policies.get(getattr(f, "policy", None) or "") is False)
                ]

            pre_dedup_count = len(all_findings)
            all_findings = deduplicate_findings(all_findings)
            if pre_dedup_count != len(all_findings):
                logger.info(f"[Bicep-Azure][3/5] Removed {pre_dedup_count - len(all_findings)} duplicate(s)")


            all_findings = [
                f for f in all_findings
                if AzurePSRulePolicyMetadata.lookup(f.policy) is not None
            ]

            duration = time.time() - start_time

            sev_counts: Dict[str, int] = {}
            for f in all_findings:
                sev = str(f.severity.value) if hasattr(f.severity, 'value') else str(f.severity)
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
            if sev_counts:
                logger.info(f"[Bicep-Azure] Severity breakdown: {sev_counts}")

            return self._create_success_response(request.scan_id, ScanResult(
                scanner_type=self.scanner_type,
                status=ScanStatus.COMPLETED,
                findings=all_findings,
                scanned_files=target_files,
                scan_duration=duration,
                metadata={
                    "total_bicep_files": len(native_bicep_files),
                    "total_arm_files": len(arm_files),
                    "total_violations": len(all_findings),
                }
            ))

        except Exception as e:
            logger.error(f"[Bicep-Azure] Scan failed after {time.time() - start_time:.2f}s: {e}", exc_info=True)
            return self._create_error_response(request.scan_id, str(e))

    def _run_psrule_scan(self, repo_path: str, config_path: str = None, arm_files: List[str] = None) -> List[ScanFinding]:
        """
        Two-phase scan:
          Phase 1: Compile each .bicep → ARM JSON via `bicep build` (for
                   resource-name → original-bicep-file mapping only).
          Phase 2: Run Invoke-PSRule directly on the .bicep files using the
                   Azure.ExpandBicep convention (AZURE_BICEP_FILE_EXPANSION=True).
                   PSRule.Rules.Azure compiles and expands each bicep file
                   internally, then applies Azure.* rules to each resource.

        Key findings from debugging:
        - PSRule.Rules.Azure 1.47 / PSRule 2.9 requires Set-Location to the
          target directory; passing an absolute path to -InputPath silently
          produces zero output.
        - ARM template expansion via Azure.ExpandBicep requires
          AZURE_BICEP_FILE_EXPANSION=True in the PSRule configuration.
        - The default bicep compile timeout (5 s) is too short; increase to 60 s.
        - PSRule 2.9 JSON output uses camelCase field names (outcome, ruleName,
          targetName, source) not PascalCase.
        - PSRule mixes ANSI-coloured warnings into stdout; strip them before
          parsing JSON.
        """
        findings = []
        arm_dir = None
        bicep_workdir = None

        try:
            if shutil.which("pwsh") is None:
                raise RuntimeError(
                    "PowerShell (pwsh) is not installed or not on PATH. "
                    "Install it via: https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-linux"
                )
            if shutil.which("bicep") is None:
                raise RuntimeError("Bicep CLI is not installed or not on PATH.")

            arm_files = arm_files or []
            bicep_files = self._find_bicep_files(repo_path)
            all_bicep_for_scan = bicep_files + arm_files

            if not all_bicep_for_scan:
                logger.info("[Bicep-Azure] No bicep or ARM files to scan — skipping PSRule")
                return findings

            # --- Phase 1: Compile .bicep → ARM JSON (for resource→bicep mapping) ---
            arm_dir = tempfile.mkdtemp(prefix="psrule_arm_")
            compiled = {}  # arm_json_path -> original_bicep_path

            def _compile(bicep_path):
                rel = os.path.relpath(bicep_path, repo_path)
                arm_name = rel.replace(os.sep, "__").replace(".bicep", ".json")
                arm_out = os.path.join(arm_dir, arm_name)
                try:
                    result = subprocess.run(
                        ["bicep", "build", "--outfile", arm_out, bicep_path],
                        capture_output=True, text=True, timeout=120
                    )
                except subprocess.TimeoutExpired:
                    logger.info(f"[Bicep-Azure]   Bicep build timed out for {rel}")
                    return
                if result.returncode == 0 and os.path.exists(arm_out):
                    compiled[arm_out] = bicep_path
                    logger.info(f"[Bicep-Azure]   Compiled: {rel} -> {arm_name}")
                else:
                    logger.info(
                        f"[Bicep-Azure]   Bicep build failed for {rel} "
                        f"(rc={result.returncode}): {result.stderr[:500]}"
                    )

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
                list(pool.map(_compile, bicep_files))

            logger.info(f"[Bicep-Azure] {len(compiled)}/{len(bicep_files)} native file(s) compiled to ARM JSON")
            if not compiled and not arm_files:
                logger.info("[Bicep-Azure] No files available for PSRule scan — skipping")
                return findings

            # Build resource_name → original source file mapping
            resource_to_bicep: dict = {}
            # From native .bicep → compiled ARM JSON
            for arm_file, original_bicep in compiled.items():
                try:
                    with open(arm_file, 'r') as fh:
                        arm_data = json.load(fh)
                    for res in arm_data.get("resources", []):
                        name = res.get("name", "")
                        if name and not name.startswith("["):
                            resource_to_bicep[name] = original_bicep
                except Exception as e:
                    logger.info(f"[Bicep-Azure]   Could not parse {os.path.basename(arm_file)} for resource names: {e}")
            # From ARM templates — parse the original JSON directly
            for arm_path in arm_files:
                try:
                    with open(arm_path, "r") as fh:
                        arm_data = json.load(fh)
                    for res in arm_data.get("resources", []):
                        name = res.get("name", "")
                        if name and not name.startswith("["):
                            resource_to_bicep[name] = arm_path
                except Exception as exc:
                    logger.info(
                        f"[Bicep-Azure]   Could not parse {os.path.basename(arm_path)} "
                        f"for resource names: {exc}"
                    )

            logger.info(f"[Bicep-Azure] Resource→file map: {list(resource_to_bicep.keys())}")
            # flat workdir filename → original source path (fallback for findings attribution)
            flat_to_source: Dict[str, str] = {}

            # --- Phase 2: Run Invoke-PSRule on .bicep files via Azure.ExpandBicep ---
            # Requirements discovered via debug:
            # - AZURE_BICEP_FILE_EXPANSION must be $True (enables Azure.ExpandBicep convention)
            # - AZURE_BICEP_FILE_EXPANSION_TIMEOUT must be raised (default 5 s too short;
            #   bicep compilation takes ~10 s per file in this container)
            # - PSRule MUST be run with Set-Location to the target dir + -InputPath '.'
            #   Passing an absolute directory path to -InputPath silently scans zero files.
            # - Copy bicep files to a flat temp dir so Set-Location points to one place.
            # - JSON output uses camelCase keys: outcome, ruleName, targetName, source.
            # - PSRule mixes ANSI warnings into stdout; strip them before JSON parsing.
            bicep_workdir = tempfile.mkdtemp(prefix="psrule_bicep_")
            # Split files across up to MAX_WORKERS chunks, each scanned by its own
            # pwsh process in parallel (bicep expansion inside PSRule dominates runtime).
            n_chunks = max(1, min(MAX_WORKERS, len(all_bicep_for_scan)))
            chunk_dirs = []
            for i in range(n_chunks):
                d = os.path.join(bicep_workdir, f"chunk_{i}")
                os.makedirs(d)
                chunk_dirs.append(d)

            entries = []  # (flat_name, source_path)
            for bicep_path in bicep_files:
                rel = os.path.relpath(bicep_path, repo_path)
                entries.append((rel.replace(os.sep, "__"), bicep_path))
            for arm_path in arm_files:
                entries.append((f"_arm_{os.path.basename(arm_path)}", arm_path))

            for idx, (flat_name, src) in enumerate(entries):
                shutil.copy2(src, os.path.join(chunk_dirs[idx % n_chunks], flat_name))
                flat_to_source[flat_name] = src

            per_file_timeout = 60
            files_per_chunk = -(-len(entries) // n_chunks)
            chunk_timeout = max(120, files_per_chunk * per_file_timeout)

            def _run_chunk(chunk_dir: str) -> str:
                cwd_q = chunk_dir.replace("'", "''")
                ps1_path = os.path.join(chunk_dir, "_run.ps1")
                with open(ps1_path, "w") as ps1_fh:
                    ps1_fh.write(
                        f"Set-Location '{cwd_q}'\n"
                        f"$opt = New-PSRuleOption -Configuration @{{\n"
                        f"    'AZURE_BICEP_FILE_EXPANSION' = $True\n"
                        f"    'AZURE_BICEP_FILE_EXPANSION_TIMEOUT' = {per_file_timeout}\n"
                        f"}}\n"
                        f"Invoke-PSRule -InputPath '.' -Module 'PSRule.Rules.Azure' "
                        f"-Option $opt -Format File -As Detail -Outcome Fail "
                        f"-ErrorAction SilentlyContinue -OutputFormat Json\n"
                    )
                try:
                    proc = subprocess.run(
                        ["pwsh", "-NonInteractive", "-File", ps1_path],
                        capture_output=True, text=True, timeout=chunk_timeout
                    )
                    return proc.stdout
                except subprocess.TimeoutExpired:
                    logger.error(f"[Bicep-Azure] PSRule chunk timed out: {os.path.basename(chunk_dir)}")
                    return ""

            non_empty = [d for d in chunk_dirs if os.listdir(d)]
            with ThreadPoolExecutor(max_workers=len(non_empty) or 1) as pool:
                outputs = list(pool.map(_run_chunk, non_empty))

            records: list = []

            def _flatten(obj: Any) -> None:
                if isinstance(obj, list):
                    for item in obj:
                        _flatten(item)
                elif isinstance(obj, dict):
                    records.append(obj)

            for stdout in outputs:
                # Strip ANSI warning lines that PSRule mixes into stdout before JSON
                json_lines = []
                for line in stdout.splitlines():
                    clean = _ANSI.sub("", line).strip()
                    if clean.startswith("WARNING:") or clean.startswith("VERBOSE:"):
                        logger.info(f"[Bicep-Azure]   psrule: {clean[:200]}")
                        continue
                    if clean:
                        json_lines.append(clean)
                raw = "\n".join(json_lines).strip()
                if not raw:
                    continue
                try:
                    _flatten(json.loads(raw))
                except json.JSONDecodeError:
                    for line in raw.splitlines():
                        try:
                            _flatten(json.loads(line))
                        except json.JSONDecodeError:
                            pass

            if not records:
                logger.info("[Bicep-Azure]   No findings from PSRule (empty output after stripping warnings)")
                return findings

            outcome_counts: Dict[str, int] = {}
            for rec in records:
                oc = rec.get("outcome", "Unknown")
                outcome_counts[oc] = outcome_counts.get(oc, 0) + 1
            logger.info(f"[Bicep-Azure]   Total records: {len(records)} | by outcome: {outcome_counts}")

            for record in records:
                # PSRule 2.9 uses camelCase field names
                outcome = record.get("outcome")
                if outcome not in ["Fail", "Error"]:
                    continue

                rule_name = record.get("ruleName", "UnknownRule")
                target_name = record.get("targetName", "UnknownTarget")
                info = record.get("info", {})
                description = info.get("recommendation", info.get("synopsis", "No recommendation provided."))
                source_info = record.get("source", [])
                line_num = str(source_info[0].get("line", "1")) if source_info else "1"

                # 1. Try static resource-name map (works for non-expression names)
                original_bicep = resource_to_bicep.get(target_name)
                # 2. Fall back to the source file PSRule reports for this record
                if not original_bicep and source_info:
                    src_basename = os.path.basename(source_info[0].get("file", ""))
                    original_bicep = flat_to_source.get(src_basename)
                # 3. Final fallback: first available source
                if not original_bicep:
                    original_bicep = (
                        next(iter(compiled.values()), None)
                        or next(iter(arm_files), "unknown")
                    )

                # Enrich finding with AzurePSRulePolicyMetadata
                policy_meta = AzurePSRulePolicyMetadata.lookup(rule_name)
                if policy_meta:
                    finding_policy = policy_meta.policy_id
                    finding_severity = self._map_psrule_severity(policy_meta.severity)
                    finding_description = f"{policy_meta.description}"
                    finding_title = f"{policy_meta.title}"
                else:
                    finding_policy = "psrule_azure"
                    finding_severity = ScanSeverity.MEDIUM
                    finding_description = f"[{target_name}] {description}"
                    finding_title = ""

                finding = ScanFinding(
                    policy=rule_name,
                    code=finding_policy,
                    severity=finding_severity,
                    description=finding_description,
                    file=original_bicep,
                    line=line_num
                )

                findings.append(finding)

        except subprocess.TimeoutExpired:
            logger.error("[Bicep-Azure] PSRule execution timed out")
        except Exception as e:
            logger.error(f"[Bicep-Azure] Exception during PSRule execution: {e}", exc_info=True)
        finally:
            if arm_dir and os.path.exists(arm_dir):
                shutil.rmtree(arm_dir, ignore_errors=True)
            if bicep_workdir and os.path.exists(bicep_workdir):
                shutil.rmtree(bicep_workdir, ignore_errors=True)

        return findings

    def _find_arm_files(self, search_path: str) -> List[str]:
        """Find ARM template JSON files by checking the first 4 KB for schema + resources markers."""
        arm_files = []
        for root, dirs, files in os.walk(search_path):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for file in files:
                if not file.endswith(".json"):
                    continue
                full_path = os.path.join(root, file)
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
                        head = fh.read(4096)
                except OSError:
                    continue
                if '"$schema"' in head and '"resources"' in head and any(h in head for h in ARM_SCHEMA_HINTS):
                    arm_files.append(full_path)
        return arm_files

    def _validate_arm_template(self, path: str) -> List[str]:
        """Return validation issues for an ARM template. Empty list = valid."""
        issues: List[str] = []
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            return [f"Cannot read/parse: {exc}"]
        schema = data.get("$schema", "")
        if not any(h in schema for h in ARM_SCHEMA_HINTS):
            issues.append(f"Unrecognised $schema: {schema!r}")
        if "contentVersion" not in data:
            issues.append("Missing 'contentVersion'")
        if not isinstance(data.get("resources"), list):
            issues.append("Missing or invalid 'resources' array")
        return issues

    def _decompile_arm_files(self, arm_files: List[str], output_dir: str) -> Dict[str, str]:
        """
        Decompile ARM template JSON files to .bicep using `bicep decompile`.
        The standalone Bicep CLI (already required for PSRule) supports ARM→Bicep
        decompilation natively; no Azure CLI ('az') is needed.
        Returns {decompiled_bicep_path: original_arm_path} for successful conversions.
        Files that fail validation or decompilation are skipped with a warning.
        """
        if shutil.which("bicep") is None:
            logger.warning(
                "[Bicep-Azure] Bicep CLI not found — ARM template decompilation skipped."
            )
            return {}

        result_map: Dict[str, str] = {}
        for arm_path in arm_files:
            issues = self._validate_arm_template(arm_path)
            if any("invalid 'resources'" in i or "Cannot read" in i for i in issues):
                logger.info(
                    f"[Bicep-Azure]   Skipping invalid ARM template {os.path.basename(arm_path)}: "
                    + "; ".join(issues)
                )
                continue
            if issues:
                logger.info(
                    f"[Bicep-Azure]   ARM template {os.path.basename(arm_path)} has warnings: "
                    + "; ".join(issues)
                )

            # `bicep decompile` writes <stem>.bicep next to the source file.
            # Work in a private temp copy so we don't touch the repo.
            with tempfile.TemporaryDirectory() as tmp:
                tmp_src = os.path.join(tmp, os.path.basename(arm_path))
                shutil.copy2(arm_path, tmp_src)

                proc = subprocess.run(
                    ["bicep", "decompile", tmp_src],
                    capture_output=True, text=True
                )
                stem = os.path.splitext(os.path.basename(arm_path))[0]
                produced = os.path.join(tmp, f"{stem}.bicep")

                if proc.returncode != 0 or not os.path.exists(produced):
                    logger.warning(
                        f"[Bicep-Azure]   ARM decompile failed for {os.path.basename(arm_path)}: "
                        + (proc.stderr or proc.stdout or "unknown error").strip()[:300]
                    )
                    continue

                # Move decompiled file to output_dir with a unique name to avoid collisions
                dest_name = f"{stem}.bicep"
                dest_path = os.path.join(output_dir, dest_name)
                counter = 1
                while os.path.exists(dest_path):
                    dest_path = os.path.join(output_dir, f"{stem}_{counter}.bicep")
                    counter += 1
                shutil.move(produced, dest_path)
                result_map[dest_path] = arm_path
                if proc.stderr:
                    for line in proc.stderr.splitlines():
                        if line.strip():
                            logger.info(f"[Bicep-Azure]   decompile warn: {line.strip()[:200]}")
                logger.info(
                    f"[Bicep-Azure]   Decompiled: {os.path.basename(arm_path)} -> {os.path.basename(dest_path)}"
                )
        return result_map

    @staticmethod
    def _map_psrule_severity(severity_str: str) -> ScanSeverity:
        """Map a PSRule/metadata severity string to ScanSeverity."""
        return {
            "CRITICAL": ScanSeverity.CRITICAL,
            "HIGH": ScanSeverity.HIGH,
            "MEDIUM": ScanSeverity.MEDIUM,
            "LOW": ScanSeverity.LOW,
        }.get(str(severity_str or "").upper(), ScanSeverity.MEDIUM)

    def _find_bicep_files(self, search_path: str) -> List[str]:
        bicep_files = []
        for root, dirs, files in os.walk(search_path):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for file in files:
                if file.endswith(".bicep"):
                    bicep_files.append(os.path.join(root, file))
        return bicep_files

    def _write_findings_report(self, findings: List[ScanFinding], output_path: str, title: str):
        try:
            from scanner_core.policy_scanner_common.utils import write_markdown_report
            formatted = [{'file': f.file, 'deny': [f.description]} for f in findings]
            write_markdown_report(formatted, output_path, title)
        except Exception as e:
            logger.warning(f"[Bicep-Azure] Failed to write report: {e}")

def scan_bicep_azure(request: ScanRequest) -> ScanResponse:
    return BicepAzureScanner().scan(request)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-path", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--scan-id", required=True)
    args = parser.parse_args()
    print(scan_bicep_azure(ScanRequest(args.repo_path, args.output_dir, args.scan_id)).json())