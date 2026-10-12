import os
import sys
import yaml
import time
import re
from typing import List, Dict, Any, Tuple

# ── YAML line-tracking helpers ─────────────────────────────────────────────────

class _LineTrackingLoader(yaml.SafeLoader):
    """YAML loader that injects ``__line__`` (1-indexed) into every mapping."""


def _construct_mapping_with_line(loader: yaml.SafeLoader, node: yaml.MappingNode) -> dict:
    mapping = loader.construct_mapping(node, deep=True)
    mapping["__line__"] = node.start_mark.line + 1
    mapping["__key_lines__"] = {
        str(loader.construct_object(key_node, deep=True)): key_node.start_mark.line + 1
        for key_node, _ in node.value
    }
    return mapping


_LineTrackingLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping_with_line,
)


def _strip_line_tracking(obj: Any) -> Any:
    """Recursively remove ``__line__`` keys so validators see clean dicts."""
    if isinstance(obj, dict):
        return {
            k: _strip_line_tracking(v)
            for k, v in obj.items()
            if k not in {"__line__", "__key_lines__"}
        }
    if isinstance(obj, list):
        return [_strip_line_tracking(item) for item in obj]
    return obj

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from scanner_core.base_scanner import (
    BaseScanner, ScanRequest, ScanResponse, ScanResult, 
    ScanFinding, ScanStatus, ScanSeverity
)
from scanner_core.policy_scanner_common.utils import (
    write_markdown_report
)
from scanner_core.logging_config import get_scanner_logger
from scanner_core.helpers.scoring_engine import OPABasedScoreAdapter
from core.validator import K8sSecurityValidator
from scanner_core.policies.kubernetes.deprecated_api_checker import DeprecatedAPIChecker

logger = get_scanner_logger()


class KubernetesScanner(BaseScanner):
    """Kubernetes security scanner microservice using K8sSecurityValidator"""
    
    def __init__(self):
        super().__init__("kubernetes")
        self.validator = K8sSecurityValidator()
        self.deprecated_checker = DeprecatedAPIChecker()
    
    def scan(self, request: ScanRequest) -> ScanResponse:
        """Execute Kubernetes security scan"""
        start_time = time.time()
        
        try:
            logger.info(f"Starting Kubernetes security scan for: {request.repo_path}")
            
            kube_yaml_files = self._find_kube_yaml_files(request.repo_path)
            
            if not kube_yaml_files:
                logger.info("No Kubernetes YAML files found")
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
            
            logger.info(f"Found {len(kube_yaml_files)} Kubernetes YAML file(s)")
            
            disabled_policies = (request.metadata or {}).get("disabled_policies", {})
            findings = []
            scanned_files = []
            # Raw deprecated-API findings aggregated per kind+apiVersion key
            _deprecated_raw: dict = {}  # key -> {kind, deprecated_version, replacement_version, removed_in, since, source_files: []}

            for yaml_path in kube_yaml_files:
                try:
                    scanned_files.append(yaml_path)

                    resources, line_map = self._load_resources_from_file(yaml_path)
                    if not resources:
                        continue

                    # ── Security checks (go into findings / IAC page) ────────
                    violations = self.validator.validate(resources)
                    if violations:
                        parsed_findings = self._map_violations_to_findings(violations, yaml_path, line_map)
                        if disabled_policies:
                            parsed_findings = [
                                f for f in parsed_findings
                                if not (disabled_policies.get(getattr(f, 'code', None) or '') is False
                                        or disabled_policies.get(getattr(f, 'policy', None) or '') is False)
                            ]
                        findings.extend(parsed_findings)
                        logger.info(f"Found {len(parsed_findings)} policy violation(s) in {yaml_path}")

                    # ── Deprecated API checks (go into metadata only) ─────────
                    deprecated_hits = self.deprecated_checker.check_resources(resources, yaml_path)
                    for hit in deprecated_hits:
                        agg_key = f"{hit['kind']}__{hit['deprecated_version']}"
                        if agg_key not in _deprecated_raw:
                            _deprecated_raw[agg_key] = {
                                "kind": hit["kind"],
                                "deprecated_version": hit["deprecated_version"],
                                "replacement_version": hit["replacement_version"],
                                "removed_in": hit["removed_in"],
                                "since": hit["since"],
                                "source_files": [],
                            }
                        if yaml_path not in _deprecated_raw[agg_key]["source_files"]:
                            _deprecated_raw[agg_key]["source_files"].append(yaml_path)

                except Exception as e:
                    logger.error(f"Error processing file {yaml_path}: {e}", exc_info=True)
                    continue

            if _deprecated_raw:
                logger.info(
                    f"Found {len(_deprecated_raw)} deprecated K8s API(s) across scanned manifests"
                )
            
            write_artifacts = os.getenv("WRITE_ARTIFACTS", "false").lower() == "true"
            if findings and request.output_dir and write_artifacts:
                result_md_path = os.path.join(request.output_dir, "Kubernetes-Security-Scan-Result.md")
                self._write_findings_report(findings, result_md_path, "Kubernetes Security Scan Results")
            
            scan_duration = time.time() - start_time
            
            overall_score = 100.0
            file_scores = {}
            try:
                findings_dicts = []
                for finding in findings:
                    severity = finding.severity
                    if hasattr(severity, 'value'):
                        severity = severity.value
                    else:
                        severity = str(severity)
                    
                    findings_dicts.append({
                        "policy": finding.policy or "",
                        "severity": severity,
                        "description": finding.description,
                        "code": finding.code,
                        "file": finding.file,
                        "line": finding.line
                    })
                
                adapter = OPABasedScoreAdapter()
                overall_score, file_scores = adapter.calculate_score(
                    findings=findings_dicts,
                    scanned_files=scanned_files
                )
                
                logger.info(f"Kubernetes security score calculated: {overall_score:.2f}")
            except Exception as score_error:
                logger.warning(f"Failed to calculate Kubernetes scores: {score_error}", exc_info=True)
            
            if findings:
                logger.warning(f"Kubernetes scan completed with {len(findings)} finding(s)")
            else:
                logger.info("No policy violations found in any Kubernetes YAML file")
            
            return self._create_success_response(
                request.scan_id,
                ScanResult(
                    scanner_type=self.scanner_type,
                    status=ScanStatus.COMPLETED,
                    findings=findings,
                    scanned_files=scanned_files,
                    scan_duration=scan_duration,
                    metadata={
                        "k8s_files_found": len(kube_yaml_files),
                        "validator_summary": self.validator.get_summary(),
                        "overall_score": overall_score,
                        "file_scores": file_scores,
                        # Deprecated API findings go here — NOT in findings list
                        # so they never appear on the IaC findings page.
                        # The frontend reads this from:
                        #   scanner_results.kubernetes.metadata.k8s_deprecated
                        "k8s_deprecated": _deprecated_raw if _deprecated_raw else None,
                    }
                )
            )
            
        except Exception as e:
            logger.error(f"Kubernetes scan failed: {e}", exc_info=True)
            return self._create_error_response(
                request.scan_id,
                f"Kubernetes scan failed: {str(e)}"
            )

    def _load_resources_from_file(self, file_path: str) -> Tuple[List[Dict[str, Any]], Dict]:
        """Load Kubernetes resources from a YAML file.

        Returns a tuple of (clean_docs, line_map) where line_map maps
        (resource_kind, resource_name) -> 1-indexed line number.
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                tracked_docs = [
                    doc for doc in yaml.load_all(f, Loader=_LineTrackingLoader)
                    if doc is not None
                ]
            # Build line map for both resources and nested checker key paths.
            line_map: Dict[tuple, int] = {}
            for doc in tracked_docs:
                kind = doc.get('kind')
                name = (doc.get('metadata') or {}).get('name')
                line_num = doc.get('__line__')
                if kind and name and line_num:
                    line_map[(kind, name)] = line_num
                    self._add_path_line_map(
                        doc, kind, name, line_map, path=''
                    )
            # Strip __line__ before handing resources to validators
            clean_docs = [_strip_line_tracking(doc) for doc in tracked_docs]
            return clean_docs, line_map
        except Exception as e:
            logger.warning(f"Failed to parse YAML {file_path}: {e}")
            return [], {}

    @classmethod
    def _add_path_line_map(
        cls,
        value: Any,
        kind: str,
        name: str,
        line_map: Dict[tuple, int],
        path: str,
    ) -> None:
        """Index tracked YAML mapping paths by their source line."""
        if isinstance(value, dict):
            line = value.get('__line__')
            if path and line:
                line_map[(kind, name, path)] = line
            for key, child in value.items():
                if key in {'__line__', '__key_lines__'}:
                    continue
                child_path = f'{path}.{key}' if path else str(key)
                key_lines = value.get('__key_lines__', {})
                if child_path and key_lines.get(str(key)):
                    line_map[(kind, name, child_path)] = key_lines[str(key)]
                cls._add_path_line_map(child, kind, name, line_map, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                cls._add_path_line_map(
                    child, kind, name, line_map, f'{path}[{index}]'
                )

    @staticmethod
    def _line_for_key_path(
        line_map: Dict[tuple, int],
        kind: str,
        name: str,
        key_path: str,
    ) -> Any:
        """Return the tracked line for a checker key path, if available."""
        if not key_path:
            return None

        path = re.sub(r'\[(\d+)\]', r'[\1]', key_path)
        while path:
            line = line_map.get((kind, name, path))
            if line:
                return line
            path = path.rsplit('.', 1)[0] if '.' in path else ''
        return None

    def _map_violations_to_findings(self, violations: List[Any], file_path: str, line_map: Dict = None) -> List[ScanFinding]:
        """Convert new Validator violations to ScanFinding objects"""
        findings = []
        
        for v in violations:
            v_data = v.to_dict() if hasattr(v, 'to_dict') else v
            
            severity_str = v_data.get('severity', 'MEDIUM')
            severity = self._map_severity(severity_str)
            
            description = v_data.get('message', 'Policy violation detected')
            rule_id = v_data.get('cve_id')
            
            resource_kind = v_data.get('kind') or v_data.get('resource_kind')
            resource_name = v_data.get('name') or v_data.get('resource_name')

            # Prefer a checker-provided line, then resolve its nested YAML path,
            # and finally fall back to the resource header.
            line = v_data.get('line')
            if not line and line_map and resource_kind and resource_name:
                lnum = self._line_for_key_path(
                    line_map,
                    resource_kind,
                    resource_name,
                    v_data.get('key_path', ''),
                )
                if not lnum:
                    lnum = line_map.get((resource_kind, resource_name))
                if lnum:
                    line = str(lnum)
            
            full_description = description
            if resource_kind and resource_name:
                full_description = f"[{resource_kind}: {resource_name}] {description}"

            finding = ScanFinding(
                policy=resource_name,
                severity=severity,
                description=full_description,
                file=file_path,
                line=line,
                code=rule_id,
                deny=[full_description] 
            )
            findings.append(finding)
            
        return findings

    def _map_severity(self, severity_str: str) -> ScanSeverity:
        """Map string severity to Enum"""
        if not isinstance(severity_str, str):
            return ScanSeverity.MEDIUM
            
        sev_map = {
            'CRITICAL': ScanSeverity.CRITICAL,
            'HIGH': ScanSeverity.HIGH,
            'MEDIUM': ScanSeverity.MEDIUM,
            'LOW': ScanSeverity.LOW,
            'INFO': ScanSeverity.INFO
        }
        return sev_map.get(severity_str.upper(), ScanSeverity.MEDIUM)

    def _is_kubernetes_yaml(self, file_path: str) -> bool:
        """Check if a YAML file is a Kubernetes resource"""
        try:
            with open(file_path, 'r') as f:
                docs = list(yaml.safe_load_all(f))
                for doc in docs:
                    if isinstance(doc, dict) and 'apiVersion' in doc and 'kind' in doc:
                        return True
        except Exception:
            pass
        return False
    
    def _find_kube_yaml_files(self, root_dir: str) -> List[str]:
        """Find all Kubernetes YAML files recursively"""
        yaml_files = []
        for dirpath, _, files in os.walk(root_dir):
            for f in files:
                if f.endswith(('.yaml', '.yml')):
                    full_path = os.path.join(dirpath, f)
                    if self._is_kubernetes_yaml(full_path):
                        yaml_files.append(full_path)
        return yaml_files

    def _write_findings_report(self, findings: List[ScanFinding], output_path: str, title: str):
        """Write findings to markdown report"""
        try:
            formatted_findings = []
            for finding in findings:
                formatted_findings.append({
                    'file': finding.file,
                    'deny': finding.deny or [finding.description]
                })
            write_markdown_report(formatted_findings, output_path, title)
        except Exception as e:
            logger.warning(f"Could not write markdown report: {e}", exc_info=True)


def scan_kubernetes(request: ScanRequest) -> ScanResponse:
    """
    Kubernetes scanner microservice endpoint
    """
    scanner = KubernetesScanner()
    return scanner.scan(request)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Kubernetes Scanner Microservice")
    parser.add_argument("--repo-path", required=True, help="Repository path to scan")
    parser.add_argument("--output-dir", required=True, help="Output directory for results")
    parser.add_argument("--scan-id", required=True, help="Unique scan ID")
    
    args = parser.parse_args()
    
    request = ScanRequest(
        repo_path=args.repo_path,
        output_dir=args.output_dir,
        scan_id=args.scan_id
    )
    
    response = scan_kubernetes(request)
    print(f"Scan Response: {response.json()}")