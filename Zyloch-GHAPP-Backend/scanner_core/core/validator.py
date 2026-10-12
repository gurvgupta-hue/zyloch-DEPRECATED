from typing import Dict, List, Any
from pathlib import Path
from collections import defaultdict
import logging

# Module-level logger shared by all validators in this file.
# Uses the same name hierarchy as the rest of the scanner_core package so
# log output is captured by whatever handler the application configures.
try:
    from scanner_core.logging_config import get_scanner_logger as _get_logger
    _validator_logger = _get_logger()
except Exception:
    _validator_logger = logging.getLogger("scanner_core.validator")

from scanner_core.models.violation import DockerSecurityViolation
from scanner_core.helpers.docker_helper import DockerHelper
from scanner_core.policies.docker.env_secrets_checker import EnvSecretsChecker
from scanner_core.policies.docker.latest_tag_checker import LatestTagChecker
from scanner_core.policies.docker.root_user_checker import RootUserChecker
from scanner_core.policies.docker.privileged_port_checker import PrivilegedPortChecker
from scanner_core.policies.docker.mining_detection_checker import MiningDetectionChecker
from scanner_core.policies.docker.missing_healthcheck_checker import MissingHealthcheckChecker
from scanner_core.policies.docker.package_upgrade_checker import PackageUpgradeChecker
from scanner_core.policies.docker.add_vs_copy_checker import AddVsCopyChecker
from scanner_core.policies.docker.sudo_usage_checker import SudoUsageChecker
from scanner_core.policies.docker.unallowed_images_checker import UnallowedImagesChecker
from scanner_core.policies.docker.unallowed_commands_checker import UnallowedCommandsChecker
from scanner_core.policies.docker.missing_metadata_checker import MissingMetadataChecker
from scanner_core.policies.docker.hardcoded_secrets_checker import HardcodedSecretsChecker
from scanner_core.policies.docker.privileged_mode_checker import PrivilegedModeChecker
from scanner_core.policies.docker.dangerous_capabilities_checker import DangerousCapabilitiesChecker
from scanner_core.policies.docker.insecure_network_mode_checker import InsecureNetworkModeChecker
from scanner_core.policies.docker.volume_mounts_checker import VolumeMountsChecker
from scanner_core.policies.docker.insecure_base_image_checker import InsecureBaseImageChecker
from scanner_core.policies.docker.resource_limits_checker import ResourceLimitsChecker
from scanner_core.policies.docker.restart_policy_checker import RestartPolicyChecker
from scanner_core.policies.docker.security_options_checker import SecurityOptionsChecker
from scanner_core.policies.docker.multistage_build_checker import MultistageBuildChecker
from scanner_core.policies.docker.curl_verification_checker import CurlVerificationChecker
from scanner_core.policies.docker.unnecessary_services_checker import UnnecessaryServicesChecker

from scanner_core.models.violation import PolicyViolation
from scanner_core.policies.kubernetes.app_armor_checker import AppArmorChecker
from scanner_core.policies.kubernetes.capabilities_checker import CapabilitiesChecker
from scanner_core.policies.kubernetes.host_network_checker import HostNetworkChecker
from scanner_core.policies.kubernetes.host_path_checker import HostPathChecker
from scanner_core.policies.kubernetes.host_process_checker import HostProcessChecker
from scanner_core.policies.kubernetes.image_pull_policy_checker import ImagePullPolicyChecker
from scanner_core.policies.kubernetes.latest_image_checker import LatestImageChecker
from scanner_core.policies.kubernetes.privileged_mode_checker import PrivilegedModeChecker as K8sPrivilegedModeChecker
from scanner_core.policies.kubernetes.probe_checkers import ProbeChecker
from scanner_core.policies.kubernetes.proc_mount_checker import ProcMountChecker
from scanner_core.policies.kubernetes.resource_limits_checker import ResourceLimitsChecker as K8sResourceLimitsChecker
from scanner_core.policies.kubernetes.seccomp_profile_checker import SecCompProfileChecker
from scanner_core.policies.kubernetes.selinux_checker import selinuxChecker
from scanner_core.policies.kubernetes.sysctls_checker import SysCtlsChecker

from collections import defaultdict
from models.violation import PolicyViolation
from scanner_core.policies.terraform_gcp.bigquery_dataset_private_checker import BigQueryDatasetPrivateChecker
from scanner_core.policies.terraform_gcp.bigquery_security_controls_checker import BigQuerySecurityControlsChecker
from scanner_core.policies.terraform_gcp.bucket_logging_enabled_checker import BucketLoggingEnabledChecker
from scanner_core.policies.terraform_gcp.cloud_sql_prevent_public_ip_checker import CloudSqlPreventPublicIpChecker
from scanner_core.policies.terraform_gcp.cloud_functions_security_checker import CloudFunctionsSecurityChecker
from scanner_core.policies.terraform_gcp.compute_instance_default_svc_account_checker import ComputeInstanceDefaultSvcAccountChecker
from scanner_core.policies.terraform_gcp.dnssec_enabled_checker import DnssecEnabledChecker
from scanner_core.policies.terraform_gcp.encryption_key_365_rotation_checker import EncryptionKey365RotationChecker
from scanner_core.policies.terraform_gcp.gke_legacy_authorization_disabled_checker import GkeLegacyAuthorizationDisabledChecker
from scanner_core.policies.terraform_gcp.kms_encryption_key_90_days_checker import KmsEncryptionKey90DaysChecker
from scanner_core.policies.terraform_gcp.loadbalancer_ssl_forwarding_rule_checker import LoadbalancerSslForwardingRuleChecker
from scanner_core.policies.terraform_gcp.loadbalancer_security_checker import LoadBalancerSecurityChecker
from scanner_core.policies.terraform_gcp.logging_security_checker import LoggingSecurityChecker
from scanner_core.policies.terraform_gcp.monitoring_security_checker import MonitoringSecurityChecker
from scanner_core.policies.terraform_gcp.iam_security_checker import IAMSecurityChecker
from scanner_core.policies.terraform_gcp.no_ip_forwarding_checker import NoIpForwardingChecker
from scanner_core.policies.terraform_gcp.project_os_login_checker import ProjectOsLoginChecker
from scanner_core.policies.terraform_gcp.storage_bucket_no_public_checker import StorageBucketNoPublicChecker
from scanner_core.policies.terraform_gcp.storage_bucket_versioning_enabled_checker import StorageBucketVersioningEnabledChecker
from scanner_core.policies.terraform_gcp.storage_bucket_public_access_prevention_checker import StorageBucketPublicAccessPreventionChecker
from scanner_core.policies.terraform_gcp.vm_block_project_wide_ssh_key_checker import VmBlockProjectWideSshKeyChecker
from scanner_core.policies.terraform_gcp.vm_serial_port_not_enabled_checker import VmSerialPortNotEnabledChecker
from scanner_core.policies.terraform_gcp.vpc_firewall_prevent_ssh_access_checker import VpcFirewallPreventSshAccessChecker
from scanner_core.policies.terraform_gcp.vpc_firewall_restrict_rdp_checker import VpcFirewallRestrictRdpChecker
from scanner_core.policies.terraform_gcp.vpc_firewall_restrict_ftp_checker import VpcFirewallRestrictFtpChecker
from scanner_core.policies.terraform_gcp.vpc_security_checker import VPCSecurityChecker
import json


from typing import Dict, List, Any
from collections import defaultdict
import json

from models.violation import AWSPolicyViolation
from scanner_core.policies.terraform_aws.s3_checker import S3BucketChecker, S3BucketPolicyChecker, S3ACLChecker, S3EncryptionChecker
from scanner_core.policies.terraform_aws.iam_checker import IAMRoleChecker, IAMPolicyChecker, IAMAccessKeyChecker
from scanner_core.policies.terraform_aws.ec2_checker import SecurityGroupChecker, EC2InstanceChecker, EBSChecker
from scanner_core.policies.terraform_aws.rds_checker import RDSInstanceChecker, RDSClusterChecker, RDSParameterGroupChecker
from scanner_core.policies.terraform_aws.lambda_checker import LambdaFunctionChecker, LambdaPermissionChecker, LambdaLayerChecker
from scanner_core.policies.terraform_aws.kms_checker import KMSKeyChecker, KMSGrantChecker, KMSAliasChecker
from scanner_core.policies.terraform_aws.vpc_checker import VPCChecker, SubnetChecker, NetworkACLChecker, RouteTableChecker, VPCPeeringChecker
from scanner_core.policies.terraform_aws.cloudtrail_checker import CloudTrailChecker, CloudWatchLogGroupChecker, S3LoggingChecker, VPCFlowLogsChecker
from scanner_core.policies.terraform_aws.services_checker import CloudFormationStackChecker, SNSTopicChecker, SQSQueueChecker, DynamoDBChecker, ElastiCacheChecker
from scanner_core.policies.terraform_aws.api_secrets_checker import APIGatewayChecker, SecretsManagerChecker, SecretsManagerSecretVersionChecker



class DockerSecurityValidator:
    """
    Main validator coordinating all Docker security policy checks.
    
    This class orchestrates multiple security checkers and provides
    aggregated results and analysis capabilities based on Rego deny rules.
    """
    
    def __init__(self):
        """Initialize validator with all checkers"""
        self.checkers = [
            EnvSecretsChecker(),
            LatestTagChecker(),
            RootUserChecker(),
            PrivilegedPortChecker(),
            MiningDetectionChecker(),
            MissingHealthcheckChecker(),
            PackageUpgradeChecker(),              
            AddVsCopyChecker(),                   
            SudoUsageChecker(),                   
            UnallowedImagesChecker(),             
            UnallowedCommandsChecker(),           
            MissingMetadataChecker(),             
            HardcodedSecretsChecker(),
            PrivilegedModeChecker(),
            DangerousCapabilitiesChecker(),
            InsecureNetworkModeChecker(),
            VolumeMountsChecker(),
            InsecureBaseImageChecker(),
            ResourceLimitsChecker(),
            RestartPolicyChecker(),
            SecurityOptionsChecker(),
            MultistageBuildChecker(),
            CurlVerificationChecker(),
            UnnecessaryServicesChecker(),
        ]
        self.helper = DockerHelper()
        self.all_violations: List[DockerSecurityViolation] = []
        self.analyzed_files: List[str] = []
    
    def validate_file(self, file_path: str) -> List[DockerSecurityViolation]:
        """
        Validate a single Docker file.
        
        Args:
            file_path: Path to Dockerfile or docker-compose.yml
            
        Returns:
            List of security violations found
        """
        return self.validate_files([file_path])
    
    def validate_files(self, file_paths: List[str]) -> List[DockerSecurityViolation]:
        """
        Validate multiple Docker files.
        
        Args:
            file_paths: List of paths to Docker files
            
        Returns:
            List of all security violations found
        """
        _validator_logger.info(f"[Docker] validate_files called with {len(file_paths)} file(s)")
        contexts = []
        
        for file_path in file_paths:
            try:
                _validator_logger.debug(f"[Docker] Loading context for: {file_path}")
                context = self._load_file_context(file_path)
                if context:
                    contexts.append(context)
                    _validator_logger.debug(f"[Docker] Context loaded successfully: {file_path}")
                else:
                    _validator_logger.warning(f"[Docker] Empty context returned for: {file_path}")
            except Exception as e:
                _validator_logger.warning(f"[Docker] Could not parse {file_path}: {e}")
                continue
        
        _validator_logger.info(f"[Docker] {len(contexts)}/{len(file_paths)} file(s) parsed successfully")
        return self.validate_contexts(contexts)
    
    def validate_contexts(self, contexts: List[Dict[str, Any]]) -> List[DockerSecurityViolation]:
        """
        Run all security checks on provided Docker file contexts.
        
        Args:
            contexts: List of Docker file contexts to analyze
            
        Returns:
            List of all security violations found
        """
        _validator_logger.info(
            f"[Docker] Running {len(self.checkers)} checker(s) against {len(contexts)} context(s)"
        )
        self.all_violations = []
        self.analyzed_files = contexts
        
        for checker in self.checkers:
            checker_name = checker.__class__.__name__
            try:
                violations = checker.check(contexts)
                count = len(violations) if violations else 0
                if count:
                    _validator_logger.info(f"[Docker]   {checker_name}: {count} violation(s)")
                else:
                    _validator_logger.debug(f"[Docker]   {checker_name}: no violations")
                self.all_violations.extend(violations)
            except Exception as e:
                _validator_logger.error(
                    f"[Docker]   Checker {checker_name} raised an exception: {e}", exc_info=True
                )
                continue
        
        _validator_logger.info(
            f"[Docker] validate_contexts complete: {len(self.all_violations)} total violation(s)"
        )
        return self.all_violations
    
    def validate_directory(self, directory_path: str, recursive: bool = True) -> List[DockerSecurityViolation]:
        """
        Validate all Docker files in a directory.
        
        Args:
            directory_path: Path to directory to scan
            recursive: Whether to scan subdirectories
            
        Returns:
            List of all security violations found
        """
        docker_files = self._find_docker_files(directory_path, recursive)
        return self.validate_files(docker_files)
    
    def _load_file_context(self, file_path: str) -> Dict[str, Any]:
        """Load and parse a Docker file"""
        file_path = Path(file_path).resolve()
        
        if file_path.name.lower() in ['dockerfile', 'dockerfile.dev', 'dockerfile.prod'] or 'dockerfile' in file_path.name.lower():
            return self.helper.parse_dockerfile(str(file_path))
        elif file_path.name.lower().startswith('docker-compose') and file_path.suffix.lower() in ['.yml', '.yaml']:
            return self.helper.parse_docker_compose(str(file_path))
        else:
            raise ValueError(f"Unsupported file type: {file_path}")
    
    def _find_docker_files(self, directory_path: str, recursive: bool = True) -> List[str]:
        """Find all Docker files in directory"""
        docker_files = []
        directory = Path(directory_path)
        
        if not directory.exists():
            return docker_files
        
        patterns = [
            "**/Dockerfile*" if recursive else "Dockerfile*",
            "**/docker-compose*.yml" if recursive else "docker-compose*.yml",
            "**/docker-compose*.yaml" if recursive else "docker-compose*.yaml"
        ]
        
        for pattern in patterns:
            docker_files.extend([str(f) for f in directory.glob(pattern) if f.is_file()])
        
        return sorted(set(docker_files))
    
    def get_violations_by_severity(self) -> Dict[str, List[DockerSecurityViolation]]:
        """Group violations by severity level"""
        by_severity = {}
        for violation in self.all_violations:
            if violation.severity not in by_severity:
                by_severity[violation.severity] = []
            by_severity[violation.severity].append(violation)
        return by_severity
    
    def get_violations_by_cve(self) -> Dict[str, List[DockerSecurityViolation]]:
        """Group violations by CVE ID"""
        by_cve = {}
        for violation in self.all_violations:
            if violation.cve_id not in by_cve:
                by_cve[violation.cve_id] = []
            by_cve[violation.cve_id].append(violation)
        return by_cve
    
    def get_violations_by_file(self) -> Dict[str, List[DockerSecurityViolation]]:
        """Group violations by file"""
        by_file = {}
        for violation in self.all_violations:
            if violation.file_name not in by_file:
                by_file[violation.file_name] = []
            by_file[violation.file_name].append(violation)
        return by_file
    
    def get_violations_by_type(self) -> Dict[str, List[DockerSecurityViolation]]:
        """Group violations by file type"""
        by_type = {}
        for violation in self.all_violations:
            if violation.file_type not in by_type:
                by_type[violation.file_type] = []
            by_type[violation.file_type].append(violation)
        return by_type
    
    def get_summary(self) -> Dict[str, Any]:
        """Get comprehensive validation summary"""
        return {
            "total_violations": len(self.all_violations),
            "total_files": len(self.analyzed_files),
            "by_severity": {
                k: len(v) for k, v in self.get_violations_by_severity().items()
            },
            "by_cve": {
                k: len(v) for k, v in self.get_violations_by_cve().items()
            },
            "by_file": {
                k: len(v) for k, v in self.get_violations_by_file().items()
            },
            "by_type": {
                k: len(v) for k, v in self.get_violations_by_type().items()
            }
        }
    
    def print_report(self, verbose: bool = False, show_file_details: bool = True) -> None:
        """
        Print formatted validation report.
        
        Args:
            verbose: Include detailed violation information
            show_file_details: Show per-file breakdown
        """
        if not self.all_violations:
            print("✓ No Docker security violations found!")
            return
        
        print(f"\n{'='*70}")
        print(f"  DOCKER SECURITY VALIDATION REPORT")
        print(f"{'='*70}\n")
        
        summary = self.get_summary()
        print(f"Total Violations: {summary['total_violations']}")
        print(f"Files Analyzed: {summary['total_files']}")
        
        print("\nViolations by Severity:")
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        for severity in severity_order:
            if severity in summary['by_severity']:
                count = summary['by_severity'][severity]
                print(f"  {severity:10s}: {count:3d}")
        
        print("\nViolations by File Type:")
        for file_type, count in summary['by_type'].items():
            print(f"  {file_type:15s}: {count:3d}")
        
        if show_file_details:
            print(f"\n{'='*70}")
            print("FILE BREAKDOWN")
            print(f"{'='*70}\n")
            
            for file_path, violations in self.get_violations_by_file().items():
                print(f"📁 {Path(file_path).name} ({len(violations)} violations)")
                
                if verbose:
                    for violation in violations:
                        print(f"   [{violation.severity}] Line {violation.line_number}: {violation.message}")
                else:
                    # Show summary by severity for this file
                    file_by_severity = {}
                    for v in violations:
                        file_by_severity[v.severity] = file_by_severity.get(v.severity, 0) + 1
                    
                    severity_summary = []
                    for severity in severity_order:
                        if severity in file_by_severity:
                            severity_summary.append(f"{severity}: {file_by_severity[severity]}")
                    
                    print(f"   {', '.join(severity_summary)}")
                print()
        
        if verbose:
            print(f"\n{'='*70}")
            print("DETAILED VIOLATIONS")
            print(f"{'='*70}\n")
            
            for i, violation in enumerate(self.all_violations, 1):
                print(f"{i}. [{violation.severity}] {violation.cve_id}")
                print(f"   File: {Path(violation.file_name).name}:{violation.line_number}")
                print(f"   Type: {violation.file_type}")
                print(f"   Instruction: {violation.instruction}")
                print(f"   Issue: {violation.message}")
                print()
    
    def export_json(self) -> Dict[str, Any]:
        """Export results as JSON-serializable dictionary"""
        return {
            "summary": self.get_summary(),
            "violations": [v.to_dict() for v in self.all_violations],
            "analyzed_files": [
                {
                    "file_path": ctx.file_path,
                    "file_type": ctx.file_type
                }
                for ctx in self.analyzed_files
            ]
        }
    
    def get_risk_score(self) -> int:
        """
        Calculate overall risk score based on violations.
        
        Returns:
            Risk score from 0-100
        """
        if not self.all_violations:
            return 0
        
        severity_weights = {
            'CRITICAL': 25,
            'HIGH': 15,
            'MEDIUM': 8,
            'LOW': 3,
            'INFO': 1
        }
        
        total_score = 0
        for violation in self.all_violations:
            total_score += severity_weights.get(violation.severity, 1)
        
        # Cap at 100
        return min(total_score, 100)
    
    def has_critical_issues(self) -> bool:
        """Check if any critical security issues were found"""
        return any(v.severity == 'CRITICAL' for v in self.all_violations)
    
    def has_high_issues(self) -> bool:
        """Check if any high severity issues were found"""
        return any(v.severity in ['CRITICAL', 'HIGH'] for v in self.all_violations)




class TableFormatter:
    """Professional table formatter with Unicode borders."""
    
    @staticmethod
    def format_table(headers: List[str], rows: List[List[str]], title: str = None) -> str:
        """Format data as a bordered table."""
        if not rows:
            return "No data to display"
        
        # Calculate column widths
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Table formatting characters
        top_left, top_right = "┌", "┐"
        bottom_left, bottom_right = "└", "┘"
        horizontal, vertical = "─", "│"
        cross_top, cross_bottom = "┬", "┴"
        cross_middle = "┼"
        t_left, t_right = "├", "┤"
        
        # Build table
        result = []
        
        # Title
        if title:
            total_width = sum(col_widths) + len(headers) * 3 + 1
            result.append(f"\n{'=' * total_width}")
            result.append(f"{title:^{total_width}}")
            result.append(f"{'=' * total_width}")
        
        # Top border
        top_border = top_left
        for i, width in enumerate(col_widths):
            top_border += horizontal * (width + 2)
            if i < len(col_widths) - 1:
                top_border += cross_top
        top_border += top_right
        result.append(top_border)
        
        # Header row
        header_row = vertical
        for i, (header, width) in enumerate(zip(headers, col_widths)):
            header_row += f" {header:<{width}} "
            header_row += vertical
        result.append(header_row)
        
        # Header separator
        sep_border = t_left
        for i, width in enumerate(col_widths):
            sep_border += horizontal * (width + 2)
            if i < len(col_widths) - 1:
                sep_border += cross_middle
        sep_border += t_right
        result.append(sep_border)
        
        # Data rows
        for row in rows:
            data_row = vertical
            for i, (cell, width) in enumerate(zip(row, col_widths)):
                data_row += f" {str(cell):<{width}} "
                data_row += vertical
            result.append(data_row)
        
        # Bottom border
        bottom_border = bottom_left
        for i, width in enumerate(col_widths):
            bottom_border += horizontal * (width + 2)
            if i < len(col_widths) - 1:
                bottom_border += cross_bottom
        bottom_border += bottom_right
        result.append(bottom_border)
        
        return "\n".join(result)


class K8sSecurityValidator:
    """
    Main validator coordinating all security policy checks.
    
    This class orchestrates multiple security checkers and provides
    aggregated results and analysis capabilities.
    """
    
    def __init__(self):
        """Initialize validator with all checkers"""
        self.checkers = [
            AppArmorChecker(),
            CapabilitiesChecker(),
            HostNetworkChecker(),
            HostPathChecker(),
            HostProcessChecker(),
            ImagePullPolicyChecker(),
            LatestImageChecker(),
            K8sPrivilegedModeChecker(),
            ProbeChecker(),
            ProcMountChecker(),
            K8sResourceLimitsChecker(),
            SecCompProfileChecker(),
            selinuxChecker(),
            SysCtlsChecker(),
        ]
        self.all_violations: List[PolicyViolation] = []
    
    def validate(self, resources: List[Dict[str, Any]]) -> List[PolicyViolation]:
        """
        Run all security checks on provided resources.
        
        Args:
            resources: List of Kubernetes resource dictionaries
            
        Returns:
            List of all policy violations found
        """
        resource_count = len(resources) if resources else 0
        _validator_logger.info(
            f"[K8s] Starting validation: {resource_count} resource(s), "
            f"{len(self.checkers)} checker(s)"
        )
        self.all_violations = []
        
        for checker in self.checkers:
            checker_name = checker.__class__.__name__
            try:
                _validator_logger.debug(f"[K8s]   Running checker: {checker_name}")
                violations = checker.check(resources)
                count = len(violations) if violations else 0
                if count:
                    _validator_logger.info(f"[K8s]   {checker_name}: {count} violation(s)")
                else:
                    _validator_logger.debug(f"[K8s]   {checker_name}: no violations")
                self.all_violations.extend(violations)
            except Exception as e:
                _validator_logger.error(
                    f"[K8s]   Checker {checker_name} raised an exception: {e}", exc_info=True
                )
        
        _validator_logger.info(
            f"[K8s] Validation complete: {len(self.all_violations)} total violation(s)"
        )
        return self.all_violations
    
    def get_violations_by_severity(self) -> Dict[str, List[PolicyViolation]]:
        """Group violations by severity level"""
        by_severity = {}
        for violation in self.all_violations:
            if violation.severity not in by_severity:
                by_severity[violation.severity] = []
            by_severity[violation.severity].append(violation)
        return by_severity
    
    def get_violations_by_cve(self) -> Dict[str, List[PolicyViolation]]:
        """Group violations by CVE ID"""
        by_cve = {}
        for violation in self.all_violations:
            if violation.cve_id not in by_cve:
                by_cve[violation.cve_id] = []
            by_cve[violation.cve_id].append(violation)
        return by_cve
    
    def get_violations_by_resource(self) -> Dict[str, List[PolicyViolation]]:
        """Group violations by resource"""
        by_resource = {}
        for violation in self.all_violations:
            key = f"{violation.resource_kind}/{violation.resource_name}"
            if key not in by_resource:
                by_resource[key] = []
            by_resource[key].append(violation)
        return by_resource
    
    def get_summary(self) -> Dict[str, Any]:
        """Get comprehensive validation summary"""
        return {
            "total_violations": len(self.all_violations),
            "by_severity": {
                k: len(v) for k, v in self.get_violations_by_severity().items()
            },
            "by_cve": {
                k: len(v) for k, v in self.get_violations_by_cve().items()
            },
            "unique_resources": len(self.get_violations_by_resource())
        }
    
    def print_report(self, verbose: bool = False) -> None:
        """
        Print formatted validation report with table borders.
        
        Args:
            verbose: Include detailed violation information
        """
        if not self.all_violations:
            print("✓ No policy violations found!")
            return
        
        summary = self.get_summary()
        
        # Summary table
        summary_data = [
            ["Total Violations", str(summary['total_violations'])],
            ["Affected Resources", str(summary['unique_resources'])]
        ]
        summary_table = TableFormatter.format_table(
            ["Metric", "Count"], 
            summary_data,
            "KUBERNETES SECURITY VALIDATION SUMMARY"
        )
        print(summary_table)
        
        # Severity breakdown table
        severity_data = []
        for severity, count in sorted(summary['by_severity'].items()):
            severity_data.append([severity, str(count)])
        
        severity_table = TableFormatter.format_table(
            ["Severity Level", "Violations"],
            severity_data,
            "VIOLATIONS BY SEVERITY"
        )
        print(f"\n{severity_table}")
        
        # CVE breakdown table
        if summary['by_cve']:
            cve_data = []
            by_cve = self.get_violations_by_cve()
            for cve_id, violations in sorted(by_cve.items()):
                cve_data.append([cve_id, str(len(violations))])
            
            cve_table = TableFormatter.format_table(
                ["CVE ID", "Count"],
                cve_data,
                "VIOLATIONS BY CVE"
            )
            print(f"\n{cve_table}")
        
        if verbose:
            # Detailed violations table
            violation_data = []
            for i, violation in enumerate(self.all_violations, 1):
                violation_data.append([
                    str(i),
                    violation.severity,
                    violation.cve_id,
                    f"{violation.resource_kind}/{violation.resource_name}",
                    violation.key_path[:30] + "..." if len(violation.key_path) > 30 else violation.key_path,
                    violation.message[:40] + "..." if len(violation.message) > 40 else violation.message
                ])
            
            detailed_table = TableFormatter.format_table(
                ["#", "Severity", "CVE ID", "Resource", "Path", "Message"],
                violation_data,
                "DETAILED VIOLATIONS"
            )
            print(f"\n{detailed_table}")




class GCPTableFormatter:
    """Professional table formatter with Unicode borders."""

    @staticmethod
    def format_table(headers: List[str], rows: List[List[str]], title: str = None) -> str:
        """Format data as a bordered table."""
        if not rows:
            return "No data to display"

        # Calculate column widths
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    col_widths[i] = max(col_widths[i], len(str(cell)))

        # Table formatting characters (ASCII for compatibility)
        top_left, top_right = "+", "+"
        bottom_left, bottom_right = "+", "+"
        horizontal, vertical = "-", "|"
        cross_top, cross_bottom = "+", "+"
        cross_middle = "+"
        t_left, t_right = "+", "+"

        # Build table
        result = []

        # Title
        if title:
            total_width = sum(col_widths) + len(headers) * 3 + 1
            result.append(f"\n{'=' * total_width}")
            result.append(f"{title:^{total_width}}")
            result.append(f"{'=' * total_width}")

        # Top border
        top_border = top_left
        for i, width in enumerate(col_widths):
            top_border += horizontal * (width + 2)
            if i < len(col_widths) - 1:
                top_border += cross_top
        top_border += top_right
        result.append(top_border)

        # Header row
        header_row = vertical
        for i, (header, width) in enumerate(zip(headers, col_widths)):
            header_row += f" {header:<{width}} "
            header_row += vertical
        result.append(header_row)

        # Header separator
        sep_border = t_left
        for i, width in enumerate(col_widths):
            sep_border += horizontal * (width + 2)
            if i < len(col_widths) - 1:
                sep_border += cross_middle
        sep_border += t_right
        result.append(sep_border)

        # Data rows
        for row in rows:
            data_row = vertical
            for i, (cell, width) in enumerate(zip(row, col_widths)):
                data_row += f" {str(cell):<{width}} "
                data_row += vertical
            result.append(data_row)

        # Bottom border
        bottom_border = bottom_left
        for i, width in enumerate(col_widths):
            bottom_border += horizontal * (width + 2)
            if i < len(col_widths) - 1:
                bottom_border += cross_bottom
        bottom_border += bottom_right
        result.append(bottom_border)

        return "\n".join(result)


class GCPSecurityValidator:
    """
    Main validator coordinating all GCP security policy checks.

    This class orchestrates multiple security checkers and provides
    aggregated results and analysis capabilities.
    """

    def __init__(self):
        """Initialize validator with all scanner_core.policies.terraform_gcp."""
        self.checkers = [
            BigQueryDatasetPrivateChecker(),
            BigQuerySecurityControlsChecker(),
            BucketLoggingEnabledChecker(),
            CloudSqlPreventPublicIpChecker(),
            CloudFunctionsSecurityChecker(),
            ComputeInstanceDefaultSvcAccountChecker(),
            DnssecEnabledChecker(),
            EncryptionKey365RotationChecker(),
            GkeLegacyAuthorizationDisabledChecker(),
            KmsEncryptionKey90DaysChecker(),
            LoadbalancerSslForwardingRuleChecker(),
            LoadBalancerSecurityChecker(),
            LoggingSecurityChecker(),
            MonitoringSecurityChecker(),
            IAMSecurityChecker(),
            NoIpForwardingChecker(),
            ProjectOsLoginChecker(),
            StorageBucketNoPublicChecker(),
            StorageBucketVersioningEnabledChecker(),
            StorageBucketPublicAccessPreventionChecker(),
            VmBlockProjectWideSshKeyChecker(),
            VmSerialPortNotEnabledChecker(),
            VpcFirewallPreventSshAccessChecker(),
            VpcFirewallRestrictRdpChecker(),
            VpcFirewallRestrictFtpChecker(),
            VPCSecurityChecker(),
        ]
        self.all_violations: List[PolicyViolation] = []
        self.check_summary: Dict[str, int] = defaultdict(int)

    def add_checker(self, checker):
        """Add a security checker to the validator."""
        self.scanner_core.policies.terraform_gcp.append(checker)

    def validate(self, resources: Dict[str, Any]) -> List[PolicyViolation]:
        """
        Run all security checks on provided resources.

        Args:
            resources: Dictionary of Terraform resources

        Returns:
            List of all policy violations found
        """
        resource_type_count = len(resources)
        resource_instance_count = sum(len(v) for v in resources.values() if isinstance(v, dict))
        _validator_logger.info(
            f"[GCP] Starting validation: {resource_instance_count} resource instance(s) across "
            f"{resource_type_count} type(s): {list(resources.keys())}"
        )
        self.all_violations = []
        self.check_summary = defaultdict(int)

        for checker in self.checkers:
            checker_name = checker.__class__.__name__
            try:
                _validator_logger.debug(f"[GCP]   Running checker: {checker_name}")
                violations = checker.check(resources)
                count = len(violations) if violations else 0
                if count:
                    _validator_logger.info(f"[GCP]   {checker_name}: {count} violation(s)")
                    for v in violations:
                        _validator_logger.debug(
                            f"[GCP]     -> {getattr(v, 'policy_id', '?')} | "
                            f"{getattr(v, 'resource_name', '?')} | "
                            f"{getattr(v, 'message', str(v))[:80]}"
                        )
                else:
                    _validator_logger.debug(f"[GCP]   {checker_name}: no violations")
                if violations:
                    self.all_violations.extend(violations)
            except Exception as e:
                _validator_logger.error(
                    f"[GCP]   Checker {checker_name} raised an exception: {e}", exc_info=True
                )

        # Update summary
        for violation in self.all_violations:
            self.check_summary[violation.severity] += 1

        _validator_logger.info(
            f"[GCP] Validation complete: {len(self.all_violations)} total violation(s) | "
            f"severity breakdown: {dict(self.check_summary)}"
        )
        return self.all_violations

    def get_summary(self) -> Dict[str, Any]:
        """Get validation summary."""
        return {
            "total_violations": len(self.all_violations),
            "by_severity": dict(self.check_summary),
            "violations": [v.to_dict() for v in self.all_violations]
        }

    def print_report(self, verbose: bool = False):
        """Print validation report."""
        if not self.all_violations:
            print("\n✓ No policy violations found!")
            return

        # Summary table
        summary_rows = [
            ["Total Violations", str(len(self.all_violations))],
            ["Critical", str(self.check_summary.get("Critical", 0))],
            ["High", str(self.check_summary.get("High", 0))],
            ["Medium", str(self.check_summary.get("Medium", 0))],
            ["Low", str(self.check_summary.get("Low", 0))],
        ]

        print(TableFormatter.format_table(
            ["Severity", "Count"],
            summary_rows,
            "VALIDATION SUMMARY"
        ))

        if verbose and self.all_violations:
            # Violations table
            violation_rows = []
            for v in self.all_violations:
                violation_rows.append([
                    v.policy_id,
                    v.severity,
                    v.resource_type,
                    v.resource_name,
                    v.message[:50] + "..." if len(v.message) > 50 else v.message
                ])

            print(TableFormatter.format_table(
                ["Policy ID", "Severity", "Resource Type", "Resource", "Message"],
                violation_rows,
                "VIOLATIONS"
            ))

    def export_results(self, file_path: str):
        """Export validation results to JSON file."""
        results = self.get_summary()
        with open(file_path, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results exported to {file_path}")


class AWSSecurityValidator:
    """
    Main validator coordinating all AWS security policy checks.

    This class orchestrates multiple security checkers and provides
    aggregated results and analysis capabilities.
    """

    def __init__(self):
        """Initialize validator with all checkers."""
        self.checkers = [
            # S3 Checkers
            S3BucketChecker(),
            S3BucketPolicyChecker(),
            S3ACLChecker(),
            S3EncryptionChecker(),
            # IAM Checkers
            IAMRoleChecker(),
            IAMPolicyChecker(),
            IAMAccessKeyChecker(),
            # EC2 Checkers
            SecurityGroupChecker(),
            EC2InstanceChecker(),
            EBSChecker(),
            # RDS Checkers
            RDSInstanceChecker(),
            RDSClusterChecker(),
            RDSParameterGroupChecker(),
            # Lambda Checkers
            LambdaFunctionChecker(),
            LambdaPermissionChecker(),
            LambdaLayerChecker(),
            # KMS Checkers
            KMSKeyChecker(),
            KMSGrantChecker(),
            KMSAliasChecker(),
            # VPC Checkers
            VPCChecker(),
            SubnetChecker(),
            NetworkACLChecker(),
            RouteTableChecker(),
            VPCPeeringChecker(),
            # CloudTrail Checkers
            CloudTrailChecker(),
            CloudWatchLogGroupChecker(),
            S3LoggingChecker(),
            VPCFlowLogsChecker(),
            # Services Checkers
            CloudFormationStackChecker(),
            SNSTopicChecker(),
            SQSQueueChecker(),
            DynamoDBChecker(),
            ElastiCacheChecker(),
            # API & Secrets Checkers
            APIGatewayChecker(),
            SecretsManagerChecker(),
            SecretsManagerSecretVersionChecker(),
        ]
        self.all_violations: List[AWSPolicyViolation] = []
        self.check_summary: Dict[str, int] = defaultdict(int)

    def add_checker(self, checker):
        """Add a security checker to the validator."""
        self.checkers.append(checker)

    def validate(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """
        Run all security checks on provided resources.

        Args:
            resources: Dictionary of Terraform resources

        Returns:
            List of all policy violations found
        """
        resource_type_count = len(resources)
        resource_instance_count = sum(len(v) for v in resources.values() if isinstance(v, dict))
        _validator_logger.info(
            f"[AWS] Starting validation: {resource_instance_count} resource instance(s) across "
            f"{resource_type_count} type(s): {list(resources.keys())}"
        )
        self.all_violations = []
        self.check_summary = defaultdict(int)

        for checker in self.checkers:
            checker_name = checker.__class__.__name__
            try:
                _validator_logger.debug(f"[AWS]   Running checker: {checker_name}")
                violations = checker.check(resources)
                count = len(violations) if violations else 0
                if count:
                    _validator_logger.info(f"[AWS]   {checker_name}: {count} violation(s)")
                    for v in violations:
                        _validator_logger.debug(
                            f"[AWS]     -> {getattr(v, 'policy_id', '?')} | "
                            f"{getattr(v, 'resource_name', '?')} | "
                            f"{getattr(v, 'message', str(v))[:80]}"
                        )
                else:
                    _validator_logger.debug(f"[AWS]   {checker_name}: no violations")
                if violations:
                    self.all_violations.extend(violations)
            except Exception as e:
                _validator_logger.error(
                    f"[AWS]   Checker {checker_name} raised an exception: {e}", exc_info=True
                )

        # Update summary
        for violation in self.all_violations:
            self.check_summary[violation.severity] += 1

        _validator_logger.info(
            f"[AWS] Validation complete: {len(self.all_violations)} total violation(s) | "
            f"severity breakdown: {dict(self.check_summary)}"
        )
        return self.all_violations

    def get_summary(self) -> Dict[str, Any]:
        """Get validation summary."""
        return {
            "total_violations": len(self.all_violations),
            "by_severity": dict(self.check_summary),
            "violations": [v.to_dict() for v in self.all_violations]
        }

    def print_report(self, verbose: bool = False):
        """Print validation report."""
        if not self.all_violations:
            print("\n✓ No policy violations found!")
            return

        # Summary table
        summary_rows = [
            ["Total Violations", str(len(self.all_violations))],
            ["Critical", str(self.check_summary.get("CRITICAL", 0))],
            ["High", str(self.check_summary.get("HIGH", 0))],
            ["Medium", str(self.check_summary.get("MEDIUM", 0))],
            ["Low", str(self.check_summary.get("LOW", 0))],
        ]

        print(TableFormatter.format_table(
            ["Severity", "Count"],
            summary_rows,
            "VALIDATION SUMMARY"
        ))

        if verbose and self.all_violations:
            # Violations table
            violation_rows = []
            for v in self.all_violations:
                violation_rows.append([
                    v.policy_id,
                    v.severity,
                    v.resource_type,
                    v.resource_name,
                    v.message[:50] + "..." if len(v.message) > 50 else v.message
                ])

            print(TableFormatter.format_table(
                ["Policy ID", "Severity", "Resource Type", "Resource", "Message"],
                violation_rows,
                "VIOLATIONS"
            ))

    def export_results(self, file_path: str):
        """Export validation results to JSON file."""
        results = self.get_summary()
        with open(file_path, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results exported to {file_path}")

