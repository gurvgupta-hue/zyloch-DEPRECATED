"""
RDS Security Checkers for AWS

Implements comprehensive RDS database security validation policies.
"""

from typing import Dict, List, Any
from scanner_core.models.violation import AWSPolicyViolation
from scanner_core.constants.aws_policy_ids import AWSPolicyIDs
from .base_checker import AWSSecurityChecker


class RDSInstanceChecker(AWSSecurityChecker):
    """Check RDS DB instance security configurations."""
    
    POLICY_PREFIX = "AWS-SEC-RDS"
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all RDS instance checks."""
        violations = []
        
        if 'aws_db_instance' not in resources:
            return violations
        
        for resource_name, config in resources['aws_db_instance'].items():
            violations.extend(self._check_instance(resource_name, config))
        
        return violations
    
    def _check_instance(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual RDS instance."""
        violations = []
        
        # RDS-001: Encryption enabled
        if not config.get('storage_encrypted'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.RDS_ENCRYPTION,
                severity='HIGH',
                resource_type='aws_db_instance',
                resource_name=resource_name,
                message='RDS instance does not have encryption at rest enabled',
                guide='https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html'
            ))
        
        # RDS-002: Multi-AZ enabled
        if not config.get('multi_az'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.RDS_MULTI_AZ,
                severity='MEDIUM',
                resource_type='aws_db_instance',
                resource_name=resource_name,
                message='RDS instance does not have Multi-AZ enabled',
                guide='https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html'
            ))
        
        # RDS-003: Deletion protection enabled
        if not config.get('deletion_protection'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.RDS_DELETION_PROTECTION,
                severity='HIGH',
                resource_type='aws_db_instance',
                resource_name=resource_name,
                message='RDS instance does not have deletion protection enabled',
                guide='https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html'
            ))
        
        # RDS-004: Publicly accessible is false
        if config.get('publicly_accessible') is True:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.RDS_PUBLIC_ACCESSIBLE,
                severity='CRITICAL',
                resource_type='aws_db_instance',
                resource_name=resource_name,
                message='RDS instance is publicly accessible',
                guide='https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html'
            ))
        
        # RDS-005: Backup retention period
        backup_retention_days = config.get('backup_retention_period', 0)
        if backup_retention_days < 7:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.RDS_BACKUP_RETENTION,
                severity='MEDIUM',
                resource_type='aws_db_instance',
                resource_name=resource_name,
                message=f'RDS instance backup retention is only {backup_retention_days} days (minimum 7 recommended)',
                guide='https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_BackupRestore.html'
            ))
        
        # RDS-006: Copy backups to another region
        if not config.get('copy_tags_to_snapshot'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.RDS_SECURITY_GROUP,
                severity='MEDIUM',
                resource_type='aws_db_instance',
                resource_name=resource_name,
                message='RDS instance does not have copy_tags_to_snapshot enabled',
                guide='https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Tagging.html'
            ))
        
        # RDS-008: Monitoring enabled
        if not config.get('monitoring_interval') or config.get('monitoring_interval') == 0:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.RDS_ENHANCED_MONITORING,
                severity='MEDIUM',
                resource_type='aws_db_instance',
                resource_name=resource_name,
                message='RDS instance does not have enhanced monitoring enabled',
                guide='https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Monitoring.html'
            ))
        
        # RDS-009: No default DB name
        db_name = config.get('db_name', '')
        if db_name and db_name.lower() in ['test', 'default', 'sample']:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.RDS_LOG_RETENTION,
                severity='LOW',
                resource_type='aws_db_instance',
                resource_name=resource_name,
                message=f'RDS instance uses default database name: {db_name}',
                guide='https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_CreateDBInstance.html'
            ))
        
        return violations


class RDSClusterChecker(AWSSecurityChecker):
    """Check RDS DB cluster security configurations."""
    
    POLICY_PREFIX = "AWS-SEC-RDS"
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all RDS cluster checks."""
        violations = []
        
        if 'aws_rds_cluster' not in resources:
            return violations
        
        for resource_name, config in resources['aws_rds_cluster'].items():
            violations.extend(self._check_cluster(resource_name, config))
        
        return violations
    
    def _check_cluster(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual RDS cluster."""
        violations = []
        
        # RDS-001: Encryption enabled
        if not config.get('storage_encrypted'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.RDS_ENCRYPTION,
                severity='HIGH',
                resource_type='aws_rds_cluster',
                resource_name=resource_name,
                message='RDS cluster does not have encryption at rest enabled',
                guide='https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html'
            ))
        
        # RDS-003: Deletion protection enabled
        if not config.get('deletion_protection'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.RDS_DELETION_PROTECTION,
                severity='HIGH',
                resource_type='aws_rds_cluster',
                resource_name=resource_name,
                message='RDS cluster does not have deletion protection enabled',
                guide='https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html'
            ))
        
        # RDS-005: Backup retention period
        backup_retention_days = config.get('backup_retention_period', 0)
        if backup_retention_days < 7:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.RDS_BACKUP_RETENTION,
                severity='MEDIUM',
                resource_type='aws_rds_cluster',
                resource_name=resource_name,
                message=f'RDS cluster backup retention is only {backup_retention_days} days (minimum 7 recommended)',
                guide='https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_BackupRestore.html'
            ))
        
        # RDS-010: Backtrack enabled (for Aurora MySQL)
        engine = config.get('engine', '')
        if 'aurora' in engine.lower() and not config.get('backtrack_window'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.RDS_LOG_RETENTION,
                severity='MEDIUM',
                resource_type='aws_rds_cluster',
                resource_name=resource_name,
                message='Aurora cluster does not have backtrack enabled',
                guide='https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/AuroraMySQL.Managing.Backtrack.html'
            ))
        
        return violations


class RDSParameterGroupChecker(AWSSecurityChecker):
    """Check RDS parameter group security configurations."""
    
    POLICY_PREFIX = "AWS-SEC-RDS"
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all RDS parameter group checks."""
        violations = []
        
        if 'aws_db_parameter_group' not in resources:
            return violations
        
        for resource_name, config in resources['aws_db_parameter_group'].items():
            violations.extend(self._check_parameter_group(resource_name, config))
        
        return violations
    
    def _check_parameter_group(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual RDS parameter group."""
        violations = []
        
        # RDS-007: Parameter group configured with security parameters
        parameters = config.get('parameter', [])
        
        critical_params = {
            'require_secure_transport': 'ON',
            'log_connections': 'ON',
            'log_disconnections': 'ON',
            'log_statement': 'ALL'
        }
        
        missing_params = []
        for param, required_value in critical_params.items():
            param_found = False
            for p in parameters:
                if p.get('name') == param and p.get('value') == required_value:
                    param_found = True
                    break
            if not param_found:
                missing_params.append(param)
        
        if missing_params:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.RDS_PARAMETER_ENCRYPTION,
                severity='MEDIUM',
                resource_type='aws_db_parameter_group',
                resource_name=resource_name,
                message=f'RDS parameter group missing critical security parameters: {", ".join(missing_params)}',
                guide='https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithParamGroups.html'
            ))
        
        return violations
