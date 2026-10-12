"""
KMS Security Checkers for AWS

Implements comprehensive KMS key security validation policies.
"""

from typing import Dict, List, Any
import json
from scanner_core.models.violation import AWSPolicyViolation
from scanner_core.constants.aws_policy_ids import AWSPolicyIDs
from .base_checker import AWSSecurityChecker


class KMSKeyChecker(AWSSecurityChecker):
    """Check KMS key security configurations."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all KMS key checks."""
        violations = []
        
        if 'aws_kms_key' not in resources:
            return violations
        
        for resource_name, config in resources['aws_kms_key'].items():
            violations.extend(self._check_key(resource_name, config))
        
        return violations
    
    def _check_key(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual KMS key."""
        violations = []
        
        # KMS-001: Rotation enabled
        rotation_period = config.get('rotation_period_in_days')
        if rotation_period is None or (isinstance(rotation_period, (int, float)) and rotation_period == 0):
            if config.get('enable_key_rotation') is not True:
                violations.append(AWSPolicyViolation(
                    policy_id=AWSPolicyIDs.KMS_KEY_ROTATION,
                    severity='HIGH',
                    resource_type='aws_kms_key',
                    resource_name=resource_name,
                    message='KMS key does not have rotation enabled',
                    guide='https://docs.aws.amazon.com/kms/latest/developerguide/rotating-keys.html'
                ))
        
        # KMS-002: Key policy restricts deletion
        key_policy = config.get('policy')
        if key_policy:
            if self._key_policy_allows_deletion(key_policy):
                violations.append(AWSPolicyViolation(
                    policy_id=AWSPolicyIDs.KMS_KEY_POLICY_DELETION,
                    severity='HIGH',
                    resource_type='aws_kms_key',
                    resource_name=resource_name,
                    message='KMS key policy allows deletion without restrictions',
                    guide='https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html'
                ))
        
        # KMS-003: Key is not disabled
        if config.get('is_enabled') is False:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.KMS_KEY_DISABLED,
                severity='MEDIUM',
                resource_type='aws_kms_key',
                resource_name=resource_name,
                message='KMS key is disabled',
                guide='https://docs.aws.amazon.com/kms/latest/developerguide/enable-key.html'
            ))
        
        # KMS-004: Multi-region replication configured
        multi_region = config.get('multi_region')
        if multi_region is True:
            replication_region = config.get('replication_region')
            if not replication_region:
                violations.append(AWSPolicyViolation(
                    policy_id=AWSPolicyIDs.KMS_MULTI_REGION_REPLICATION,
                    severity='MEDIUM',
                    resource_type='aws_kms_key',
                    resource_name=resource_name,
                    message='Multi-region KMS key missing replication_region configuration',
                    guide='https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-replicate.html'
                ))
        
        # KMS-005: Description provided
        description = config.get('description', '')
        if not description or len(description) < 10:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.KMS_KEY_DESCRIPTION,
                severity='LOW',
                resource_type='aws_kms_key',
                resource_name=resource_name,
                message='KMS key missing or has insufficient description',
                guide='https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html'
            ))
        
        # KMS-006: Tags applied for organization
        tags = config.get('tags', {})
        required_tags = ['Environment', 'Owner', 'CostCenter']
        missing_tags = [tag for tag in required_tags if tag not in tags]
        
        if missing_tags:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.KMS_KEY_TAGS,
                severity='LOW',
                resource_type='aws_kms_key',
                resource_name=resource_name,
                message=f'KMS key missing organizational tags: {", ".join(missing_tags)}',
                guide='https://docs.aws.amazon.com/kms/latest/developerguide/tagging-keys.html'
            ))
        
        return violations
    
    def _key_policy_allows_deletion(self, policy: str) -> bool:
        """Check if key policy allows unrestricted deletion."""
        try:
            if isinstance(policy, str):
                policy_doc = json.loads(policy)
            else:
                policy_doc = policy
            
            for statement in policy_doc.get('Statement', []):
                if statement.get('Effect') == 'Allow':
                    actions = statement.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    
                    # Check for kms:ScheduleKeyDeletion
                    for action in actions:
                        if 'ScheduleKeyDeletion' in action or 'kms:*' in action:
                            # Check if principal is not restricted
                            principal = statement.get('Principal', {})
                            if isinstance(principal, dict):
                                aws_principal = principal.get('AWS', [])
                                if isinstance(aws_principal, str):
                                    aws_principal = [aws_principal]
                                if '*' in aws_principal or any('*' in str(p) for p in aws_principal):
                                    return True
            return False
        except (json.JSONDecodeError, TypeError, AttributeError):
            return False


class KMSAliasChecker(AWSSecurityChecker):
    """Check KMS alias security configurations."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all KMS alias checks."""
        violations = []
        
        if 'aws_kms_alias' not in resources:
            return violations
        
        for resource_name, config in resources['aws_kms_alias'].items():
            violations.extend(self._check_alias(resource_name, config))
        
        return violations
    
    def _check_alias(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual KMS alias."""
        violations = []
        
        # KMS-007: Alias follows naming convention
        alias_name = config.get('name', '')
        if not alias_name.startswith('alias/'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.KMS_ALIAS_NAMING_CONVENTION,
                severity='LOW',
                resource_type='aws_kms_alias',
                resource_name=resource_name,
                message=f'KMS alias does not follow naming convention: {alias_name}',
                guide='https://docs.aws.amazon.com/kms/latest/developerguide/programming-aliases.html'
            ))
        
        # Check for AWS managed key aliases
        if 'aws/' in alias_name.lower():
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.KMS_ALIAS_AWS_RESERVED,
                severity='HIGH',
                resource_type='aws_kms_alias',
                resource_name=resource_name,
                message=f'Cannot create custom alias with AWS reserved prefix: {alias_name}',
                guide='https://docs.aws.amazon.com/kms/latest/developerguide/programming-aliases.html'
            ))
        
        return violations


class KMSGrantChecker(AWSSecurityChecker):
    """Check KMS grant security configurations."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all KMS grant checks."""
        violations = []
        
        if 'aws_kms_grant' not in resources:
            return violations
        
        for resource_name, config in resources['aws_kms_grant'].items():
            violations.extend(self._check_grant(resource_name, config))
        
        return violations
    
    def _check_grant(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual KMS grant."""
        violations = []
        
        # KMS-009: Grant operations restricted
        operations = config.get('operations', [])
        dangerous_ops = ['ScheduleKeyDeletion', 'DisableKey', 'CreateGrant']
        
        risky_operations = [op for op in operations if op in dangerous_ops]
        if risky_operations:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.KMS_GRANT_OPERATIONS,
                severity='HIGH',
                resource_type='aws_kms_grant',
                resource_name=resource_name,
                message=f'KMS grant allows dangerous operations: {", ".join(risky_operations)}',
                guide='https://docs.aws.amazon.com/kms/latest/developerguide/grants.html'
            ))
        
        # KMS-010: Retiring principal set for granular control
        retiring_principal = config.get('retiring_principal')
        if not retiring_principal:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.KMS_GRANT_RETIRING_PRINCIPAL,
                severity='MEDIUM',
                resource_type='aws_kms_grant',
                resource_name=resource_name,
                message='KMS grant does not have retiring principal for revocation control',
                guide='https://docs.aws.amazon.com/kms/latest/developerguide/grants.html'
            ))
        
        return violations
