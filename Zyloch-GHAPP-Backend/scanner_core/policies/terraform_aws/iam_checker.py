"""
IAM Security Checkers for AWS

Implements comprehensive IAM security validation policies.
"""

from typing import Dict, List, Any
import json
from scanner_core.models.violation import AWSPolicyViolation
from scanner_core.constants.aws_policy_ids import AWSPolicyIDs
from .base_checker import AWSSecurityChecker


class IAMRoleChecker(AWSSecurityChecker):
    """Check IAM role security configurations."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all IAM role checks."""
        violations = []
        
        if 'aws_iam_role' not in resources:
            return violations
        
        for resource_name, config in resources['aws_iam_role'].items():
            violations.extend(self._check_role(resource_name, config))
        
        return violations
    
    def _check_role(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual IAM role configuration."""
        violations = []
        
        assume_role_policy = config.get('assume_role_policy', '{}')
        
        # IAM-005: No wildcard principal
        if self._has_wildcard_principal(assume_role_policy):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.IAM_WILDCARD_PRINCIPAL,
                severity='CRITICAL',
                resource_type='aws_iam_role',
                resource_name=resource_name,
                message='IAM role trust policy allows wildcard principal (*)',
                guide='https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html'
            ))
        
        # IAM-007: No service principal in AssumeRole
        if not self._has_trusted_service(assume_role_policy):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.IAM_MFA_ENFORCEMENT,
                severity='MEDIUM',
                resource_type='aws_iam_role',
                resource_name=resource_name,
                message='IAM role does not have trusted service principals defined',
                guide='https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_sts_assume-role-with-mfa.html'
            ))
        
        return violations
    
    def _has_wildcard_principal(self, policy: str) -> bool:
        """Check if policy has wildcard principal."""
        try:
            policy_doc = json.loads(policy) if isinstance(policy, str) else policy
            statements = policy_doc.get('Statement', [])
            for stmt in statements:
                principal = stmt.get('Principal', {})
                if principal == '*':
                    return True
                if isinstance(principal, dict):
                    for key, value in principal.items():
                        if value == '*' or value == ['*']:
                            return True
            return False
        except:
            return False
    
    def _has_trusted_service(self, policy: str) -> bool:
        """Check if policy has trusted service."""
        try:
            policy_doc = json.loads(policy) if isinstance(policy, str) else policy
            statements = policy_doc.get('Statement', [])
            for stmt in statements:
                principal = stmt.get('Principal', {})
                if isinstance(principal, dict):
                    service = principal.get('Service')
                    if service:
                        return True
            return False
        except:
            return False


class IAMPolicyChecker(AWSSecurityChecker):
    """Check IAM policy security configurations."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all IAM policy checks."""
        violations = []
        
        policy_types = ['aws_iam_role_policy', 'aws_iam_policy', 'aws_iam_user_policy', 'aws_iam_group_policy']
        
        for policy_type in policy_types:
            if policy_type in resources:
                for resource_name, config in resources[policy_type].items():
                    violations.extend(self._check_policy(resource_name, config, policy_type))
        
        return violations
    
    def _check_policy(self, resource_name: str, config: Dict, resource_type: str) -> List[AWSPolicyViolation]:
        """Check individual IAM policy."""
        violations = []
        
        policy = config.get('policy', '{}')
        
        # IAM-005: No wildcard principal
        if self._has_wildcard_principal(policy):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.IAM_WILDCARD_PRINCIPAL,
                severity='CRITICAL',
                resource_type=resource_type,
                resource_name=resource_name,
                message='IAM policy allows wildcard principal (*)',
                guide='https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html'
            ))
        
        # IAM-006: No wildcard action
        if self._has_wildcard_action(policy):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.IAM_WILDCARD_ACTION,
                severity='HIGH',
                resource_type=resource_type,
                resource_name=resource_name,
                message='IAM policy allows wildcard actions (*)',
                guide='https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html'
            ))
        
        # IAM-007: Excessive permissions
        if self._has_excessive_permissions(policy):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.IAM_EXCESSIVE_PERMISSIONS,
                severity='HIGH',
                resource_type=resource_type,
                resource_name=resource_name,
                message='IAM policy grants excessive permissions',
                guide='https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices_user-permissions.html'
            ))
        
        return violations
    
    def _has_wildcard_principal(self, policy: str) -> bool:
        """Check if policy has wildcard principal."""
        try:
            policy_doc = json.loads(policy) if isinstance(policy, str) else policy
            statements = policy_doc.get('Statement', [])
            for stmt in statements:
                if stmt.get('Effect') == 'Allow':
                    principal = stmt.get('Principal', {})
                    if principal == '*':
                        return True
            return False
        except:
            return False
    
    def _has_wildcard_action(self, policy: str) -> bool:
        """Check if policy has wildcard actions."""
        try:
            policy_doc = json.loads(policy) if isinstance(policy, str) else policy
            statements = policy_doc.get('Statement', [])
            for stmt in statements:
                actions = stmt.get('Action', [])
                if isinstance(actions, str):
                    if actions == '*':
                        return True
                elif isinstance(actions, list):
                    if '*' in actions:
                        return True
            return False
        except:
            return False
    
    def _has_excessive_permissions(self, policy: str) -> bool:
        """Check for overly permissive policies."""
        try:
            policy_doc = json.loads(policy) if isinstance(policy, str) else policy
            statements = policy_doc.get('Statement', [])
            
            for stmt in statements:
                if stmt.get('Effect') == 'Allow':
                    # Check for admin access
                    actions = stmt.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    
                    resources = stmt.get('Resource', [])
                    if isinstance(resources, str):
                        resources = [resources]
                    
                    # Flag if all actions and all resources
                    if '*' in actions and '*' in resources:
                        return True
                    
                    # Flag common excessive patterns
                    for action in actions:
                        if any(x in action.lower() for x in ['*', 'iam:*', 's3:*', 'ec2:*']):
                            if '*' in resources:
                                return True
            
            return False
        except:
            return False


class IAMAccessKeyChecker(AWSSecurityChecker):
    """Check IAM access key security."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all IAM access key checks."""
        violations = []
        
        if 'aws_iam_access_key' not in resources:
            return violations
        
        for resource_name, config in resources['aws_iam_access_key'].items():
            violations.extend(self._check_access_key(resource_name))
        
        return violations
    
    def _check_access_key(self, resource_name: str) -> List[AWSPolicyViolation]:
        """Check access key configuration."""
        violations = []
        
        # IAM-002: No root access keys (best check in plan)
        violations.append(AWSPolicyViolation(
            policy_id=AWSPolicyIDs.IAM_ACCESS_KEY_SECURITY,
            severity='CRITICAL',
            resource_type='aws_iam_access_key',
            resource_name=resource_name,
            message='IAM access key created - ensure not for root account',
            guide='https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html'
        ))
        
        return violations
