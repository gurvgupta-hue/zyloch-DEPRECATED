"""
S3 Security Checkers for AWS

Implements comprehensive S3 bucket security validation policies.
"""

from typing import List, Dict, Any
from scanner_core.models.violation import AWSPolicyViolation
from scanner_core.constants.aws_policy_ids import AWSPolicyIDs
from .base_checker import AWSSecurityChecker


class S3BucketChecker(AWSSecurityChecker):
    """Check S3 bucket security configurations."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all S3 security checks."""
        violations = []
        
        if 'aws_s3_bucket' not in resources:
            return violations
        
        for resource_name, resource_config in resources['aws_s3_bucket'].items():
            # S3-006: Access logging enabled
            if not self._has_access_logging(resource_name, resources):
                violations.append(AWSPolicyViolation(
                    policy_id=AWSPolicyIDs.S3_ACCESS_LOGGING,
                    severity='HIGH',
                    resource_type='aws_s3_bucket',
                    resource_name=resource_name,
                    message='S3 bucket does not have access logging enabled',
                    guide='https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-logging-console.html'
                ))
            
            # S3-003: Encryption at rest
            if not self._has_encryption(resource_name, resources):
                violations.append(AWSPolicyViolation(
                    policy_id=AWSPolicyIDs.S3_SERVER_SIDE_ENCRYPTION,
                    severity='CRITICAL',
                    resource_type='aws_s3_bucket',
                    resource_name=resource_name,
                    message='S3 bucket does not have encryption enabled',
                    guide='https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-encryption.html'
                ))
            
            # S3-002: Versioning enabled
            if not self._has_versioning(resource_name, resources):
                violations.append(AWSPolicyViolation(
                    policy_id=AWSPolicyIDs.S3_VERSIONING,
                    severity='HIGH',
                    resource_type='aws_s3_bucket',
                    resource_name=resource_name,
                    message='S3 bucket versioning is not enabled',
                    guide='https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html'
                ))
            
            # S3-001: Public access block enabled
            if not self._has_public_access_block(resource_name, resources):
                violations.append(AWSPolicyViolation(
                    policy_id=AWSPolicyIDs.S3_PUBLIC_ACCESS,
                    severity='CRITICAL',
                    resource_type='aws_s3_bucket',
                    resource_name=resource_name,
                    message='S3 bucket does not have public access block enabled',
                    guide='https://docs.aws.amazon.com/AmazonS3/latest/userguide/publicAccessBlockGuide.html'
                ))
        
        return violations
    
    def _has_access_logging(self, bucket_name: str, resources: Dict[str, Any]) -> bool:
        """Check if S3 bucket has access logging enabled."""
        if 'aws_s3_bucket_logging' not in resources:
            return False
        
        for res_name in resources.get('aws_s3_bucket_logging', {}).keys():
            if bucket_name in res_name:
                return True
        return False
    
    def _has_encryption(self, bucket_name: str, resources: Dict[str, Any]) -> bool:
        """Check if S3 bucket has encryption enabled."""
        if 'aws_s3_bucket_server_side_encryption_configuration' not in resources:
            return False
        
        for res_name in resources.get('aws_s3_bucket_server_side_encryption_configuration', {}).keys():
            if bucket_name in res_name:
                return True
        return False
    
    def _has_versioning(self, bucket_name: str, resources: Dict[str, Any]) -> bool:
        """Check if S3 bucket has versioning enabled."""
        if 'aws_s3_bucket_versioning' not in resources:
            return False
        
        for res_name, res_config in resources.get('aws_s3_bucket_versioning', {}).items():
            if bucket_name in res_name:
                versioning = res_config.get('versioning_configuration', {})
                # Handle both dict and list formats
                if isinstance(versioning, list) and len(versioning) > 0:
                    versioning = versioning[0]
                if isinstance(versioning, dict) and versioning.get('status') == 'Enabled':
                    return True
        return False
    
    def _has_public_access_block(self, bucket_name: str, resources: Dict[str, Any]) -> bool:
        """Check if S3 bucket has public access block enabled."""
        if 'aws_s3_bucket_public_access_block' not in resources:
            return False
        
        for res_name, res_config in resources.get('aws_s3_bucket_public_access_block', {}).items():
            if bucket_name in res_name:
                return (res_config.get('block_public_acls') and 
                        res_config.get('block_public_policy') and 
                        res_config.get('ignore_public_acls') and 
                        res_config.get('restrict_public_buckets'))
        return False


class S3BucketPolicyChecker(AWSSecurityChecker):
    """Check S3 bucket policy security configurations."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all S3 bucket policy checks."""
        violations = []
        
        if 'aws_s3_bucket_policy' not in resources:
            return violations
        
        for resource_name, resource_config in resources['aws_s3_bucket_policy'].items():
            policy = resource_config.get('policy', '{}')
            
            # S3-010: No wildcard principal
            if self._has_wildcard_principal(policy):
                violations.append(AWSPolicyViolation(
                    policy_id=AWSPolicyIDs.S3_BUCKET_POLICY,
                    severity='CRITICAL',
                    resource_type='aws_s3_bucket_policy',
                    resource_name=resource_name,
                    message='S3 bucket policy allows wildcard principal (*)',
                    guide='https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html'
                ))
            
            # S3-008: Secure transport (HTTPS)
            if not self._enforces_secure_transport(policy):
                violations.append(AWSPolicyViolation(
                    policy_id=AWSPolicyIDs.S3_SECURE_TRANSPORT,
                    severity='HIGH',
                    resource_type='aws_s3_bucket_policy',
                    resource_name=resource_name,
                    message='S3 bucket policy does not enforce secure transport (HTTPS)',
                    guide='https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html'
                ))
        
        return violations
    
    def _has_wildcard_principal(self, policy: str) -> bool:
        """Check if policy has wildcard principal in Allow statements."""
        import json
        try:
            policy_doc = json.loads(policy) if isinstance(policy, str) else policy
            statements = policy_doc.get('Statement', [])
            for stmt in statements:
                if stmt.get('Effect') == 'Allow':
                    principal = stmt.get('Principal', {})
                    if principal == '*' or principal.get('AWS') == '*':
                        return True
            return False
        except:
            return False
    
    def _enforces_secure_transport(self, policy: str) -> bool:
        """Check if policy enforces HTTPS."""
        import json
        try:
            policy_doc = json.loads(policy) if isinstance(policy, str) else policy
            statements = policy_doc.get('Statement', [])
            for stmt in statements:
                if stmt.get('Effect') == 'Deny':
                    condition = stmt.get('Condition', {})
                    if 'Bool' in condition:
                        if condition['Bool'].get('aws:SecureTransport') == 'false':
                            return True
            return False
        except:
            return False


class S3ACLChecker(AWSSecurityChecker):
    """Check S3 bucket ACL security."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all S3 ACL checks."""
        violations = []
        
        if 'aws_s3_bucket_acl' not in resources:
            return violations
        
        for resource_name, resource_config in resources['aws_s3_bucket_acl'].items():
            acl = resource_config.get('acl', '')
            
            # S3-009: No public READ
            if acl in ['public-read', 'public-read-write', 'authenticated-read']:
                violations.append(AWSPolicyViolation(
                    policy_id=AWSPolicyIDs.S3_BUCKET_ACL,
                    severity='CRITICAL',
                    resource_type='aws_s3_bucket_acl',
                    resource_name=resource_name,
                    message=f'S3 bucket ACL allows public access: {acl}',
                    guide='https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html'
                ))
            
            # S3-009: No public WRITE
            if acl in ['public-read-write']:
                violations.append(AWSPolicyViolation(
                    policy_id=AWSPolicyIDs.S3_BUCKET_ACL,
                    severity='CRITICAL',
                    resource_type='aws_s3_bucket_acl',
                    resource_name=resource_name,
                    message='S3 bucket ACL allows public WRITE access',
                    guide='https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html'
                ))
        
        return violations


class S3EncryptionChecker(AWSSecurityChecker):
    """Check S3 bucket encryption configuration."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all S3 encryption checks."""
        violations = []
        
        if 'aws_s3_bucket_server_side_encryption_configuration' not in resources:
            return violations
        
        for resource_name, resource_config in resources['aws_s3_bucket_server_side_encryption_configuration'].items():
            rule = resource_config.get('rule', [{}])[0] if resource_config.get('rule') else {}
            encryption_default = rule.get('apply_server_side_encryption_by_default', {})
            # Handle both dict and list formats
            if isinstance(encryption_default, list) and len(encryption_default) > 0:
                encryption_default = encryption_default[0]
            algorithm = encryption_default.get('sse_algorithm', '') if isinstance(encryption_default, dict) else ''
            
            # S3-005: KMS encryption by default
            if algorithm != 'aws:kms':
                violations.append(AWSPolicyViolation(
                    policy_id=AWSPolicyIDs.S3_BUCKET_ENCRYPTION,
                    severity='MEDIUM',
                    resource_type='aws_s3_bucket_server_side_encryption_configuration',
                    resource_name=resource_name,
                    message='S3 bucket not encrypted with KMS (using AES256 instead)',
                    guide='https://docs.aws.amazon.com/AmazonS3/latest/userguide/specifying-kms-encryption.html'
                ))
        
        return violations
