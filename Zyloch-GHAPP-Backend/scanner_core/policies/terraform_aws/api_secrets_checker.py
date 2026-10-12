"""
API Gateway and Secrets Manager Security Checkers for AWS

Implements security validation for APIs and secrets management.
"""

from typing import Dict, List, Any
from scanner_core.models.violation import AWSPolicyViolation
from scanner_core.constants.aws_policy_ids import AWSPolicyIDs
from .base_checker import AWSSecurityChecker


class APIGatewayChecker(AWSSecurityChecker):
    """Check API Gateway security configurations."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all API Gateway checks."""
        violations = []
        
        # Check REST APIs
        if 'aws_api_gateway_rest_api' in resources:
            for resource_name, config in resources['aws_api_gateway_rest_api'].items():
                violations.extend(self._check_api(resource_name, config))
        
        # Check Stages
        if 'aws_api_gateway_stage' in resources:
            for resource_name, config in resources['aws_api_gateway_stage'].items():
                violations.extend(self._check_stage(resource_name, config))
        
        return violations
    
    def _check_api(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual API Gateway REST API."""
        violations = []
        
        # APIGW-001: Endpoint type
        endpoint_config = config.get('endpoint_configuration', {})
        endpoint_type = endpoint_config.get('types', []) if isinstance(endpoint_config, dict) else []
        
        if not endpoint_type or 'PRIVATE' not in endpoint_type:
            if endpoint_type and 'REGIONAL' in endpoint_type:
                pass  # REGIONAL is acceptable
            else:
                violations.append(AWSPolicyViolation(
                    policy_id=AWSPolicyIDs.APIGW_ENDPOINT_TYPE,
                    severity='MEDIUM',
                    resource_type='aws_api_gateway_rest_api',
                    resource_name=resource_name,
                    message='API Gateway is not private or regional',
                    guide='https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-api-endpoint-types.html'
                ))
        
        # APIGW-002: Binary media types
        binary_media_types = config.get('binary_media_types', [])
        # This is more informational
        
        # APIGW-003: VPC endpoint configured for private APIs
        if endpoint_type and 'PRIVATE' in endpoint_type:
            policy = config.get('policy')
            if not policy:
                violations.append(AWSPolicyViolation(
                    policy_id=AWSPolicyIDs.APIGW_RESOURCE_POLICY,
                    severity='HIGH',
                    resource_type='aws_api_gateway_rest_api',
                    resource_name=resource_name,
                    message='Private API Gateway does not have resource policy',
                    guide='https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-resource-policy.html'
                ))
        
        return violations
    
    def _check_stage(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check API Gateway stage."""
        violations = []
        
        # APIGW-004: CloudWatch logging enabled
        method_settings = config.get('method_settings', [])
        logging_enabled = any(
            m.get('logging_level') and m.get('logging_level') != 'OFF' 
            for m in method_settings
        )
        
        if not logging_enabled:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.APIGW_CLOUDWATCH_LOGGING,
                severity='MEDIUM',
                resource_type='aws_api_gateway_stage',
                resource_name=resource_name,
                message='API Gateway stage does not have CloudWatch logging enabled',
                guide='https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html'
            ))
        
        # APIGW-005: Tracing enabled
        if not config.get('tracing_enabled'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.APIGW_XRAY_TRACING,
                severity='MEDIUM',
                resource_type='aws_api_gateway_stage',
                resource_name=resource_name,
                message='API Gateway stage does not have X-Ray tracing enabled',
                guide='https://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-set-up-tracing.html'
            ))
        
        # APIGW-006: WAF enabled
        web_acl_arn = config.get('web_acl_arn')
        if not web_acl_arn:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.APIGW_WAF,
                severity='MEDIUM',
                resource_type='aws_api_gateway_stage',
                resource_name=resource_name,
                message='API Gateway stage is not protected with WAF',
                guide='https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html'
            ))
        
        return violations


class SecretsManagerChecker(AWSSecurityChecker):
    """Check AWS Secrets Manager security configurations."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all Secrets Manager checks."""
        violations = []
        if 'aws_secretsmanager_secret' not in resources:
            return violations
        for resource_name, config in resources['aws_secretsmanager_secret'].items():
            violations.extend(self._check_secret(resource_name, config))
        return violations
    
    def _check_secret(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual secret."""
        violations = []
        
        # SM-001: KMS encryption enabled
        kms_key_id = config.get('kms_key_id')
        if not kms_key_id:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.SECRETS_KMS_ENCRYPTION,
                severity='HIGH',
                resource_type='aws_secretsmanager_secret',
                resource_name=resource_name,
                message='Secret is not encrypted with customer-managed KMS key',
                guide='https://docs.aws.amazon.com/secretsmanager/latest/userguide/encryption.html'
            ))
        
        # SM-002: Rotation enabled
        rotation_rules = config.get('rotation_rules', {})
        if isinstance(rotation_rules, dict):
            auto_rotate_days = rotation_rules.get('automatically_after_days')
            if not auto_rotate_days:
                violations.append(AWSPolicyViolation(
                    policy_id=AWSPolicyIDs.SECRETS_ROTATION,
                    severity='MEDIUM',
                    resource_type='aws_secretsmanager_secret',
                    resource_name=resource_name,
                    message='Secret does not have automatic rotation enabled',
                    guide='https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html'
                ))
        
        # SM-003: Resource policy restricts access
        policy = config.get('policy')
        if policy and self._policy_allows_public_access(policy):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.SECRETS_PUBLIC_ACCESS,
                severity='CRITICAL',
                resource_type='aws_secretsmanager_secret',
                resource_name=resource_name,
                message='Secret policy allows public access',
                guide='https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access.html'
            ))
        
        # SM-004: Tags applied
        tags = config.get('tags', {})
        required_tags = ['Application', 'Owner']
        missing_tags = [tag for tag in required_tags if tag not in tags]
        
        if missing_tags:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.SECRETS_TAGGING,
                severity='LOW',
                resource_type='aws_secretsmanager_secret',
                resource_name=resource_name,
                message=f'Secret missing tags: {", ".join(missing_tags)}',
                guide='https://docs.aws.amazon.com/secretsmanager/latest/userguide/manage_tagging.html'
            ))
        
        return violations
    
    def _policy_allows_public_access(self, policy: str) -> bool:
        """Check if policy allows public access."""
        import json
        try:
            if isinstance(policy, str):
                policy_doc = json.loads(policy)
            else:
                policy_doc = policy
            
            for statement in policy_doc.get('Statement', []):
                if statement.get('Effect') == 'Allow':
                    principal = statement.get('Principal', {})
                    if principal == '*':
                        return True
                    if isinstance(principal, dict):
                        aws = principal.get('AWS', [])
                        if isinstance(aws, str):
                            aws = [aws]
                        if '*' in aws or any('*' in str(p) for p in aws):
                            return True
            return False
        except (json.JSONDecodeError, TypeError, AttributeError):
            return False


class SecretsManagerSecretVersionChecker(AWSSecurityChecker):
    """Check Secrets Manager secret version security."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all secret version checks."""
        violations = []
        if 'aws_secretsmanager_secret_version' not in resources:
            return violations
        for resource_name, config in resources['aws_secretsmanager_secret_version'].items():
            violations.extend(self._check_secret_version(resource_name, config))
        return violations
    
    def _check_secret_version(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual secret version."""
        violations = []
        
        # SM-005: Secret value not in plain text in terraform
        # This check warns about plaintext secrets in code
        secret_string = config.get('secret_string', '')
        secret_binary = config.get('secret_binary', '')
        
        if not secret_binary and (not secret_string or len(secret_string) < 20):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.SECRETS_REPLICA,
                severity='HIGH',
                resource_type='aws_secretsmanager_secret_version',
                resource_name=resource_name,
                message='Secret appears to be in plain text in Terraform code',
                guide='https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html'
            ))
        
        return violations
