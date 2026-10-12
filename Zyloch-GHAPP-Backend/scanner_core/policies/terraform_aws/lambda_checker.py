"""
Lambda Security Checkers for AWS

Implements comprehensive Lambda function security validation policies.
"""

from typing import Dict, List, Any
import json
from scanner_core.models.violation import AWSPolicyViolation
from scanner_core.constants.aws_policy_ids import AWSPolicyIDs
from .base_checker import AWSSecurityChecker


class LambdaFunctionChecker(AWSSecurityChecker):
    """Check Lambda function security configurations."""
    
    POLICY_PREFIX = "AWS-SEC-LAMBDA"
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all Lambda function checks."""
        violations = []
        
        if 'aws_lambda_function' not in resources:
            return violations
        
        for resource_name, config in resources['aws_lambda_function'].items():
            violations.extend(self._check_function(resource_name, config))
        
        return violations
    
    def _check_function(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual Lambda function."""
        violations = []
        
        # LAMBDA-001: VPC configuration
        if not config.get('vpc_config'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.LAMBDA_VPC_CONFIGURED,
                severity='MEDIUM',
                resource_type='aws_lambda_function',
                resource_name=resource_name,
                message='Lambda function not configured in VPC',
                guide='https://docs.aws.amazon.com/lambda/latest/dg/vpc.html'
            ))
        else:
            vpc_config = config.get('vpc_config', {})
            # vpc_config can be a list or dict depending on Terraform output format
            if isinstance(vpc_config, list):
                if vpc_config and isinstance(vpc_config[0], dict):
                    vpc_config = vpc_config[0]
                else:
                    vpc_config = {}
            
            if not vpc_config.get('subnet_ids') or not vpc_config.get('security_group_ids'):
                violations.append(AWSPolicyViolation(
                    policy_id=AWSPolicyIDs.LAMBDA_VPC_CONFIGURED,
                    severity='MEDIUM',
                    resource_type='aws_lambda_function',
                    resource_name=resource_name,
                    message='Lambda VPC configuration incomplete',
                    guide='https://docs.aws.amazon.com/lambda/latest/dg/vpc.html'
                ))
        
        # LAMBDA-002: IAM role attached
        role = config.get('role')
        if not role:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.LAMBDA_EXECUTION_ROLE,
                severity='HIGH',
                resource_type='aws_lambda_function',
                resource_name=resource_name,
                message='Lambda function does not have IAM role attached',
                guide='https://docs.aws.amazon.com/lambda/latest/dg/lambda-execution-role.html'
            ))
        
        # LAMBDA-003: No environment variables with secrets
        environment = config.get('environment', {})
        variables = environment.get('variables', {}) if isinstance(environment, dict) else {}
        
        secret_keywords = ['password', 'secret', 'api_key', 'token', 'credential', 'key']
        for key, value in variables.items():
            if any(keyword in key.lower() for keyword in secret_keywords):
                violations.append(AWSPolicyViolation(
                    policy_id=AWSPolicyIDs.LAMBDA_ENVIRONMENT_ENCRYPTION,
                    severity='CRITICAL',
                    resource_type='aws_lambda_function',
                    resource_name=resource_name,
                    message=f'Lambda function has sensitive data in environment variable: {key}',
                    guide='https://docs.aws.amazon.com/secretsmanager/'
                ))
                break
        
        # LAMBDA-004: Timeout configured
        timeout = config.get('timeout')
        if not timeout or timeout == 0:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.LAMBDA_TIMEOUT_CONFIGURED,
                severity='LOW',
                resource_type='aws_lambda_function',
                resource_name=resource_name,
                message='Lambda function does not have timeout configured',
                guide='https://docs.aws.amazon.com/lambda/latest/dg/functions-configuration.html'
            ))
        
        # LAMBDA-005: Memory allocated
        memory_size = config.get('memory_size')
        if not memory_size or memory_size < 128:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.LAMBDA_MEMORY_CONFIGURED,
                severity='LOW',
                resource_type='aws_lambda_function',
                resource_name=resource_name,
                message=f'Lambda function has insufficient memory: {memory_size}MB',
                guide='https://docs.aws.amazon.com/lambda/latest/dg/functions-configuration.html'
            ))
        
        # LAMBDA-006: Logging enabled
        if not config.get('logging_config') and not config.get('environment'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.LAMBDA_LOGGING_ENABLED,
                severity='MEDIUM',
                resource_type='aws_lambda_function',
                resource_name=resource_name,
                message='Lambda function does not have logging configured',
                guide='https://docs.aws.amazon.com/lambda/latest/dg/monitoring.html'
            ))
        
        # LAMBDA-007: Ephemeral storage encrypted
        ephemeral_storage = config.get('ephemeral_storage', {})
        if isinstance(ephemeral_storage, dict) and ephemeral_storage.get('size') and \
           not ephemeral_storage.get('encrypted'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.LAMBDA_FUNCTION_PUBLIC,
                severity='MEDIUM',
                resource_type='aws_lambda_function',
                resource_name=resource_name,
                message='Lambda ephemeral storage is not encrypted',
                guide='https://docs.aws.amazon.com/lambda/latest/dg/functions-configuration.html'
            ))
        
        # LAMBDA-008: Tracing enabled
        tracing_config = config.get('tracing_config', {})
        # tracing_config can be a list or dict depending on Terraform output format
        if isinstance(tracing_config, list):
            if tracing_config and isinstance(tracing_config[0], dict):
                tracing_config = tracing_config[0]
            else:
                tracing_config = {}
        
        if isinstance(tracing_config, dict) and tracing_config.get('mode') != 'Active':
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.LAMBDA_FUNCTION_PUBLIC,
                severity='MEDIUM',
                resource_type='aws_lambda_function',
                resource_name=resource_name,
                message='Lambda function does not have X-Ray tracing enabled',
                guide='https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html'
            ))
        
        return violations


class LambdaPermissionChecker(AWSSecurityChecker):
    """Check Lambda function permission security."""
    
    POLICY_PREFIX = "AWS-SEC-LAMBDA"
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all Lambda permission checks."""
        violations = []
        
        if 'aws_lambda_permission' not in resources:
            return violations
        
        for resource_name, config in resources['aws_lambda_permission'].items():
            violations.extend(self._check_permission(resource_name, config))
        
        return violations
    
    def _check_permission(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual Lambda permission."""
        violations = []
        
        # LAMBDA-009: Wildcard principals
        principal = config.get('principal', '')
        if principal == '*':
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.LAMBDA_PERMISSION_WILDCARD,
                severity='CRITICAL',
                resource_type='aws_lambda_permission',
                resource_name=resource_name,
                message='Lambda permission grants access to all principals (*)',
                guide='https://docs.aws.amazon.com/lambda/latest/dg/lambda-permissions.html'
            ))
        
        return violations


class LambdaLayerChecker(AWSSecurityChecker):
    """Check Lambda layer security configurations."""
    
    POLICY_PREFIX = "AWS-SEC-LAMBDA"
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all Lambda layer checks."""
        violations = []
        
        if 'aws_lambda_layer_version' not in resources:
            return violations
        
        for resource_name, config in resources['aws_lambda_layer_version'].items():
            violations.extend(self._check_layer(resource_name, config))
        
        return violations
    
    def _check_layer(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual Lambda layer."""
        violations = []
        
        # LAMBDA-010: Layer source code access
        source_code_hash = config.get('source_code_hash')
        if not source_code_hash:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.LAMBDA_LAYER_SOURCE,
                severity='LOW',
                resource_type='aws_lambda_layer_version',
                resource_name=resource_name,
                message='Lambda layer does not have source code hash for integrity verification',
                guide='https://docs.aws.amazon.com/lambda/latest/dg/lambda-layers.html'
            ))
        
        return violations
