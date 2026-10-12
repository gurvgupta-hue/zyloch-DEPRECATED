"""
CloudFormation Stack Security Checkers for AWS

Implements comprehensive CloudFormation security validation policies.
"""

from typing import Dict, List, Any
from scanner_core.models.violation import AWSPolicyViolation
from scanner_core.constants.aws_policy_ids import AWSPolicyIDs
from .base_checker import AWSSecurityChecker


class CloudFormationStackChecker(AWSSecurityChecker):
    """Check CloudFormation stack security configurations."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all CloudFormation checks."""
        violations = []
        if 'aws_cloudformation_stack' not in resources:
            return violations
        for resource_name, config in resources['aws_cloudformation_stack'].items():
            violations.extend(self._check_stack(resource_name, config))
        return violations
    
    def _check_stack(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual CloudFormation stack."""
        violations = []
        
        # CFN-001: Termination protection enabled
        if not config.get('enable_termination_protection'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.CFN_TERMINATION_PROTECTION,
                severity='MEDIUM',
                resource_type='aws_cloudformation_stack',
                resource_name=resource_name,
                message='CloudFormation stack does not have termination protection',
                guide='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stack-protection.html'
            ))
        
        # CFN-002: IAM capabilities acknowledged
        capabilities = config.get('capabilities', [])
        if not capabilities or 'CAPABILITY_NAMED_IAM' not in capabilities:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.CFN_002,
                severity='HIGH',
                resource_type='aws_cloudformation_stack',
                resource_name=resource_name,
                message='CloudFormation stack does not acknowledge IAM capabilities',
                guide='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-template.html'
            ))
        
        # CFN-003: Notification ARNs configured
        notification_arns = config.get('notification_arns', [])
        if not notification_arns:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.CFN_003,
                severity='LOW',
                resource_type='aws_cloudformation_stack',
                resource_name=resource_name,
                message='CloudFormation stack does not have SNS notifications configured',
                guide='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/notification-set-up.html'
            ))
        
        # CFN-004: Tags applied
        tags = config.get('tags', {})
        required_tags = ['Environment', 'Owner', 'CostCenter']
        missing_tags = [tag for tag in required_tags if tag not in tags]
        
        if missing_tags:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.CFN_004,
                severity='LOW',
                resource_type='aws_cloudformation_stack',
                resource_name=resource_name,
                message=f'CloudFormation stack missing organizational tags: {", ".join(missing_tags)}',
                guide='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html'
            ))
        
        return violations


class SNSTopicChecker(AWSSecurityChecker):
    """Check SNS topic security configurations."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all SNS checks."""
        violations = []
        if 'aws_sns_topic' not in resources:
            return violations
        for resource_name, config in resources['aws_sns_topic'].items():
            violations.extend(self._check_topic(resource_name, config))
        return violations
    
    def _check_topic(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual SNS topic."""
        violations = []
        
        # SNS-001: Encryption enabled
        if not config.get('kms_master_key_id'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.SNS_ENCRYPTION,
                severity='HIGH',
                resource_type='aws_sns_topic',
                resource_name=resource_name,
                message='SNS topic is not encrypted with KMS',
                guide='https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html'
            ))
        
        # SNS-002: Access policy restricts public access
        policy = config.get('policy')
        if policy and self._policy_allows_public_access(policy):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.SNS_002,
                severity='CRITICAL',
                resource_type='aws_sns_topic',
                resource_name=resource_name,
                message='SNS topic policy allows public access',
                guide='https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-use-cases.html'
            ))
        
        # SNS-003: Tags applied
        tags = config.get('tags', {})
        if not tags.get('Environment'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.SNS_003,
                severity='LOW',
                resource_type='aws_sns_topic',
                resource_name=resource_name,
                message='SNS topic missing Environment tag',
                guide='https://docs.aws.amazon.com/sns/latest/dg/sns-using-tags.html'
            ))
        
        # SNS-004: FIFO message ordering
        fifo_topic = config.get('fifo_topic')
        content_based_dedup = config.get('content_based_deduplication')
        
        if fifo_topic and not content_based_dedup:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.SNS_004,
                severity='LOW',
                resource_type='aws_sns_topic',
                resource_name=resource_name,
                message='FIFO SNS topic does not have content-based deduplication',
                guide='https://docs.aws.amazon.com/sns/latest/dg/fifo-topics.html'
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


class SQSQueueChecker(AWSSecurityChecker):
    """Check SQS queue security configurations."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all SQS checks."""
        violations = []
        if 'aws_sqs_queue' not in resources:
            return violations
        for resource_name, config in resources['aws_sqs_queue'].items():
            violations.extend(self._check_queue(resource_name, config))
        return violations
    
    def _check_queue(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual SQS queue."""
        violations = []
        
        # SQS-001: Encryption enabled
        if not config.get('kms_master_key_id') and not config.get('sqs_managed_sse_enabled'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.SQS_ENCRYPTION,
                severity='HIGH',
                resource_type='aws_sqs_queue',
                resource_name=resource_name,
                message='SQS queue is not encrypted',
                guide='https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-encryption-details.html'
            ))
        
        # SQS-002: Message retention policy
        message_retention = config.get('message_retention_seconds')
        if not message_retention or message_retention < 60:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.SQS_002,
                severity='LOW',
                resource_type='aws_sqs_queue',
                resource_name=resource_name,
                message='SQS queue has very short message retention',
                guide='https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/manage-message-retention.html'
            ))
        
        # SQS-003: Dead-letter queue configured
        redrive_policy = config.get('redrive_policy')
        if not redrive_policy:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.SQS_003,
                severity='MEDIUM',
                resource_type='aws_sqs_queue',
                resource_name=resource_name,
                message='SQS queue does not have dead-letter queue configured',
                guide='https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html'
            ))
        
        # SQS-004: Access policy restricts public access
        policy = config.get('policy')
        if policy and self._policy_allows_public_access(policy):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.SQS_004,
                severity='CRITICAL',
                resource_type='aws_sqs_queue',
                resource_name=resource_name,
                message='SQS queue policy allows public access',
                guide='https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-authentication-and-access-control.html'
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


class DynamoDBChecker(AWSSecurityChecker):
    """Check DynamoDB security configurations."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all DynamoDB checks."""
        violations = []
        if 'aws_dynamodb_table' not in resources:
            return violations
        for resource_name, config in resources['aws_dynamodb_table'].items():
            violations.extend(self._check_table(resource_name, config))
        return violations
    
    def _check_table(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual DynamoDB table."""
        violations = []
        
        # DDB-001: Encryption enabled
        if not config.get('server_side_encryption'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.DYNAMODB_ENCRYPTION,
                severity='HIGH',
                resource_type='aws_dynamodb_table',
                resource_name=resource_name,
                message='DynamoDB table does not have encryption enabled',
                guide='https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/encryption.html'
            ))
        
        # DDB-002: Point-in-time recovery
        if not config.get('point_in_time_recovery_enabled'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.DYNAMODB_POINT_IN_TIME_RECOVERY,
                severity='MEDIUM',
                resource_type='aws_dynamodb_table',
                resource_name=resource_name,
                message='DynamoDB table does not have point-in-time recovery enabled',
                guide='https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.html'
            ))
        
        # DDB-003: TTL not exposing sensitive data
        ttl_spec = config.get('ttl', {})
        # This is more of a warning for policy review
        
        # DDB-004: Tags applied for cost allocation
        tags = config.get('tags', {})
        if not tags.get('CostCenter'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.DYNAMODB_TAGGING,
                severity='LOW',
                resource_type='aws_dynamodb_table',
                resource_name=resource_name,
                message='DynamoDB table missing CostCenter tag',
                guide='https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/resource-tagging.html'
            ))
        
        # DDB-005: Backup configuration
        if not config.get('backup_name'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.DYNAMODB_POINT_IN_TIME_RECOVERY,
                severity='MEDIUM',
                resource_type='aws_dynamodb_table',
                resource_name=resource_name,
                message='DynamoDB table does not have backup on demand configured',
                guide='https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/BackupRestore.html'
            ))
        
        # DDB-006: Billing mode (On-demand vs Provisioned)
        billing_mode = config.get('billing_mode', 'PROVISIONED')
        # This is informational
        
        return violations


class ElastiCacheChecker(AWSSecurityChecker):
    """Check ElastiCache cluster security."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all ElastiCache checks."""
        violations = []
        if 'aws_elasticache_cluster' not in resources:
            return violations
        for resource_name, config in resources['aws_elasticache_cluster'].items():
            violations.extend(self._check_cluster(resource_name, config))
        return violations
    
    def _check_cluster(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual ElastiCache cluster."""
        violations = []
        
        # EC-001: Encryption at rest
        if not config.get('at_rest_encryption_enabled'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.ELASTICACHE_ENCRYPTION_AT_REST,
                severity='HIGH',
                resource_type='aws_elasticache_cluster',
                resource_name=resource_name,
                message='ElastiCache cluster does not have encryption at rest',
                guide='https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/at-rest-encryption.html'
            ))
        
        # EC-002: Encryption in transit
        if not config.get('transit_encryption_enabled'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.ELASTICACHE_ENCRYPTION_IN_TRANSIT,
                severity='HIGH',
                resource_type='aws_elasticache_cluster',
                resource_name=resource_name,
                message='ElastiCache cluster does not have encryption in transit',
                guide='https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/in-transit-encryption.html'
            ))
        
        # EC-003: In VPC
        subnet_group = config.get('subnet_group_name')
        if not subnet_group:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.EC_003,
                severity='HIGH',
                resource_type='aws_elasticache_cluster',
                resource_name=resource_name,
                message='ElastiCache cluster is not in VPC',
                guide='https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/VPCs.html'
            ))
        
        # EC-004: Multi-AZ enabled
        if not config.get('automatic_failover_enabled'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.EC_004,
                severity='MEDIUM',
                resource_type='aws_elasticache_cluster',
                resource_name=resource_name,
                message='ElastiCache cluster does not have automatic failover',
                guide='https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/AutomaticFailover.html'
            ))
        
        return violations
