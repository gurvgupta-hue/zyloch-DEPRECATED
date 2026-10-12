"""
CloudTrail and Logging Security Checkers for AWS

Implements comprehensive logging and audit trail validation policies.
"""

from typing import Dict, List, Any
from scanner_core.models.violation import AWSPolicyViolation
from scanner_core.constants.aws_policy_ids import AWSPolicyIDs
from .base_checker import AWSSecurityChecker


class CloudTrailChecker(AWSSecurityChecker):
    """Check CloudTrail security configurations."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all CloudTrail checks."""
        violations = []
        if 'aws_cloudtrail' not in resources:
            return violations
        for resource_name, config in resources['aws_cloudtrail'].items():
            violations.extend(self._check_trail(resource_name, config))
        return violations
    
    def _check_trail(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual CloudTrail."""
        violations = []
        
        # CT-001: CloudTrail enabled
        if not config.get('enable_logging'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.CLOUDTRAIL_ENABLED,
                severity='CRITICAL',
                resource_type='aws_cloudtrail',
                resource_name=resource_name,
                message='CloudTrail is disabled',
                guide='https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-enable.html'
            ))
        
        # CT-002: Multi-region trail
        if not config.get('is_multi_region_trail'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.CLOUDTRAIL_MULTI_REGION,
                severity='HIGH',
                resource_type='aws_cloudtrail',
                resource_name=resource_name,
                message='CloudTrail is not configured for all regions',
                guide='https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-multi-region.html'
            ))
        
        # CT-003: S3 bucket specified
        s3_bucket_name = config.get('s3_bucket_name')
        if not s3_bucket_name:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.CLOUDTRAIL_S3_ENCRYPTION,
                severity='HIGH',
                resource_type='aws_cloudtrail',
                resource_name=resource_name,
                message='CloudTrail does not have S3 bucket specified for logs',
                guide='https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-set-bucket.html'
            ))
        
        # CT-004: Log file validation
        if not config.get('enable_log_file_validation'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.CLOUDTRAIL_LOG_FILE_VALIDATION,
                severity='HIGH',
                resource_type='aws_cloudtrail',
                resource_name=resource_name,
                message='CloudTrail does not have log file validation enabled',
                guide='https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation.html'
            ))
        
        # CT-005: CloudWatch integration
        cloud_watch_logs_group = config.get('cloud_watch_logs_group_arn')
        if not cloud_watch_logs_group:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.CLOUDTRAIL_CLOUDWATCH_INTEGRATION,
                severity='MEDIUM',
                resource_type='aws_cloudtrail',
                resource_name=resource_name,
                message='CloudTrail is not integrated with CloudWatch Logs',
                guide='https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html'
            ))
        
        # CT-006: KMS encryption for logs
        kms_key_id = config.get('kms_key_id')
        if not kms_key_id:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.CLOUDTRAIL_KMS_ENCRYPTION,
                severity='MEDIUM',
                resource_type='aws_cloudtrail',
                resource_name=resource_name,
                message='CloudTrail logs are not encrypted with KMS',
                guide='https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-logs.html'
            ))
        
        # CT-007: Include management events
        event_selector = config.get('event_selector', [])
        has_management_events = False
        if event_selector and isinstance(event_selector, list):
            for selector in event_selector:
                if isinstance(selector, dict) and selector.get('include_management_events'):
                    has_management_events = True
                    break
        
        if not has_management_events:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.CLOUDTRAIL_MANAGEMENT_EVENTS,
                severity='HIGH',
                resource_type='aws_cloudtrail',
                resource_name=resource_name,
                message='CloudTrail does not include management events',
                guide='https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-selectors.html'
            ))
        
        # CT-008: Data events enabled
        has_data_events = False
        if event_selector and isinstance(event_selector, list):
            for selector in event_selector:
                if isinstance(selector, dict) and selector.get('data_resource'):
                    has_data_events = True
                    break
        
        if not has_data_events:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.CLOUDTRAIL_DATA_EVENTS,
                severity='MEDIUM',
                resource_type='aws_cloudtrail',
                resource_name=resource_name,
                message='CloudTrail does not have event selectors for data events',
                guide='https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-selectors.html'
            ))
        
        return violations


class CloudWatchLogGroupChecker(AWSSecurityChecker):
    """Check CloudWatch Logs group security."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all CloudWatch Logs group checks."""
        violations = []
        if 'aws_cloudwatch_log_group' not in resources:
            return violations
        for resource_name, config in resources['aws_cloudwatch_log_group'].items():
            violations.extend(self._check_log_group(resource_name, config))
        return violations
    
    def _check_log_group(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual CloudWatch Logs group."""
        violations = []
        
        # CT-009: Log retention policy
        retention_days = config.get('retention_in_days')
        if not retention_days or retention_days == 0:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.CLOUDTRAIL_LOG_RETENTION,
                severity='MEDIUM',
                resource_type='aws_cloudwatch_log_group',
                resource_name=resource_name,
                message='CloudWatch Logs group does not have retention policy',
                guide='https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/WhatIsCloudWatchLogs.html'
            ))
        
        return violations


class S3LoggingChecker(AWSSecurityChecker):
    """Check S3 logging security configurations."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all S3 logging checks."""
        violations = []
        if 'aws_s3_bucket_logging' not in resources:
            return violations
        for resource_name, config in resources['aws_s3_bucket_logging'].items():
            violations.extend(self._check_s3_logging(resource_name, config))
        return violations
    
    def _check_s3_logging(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check S3 bucket logging."""
        violations = []
        
        # CT-010: S3 bucket logging target
        target_bucket = config.get('target_bucket')
        if not target_bucket:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.CLOUDTRAIL_S3_BUCKET_LOGGING,
                severity='HIGH',
                resource_type='aws_s3_bucket_logging',
                resource_name=resource_name,
                message='S3 bucket does not have logging target specified',
                guide='https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html'
            ))
        
        # CT-011: Log file prefix for organization
        target_prefix = config.get('target_prefix', '')
        if not target_prefix:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.S3_LOGGING,
                severity='LOW',
                resource_type='aws_s3_bucket_logging',
                resource_name=resource_name,
                message='S3 bucket logging does not have target prefix',
                guide='https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html'
            ))
        
        return violations


class VPCFlowLogsChecker(AWSSecurityChecker):
    """Check VPC Flow Logs security configurations."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all VPC Flow Logs checks."""
        violations = []
        if 'aws_flow_log' not in resources:
            return violations
        for resource_name, config in resources['aws_flow_log'].items():
            violations.extend(self._check_flow_logs(resource_name, config))
        return violations
    
    def _check_flow_logs(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual VPC Flow Log."""
        violations = []
        
        # CT-012: Flow Logs traffic type
        traffic_type = config.get('traffic_type', '')
        if traffic_type != 'ALL':
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.VPC_FLOW_LOGS,
                severity='MEDIUM',
                resource_type='aws_flow_log',
                resource_name=resource_name,
                message=f'VPC Flow Logs traffic_type is not ALL (currently: {traffic_type})',
                guide='https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html'
            ))
        
        # CT-013: Flow Logs destination
        log_destination = config.get('log_destination')
        if not log_destination:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.VPC_FLOW_LOGS,
                severity='HIGH',
                resource_type='aws_flow_log',
                resource_name=resource_name,
                message='VPC Flow Logs does not have destination specified',
                guide='https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html'
            ))
        
        return violations
