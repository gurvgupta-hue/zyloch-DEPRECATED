"""
AWS Security Checkers Package

Comprehensive security validation for AWS resources using Terraform configurations.
Provides standardized checker interfaces following the base_checker abstract class pattern.
"""

from .base_checker import AWSSecurityChecker

# Import all checker classes
from .s3_checker import (
    S3BucketChecker,
    S3BucketPolicyChecker,
    S3ACLChecker,
    S3EncryptionChecker
)

from .iam_checker import (
    IAMRoleChecker,
    IAMPolicyChecker,
    IAMAccessKeyChecker
)

from .ec2_checker import (
    SecurityGroupChecker,
    EC2InstanceChecker,
    EBSChecker
)

from .rds_checker import (
    RDSInstanceChecker,
    RDSClusterChecker,
    RDSParameterGroupChecker
)

from .lambda_checker import (
    LambdaFunctionChecker,
    LambdaPermissionChecker,
    LambdaLayerChecker
)

from .kms_checker import (
    KMSKeyChecker,
    KMSAliasChecker,
    KMSGrantChecker
)

from .vpc_checker import (
    VPCChecker,
    SubnetChecker,
    NetworkACLChecker,
    RouteTableChecker,
    VPCPeeringChecker
)

from .cloudtrail_checker import (
    CloudTrailChecker,
    CloudWatchLogGroupChecker,
    S3LoggingChecker,
    VPCFlowLogsChecker
)

from .services_checker import (
    CloudFormationStackChecker,
    SNSTopicChecker,
    SQSQueueChecker,
    DynamoDBChecker,
    ElastiCacheChecker
)

from .api_secrets_checker import (
    APIGatewayChecker,
    SecretsManagerChecker,
    SecretsManagerSecretVersionChecker
)

# Comprehensive registry of all checkers
CHECKER_REGISTRY = {
    # S3 Checkers
    'S3BucketChecker': S3BucketChecker,
    'S3BucketPolicyChecker': S3BucketPolicyChecker,
    'S3ACLChecker': S3ACLChecker,
    'S3EncryptionChecker': S3EncryptionChecker,
    
    # IAM Checkers
    'IAMRoleChecker': IAMRoleChecker,
    'IAMPolicyChecker': IAMPolicyChecker,
    'IAMAccessKeyChecker': IAMAccessKeyChecker,
    
    # EC2 Checkers
    'SecurityGroupChecker': SecurityGroupChecker,
    'EC2InstanceChecker': EC2InstanceChecker,
    'EBSChecker': EBSChecker,
    
    # RDS Checkers
    'RDSInstanceChecker': RDSInstanceChecker,
    'RDSClusterChecker': RDSClusterChecker,
    'RDSParameterGroupChecker': RDSParameterGroupChecker,
    
    # Lambda Checkers
    'LambdaFunctionChecker': LambdaFunctionChecker,
    'LambdaPermissionChecker': LambdaPermissionChecker,
    'LambdaLayerChecker': LambdaLayerChecker,
    
    # KMS Checkers
    'KMSKeyChecker': KMSKeyChecker,
    'KMSAliasChecker': KMSAliasChecker,
    'KMSGrantChecker': KMSGrantChecker,
    
    # VPC Checkers
    'VPCChecker': VPCChecker,
    'SubnetChecker': SubnetChecker,
    'NetworkACLChecker': NetworkACLChecker,
    'RouteTableChecker': RouteTableChecker,
    'VPCPeeringChecker': VPCPeeringChecker,
    
    # CloudTrail & Logging Checkers
    'CloudTrailChecker': CloudTrailChecker,
    'CloudWatchLogGroupChecker': CloudWatchLogGroupChecker,
    'S3LoggingChecker': S3LoggingChecker,
    'VPCFlowLogsChecker': VPCFlowLogsChecker,
    
    # CloudFormation & Services Checkers
    'CloudFormationStackChecker': CloudFormationStackChecker,
    'SNSTopicChecker': SNSTopicChecker,
    'SQSQueueChecker': SQSQueueChecker,
    'DynamoDBChecker': DynamoDBChecker,
    'ElastiCacheChecker': ElastiCacheChecker,
    
    # API Gateway & Secrets Manager Checkers
    'APIGatewayChecker': APIGatewayChecker,
    'SecretsManagerChecker': SecretsManagerChecker,
    'SecretsManagerSecretVersionChecker': SecretsManagerSecretVersionChecker,
}

# Organize checkers by service
CHECKERS_BY_SERVICE = {
    'S3': [S3BucketChecker, S3BucketPolicyChecker, S3ACLChecker, S3EncryptionChecker],
    'IAM': [IAMRoleChecker, IAMPolicyChecker, IAMAccessKeyChecker],
    'EC2': [SecurityGroupChecker, EC2InstanceChecker, EBSChecker],
    'RDS': [RDSInstanceChecker, RDSClusterChecker, RDSParameterGroupChecker],
    'Lambda': [LambdaFunctionChecker, LambdaPermissionChecker, LambdaLayerChecker],
    'KMS': [KMSKeyChecker, KMSAliasChecker, KMSGrantChecker],
    'VPC': [VPCChecker, SubnetChecker, NetworkACLChecker, RouteTableChecker, VPCPeeringChecker],
    'CloudTrail': [CloudTrailChecker, CloudWatchLogGroupChecker, S3LoggingChecker, VPCFlowLogsChecker],
    'CloudFormation': [CloudFormationStackChecker],
    'SNS': [SNSTopicChecker],
    'SQS': [SQSQueueChecker],
    'DynamoDB': [DynamoDBChecker],
    'ElastiCache': [ElastiCacheChecker],
    'APIGateway': [APIGatewayChecker],
    'SecretsManager': [SecretsManagerChecker, SecretsManagerSecretVersionChecker],
}

__all__ = [
    # Base class
    'AWSSecurityChecker',
    
    # S3
    'S3BucketChecker',
    'S3BucketPolicyChecker',
    'S3ACLChecker',
    'S3EncryptionChecker',
    
    # IAM
    'IAMRoleChecker',
    'IAMPolicyChecker',
    'IAMAccessKeyChecker',
    
    # EC2
    'SecurityGroupChecker',
    'EC2InstanceChecker',
    'EBSChecker',
    
    # RDS
    'RDSInstanceChecker',
    'RDSClusterChecker',
    'RDSParameterGroupChecker',
    
    # Lambda
    'LambdaFunctionChecker',
    'LambdaPermissionChecker',
    'LambdaLayerChecker',
    
    # KMS
    'KMSKeyChecker',
    'KMSAliasChecker',
    'KMSGrantChecker',
    
    # VPC
    'VPCChecker',
    'SubnetChecker',
    'NetworkACLChecker',
    'RouteTableChecker',
    'VPCPeeringChecker',
    
    # CloudTrail
    'CloudTrailChecker',
    'CloudWatchLogGroupChecker',
    'S3LoggingChecker',
    'VPCFlowLogsChecker',
    
    # Services
    'CloudFormationStackChecker',
    'SNSTopicChecker',
    'SQSQueueChecker',
    'DynamoDBChecker',
    'ElastiCacheChecker',
    
    # API & Secrets
    'APIGatewayChecker',
    'SecretsManagerChecker',
    'SecretsManagerSecretVersionChecker',
    
    # Registries
    'CHECKER_REGISTRY',
    'CHECKERS_BY_SERVICE',
]
