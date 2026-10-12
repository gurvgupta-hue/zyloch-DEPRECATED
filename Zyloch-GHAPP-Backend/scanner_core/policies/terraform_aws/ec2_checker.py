"""
EC2 Security Checkers for AWS

Implements comprehensive EC2 security validation policies.
"""

from typing import Dict, List, Any
from scanner_core.models.violation import AWSPolicyViolation
from scanner_core.constants.aws_policy_ids import AWSPolicyIDs
from .base_checker import AWSSecurityChecker


class SecurityGroupChecker(AWSSecurityChecker):
    """Check EC2 security group configurations."""
    
    POLICY_PREFIX = "AWS-SEC-EC2"
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all security group checks."""
        violations = []
        
        if 'aws_security_group' in resources:
            for resource_name, config in resources['aws_security_group'].items():
                violations.extend(self._check_security_group(resource_name, config))
        
        if 'aws_security_group_rule' in resources:
            for resource_name, config in resources['aws_security_group_rule'].items():
                violations.extend(self._check_security_group_rule(resource_name, config))
        
        return violations
    
    def _check_security_group(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual security group."""
        violations = []
        
        # Check ingress rules
        ingress_rules = config.get('ingress', [])
        violations.extend(self._check_ingress_rules(ingress_rules, resource_name))
        
        # Check egress rules
        egress_rules = config.get('egress', [])
        violations.extend(self._check_egress_rules(egress_rules, resource_name))
        
        return violations
    
    def _check_security_group_rule(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual security group rule."""
        violations = []
        
        rule_type = config.get('type', '')
        from_port = config.get('from_port', -1)
        to_port = config.get('to_port', -1)
        protocol = config.get('protocol', '')
        cidr_blocks = config.get('cidr_blocks', [])
        ipv6_cidr_blocks = config.get('ipv6_cidr_blocks', [])
        
        if rule_type == 'ingress':
            violations.extend(self._check_ingress_rule_details(
                from_port, to_port, protocol, cidr_blocks, ipv6_cidr_blocks, resource_name
            ))
        
        return violations
    
    def _check_ingress_rules(self, rules: List, resource_name: str) -> List[AWSPolicyViolation]:
        """Check ingress rules for security issues."""
        violations = []
        
        for rule in rules:
            from_port = rule.get('from_port', -1)
            to_port = rule.get('to_port', -1)
            protocol = rule.get('protocol', '')
            cidr_blocks = rule.get('cidr_blocks', [])
            ipv6_cidr_blocks = rule.get('ipv6_cidr_blocks', [])
            
            violations.extend(self._check_ingress_rule_details(
                from_port, to_port, protocol, cidr_blocks, ipv6_cidr_blocks, resource_name
            ))
        
        return violations
    
    def _check_ingress_rule_details(self, from_port: int, to_port: int, 
                                    protocol: str, cidr_blocks: List, 
                                    ipv6_blocks: List, resource_name: str) -> List[AWSPolicyViolation]:
        """Check individual ingress rule details."""
        violations = []
        
        # EC2-001: No all inbound traffic (0.0.0.0/0)
        if '0.0.0.0/0' in cidr_blocks or '::/0' in ipv6_blocks:
            
            # EC2-007: No SSH from 0.0.0.0/0
            if from_port == 22 or (from_port <= 22 <= to_port and protocol in ['tcp', '-1']):
                violations.append(AWSPolicyViolation(
                    policy_id=AWSPolicyIDs.EC2_SSH_RESTRICTED,
                    severity='CRITICAL',
                    resource_type='aws_security_group',
                    resource_name=resource_name,
                    message='Security group allows SSH (port 22) from 0.0.0.0/0',
                    guide='https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html'
                ))
            
            # EC2-008: No RDP from 0.0.0.0/0
            elif from_port == 3389 or (from_port <= 3389 <= to_port and protocol in ['tcp', '-1']):
                violations.append(AWSPolicyViolation(
                    policy_id=AWSPolicyIDs.EC2_RDP_RESTRICTED,
                    severity='CRITICAL',
                    resource_type='aws_security_group',
                    resource_name=resource_name,
                    message='Security group allows RDP (port 3389) from 0.0.0.0/0',
                    guide='https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html'
                ))
            
            # EC2-002: All inbound traffic
            else:
                violations.append(AWSPolicyViolation(
                    policy_id=AWSPolicyIDs.EC2_SECURITY_GROUPS,
                    severity='HIGH',
                    resource_type='aws_security_group',
                    resource_name=resource_name,
                    message='Security group allows inbound traffic from 0.0.0.0/0',
                    guide='https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html'
                ))
        
        return violations
    
    def _check_egress_rules(self, rules: List, resource_name: str) -> List[AWSPolicyViolation]:
        """Check egress rules for security issues."""
        violations = []
        
        # EC2-004: No allow-all egress
        for rule in rules:
            from_port = rule.get('from_port', -1)
            to_port = rule.get('to_port', -1)
            protocol = rule.get('protocol', '')
            cidr_blocks = rule.get('cidr_blocks', [])
            
            if protocol == '-1' and '0.0.0.0/0' in cidr_blocks:
                violations.append(AWSPolicyViolation(
                    policy_id=AWSPolicyIDs.EC2_SECURITY_GROUPS,
                    severity='MEDIUM',
                    resource_type='aws_security_group',
                    resource_name=resource_name,
                    message='Security group allows all outbound traffic',
                    guide='https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html'
                ))
                break
        
        return violations


class EC2InstanceChecker(AWSSecurityChecker):
    """Check EC2 instance security configurations."""
    
    POLICY_PREFIX = "AWS-SEC-EC2"
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all EC2 instance checks."""
        violations = []
        
        if 'aws_instance' not in resources:
            return violations
        
        for resource_name, config in resources['aws_instance'].items():
            violations.extend(self._check_instance(resource_name, config))
        
        return violations
    
    def _check_instance(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual EC2 instance."""
        violations = []
        
        # EC2-005: Security group attached
        security_groups = config.get('security_groups', [])
        vpc_security_group_ids = config.get('vpc_security_group_ids', [])
        
        if not security_groups and not vpc_security_group_ids:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.EC2_SECURITY_GROUPS,
                severity='HIGH',
                resource_type='aws_instance',
                resource_name=resource_name,
                message='EC2 instance does not have security group attached',
                guide='https://docs.aws.amazon.com/ec2/index.html'
            ))
        
        # EC2-008: No public IP auto-assignment
        if config.get('associate_public_ip_address') is True:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.EC2_PUBLIC_IP,
                severity='MEDIUM',
                resource_type='aws_instance',
                resource_name=resource_name,
                message='EC2 instance has public IP auto-assignment enabled',
                guide='https://docs.aws.amazon.com/ec2/index.html'
            ))
        
        # EC2-009: Instance in VPC
        subnet_id = config.get('subnet_id')
        if not subnet_id:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.EC2_SECURITY_GROUPS,
                severity='HIGH',
                resource_type='aws_instance',
                resource_name=resource_name,
                message='EC2 instance not in VPC (using EC2-Classic)',
                guide='https://docs.aws.amazon.com/ec2/index.html'
            ))
        
        # EC2-010: Monitoring enabled
        if not config.get('monitoring'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.EC2_SECURITY_GROUPS,
                severity='MEDIUM',
                resource_type='aws_instance',
                resource_name=resource_name,
                message='EC2 instance does not have detailed monitoring enabled',
                guide='https://docs.aws.amazon.com/ec2/index.html'
            ))
        
        return violations


class EBSChecker(AWSSecurityChecker):
    """Check EBS volume security."""
    
    POLICY_PREFIX = "AWS-SEC-EC2"
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all EBS checks."""
        violations = []
        
        if 'aws_ebs_volume' not in resources:
            return violations
        
        for resource_name, config in resources['aws_ebs_volume'].items():
            violations.extend(self._check_ebs_volume(resource_name, config))
        
        return violations
    
    def _check_ebs_volume(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual EBS volume."""
        violations = []
        
        # EC2-007: EBS encryption enabled
        if not config.get('encrypted'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.EC2_SECURITY_GROUPS,
                severity='HIGH',
                resource_type='aws_ebs_volume',
                resource_name=resource_name,
                message='EBS volume is not encrypted',
                guide='https://docs.aws.amazon.com/ec2/index.html'
            ))
        
        return violations
