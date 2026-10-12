"""
VPC and Network Security Checkers for AWS

Implements comprehensive VPC, subnet, and network security validation policies.
"""

from typing import Dict, List, Any
from scanner_core.models.violation import AWSPolicyViolation
from scanner_core.constants.aws_policy_ids import AWSPolicyIDs
from .base_checker import AWSSecurityChecker


class VPCChecker(AWSSecurityChecker):
    """Check VPC security configurations."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all VPC checks."""
        violations = []
        
        if 'aws_vpc' not in resources:
            return violations
        
        for resource_name, config in resources['aws_vpc'].items():
            violations.extend(self._check_vpc(resource_name, config))
        
        return violations
    
    def _check_vpc(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual VPC."""
        violations = []
        
        # VPC-001: DNS hostnames enabled
        if config.get('enable_dns_hostnames') is not True:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.VPC_DNS_CONFIGURATION,
                severity='MEDIUM',
                resource_type='aws_vpc',
                resource_name=resource_name,
                message='VPC does not have DNS hostnames enabled',
                guide='https://docs.aws.amazon.com/vpc/latest/userguide/vpc-dns.html'
            ))
        
        # VPC-002: DNS support enabled
        if config.get('enable_dns_support') is not True:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.VPC_DNS_CONFIGURATION,
                severity='MEDIUM',
                resource_type='aws_vpc',
                resource_name=resource_name,
                message='VPC does not have DNS support enabled',
                guide='https://docs.aws.amazon.com/vpc/latest/userguide/vpc-dns.html'
            ))
        
        # VPC-003: VPC Flow Logs enabled
        flow_logs = config.get('enable_network_address_usage_metrics')
        if flow_logs is not True:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.VPC_FLOW_LOGS,
                severity='HIGH',
                resource_type='aws_vpc',
                resource_name=resource_name,
                message='VPC does not have Flow Logs enabled for traffic monitoring',
                guide='https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html'
            ))
        
        return violations


class SubnetChecker(AWSSecurityChecker):
    """Check subnet security configurations."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all subnet checks."""
        violations = []
        
        if 'aws_subnet' not in resources:
            return violations
        
        for resource_name, config in resources['aws_subnet'].items():
            violations.extend(self._check_subnet(resource_name, config))
        
        return violations
    
    def _check_subnet(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual subnet."""
        violations = []
        
        # VPC-004: Public subnet has public IP auto-assignment disabled
        map_public_ip = config.get('map_public_ip_on_launch')
        availability_zone = config.get('availability_zone', '')
        
        if map_public_ip is True:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.SUBNET_PUBLIC_IP_AUTO_ASSIGN,
                severity='MEDIUM',
                resource_type='aws_subnet',
                resource_name=resource_name,
                message='Subnet has map_public_ip_on_launch enabled',
                guide='https://docs.aws.amazon.com/vpc/latest/userguide/vpc-ip-addressing.html'
            ))
        
        # VPC-005: Subnet has availability zone specified
        if not availability_zone:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.SUBNET_AVAILABILITY_ZONE,
                severity='LOW',
                resource_type='aws_subnet',
                resource_name=resource_name,
                message='Subnet does not have explicit availability zone specified',
                guide='https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Subnets.html'
            ))
        
        return violations


class NetworkACLChecker(AWSSecurityChecker):
    """Check network ACL security configurations."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all network ACL checks."""
        violations = []
        
        if 'aws_network_acl' in resources:
            for resource_name, config in resources['aws_network_acl'].items():
                violations.extend(self._check_nacl(resource_name, config))
        
        if 'aws_network_acl_rule' in resources:
            for resource_name, config in resources['aws_network_acl_rule'].items():
                violations.extend(self._check_nacl_rule(resource_name, config))
        
        return violations
    
    def _check_nacl(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual network ACL."""
        violations = []
        
        ingress_rules = config.get('ingress', [])
        egress_rules = config.get('egress', [])
        
        # VPC-006: No allow-all ingress in NACL
        for rule in ingress_rules:
            if rule.get('action') == 'allow':
                cidr_block = rule.get('cidr_block', '')
                protocol = rule.get('protocol', '')
                
                if cidr_block in ['0.0.0.0/0', '::/0'] and protocol == '-1':
                    violations.append(AWSPolicyViolation(
                        policy_id=AWSPolicyIDs.NACL_ALLOW_ALL_INGRESS,
                        severity='MEDIUM',
                        resource_type='aws_network_acl',
                        resource_name=resource_name,
                        message='Network ACL allows all ingress traffic',
                        guide='https://docs.aws.amazon.com/vpc/latest/userguide/VPC_ACLs.html'
                    ))
                    break
        
        # VPC-007: Ensure explicit deny rules
        has_deny_rule = any(rule.get('action') == 'deny' for rule in ingress_rules + egress_rules)
        if not has_deny_rule:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.NACL_EXPLICIT_DENY,
                severity='LOW',
                resource_type='aws_network_acl',
                resource_name=resource_name,
                message='Network ACL does not have explicit deny rules',
                guide='https://docs.aws.amazon.com/vpc/latest/userguide/VPC_ACLs.html'
            ))
        
        return violations
    
    def _check_nacl_rule(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual network ACL rule."""
        violations = []
        
        # VPC-008: NACL rule numbering for clarity
        rule_number = config.get('rule_number')
        if not rule_number or rule_number == 32767:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.NACL_RULE_NUMBER,
                severity='LOW',
                resource_type='aws_network_acl_rule',
                resource_name=resource_name,
                message='Network ACL rule has default or missing rule number',
                guide='https://docs.aws.amazon.com/vpc/latest/userguide/VPC_ACLs.html'
            ))
        
        return violations


class RouteTableChecker(AWSSecurityChecker):
    """Check route table security configurations."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all route table checks."""
        violations = []
        
        if 'aws_route_table' in resources:
            for resource_name, config in resources['aws_route_table'].items():
                violations.extend(self._check_route_table(resource_name, config))
        
        if 'aws_route' in resources:
            for resource_name, config in resources['aws_route'].items():
                violations.extend(self._check_route(resource_name, config))
        
        return violations
    
    def _check_route_table(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual route table."""
        violations = []
        
        routes = config.get('route', [])
        
        # VPC-009: Route table tags for organization
        tags = config.get('tags') or {}
        if not tags.get('Name'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.ROUTE_TABLE_TAGS,
                severity='LOW',
                resource_type='aws_route_table',
                resource_name=resource_name,
                message='Route table missing Name tag',
                guide='https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Route_Tables.html'
            ))
        
        # VPC-010: No unnecessary default routes
        default_routes = [r for r in routes if r.get('destination_cidr_block') in ['0.0.0.0/0', '::/0']]
        if len(default_routes) > 1:
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.ROUTE_TABLE_DEFAULT_ROUTES,
                severity='MEDIUM',
                resource_type='aws_route_table',
                resource_name=resource_name,
                message='Route table has multiple default routes',
                guide='https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Route_Tables.html'
            ))
        
        return violations
    
    def _check_route(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual route."""
        violations = []
        
        destination_cidr = config.get('destination_cidr_block', '')
        
        # VPC-011: Route destination validation
        if destination_cidr and destination_cidr == '0.0.0.0/0':
            if not config.get('nat_gateway_id') and not config.get('internet_gateway_id') and \
               not config.get('instance_id') and not config.get('network_interface_id'):
                violations.append(AWSPolicyViolation(
                    policy_id=AWSPolicyIDs.ROUTE_DEFAULT_DESTINATION,
                    severity='HIGH',
                    resource_type='aws_route',
                    resource_name=resource_name,
                    message='Default route (0.0.0.0/0) missing target',
                    guide='https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Route_Tables.html'
                ))
        
        return violations


class VPCPeeringChecker(AWSSecurityChecker):
    """Check VPC peering security configurations."""
    
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """Execute all VPC peering checks."""
        violations = []
        
        if 'aws_vpc_peering_connection' not in resources:
            return violations
        
        for resource_name, config in resources['aws_vpc_peering_connection'].items():
            violations.extend(self._check_peering(resource_name, config))
        
        return violations
    
    def _check_peering(self, resource_name: str, config: Dict) -> List[AWSPolicyViolation]:
        """Check individual VPC peering connection."""
        violations = []
        
        # VPC-012: VPC peering has accepter configuration
        accepter = config.get('accepter', [])
        # accepter can be a list of dicts or empty
        accepter_config = accepter[0] if isinstance(accepter, list) and accepter else {}
        
        if not accepter_config or not accepter_config.get('allow_remote_vpc_dns_resolution'):
            violations.append(AWSPolicyViolation(
                policy_id=AWSPolicyIDs.VPC_PEERING_SECURITY,
                severity='LOW',
                resource_type='aws_vpc_peering_connection',
                resource_name=resource_name,
                message='VPC peering does not enable DNS resolution',
                guide='https://docs.aws.amazon.com/vpc/latest/peering/peering-basics.html'
            ))
        
        return violations
