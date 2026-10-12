from typing import List
from scanner_core.models.violation import GCPPolicyViolation
from scanner_core.constants.gcp_policy_ids import GCPPolicyIDs


class VpcFirewallPreventSshAccessChecker:
    """Checker for VPC Firewall Prevent SSH Access security policy (GCP-SEC-009)"""
    
    POLICY_ID = GCPPolicyIDs.VPC_FIREWALL_PREVENT_SSH_ACCESS
    PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}
    SSH_PORT = 22
    
    def check(self, resources: dict) -> List[GCPPolicyViolation]:
        """
        Validate that firewall rules do not allow SSH access from public networks.
        
        Args:
            resources: Dictionary of GCP resources
            
        Returns:
            List of violations found
        """
        violations = []
        
        if "google_compute_firewall" not in resources:
            return violations
        
        for resource_name, resource in resources["google_compute_firewall"].items():
            # Check if it's an ingress rule (default is INGRESS if direction not specified)
            direction = resource.get("direction", "INGRESS")
            if direction != "INGRESS":
                continue
            
            # Check if source ranges include public CIDRs
            source_ranges = resource.get("source_ranges", [])
            has_public_cidr = any(cidr in self.PUBLIC_CIDRS for cidr in source_ranges)
            
            if not has_public_cidr:
                continue
            
            # Check if allow rules include SSH port
            allow_rules = resource.get("allow", [])
            if not allow_rules:
                continue
            
            # Normalize allow to list
            if isinstance(allow_rules, dict):
                allow_rules = [allow_rules]
            
            for allow_rule in allow_rules:
                if self._allows_ssh(allow_rule):
                    violations.append(
                        GCPPolicyViolation(
                            policy_id=self.POLICY_ID,
                            severity="Critical",
                            resource_name=resource_name,
                            resource_type="google_compute_firewall",
                            message="Attribute 'allow.ports' must not include SSH port '22'.",
                            guide="https://myguide.com"
                        )
                    )
                    break
        
        return violations
    
    def _allows_ssh(self, allow_rule: dict) -> bool:
        """Check if an allow rule permits SSH (port 22)"""
        ports = allow_rule.get("ports", [])
        
        # If no ports specified, protocol is allowed on all ports
        if not ports:
            return False
        
        for port in ports:
            if self._is_ssh_port(port):
                return True
        
        return False
    
    def _is_ssh_port(self, port_spec: str) -> bool:
        """Check if port specification includes SSH port 22"""
        port_spec = str(port_spec).strip()
        
        # Check for port range (e.g., "20-25")
        if "-" in port_spec:
            try:
                bounds = port_spec.split("-")
                low_bound = int(bounds[0].strip())
                high_bound = int(bounds[1].strip())
                return low_bound <= self.SSH_PORT <= high_bound
            except (ValueError, IndexError):
                return False
        else:
            # Single port
            try:
                return int(port_spec) == self.SSH_PORT
            except ValueError:
                return False
