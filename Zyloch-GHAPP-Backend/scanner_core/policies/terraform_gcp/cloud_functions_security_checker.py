"""
Cloud Functions Security Policy Checker

Validates Cloud Functions (Gen 1) configurations against security policies:
- Policy 1 (GCP-SEC-020): Cloud Functions must NOT be publicly accessible
- Policy 2 (GCP-SEC-021): Cloud Functions must define VPC connector
"""

from typing import List, Dict, Any
from scanner_core.models.violation import GCPPolicyViolation
from scanner_core.constants.gcp_policy_ids import GCPPolicyIDs


class CloudFunctionsSecurityChecker:
    """Checker for Cloud Functions security policies"""
    
    POLICY_ID_NOT_PUBLIC = GCPPolicyIDs.CLOUD_FUNCTIONS_NOT_PUBLIC
    POLICY_ID_VPC_CONNECTOR = GCPPolicyIDs.CLOUD_FUNCTIONS_VPC_CONNECTOR
    
    def check(self, resources: Dict[str, Any]) -> List[GCPPolicyViolation]:
        """
        Validate Cloud Functions security policies:
        1. Functions must NOT be publicly accessible (no allUsers/allAuthenticatedUsers)
        2. Functions must define vpc_connector
        
        Args:
            resources: Dictionary of GCP resources from tfplan.json
            
        Returns:
            List of GCPPolicyViolation objects for any violations found
        """
        violations = []
        
        # Check google_cloudfunctions_function resources
        if "google_cloudfunctions_function" not in resources:
            return violations
        
        functions = resources["google_cloudfunctions_function"]
        
        for function_name, function_config in functions.items():
            # Check Policy 2: VPC Connector must be defined
            vpc_connector_violations = self._check_vpc_connector(function_name, function_config)
            violations.extend(vpc_connector_violations)
        
        # Check google_cloudfunctions_function_iam_member resources
        if "google_cloudfunctions_function_iam_member" in resources:
            iam_violations = self._check_iam_bindings(resources["google_cloudfunctions_function_iam_member"])
            violations.extend(iam_violations)
        
        # Also check google_cloudfunctions_iam_member (alternative resource name)
        if "google_cloudfunctions_iam_member" in resources:
            iam_violations = self._check_iam_bindings(resources["google_cloudfunctions_iam_member"])
            violations.extend(iam_violations)
        
        return violations
    
    def _check_vpc_connector(self, function_name: str, function_config: Dict[str, Any]) -> List[GCPPolicyViolation]:
        """
        Check if Cloud Function defines vpc_connector (Policy 2: GCP-SEC-021)
        
        Args:
            function_name: Name of the Cloud Function resource
            function_config: Configuration dictionary for the function
            
        Returns:
            List of violations if vpc_connector is not defined
        """
        violations = []
        
        # Check if vpc_connector is defined and not empty
        vpc_connector = function_config.get("vpc_connector")
        
        if not vpc_connector or (isinstance(vpc_connector, list) and len(vpc_connector) == 0):
            violations.append(
                GCPPolicyViolation(
                    policy_id=self.POLICY_ID_VPC_CONNECTOR,
                    severity="High",
                    resource_name=function_name,
                    resource_type="google_cloudfunctions_function",
                    message="Cloud Function must define 'vpc_connector' for network isolation. "
                            "This ensures the function operates within a VPC and cannot directly access the public internet.",
                    guide="https://cloud.google.com/functions/docs/networking/vpc-service-connectors"
                )
            )
        
        return violations
    
    def _check_iam_bindings(self, iam_bindings: Dict[str, Any]) -> List[GCPPolicyViolation]:
        """
        Check if Cloud Function IAM bindings grant public access (Policy 1: GCP-SEC-020)
        
        Args:
            iam_bindings: Dictionary of IAM binding resources
            
        Returns:
            List of violations if public access is found
        """
        violations = []
        
        for binding_name, binding_config in iam_bindings.items():
            # Get the member(s) from the binding
            member = binding_config.get("member")
            members = binding_config.get("members")
            
            # Check single member field
            if member:
                if self._is_public_member(member):
                    violations.append(
                        self._create_public_access_violation(binding_name, member)
                    )
            
            # Check members list
            if members:
                if isinstance(members, list):
                    for m in members:
                        if self._is_public_member(m):
                            violations.append(
                                self._create_public_access_violation(binding_name, m)
                            )
                elif isinstance(members, str):
                    if self._is_public_member(members):
                        violations.append(
                            self._create_public_access_violation(binding_name, members)
                        )
        
        return violations
    
    def _is_public_member(self, member: str) -> bool:
        """
        Check if a member string grants public access
        
        Args:
            member: IAM member string
            
        Returns:
            True if member is allUsers or allAuthenticatedUsers
        """
        if not member:
            return False
        
        member_lower = str(member).lower()
        return "allusers" in member_lower or "allauthenticatedusers" in member_lower
    
    def _create_public_access_violation(self, binding_name: str, member: str) -> GCPPolicyViolation:
        """
        Create a GCPPolicyViolation for public IAM access
        
        Args:
            binding_name: Name of the IAM binding resource
            member: The public member causing the violation
            
        Returns:
            GCPPolicyViolation object
        """
        public_group = "allUsers" if "allUsers" in member else "allAuthenticatedUsers"
        
        return GCPPolicyViolation(
            policy_id=self.POLICY_ID_NOT_PUBLIC,
            severity="Critical",
            resource_name=binding_name,
            resource_type="google_cloudfunctions_function_iam_member",
            message=f"Cloud Function has public access via IAM binding with '{public_group}'. "
                    f"This allows anyone to invoke the function. Restrict access to specific service accounts.",
            guide="https://cloud.google.com/functions/docs/securing/managing-access-iam"
        )
