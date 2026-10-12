from typing import Dict, List, Any
from scanner_core.policies.kubernetes.base_checker import BaseSecurityChecker
from scanner_core.models.violation import PolicyViolation
from scanner_core.constants.security_constants import SecurityConstants
from scanner_core.constants.k8s_cve_ids import K8SCVEIDs

class AppArmorChecker(BaseSecurityChecker):
    """ Checks for disallowed App Aromor profile settings in container security contexts """
    SUPPORTED_KINDS = ["Deployment", "DaemonSet", "Pod"]

    def check(self, resources: List[Dict[str, Any]]) -> List[PolicyViolation]:
        """Check AppArmor profiles for all containers"""
        self.violations = []
        for resource in resources:
            if not self.should_check_resource(resource, self.SUPPORTED_KINDS):
                continue
            
            self.check_apparmor_profiles(resource)
        return self.violations
    
    def check_apparmor_profiles(self, resource: Dict[str, Any]) -> None:
        """K8S-SEC-002: Check for disallowed AppArmor profiles"""
    
        kind = resource.get("kind", "")
        if kind not in ["Deployment", "DaemonSet", "Pod"]:
            return
        
        # Check AppArmor annotations at the *pod template* metadata level -
        # this is what actually reaches the running pod. For Deployment/
        # DaemonSet that's spec.template.metadata.annotations; the workload
        # object's own top-level metadata.annotations has no effect on the
        # pod and must not be inspected.
        if kind == "Pod":
            annotations = self.helper.safe_get(resource, "metadata", "annotations", default={})
        else:
            annotations = self.helper.safe_get(
                resource, "spec", "template", "metadata", "annotations", default={}
            )

        if not annotations:
            return
        
        # Find all AppArmor profile annotations
        disallowed_profiles = []
        for annotation_key, annotation_value in annotations.items():
            if annotation_key.startswith("container.apparmor.security.beta.kubernetes.io/"):
                # Check if the profile is disallowed
                # Allowed values: "runtime/default" or anything starting with "localhost/"
                if annotation_value != "runtime/default" and not annotation_value.startswith("localhost/"):
                    disallowed_profiles.append(annotation_value)
        
        if disallowed_profiles:
            # Determine the correct path prefix based on resource kind
            if kind == "Pod":
                key_path = "metadata.annotations[\"container.apparmor.security.beta.kubernetes.io/*\"]"
            else:  # Deployment or DaemonSet
                key_path = "spec.template.metadata.annotations[\"container.apparmor.security.beta.kubernetes.io/*\"]"
            
            self.add_violation(
                cve_id=K8SCVEIDs.APPARMOR_PROFILE_MISSING,
                severity="Medium",
                resource=resource,
                key_path=key_path,
                message=(
                    f"Specifying other AppArmor profiles is disallowed in resource kind {kind}. "
                    f"The annotation 'container.apparmor.security.beta.kubernetes.io' if defined "
                    f"must not be set to anything other than 'runtime/default' or 'localhost/*'."
                )
            )