from typing import List
from scanner_core.models.violation import GCPPolicyViolation
from scanner_core.constants.gcp_policy_ids import GCPPolicyIDs


class VmSerialPortNotEnabledChecker:
    """Checker for VM Serial Port Not Enabled security policy (GCP-SEC-007)"""
    
    POLICY_ID = GCPPolicyIDs.VM_SERIAL_PORT_NOT_ENABLED
    
    def check(self, resources: dict) -> List[GCPPolicyViolation]:
        """
        Validate that serial port access is not enabled on compute instances and project metadata.
        
        Args:
            resources: Dictionary of GCP resources
            
        Returns:
            List of violations found
        """
        violations = []
        
        # Check google_compute_instance resources
        if "google_compute_instance" in resources:
            for resource_name, resource in resources["google_compute_instance"].items():
                metadata = resource.get("metadata", {})
                if self._is_serial_port_enabled(metadata):
                    violations.append(
                        GCPPolicyViolation(
                            policy_id=self.POLICY_ID,
                            severity="High",
                            resource_name=resource_name,
                            resource_type="google_compute_instance",
                            message="Attribute 'metadata.serial-port-enable' must not be defined or set to 'false'.",
                            guide="https://myguide.com"
                        )
                    )
        
        # Check google_compute_project_metadata resources
        if "google_compute_project_metadata" in resources:
            for resource_name, resource in resources["google_compute_project_metadata"].items():
                metadata = resource.get("metadata", {})
                if self._is_serial_port_enabled(metadata):
                    violations.append(
                        GCPPolicyViolation(
                            policy_id=self.POLICY_ID,
                            severity="High",
                            resource_name=resource_name,
                            resource_type="google_compute_project_metadata",
                            message="Attribute 'metadata.serial-port-enable' must not be defined or set to 'false'.",
                            guide="https://myguide.com"
                        )
                    )
        
        # Check google_compute_project_metadata_item resources
        if "google_compute_project_metadata_item" in resources:
            for resource_name, resource in resources["google_compute_project_metadata_item"].items():
                key = resource.get("key")
                value = resource.get("value")
                if key == "serial-port-enable" and self._is_true(value):
                    violations.append(
                        GCPPolicyViolation(
                            policy_id=self.POLICY_ID,
                            severity="High",
                            resource_name=resource_name,
                            resource_type="google_compute_project_metadata_item",
                            message="Attribute 'serial-port-enable' must not be defined or set to 'false'.",
                            guide="https://myguide.com"
                        )
                    )
        
        return violations
    
    def _is_serial_port_enabled(self, metadata) -> bool:
        """Check if serial-port-enable is set to true.
        In tfplan.json, metadata may be None when no metadata is set."""
        if metadata is None:
            return False
        serial_enabled = metadata.get("serial-port-enable", "undefined")
        return self._is_true(serial_enabled)
    
    def _is_true(self, value) -> bool:
        """Check if value is True (boolean or string "true")"""
        if isinstance(value, bool):
            return value is True
        if isinstance(value, str):
            return value.lower() == "true"
        return False
