# ============================================================================
# FILE: utils/k8s_resource_helper.py
# ============================================================================
"""Helper utilities for Kubernetes resource manipulation"""

from typing import Any, Dict, List, Tuple, Optional


class K8sResourceHelper:
    """Utilities for safely accessing Kubernetes resource fields"""
    
    @staticmethod
    def safe_get(obj: Any, *keys: str, default: Any = None) -> Any:
        """
        Safely navigate nested dictionary structure.
        
        Args:
            obj: The object to navigate
            keys: Sequence of keys to navigate
            default: Default value if navigation fails
            
        Returns:
            Value at the nested location or default
            
        Example:
            >>> safe_get({"a": {"b": {"c": 1}}}, "a", "b", "c")
            1
        """
        for key in keys:
            if isinstance(obj, dict):
                obj = obj.get(key)
                if obj is None:
                    return default
            else:
                return default
        return obj if obj is not None else default
    
    @staticmethod
    def get_pod_spec(resource: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract pod specification from various resource types.
        
        Args:
            resource: Kubernetes resource dictionary
            
        Returns:
            Pod spec dictionary
        """
        kind = resource.get("kind", "")
        
        if kind == "Pod":
            return K8sResourceHelper.safe_get(resource, "spec", default={})
        
        # For Deployment, DaemonSet, StatefulSet, ReplicaSet
        return K8sResourceHelper.safe_get(
            resource, "spec", "template", "spec", default={}
        )
    
    @staticmethod
    def get_path_prefix(kind: str) -> str:
        """
        Get JSON path prefix based on resource kind.
        
        Args:
            kind: Kubernetes resource kind
            
        Returns:
            Path prefix string
        """
        return "spec" if kind == "Pod" else "spec.template.spec"
    
    @staticmethod
    def get_resource_name(resource: Dict[str, Any]) -> str:
        """
        Extract resource name from metadata.
        
        Args:
            resource: Kubernetes resource dictionary
            
        Returns:
            Resource name or 'unknown'
        """
        return K8sResourceHelper.safe_get(
            resource, "metadata", "name", default="unknown"
        )
    
    @staticmethod
    def get_resource_namespace(resource: Dict[str, Any]) -> str:
        """
        Extract resource namespace from metadata.
        
        Args:
            resource: Kubernetes resource dictionary
            
        Returns:
            Resource namespace or 'default'
        """
        return K8sResourceHelper.safe_get(
            resource, "metadata", "namespace", default="default"
        )
    
    @staticmethod
    def get_containers(
        pod_spec: Dict[str, Any],
        container_type: Optional[str] = None
    ) -> List[Tuple[str, int, Dict[str, Any]]]:
        """
        Extract all containers from pod spec with metadata.
        
        Args:
            pod_spec: Pod specification dictionary
            container_type: Specific container type to filter (optional)
            
        Returns:
            List of tuples: (container_type, index, container_dict)
        """
        from constants.security_constants import SecurityConstants
        
        results = []
        types_to_check = (
            [container_type] if container_type
            else SecurityConstants.CONTAINER_TYPES
        )
        
        for ctype in types_to_check:
            containers = K8sResourceHelper.safe_get(pod_spec, ctype, default=[])
            for idx, container in enumerate(containers):
                results.append((ctype, idx, container))
        
        return results
    
    @staticmethod
    def is_supported_kind(resource: Dict[str, Any]) -> bool:
        """
        Check if resource kind is supported for validation.
        
        Args:
            resource: Kubernetes resource dictionary
            
        Returns:
            True if kind is supported
        """
        from constants.security_constants import SecurityConstants
        
        kind = resource.get("kind", "")
        return kind in SecurityConstants.SUPPORTED_KINDS

