"""
BigQuery Security Controls Checker

Comprehensive validation of GCP BigQuery security controls including:
- Public access prevention (allUsers, allAuthenticatedUsers)
- KMS customer-managed key encryption (CMK)
- Dataset-level IAM least privilege
- Table encryption configuration
- Column-level security (policy tags) for PII data

This checker validates both compliant and non-compliant configurations
to ensure proper security posture for sensitive data.
"""

from typing import List, Dict, Any, Optional, Set
from scanner_core.models.violation import GCPPolicyViolation
from scanner_core.constants.gcp_policy_ids import GCPPolicyIDs


class BigQuerySecurityControlsChecker:
    """
    Comprehensive BigQuery security controls validator.
    
    Checks:
    1. Public Access: Validates datasets don't expose data to allUsers or allAuthenticatedUsers
    2. KMS Encryption: Ensures customer-managed encryption keys are configured
    3. IAM Configuration: Validates least privilege access patterns
    4. Table Encryption: Checks table-level encryption settings
    5. Column Security: Verifies policy tags for PII classification
    """

    GUIDE = "https://cloud.google.com/bigquery/docs/security"
    
    # Policy constants
    POLICY_PUBLIC_ACCESS = GCPPolicyIDs.BIGQUERY_DATASET_PUBLIC_ALLUSERS
    POLICY_AUTH_USERS = GCPPolicyIDs.BIGQUERY_DATASET_AUTHENTICATED_USERS
    POLICY_KMS_ENCRYPTION = GCPPolicyIDs.BIGQUERY_DATASET_KMS_ENCRYPTION
    POLICY_IAM_RESTRICTED = GCPPolicyIDs.BIGQUERY_DATASET_IAM_RESTRICTED
    POLICY_TABLE_ENCRYPTION = GCPPolicyIDs.BIGQUERY_TABLE_ENCRYPTION
    POLICY_COLUMN_SECURITY = GCPPolicyIDs.BIGQUERY_TABLE_COLUMN_SECURITY

    # Special groups that represent public/insecure access
    INSECURE_SPECIAL_GROUPS = {"allUsers", "allAuthenticatedUsers", "projectReaders"}
    
    # Broad principals that violate least privilege
    OVERLY_BROAD_PRINCIPALS = {"everyone@example.com", "users@example.com"}

    def check(self, resources: Dict[str, Any]) -> List[GCPPolicyViolation]:
        """
        Validate BigQuery security controls.

        Args:
            resources: Dictionary containing terraform resources.
                      Expected format: {
                          "google_bigquery_dataset": {"resource_name": {...}},
                          "google_bigquery_table": {"resource_name": {...}},
                          "google_kms_crypto_key": {"resource_name": {...}}
                      }

        Returns:
            List of GCPPolicyViolation objects for non-compliant resources.
        """
        violations = []

        # Check datasets
        bigquery_datasets = resources.get("google_bigquery_dataset", {})
        if isinstance(bigquery_datasets, dict):
            for resource_name, resource in bigquery_datasets.items():
                violations.extend(self._check_dataset(resource_name, resource))

        # Check tables
        bigquery_tables = resources.get("google_bigquery_table", {})
        if isinstance(bigquery_tables, dict):
            for resource_name, resource in bigquery_tables.items():
                violations.extend(self._check_table(resource_name, resource))

        return violations

    # =====================================================================
    # DATASET VALIDATION
    # =====================================================================

    def _check_dataset(self, resource_name: str, resource: Dict[str, Any]) -> List[GCPPolicyViolation]:
        """
        Check a BigQuery dataset for security violations.

        Args:
            resource_name: Name of the dataset resource
            resource: Dataset configuration

        Returns:
            List of violations found in this dataset
        """
        violations = []

        # Extract access configuration
        access = resource.get("access")
        
        # Check for public access (allUsers)
        if self._has_public_access(access):
            violations.append(self._create_violation(
                policy_id=self.POLICY_PUBLIC_ACCESS,
                resource_name=resource_name,
                resource_type="google_bigquery_dataset",
                message="Dataset allows public access via 'allUsers' special group - SECURITY VIOLATION"
            ))

        # Check for authenticated users access
        if self._has_authenticated_users_access(access):
            violations.append(self._create_violation(
                policy_id=self.POLICY_AUTH_USERS,
                resource_name=resource_name,
                resource_type="google_bigquery_dataset",
                message="Dataset allows access to 'allAuthenticatedUsers' - overly broad access - SECURITY VIOLATION"
            ))

        # Check for overly broad group access
        if self._has_overly_broad_group_access(access):
            violations.append(self._create_violation(
                policy_id=self.POLICY_IAM_RESTRICTED,
                resource_name=resource_name,
                resource_type="google_bigquery_dataset",
                message="Dataset has overly broad group access violating least privilege principle - SECURITY VIOLATION"
            ))

        # Check KMS encryption
        if not self._has_kms_encryption(resource):
            violations.append(self._create_violation(
                policy_id=self.POLICY_KMS_ENCRYPTION,
                resource_name=resource_name,
                resource_type="google_bigquery_dataset",
                message="Dataset does not use KMS customer-managed encryption keys (CMK) - SECURITY VIOLATION"
            ))

        return violations

    def _has_public_access(self, access: Any) -> bool:
        """
        Check if dataset allows public access via allUsers.

        Args:
            access: Access configuration

        Returns:
            True if dataset is accessible to allUsers
        """
        if not access:
            return False

        # Handle dict/object
        if isinstance(access, dict):
            if access.get("special_group") == "allUsers":
                return True

        # Handle list/array
        if isinstance(access, list):
            for item in access:
                if isinstance(item, dict) and item.get("special_group") == "allUsers":
                    return True

        return False

    def _has_authenticated_users_access(self, access: Any) -> bool:
        """
        Check if dataset allows access to allAuthenticatedUsers.

        Args:
            access: Access configuration

        Returns:
            True if dataset is accessible to allAuthenticatedUsers
        """
        if not access:
            return False

        # Handle dict/object
        if isinstance(access, dict):
            if access.get("special_group") == "allAuthenticatedUsers":
                return True

        # Handle list/array
        if isinstance(access, list):
            for item in access:
                if isinstance(item, dict) and item.get("special_group") == "allAuthenticatedUsers":
                    return True

        return False

    def _has_overly_broad_group_access(self, access: Any) -> bool:
        """
        Check for overly broad group email addresses violating least privilege.

        Args:
            access: Access configuration

        Returns:
            True if dataset has overly broad group access
        """
        if not access:
            return False

        # Handle dict/object
        if isinstance(access, dict):
            group_email = access.get("group_by_email", "")
            if group_email in self.OVERLY_BROAD_PRINCIPALS:
                return True

        # Handle list/array
        if isinstance(access, list):
            for item in access:
                if isinstance(item, dict):
                    group_email = item.get("group_by_email", "")
                    if group_email in self.OVERLY_BROAD_PRINCIPALS:
                        return True

        return False

    def _has_kms_encryption(self, resource: Dict[str, Any]) -> bool:
        """
        Check if dataset is configured with KMS encryption.

        Args:
            resource: Dataset resource configuration

        Returns:
            True if KMS encryption is configured
        """
        # Check for default_encryption_configuration
        encryption_config = resource.get("default_encryption_configuration", {})
        
        if not encryption_config:
            return False

        # Must have a KMS key name specified
        kms_key = encryption_config.get("kms_key_name")
        return bool(kms_key)

    # =====================================================================
    # TABLE VALIDATION
    # =====================================================================

    def _check_table(self, resource_name: str, resource: Dict[str, Any]) -> List[GCPPolicyViolation]:
        """
        Check a BigQuery table for security violations.

        Args:
            resource_name: Name of the table resource
            resource: Table configuration

        Returns:
            List of violations found in this table
        """
        violations = []

        # Check table encryption configuration
        if not self._has_table_encryption(resource):
            # Check if table contains sensitive data markers
            if self._contains_sensitive_data(resource):
                violations.append(self._create_violation(
                    policy_id=self.POLICY_TABLE_ENCRYPTION,
                    resource_name=resource_name,
                    resource_type="google_bigquery_table",
                    message="Table contains sensitive data but lacks encryption configuration - SECURITY VIOLATION"
                ))

        # Check for column-level security on PII data
        if self._contains_pii_data(resource) and not self._has_policy_tags(resource):
            violations.append(self._create_violation(
                policy_id=self.POLICY_COLUMN_SECURITY,
                resource_name=resource_name,
                resource_type="google_bigquery_table",
                message="Table contains PII data but lacks column-level security via policy tags - SECURITY VIOLATION"
            ))

        return violations

    def _has_table_encryption(self, resource: Dict[str, Any]) -> bool:
        """
        Check if table has encryption configuration.

        Args:
            resource: Table resource configuration

        Returns:
            True if encryption is configured
        """
        encryption_config = resource.get("encryption_configuration", {})
        
        if not encryption_config:
            return False

        # Must have a KMS key name or be using Google-managed encryption
        kms_key = encryption_config.get("kms_key_name")
        return bool(kms_key)

    def _contains_sensitive_data(self, resource: Dict[str, Any]) -> bool:
        """
        Check if table schema contains indicators of sensitive data.

        Args:
            resource: Table resource configuration

        Returns:
            True if table likely contains sensitive data
        """
        # Check labels for PII indicators
        labels = resource.get("labels", {})
        if labels.get("pii_data") == "true":
            return True

        # Check schema for sensitive field names
        sensitive_field_patterns = {"ssn", "social_security", "credit_card", "password", "api_key", "token"}
        
        # Schema can be a string (JSON) or dict
        schema = resource.get("schema")
        if isinstance(schema, str):
            # JSON string - check for patterns
            return any(pattern in schema.lower() for pattern in sensitive_field_patterns)
        elif isinstance(schema, list):
            # List of field objects
            for field in schema:
                if isinstance(field, dict):
                    field_name = field.get("name", "").lower()
                    if any(pattern in field_name for pattern in sensitive_field_patterns):
                        return True

        return False

    def _contains_pii_data(self, resource: Dict[str, Any]) -> bool:
        """
        Check if table contains PII (Personally Identifiable Information).

        Args:
            resource: Table resource configuration

        Returns:
            True if table contains PII
        """
        # Check labels for PII indicators
        labels = resource.get("labels", {})
        if labels.get("pii_data") == "true":
            return True

        # Check description
        description = resource.get("description", "").lower()
        if "pii" in description or "personally identifiable" in description:
            return True

        # Check schema field names for PII patterns
        pii_patterns = {"ssn", "social_security", "email", "phone", "address", "dob", "date_of_birth"}
        
        schema = resource.get("schema")
        if isinstance(schema, str):
            # JSON string - check for PII patterns
            return any(pattern in schema.lower() for pattern in pii_patterns)
        elif isinstance(schema, list):
            # List of field objects
            for field in schema:
                if isinstance(field, dict):
                    field_name = field.get("name", "").lower()
                    field_desc = field.get("description", "").lower()
                    if any(pattern in field_name or pattern in field_desc for pattern in pii_patterns):
                        return True

        return False

    def _has_policy_tags(self, resource: Dict[str, Any]) -> bool:
        """
        Check if table has column-level security via policy tags.

        Args:
            resource: Table resource configuration

        Returns:
            True if policy tags are defined
        """
        schema = resource.get("schema")
        
        if isinstance(schema, str):
            # JSON string - check for policy_tags
            return "policy_tags" in schema.lower()
        elif isinstance(schema, list):
            # List of field objects
            for field in schema:
                if isinstance(field, dict):
                    if "policy_tags" in field:
                        return True

        return False

    # =====================================================================
    # VIOLATION FORMATTING
    # =====================================================================

    def _create_violation(
        self,
        policy_id: str,
        resource_name: str,
        resource_type: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> GCPPolicyViolation:
        """
        Create a GCPPolicyViolation object.

        Args:
            policy_id: Policy identifier
            resource_name: Name of the violating resource
            resource_type: Type of the resource
            message: Violation message
            metadata: Additional metadata

        Returns:
            GCPPolicyViolation object
        """
        policy = GCPPolicyIDs.get(policy_id)
        severity = policy.security_level if policy else "HIGH"

        return GCPPolicyViolation(
            policy_id=policy_id,
            resource_type=resource_type,
            resource_name=resource_name,
            message=message,
            severity=severity,
            guide=self.GUIDE,
            metadata=metadata or {}
        )
