"""Helpers for Azure Service Bus policies."""
from scanner_core.core.base import Violation


def build_deny_result(resource, key_path, msg):
    """Return a Violation similar to the Rego helper contract used by servicebus policies."""
    # resource.change.after is used in the Rego helpers; support both shapes
    return Violation("azure_servicebus_helper", msg, resource)
