"""GraphQL tenant scoping helpers (KAN-40 / MT-018).

Resolvers must never return scan data without an explicit tenantId from
context (set by BFF via X-Installation-Id / X-Tenant-Id). Filters match both
top-level ``tenantId`` and ``scan_metadata.tenantId`` for defense-in-depth
inside the tenant DB.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from graphql import GraphQLError
from strawberry.types import Info


def require_tenant_id(info: Info) -> str:
    """Return tenantId from GraphQL context or raise a GraphQL error."""
    tenant_id = None
    if isinstance(info.context, dict):
        tenant_id = info.context.get("tenant_id")
        if not tenant_id:
            request = info.context.get("request")
            if request is not None:
                headers = getattr(request, "headers", {}) or {}
                tenant_id = headers.get("X-Tenant-Id") or headers.get("X-Zyloch-Tenant-Id")

    if not tenant_id:
        raise GraphQLError(
            "tenantId is required in GraphQL context (set by BFF via "
            "X-Installation-Id and/or X-Tenant-Id)"
        )
    return str(tenant_id)


def tenant_match_filter(tenant_id: str) -> Dict[str, Any]:
    """Mongo filter that matches documents owned by ``tenant_id``."""
    tid = str(tenant_id)
    return {
        "$or": [
            {"tenantId": tid},
            {"scan_metadata.tenantId": tid},
        ]
    }


def with_tenant_filter(query: Optional[Dict[str, Any]], tenant_id: str) -> Dict[str, Any]:
    """AND an existing query with the tenant ownership filter."""
    tenant_clause = tenant_match_filter(tenant_id)
    if not query:
        return tenant_clause
    return {"$and": [tenant_clause, query]}
