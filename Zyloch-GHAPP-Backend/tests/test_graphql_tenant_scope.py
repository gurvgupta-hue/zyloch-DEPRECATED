"""KAN-40: GraphQL resolvers require tenantId and never leak cross-tenant scans."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest
from graphql import GraphQLError

from graphql_api.tenant_scope import require_tenant_id, tenant_match_filter, with_tenant_filter
from graphql_api.queries.scan_queries import Query


TENANT_A = "674a1b2c3d4e5f6789012345"
TENANT_B = "674a1b2c3d4e5f6789012346"


def _matches_tenant_clause(doc: dict, clause: dict) -> bool:
    """Evaluate the $or tenant ownership filter against a document."""
    ors = clause.get("$or") or []
    for arm in ors:
        if "tenantId" in arm and doc.get("tenantId") == arm["tenantId"]:
            return True
        if "scan_metadata.tenantId" in arm:
            meta = doc.get("scan_metadata") or {}
            if meta.get("tenantId") == arm["scan_metadata.tenantId"]:
                return True
    return False


def _matches_simple(doc: dict, query: dict) -> bool:
    if not query:
        return True
    if "$and" in query:
        return all(_matches_simple(doc, part) for part in query["$and"])
    if "$or" in query and set(query.keys()) == {"$or"}:
        return _matches_tenant_clause(doc, query)

    for key, expected in query.items():
        if key == "$or":
            if not _matches_tenant_clause(doc, {"$or": expected}):
                return False
            continue
        if "." in key:
            parts = key.split(".")
            cur: Any = doc
            for part in parts:
                if not isinstance(cur, dict) or part not in cur:
                    cur = None
                    break
                cur = cur[part]
            if cur != expected:
                return False
        elif doc.get(key) != expected:
            return False
    return True


class FakeCursor:
    def __init__(self, docs: List[dict]):
        self._docs = list(docs)

    def sort(self, *_args, **_kwargs):
        return self

    def skip(self, n: int):
        self._docs = self._docs[n:]
        return self

    def limit(self, n: int):
        self._docs = self._docs[:n]
        return self

    def __iter__(self):
        return iter(self._docs)


class FakeCollection:
    def __init__(self, docs: Optional[List[dict]] = None):
        self.docs = list(docs or [])

    def find_one(self, query=None, sort=None):
        matched = [d for d in self.docs if _matches_simple(d, query or {})]
        if sort:
            field, direction = sort[0]
            matched.sort(key=lambda d: d.get(field) or "", reverse=direction < 0)
        return matched[0] if matched else None

    def find(self, query=None):
        matched = [d for d in self.docs if _matches_simple(d, query or {})]
        return FakeCursor(matched)

    def distinct(self, field: str, query=None):
        matched = [d for d in self.docs if _matches_simple(d, query or {})]
        values = []
        for doc in matched:
            if "." in field:
                parts = field.split(".")
                cur: Any = doc
                for part in parts:
                    cur = cur.get(part) if isinstance(cur, dict) else None
                if cur is not None and cur not in values:
                    values.append(cur)
            elif field in doc and doc[field] not in values:
                values.append(doc[field])
        return values

    def count_documents(self, query=None):
        return len([d for d in self.docs if _matches_simple(d, query or {})])


class FakeDb:
    def __init__(self, scan_docs: List[dict]):
        self.scan_summary = FakeCollection(scan_docs)
        self._extra: Dict[str, FakeCollection] = {}

    def __getitem__(self, name: str) -> FakeCollection:
        if name not in self._extra:
            self._extra[name] = FakeCollection([])
        return self._extra[name]


def _scan(tenant_id: str, scan_id: str, org: str = "acme", repo: str = "api", branch: str = "main"):
    return {
        "scan_id": scan_id,
        "tenantId": tenant_id,
        "scan_status": "completed",
        "created_at": scan_id,
        "scan_metadata": {
            "organization": org,
            "repository": repo,
            "branch": branch,
            "tenantId": tenant_id,
        },
    }


def _info(tenant_id: Optional[str], db: FakeDb):
    return SimpleNamespace(context={"tenant_id": tenant_id, "db": db})


def test_require_tenant_id_errors_without_context():
    info = SimpleNamespace(context={})
    with pytest.raises(GraphQLError, match="tenantId is required"):
        require_tenant_id(info)


def test_require_tenant_id_reads_header_fallback():
    request = SimpleNamespace(headers={"X-Tenant-Id": TENANT_A})
    info = SimpleNamespace(context={"db": None, "request": request})
    assert require_tenant_id(info) == TENANT_A


def test_with_tenant_filter_and_match():
    filt = with_tenant_filter({"scan_id": "s1"}, TENANT_A)
    assert "$and" in filt
    assert tenant_match_filter(TENANT_A) in filt["$and"]


def test_scans_without_tenant_context_errors():
    db = FakeDb([_scan(TENANT_A, "a1"), _scan(TENANT_B, "b1")])
    info = _info(None, db)

    with pytest.raises(GraphQLError, match="tenantId is required"):
        asyncio.run(Query().scans(info=info))


def test_two_tenants_no_scan_list_leakage():
    db = FakeDb([
        _scan(TENANT_A, "a1"),
        _scan(TENANT_A, "a2"),
        _scan(TENANT_B, "b1", org="other-org"),
    ])

    scans_a = asyncio.run(Query().scans(info=_info(TENANT_A, db)))
    scans_b = asyncio.run(Query().scans(info=_info(TENANT_B, db)))

    ids_a = {s.scan_id for s in scans_a}
    ids_b = {s.scan_id for s in scans_b}

    assert ids_a == {"a1", "a2"}
    assert ids_b == {"b1"}
    assert ids_a.isdisjoint(ids_b)


def test_scan_by_id_blocks_cross_tenant():
    db = FakeDb([_scan(TENANT_A, "a1"), _scan(TENANT_B, "b1")])

    own = asyncio.run(Query().scan(info=_info(TENANT_A, db), scan_id="a1"))
    leaked = asyncio.run(Query().scan(info=_info(TENANT_A, db), scan_id="b1"))

    assert own is not None
    assert own.scan_id == "a1"
    assert leaked is None


def test_organizations_only_within_tenant():
    db = FakeDb([
        _scan(TENANT_A, "a1", org="acme"),
        _scan(TENANT_B, "b1", org="beta-corp"),
    ])

    orgs_a = asyncio.run(Query().organizations(info=_info(TENANT_A, db)))
    names = {o.name for o in orgs_a}
    assert names == {"acme"}
    assert all(o._tenant_id == TENANT_A for o in orgs_a)
