import strawberry
from typing import List, Optional
from .scan import Scan
from pymongo.database import Database
from graphql_api.tenant_scope import with_tenant_filter


@strawberry.type
class Organization:
    name: str
    _db: strawberry.Private[Database] = None
    _tenant_id: strawberry.Private[Optional[str]] = None

    def _scoped(self, query: dict) -> dict:
        if not self._tenant_id:
            raise ValueError("tenantId is required for organization field resolvers")
        return with_tenant_filter(query, self._tenant_id)

    @strawberry.field
    async def repositories(self) -> List[str]:
        repos = self._db.scan_summary.distinct(
            "scan_metadata.repository",
            self._scoped({"scan_metadata.organization": self.name}),
        )
        return repos

    @strawberry.field
    async def scan_count(self) -> int:
        return self._db.scan_summary.count_documents(
            self._scoped({
                "scan_metadata.organization": self.name,
                "scan_status": "completed",
            })
        )

    @strawberry.field
    async def latest_scan(self) -> Optional[Scan]:
        scan_doc = self._db.scan_summary.find_one(
            self._scoped({
                "scan_metadata.organization": self.name,
                "scan_status": "completed",
            }),
            sort=[("created_at", -1)]
        )
        if not scan_doc:
            return None
        return Scan.from_dict(scan_doc, self._db)


@strawberry.type
class Repository:
    name: str
    organization: str
    _db: strawberry.Private[Database] = None
    _tenant_id: strawberry.Private[Optional[str]] = None

    def _scoped(self, query: dict) -> dict:
        if not self._tenant_id:
            raise ValueError("tenantId is required for repository field resolvers")
        return with_tenant_filter(query, self._tenant_id)

    @strawberry.field
    async def branches(self) -> List[str]:
        branches = self._db.scan_summary.distinct(
            "scan_metadata.branch",
            self._scoped({
                "scan_metadata.organization": self.organization,
                "scan_metadata.repository": self.name,
            }),
        )
        return branches

    @strawberry.field
    async def scan_count(self) -> int:
        return self._db.scan_summary.count_documents(
            self._scoped({
                "scan_metadata.organization": self.organization,
                "scan_metadata.repository": self.name,
                "scan_status": "completed",
            })
        )

    @strawberry.field
    async def latest_scan(self) -> Optional[Scan]:
        scan_doc = self._db.scan_summary.find_one(
            self._scoped({
                "scan_metadata.organization": self.organization,
                "scan_metadata.repository": self.name,
                "scan_status": "completed",
            }),
            sort=[("created_at", -1)]
        )
        if not scan_doc:
            return None
        return Scan.from_dict(scan_doc, self._db)

    @strawberry.field
    async def scans(self, limit: int = 50, offset: int = 0) -> List[Scan]:
        cursor = self._db.scan_summary.find(
            self._scoped({
                "scan_metadata.organization": self.organization,
                "scan_metadata.repository": self.name,
                "scan_status": "completed",
            })
        ).sort("created_at", -1).skip(offset).limit(limit)

        scans = []
        for doc in cursor:
            scans.append(Scan.from_dict(doc, self._db))
        return scans
