import strawberry
from typing import Optional, List
from pymongo.database import Database
from strawberry.types import Info
from graphql_api.types.scan import Scan
from graphql_api.types.organization import Organization, Repository
from graphql_api.types.common import ScanStatus, ScannerType, Severity, ScanSortField, SortOrder
from graphql_api.types.finding import Finding
from graphql_api.tenant_scope import require_tenant_id, with_tenant_filter


@strawberry.type
class Query:
    @strawberry.field
    async def scan(self, info: Info, scan_id: str) -> Optional[Scan]:
        tenant_id = require_tenant_id(info)
        db: Database = info.context["db"]
        scan_doc = db.scan_summary.find_one(
            with_tenant_filter({"scan_id": scan_id}, tenant_id)
        )
        if not scan_doc:
            return None
        return Scan.from_dict(scan_doc, db)

    @strawberry.field
    async def scans(
        self,
        info: Info,
        organization: Optional[str] = None,
        repository: Optional[str] = None,
        branch: Optional[str] = None,
        status: Optional[ScanStatus] = None,
        limit: int = 50,
        offset: int = 0,
        sort_by: ScanSortField = ScanSortField.CREATED_AT,
        sort_order: SortOrder = SortOrder.DESC
    ) -> List[Scan]:
        tenant_id = require_tenant_id(info)
        db: Database = info.context["db"]

        query = {}
        if organization:
            query["scan_metadata.organization"] = organization
        if repository:
            query["scan_metadata.repository"] = repository
        if branch:
            query["scan_metadata.branch"] = branch
        if status:
            query["scan_status"] = status.value
        else:
            query["scan_status"] = "completed"

        scoped = with_tenant_filter(query, tenant_id)

        sort_field_map = {
            ScanSortField.CREATED_AT: "created_at",
            ScanSortField.COMPLETED_AT: "completed_at",
        }
        sort_field = sort_field_map.get(sort_by, "created_at")

        cursor = db.scan_summary.find(scoped).sort(sort_field, sort_order.value).skip(offset).limit(limit)

        scans = []
        for doc in cursor:
            scans.append(Scan.from_dict(doc, db))
        return scans

    @strawberry.field
    async def latest_scan(
        self,
        info: Info,
        organization: str,
        repository: str,
        branch: str
    ) -> Optional[Scan]:
        tenant_id = require_tenant_id(info)
        db: Database = info.context["db"]
        scan_doc = db.scan_summary.find_one(
            with_tenant_filter(
                {
                    "scan_metadata.organization": organization,
                    "scan_metadata.repository": repository,
                    "scan_metadata.branch": branch,
                    "scan_status": "completed",
                },
                tenant_id,
            ),
            sort=[("created_at", -1)]
        )
        if not scan_doc:
            return None
        return Scan.from_dict(scan_doc, db)

    @strawberry.field
    async def organizations(self, info: Info) -> List[Organization]:
        tenant_id = require_tenant_id(info)
        db: Database = info.context["db"]
        org_names = db.scan_summary.distinct(
            "scan_metadata.organization",
            with_tenant_filter({}, tenant_id),
        )
        return [
            Organization(name=name, _db=db, _tenant_id=tenant_id)
            for name in org_names
        ]

    @strawberry.field
    async def organization(self, info: Info, name: str) -> Optional[Organization]:
        tenant_id = require_tenant_id(info)
        db: Database = info.context["db"]
        exists = db.scan_summary.find_one(
            with_tenant_filter({"scan_metadata.organization": name}, tenant_id)
        )
        if not exists:
            return None
        return Organization(name=name, _db=db, _tenant_id=tenant_id)

    @strawberry.field
    async def repository(
        self,
        info: Info,
        organization: str,
        name: str
    ) -> Optional[Repository]:
        tenant_id = require_tenant_id(info)
        db: Database = info.context["db"]
        exists = db.scan_summary.find_one(
            with_tenant_filter(
                {
                    "scan_metadata.organization": organization,
                    "scan_metadata.repository": name,
                },
                tenant_id,
            )
        )
        if not exists:
            return None
        return Repository(
            name=name,
            organization=organization,
            _db=db,
            _tenant_id=tenant_id,
        )

    @strawberry.field
    async def findings(
        self,
        info: Info,
        scan_id: Optional[str] = None,
        organization: Optional[str] = None,
        repository: Optional[str] = None,
        scanner: Optional[ScannerType] = None,
        severity: Optional[Severity] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Finding]:
        tenant_id = require_tenant_id(info)
        db: Database = info.context["db"]

        scan_query = {}
        if organization:
            scan_query["scan_metadata.organization"] = organization
        if repository:
            scan_query["scan_metadata.repository"] = repository
        if scan_id:
            scan_query["scan_id"] = scan_id

        scan_query["scan_status"] = "completed"
        scoped = with_tenant_filter(scan_query, tenant_id)

        scan_docs = db.scan_summary.find(scoped).limit(10)

        all_findings = []
        scanners_to_check = [scanner.value] if scanner else ["docker", "kubernetes", "workflow", "secret_scanner"]

        for scan_doc in scan_docs:
            current_scan_id = scan_doc.get("scan_id")
            for scanner_type in scanners_to_check:
                collection_name = f"scan_results_{scanner_type}"
                result_doc = db[collection_name].find_one({
                    "scan_id": current_scan_id,
                    "scanner": scanner_type,
                })

                if result_doc:
                    # Defense: skip results that declare a different tenant
                    result_tenant = result_doc.get("tenantId") or (
                        (result_doc.get("scan_metadata") or {}).get("tenantId")
                    )
                    if result_tenant and str(result_tenant) != str(tenant_id):
                        continue

                    findings_data = result_doc.get("findings", [])
                    for f_data in findings_data:
                        finding = Finding.from_dict(f_data)
                        if severity is None or finding.severity == severity:
                            all_findings.append(finding)

        return all_findings[offset:offset + limit]
