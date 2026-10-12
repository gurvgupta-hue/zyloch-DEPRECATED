"""Tests for tenantId on scan metadata writes."""

from datetime import datetime

from scanner_core.helpers.output_formatter import ScanOutputFormatter, format_scan_result

TENANT_ID = "674a1b2c3d4e5f6789012345"


def test_create_scan_metadata_includes_tenant_id():
    metadata = ScanOutputFormatter().create_scan_metadata(
        scan_id="scan_1",
        organization="acme",
        repository="api",
        branch="main",
        commit_hash="abc123",
        commit_message="init",
        commit_author="dev",
        scan_type="docker",
        scan_timestamp="2026-07-02T00:00:00",
        commit_date=datetime(2026, 7, 2),
        repository_url="https://github.com/acme/api",
        event_type="push",
        tenant_id=TENANT_ID,
    )

    assert metadata["tenantId"] == TENANT_ID
    assert metadata["organization"] == "acme"


def test_create_scan_metadata_omits_tenant_id_when_not_provided():
    metadata = ScanOutputFormatter().create_scan_metadata(
        scan_id="scan_legacy",
        organization="acme",
        repository="api",
        branch="main",
        commit_hash="abc123",
        commit_message=None,
        commit_author=None,
        scan_type="docker",
        scan_timestamp=None,
        commit_date=None,
        repository_url="https://github.com/acme/api",
        event_type="push",
    )

    assert "tenantId" not in metadata


def test_format_scan_result_sets_top_level_and_metadata_tenant_id():
    metadata = {"scan_id": "scan_1", "organization": "acme"}
    result = format_scan_result(
        scan_id="scan_1",
        scan_status="completed",
        installation_id="12345",
        scan_metadata=metadata,
        scan_results={},
        tenant_id=TENANT_ID,
    )

    assert result["tenantId"] == TENANT_ID
    assert result["scan_metadata"]["tenantId"] == TENANT_ID


def test_format_scan_result_preserves_existing_metadata_tenant_id():
    metadata = {"scan_id": "scan_1", "tenantId": TENANT_ID}
    result = format_scan_result(
        scan_id="scan_1",
        scan_status="completed",
        installation_id="12345",
        scan_metadata=metadata,
        scan_results={},
        tenant_id=TENANT_ID,
    )

    assert result["scan_metadata"]["tenantId"] == TENANT_ID


def test_ensure_tenant_scan_indexes_includes_tenant_scan_id():
    from config.tenant_db import ensure_tenant_scan_indexes, _tenant_indexes_initialized

    created = []

    class FakeCollection:
        def create_index(self, keys, **kwargs):
            created.append((keys, kwargs.get("name")))

    class FakeDb:
        scan_summary = FakeCollection()

        def __getitem__(self, name):
            return FakeCollection()

    _tenant_indexes_initialized.discard("tenant-test")
    ensure_tenant_scan_indexes(FakeDb(), "tenant-test")

    index_names = [name for _, name in created]
    assert "tenant_scan_id_idx" in index_names
    assert "metadata_tenant_scan_id_idx" in index_names
