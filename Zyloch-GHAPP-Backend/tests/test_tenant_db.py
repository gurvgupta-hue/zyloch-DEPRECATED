"""Unit tests for Strategy C tenant DB helpers (no live Mongo required)."""

from config.tenant_db import (
    tenant_db_name,
    filter_scan_types_by_settings,
    get_policy_config,
    SCAN_CONFIG_MAP,
)


def test_tenant_db_name_prefix():
    assert tenant_db_name("674a1b2c3d4e5f6789012345") == "zyloch_tenant_674a1b2c3d4e5f6789012345"


def test_filter_scan_types_honours_tenant_settings():
    scan_types = ["docker", "workflow", "secret_scanner"]
    settings = {"scans": {"iac": False, "workflow": False}}
    filtered = filter_scan_types_by_settings(scan_types, settings)
    assert "docker" not in filtered
    assert "workflow" not in filtered
    assert filtered == ["secret_scanner"]


def test_get_policy_config_normalizes_scanners_shape():
    class FakeCollection:
        def find_one(self, _query):
            return {
                "policies": {
                    "scanners": {
                        "docker": {"enabled": True, "policies": {"DOCKER-001": True}}
                    }
                }
            }

    class FakeDb:
        tenant_settings = FakeCollection()

    cfg = get_policy_config(FakeDb())
    assert "scanners" in cfg
    assert "docker" in cfg["scanners"]


def test_scan_config_map_covers_iac_bundle():
    assert "docker" in SCAN_CONFIG_MAP["iac"]
    assert "terraform_aws" in SCAN_CONFIG_MAP["iac"]


def test_new_scanners_are_tenant_gateable():
    """Scanners main added must be disable-able per tenant.

    filter_scan_types_by_settings only disables what SCAN_CONFIG_MAP names, so a
    scanner missing from the map runs for every tenant regardless of its toggles.
    """
    for key in ("skill-scanner", "cis-agent"):
        assert key in SCAN_CONFIG_MAP, f"{key} is not gateable by tenant settings"

    assert "cloudformation" in SCAN_CONFIG_MAP["iac"]


def test_disabling_iac_also_disables_cloudformation():
    scan_types = ["cloudformation", "docker", "secret_scanner"]
    filtered = filter_scan_types_by_settings(scan_types, {"scans": {"iac": False}})
    assert filtered == ["secret_scanner"]


def test_disabling_skill_scanner_and_cis_agent():
    scan_types = ["skill-scanner", "cis-agent", "sbom"]
    filtered = filter_scan_types_by_settings(
        scan_types, {"scans": {"skill-scanner": False, "cis-agent": False}}
    )
    assert filtered == ["sbom"]


def test_every_gateable_scanner_is_a_supported_scanner():
    """The gating map must not name scanners the service does not index."""
    from config.tenant_db import SUPPORTED_SCANNERS

    mapped = {s for types in SCAN_CONFIG_MAP.values() for s in types}
    # ai-vs-human is a scan mode rather than a scan_results_<name> collection.
    unknown = mapped - set(SUPPORTED_SCANNERS) - {"ai-vs-human"}
    assert not unknown, f"gateable but not in SUPPORTED_SCANNERS: {sorted(unknown)}"
