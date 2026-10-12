import pytest

from scanner_core.policies.common.https_only import check


@pytest.mark.policies
def test_passes_when_https_only_enabled():
    resource = {"values": {"https_only": True}}
    assert check(resource) == []
