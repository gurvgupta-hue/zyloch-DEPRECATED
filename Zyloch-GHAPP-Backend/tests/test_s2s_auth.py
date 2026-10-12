"""Tests for GHAPP service-to-service authentication."""

from typing import Dict, Optional
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from config.s2s_auth import (
    HEADER_SERVICE_KEY,
    path_requires_s2s_auth,
    verify_s2s_credential,
)
from middleware.s2s_auth_middleware import S2SAuthMiddleware

TEST_API_KEY = "test-internal-service-key"


def _request(headers: Optional[Dict[str, str]] = None) -> MagicMock:
    request = MagicMock()
    request.headers = headers or {}
    return request


@pytest.mark.parametrize(
    "path,method,expected",
    [
        # Public by design: probes and the service banner.
        ("/health", "GET", False),
        ("/", "GET", False),
        # Authenticated by GitHub HMAC instead of the service key.
        ("/webhook/github", "POST", False),
        # Scan surface — always protected.
        ("/scan", "POST", True),
        ("/scans", "GET", True),
        ("/scans/latest", "GET", True),
        ("/scans/scan_123", "GET", True),
        ("/scans/scan_123/scores", "GET", True),
        ("/scan/graphql", "POST", True),
        # MT-03.1: these leaked cross-tenant org/repo names unauthenticated.
        ("/organizations", "GET", True),
        ("/organizations/acme/repositories", "GET", True),
        # MT-03.2: unauthenticated write to a platform-global catalog.
        ("/scan/policy/catalog", "POST", True),
        # AI autofix (main #363/#376) — protected by default-deny, and additionally
        # tenant-scoped in the handlers. /pr mints a write-scoped GitHub token.
        ("/scans/ai/autofix", "POST", True),
        ("/scans/ai/autofix/pr", "POST", True),
        # MT-03: default-deny — unknown paths are protected, not public.
        ("/some/new/route", "GET", True),
        ("/scanner-internal", "POST", True),
        # Docs are protected unless explicitly opened up.
        ("/docs", "GET", True),
        ("/openapi.json", "GET", True),
    ],
)
def test_path_requires_s2s_auth(path, method, expected):
    assert path_requires_s2s_auth(path, method) is expected


@pytest.mark.parametrize("path", ["/health/", "/", "//"])
def test_public_paths_tolerate_trailing_slash(path):
    assert path_requires_s2s_auth(path, "GET") is False


def test_docs_can_be_opened_for_local_development(monkeypatch):
    monkeypatch.setenv("GHAPP_PUBLIC_DOCS", "true")
    assert path_requires_s2s_auth("/docs", "GET") is False
    assert path_requires_s2s_auth("/openapi.json", "GET") is False
    # Opening docs must not open anything else.
    assert path_requires_s2s_auth("/organizations", "GET") is True


def test_docs_are_protected_by_default(monkeypatch):
    monkeypatch.delenv("GHAPP_PUBLIC_DOCS", raising=False)
    assert path_requires_s2s_auth("/docs", "GET") is True


def test_verify_s2s_credential_accepts_service_key_header(monkeypatch):
    monkeypatch.setenv("GHAPP_S2S_API_KEY", TEST_API_KEY)
    request = _request({HEADER_SERVICE_KEY: TEST_API_KEY})
    assert verify_s2s_credential(request) is True


def test_verify_s2s_credential_accepts_bearer_token(monkeypatch):
    monkeypatch.setenv("GHAPP_S2S_API_KEY", TEST_API_KEY)
    request = _request({"Authorization": f"Bearer {TEST_API_KEY}"})
    assert verify_s2s_credential(request) is True


def test_verify_s2s_credential_rejects_missing_key(monkeypatch):
    monkeypatch.setenv("GHAPP_S2S_API_KEY", TEST_API_KEY)
    assert verify_s2s_credential(_request()) is False


def test_verify_s2s_credential_rejects_invalid_key(monkeypatch):
    monkeypatch.setenv("GHAPP_S2S_API_KEY", TEST_API_KEY)
    request = _request({HEADER_SERVICE_KEY: "wrong-key"})
    assert verify_s2s_credential(request) is False


def test_verify_s2s_credential_fails_closed_when_env_unset(monkeypatch):
    monkeypatch.delenv("GHAPP_S2S_API_KEY", raising=False)
    request = _request({HEADER_SERVICE_KEY: TEST_API_KEY})
    assert verify_s2s_credential(request) is False


def _build_test_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(S2SAuthMiddleware)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/scan")
    def scan():
        return {"accepted": True}

    @app.get("/scans")
    def scans():
        return []

    @app.get("/organizations")
    def organizations():
        return []

    @app.post("/scan/policy/catalog")
    def policy_catalog():
        return {"added": []}

    return app


@pytest.fixture
def s2s_client(monkeypatch):
    monkeypatch.setenv("GHAPP_S2S_API_KEY", TEST_API_KEY)
    return TestClient(_build_test_app())


def test_health_endpoint_is_public(s2s_client):
    response = s2s_client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_scan_endpoints_require_credential(s2s_client):
    assert s2s_client.post("/scan", json={"org_name": "acme"}).status_code == 401
    assert s2s_client.get("/scans").status_code == 401


def test_scan_endpoints_accept_valid_credential(s2s_client):
    headers = {HEADER_SERVICE_KEY: TEST_API_KEY}

    scan_response = s2s_client.post(
        "/scan",
        json={"org_name": "acme"},
        headers=headers,
    )
    assert scan_response.status_code == 200

    scans_response = s2s_client.get("/scans", headers=headers)
    assert scans_response.status_code == 200


def test_organizations_route_requires_credential(s2s_client):
    """MT-03.1: previously public, leaked another tenant's org/repo names."""
    assert s2s_client.get("/organizations").status_code == 401
    assert (
        s2s_client.get("/organizations", headers={HEADER_SERVICE_KEY: TEST_API_KEY}).status_code
        == 200
    )


def test_policy_catalog_write_requires_credential(s2s_client):
    """MT-03.2: unauthenticated write to a platform-global catalog."""
    assert s2s_client.post("/scan/policy/catalog", json=[]).status_code == 401
    assert (
        s2s_client.post(
            "/scan/policy/catalog", json=[], headers={HEADER_SERVICE_KEY: TEST_API_KEY}
        ).status_code
        == 200
    )


def test_unknown_routes_are_denied_by_default(s2s_client):
    """MT-03: a route added tomorrow is protected without anyone remembering to."""
    assert s2s_client.get("/not-a-real-route").status_code == 401
