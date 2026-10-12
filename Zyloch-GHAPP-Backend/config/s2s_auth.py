"""Service-to-service credential validation for internal GHAPP callers."""

from __future__ import annotations

import hmac
import os

from starlette.requests import Request

ENV_API_KEY = "GHAPP_S2S_API_KEY"
HEADER_SERVICE_KEY = "X-Zyloch-Service-Key"

# Unauthenticated by design: liveness/readiness probes and the service banner.
# Neither reads tenant data.
PUBLIC_PATHS = frozenset({"/", "/health"})

# Authenticated by GitHub's HMAC signature instead of the shared service key —
# GitHub is the caller here and cannot hold our internal credential.
# See verify_github_webhook() in main.py.
SIGNATURE_AUTHENTICATED_PATHS = frozenset({"/webhook/github"})

# Interactive API docs. Protected by default: the schema is a map of every
# internal endpoint. Set GHAPP_PUBLIC_DOCS=true in local development to browse
# them without a credential.
DOCS_PATHS = frozenset({"/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"})


def get_expected_api_key() -> str:
    return os.getenv(ENV_API_KEY, "").strip()


def extract_provided_credential(request: Request) -> str:
    service_key = request.headers.get(HEADER_SERVICE_KEY, "").strip()
    if service_key:
        return service_key

    authorization = request.headers.get("Authorization", "").strip()
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return ""


def verify_s2s_credential(request: Request) -> bool:
    expected = get_expected_api_key()
    if not expected:
        return False

    provided = extract_provided_credential(request)
    if not provided:
        return False

    return hmac.compare_digest(provided, expected)


def _docs_are_public() -> bool:
    return os.getenv("GHAPP_PUBLIC_DOCS", "").strip().lower() == "true"


def path_requires_s2s_auth(path: str, method: str) -> bool:
    """Decide whether a request must present the internal service credential.

    DEFAULT-DENY (MT-03): anything not explicitly listed as public requires the
    credential. The previous default-allow form enumerated the protected prefixes
    (``/scan``, ``/scans``, ``/scan/graphql``) and shipped everything else
    unauthenticated — which silently exposed ``GET /organizations``,
    ``GET /organizations/{org}/repositories`` (cross-tenant recon via an
    enumerable installation_id) and other unauthenticated writes to
    platform-global catalogs.

    Under default-deny a newly added route is protected unless someone
    deliberately adds it to a public set, and unknown paths return 401 rather
    than 404, so the route table cannot be enumerated either.

    ``method`` is accepted for interface stability and future per-method rules;
    every currently public path is public for all methods. Pre-flight OPTIONS is
    short-circuited earlier, in the middleware.
    """
    # Normalize a trailing slash so "/health/" cannot be used to slip past the
    # public set into a different branch than the router will resolve.
    normalized = path.rstrip("/") or "/"

    if normalized in PUBLIC_PATHS:
        return False
    if normalized in SIGNATURE_AUTHENTICATED_PATHS:
        return False
    if normalized in DOCS_PATHS and _docs_are_public():
        return False

    return True
