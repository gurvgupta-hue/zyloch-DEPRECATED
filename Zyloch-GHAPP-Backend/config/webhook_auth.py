"""GitHub webhook signature validation.

Lives beside `config/s2s_auth.py` — the two are the service's only inbound
authentication primitives. Kept out of `main.py` so it can be unit tested without
importing the full scanner dependency stack.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os

from starlette.requests import Request

ENV_WEBHOOK_SECRET = "GITHUB_WEBHOOK_SECRET"
HEADER_SIGNATURE = "X-Hub-Signature-256"

logger = logging.getLogger(__name__)


def get_webhook_secret() -> str:
    return os.getenv(ENV_WEBHOOK_SECRET, "").strip()


def expected_signature(payload: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify_github_webhook(request: Request, payload: bytes) -> bool:
    """Verify GitHub's HMAC signature over the raw request body.

    FAILS CLOSED (MT-04.1). This previously returned True when
    GITHUB_WEBHOOK_SECRET was unset, which turned a misconfigured deployment into
    an open endpoint: anyone could POST any installation_id and trigger scans in
    that tenant, burning its monthly quota.

    `/webhook/github` is one of the few routes exempt from the service-key check
    precisely because this signature is its authentication — so it must never
    degrade to "allow".
    """
    secret = get_webhook_secret()
    if not secret:
        logger.error(
            "%s is not configured — rejecting webhook. Set it to the secret "
            "configured on the GitHub App.",
            ENV_WEBHOOK_SECRET,
        )
        return False

    signature = request.headers.get(HEADER_SIGNATURE)
    if not signature:
        return False

    return hmac.compare_digest(signature, expected_signature(payload, secret))
