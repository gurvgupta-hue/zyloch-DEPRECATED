"""MT-04.1: the GitHub webhook signature check must fail closed."""

import hashlib
import hmac
from typing import Dict, Optional
from unittest.mock import MagicMock

import pytest

from config.webhook_auth import verify_github_webhook

SECRET = "test-webhook-secret"
PAYLOAD = b'{"action":"created"}'


def _sign(payload: bytes, secret: str = SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def _request(headers: Optional[Dict[str, str]] = None) -> MagicMock:
    request = MagicMock()
    request.headers = headers or {}
    return request


def test_rejects_when_secret_unset(monkeypatch):
    """Previously returned True — a misconfigured deploy became an open endpoint."""
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)
    request = _request({"X-Hub-Signature-256": _sign(PAYLOAD)})
    assert verify_github_webhook(request, PAYLOAD) is False


def test_rejects_when_secret_is_blank(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "   ")
    request = _request({"X-Hub-Signature-256": _sign(PAYLOAD)})
    assert verify_github_webhook(request, PAYLOAD) is False


def test_rejects_missing_signature_header(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", SECRET)
    assert verify_github_webhook(_request(), PAYLOAD) is False


def test_rejects_signature_from_wrong_secret(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", SECRET)
    request = _request({"X-Hub-Signature-256": _sign(PAYLOAD, "attacker-secret")})
    assert verify_github_webhook(request, PAYLOAD) is False


def test_rejects_payload_altered_after_signing(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", SECRET)
    request = _request({"X-Hub-Signature-256": _sign(PAYLOAD)})
    assert verify_github_webhook(request, b'{"action":"deleted"}') is False


def test_accepts_valid_signature(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", SECRET)
    request = _request({"X-Hub-Signature-256": _sign(PAYLOAD)})
    assert verify_github_webhook(request, PAYLOAD) is True


@pytest.mark.parametrize("bogus", ["", "sha256=", "not-a-signature", "sha1=abc"])
def test_rejects_malformed_signatures(monkeypatch, bogus):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", SECRET)
    assert verify_github_webhook(_request({"X-Hub-Signature-256": bogus}), PAYLOAD) is False
