"""The GitHub webhook must keep its deliberate 4xx answers.

A push from an installation with no tenant mapping is an expected case, not a
crash. The handler's catch-all used to swallow its own 404 and answer 500 with a
stack trace, so every push from an unlinked installation looked like a failure.
"""

import pytest
from fastapi.testclient import TestClient

import main

PUSH = {
    "ref": "refs/heads/main",
    "after": "abc123",
    "installation": {"id": 156569970},
    "repository": {
        "name": "zyloch",
        "clone_url": "https://github.com/Secure-Code-dev/zyloch.git",
        "owner": {"login": "Secure-Code-dev"},
    },
}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(main, "verify_github_webhook", lambda request, payload: True)
    # No context manager: startup hooks (DB connections) are not needed here.
    return TestClient(main.app)


def _post(client, body, event="push"):
    return client.post("/webhook/github", json=body, headers={"X-GitHub-Event": event})


def test_unlinked_installation_is_404_not_500(client, monkeypatch):
    def unlinked(installation_id):
        raise ValueError(f"No tenant mapping for installation_id={installation_id}")

    monkeypatch.setattr(main, "resolve_tenant_db_required", unlinked)

    response = _post(client, PUSH)

    assert response.status_code == 404
    assert "No tenant mapping" in response.json()["detail"]


def test_missing_installation_is_400_not_500(client):
    body = {key: value for key, value in PUSH.items() if key != "installation"}

    response = _post(client, body, event="pull_request")

    assert response.status_code == 400


def test_unexpected_failure_is_still_500(client, monkeypatch):
    def broken(installation_id):
        raise RuntimeError("database unreachable")

    monkeypatch.setattr(main, "resolve_tenant_db_required", broken)

    response = _post(client, PUSH)

    assert response.status_code == 500
    assert response.json()["detail"] == "Error processing webhook"
