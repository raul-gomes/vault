"""Authentication, session and CSRF tests."""

from __future__ import annotations

from fastapi.testclient import TestClient

from envvault.config import Settings
from tests.conftest import PASSPHRASE, ApiClient


def test_health_reports_uninitialized_vault(client: TestClient) -> None:
    payload = client.get("/v1/health").json()
    assert payload["status"] == "ok"
    assert payload["initialized"] is False
    assert payload["unlocked"] is False


def test_login_wrong_passphrase_is_rejected(vault_ready: TestClient) -> None:
    response = vault_ready.post("/v1/auth/login", json={"passphrase": "wrong passphrase"})
    assert response.status_code == 401
    assert response.json()["detail"] == "invalid passphrase"


def test_login_is_rate_limited(vault_ready: TestClient) -> None:
    for _ in range(5):
        response = vault_ready.post("/v1/auth/login", json={"passphrase": "wrong passphrase"})
        assert response.status_code == 401
    response = vault_ready.post("/v1/auth/login", json={"passphrase": "wrong passphrase"})
    assert response.status_code == 429


def test_session_requires_csrf_for_mutations(auth: ApiClient) -> None:
    unauthenticated = auth.client.get("/v1/session").json()
    assert unauthenticated["authenticated"] is True

    without_csrf = auth.client.post(
        "/v1/projects",
        json={"slug": "nocsrf", "name": "No CSRF", "path": "/tmp"},
    )
    assert without_csrf.status_code == 403

    bad_origin = auth.client.post(
        "/v1/projects",
        headers={"x-csrf-token": auth.csrf, "origin": "http://evil.example"},
        json={"slug": "evil", "name": "Evil", "path": "/tmp"},
    )
    assert bad_origin.status_code == 403


def test_login_rejects_cross_site_origin(vault_ready: TestClient) -> None:
    response = vault_ready.post(
        "/v1/auth/login",
        headers={"origin": "http://evil.example"},
        json={"passphrase": PASSPHRASE},
    )
    assert response.status_code == 403


def test_lock_clears_session_and_requires_unlock(auth: ApiClient, project: dict) -> None:
    response = auth.post("/v1/auth/lock")
    assert response.status_code == 200
    assert response.json()["unlocked"] is False
    assert auth.client.get("/v1/session").json()["authenticated"] is False
    assert auth.get(f"/v1/projects/{project['id']}").status_code == 401


def test_change_passphrase(auth: ApiClient) -> None:
    new_passphrase = "nova passphrase bem longa"
    response = auth.post(
        "/v1/auth/passphrase",
        json={"current": PASSPHRASE, "new": new_passphrase},
    )
    assert response.status_code == 200
    auth.post("/v1/auth/lock")

    assert auth.client.post("/v1/auth/login", json={"passphrase": PASSPHRASE}).status_code == 401
    assert (
        auth.client.post("/v1/auth/login", json={"passphrase": new_passphrase}).status_code == 200
    )


def test_session_idle_timeout_locks_vault(
    auth: ApiClient, app, settings: Settings, project: dict
) -> None:
    app.state.runtime.last_activity -= settings.lock_timeout_minutes * 60 + 5
    response = auth.get(f"/v1/projects/{project['id']}")
    assert response.status_code == 423
    assert app.state.runtime.dek is None
