"""Session execution and audit integrity tests."""

from __future__ import annotations

from sqlalchemy import select

from envvault.models import AuditEntry
from tests.conftest import SECRET_VALUE, ApiClient, sse_events


def test_session_exec_injects_and_redacts(auth: ApiClient, project: dict, secret: dict) -> None:
    response = auth.post(
        "/v1/exec",
        json={
            "project_id": project["id"],
            "environment": "dev",
            "command": ["python3", "-c", "import os;print(os.environ['SECRET_KEY'])"],
        },
    )
    assert response.status_code == 200
    events = sse_events(response.text)
    output = "".join(event.get("text", "") for event in events if event["type"] == "output")
    assert "[REDACTED:SECRET_KEY]" in output
    assert SECRET_VALUE not in response.text
    assert events[-1]["code"] == 0


def test_session_exec_propagates_exit_code(auth: ApiClient, project: dict, secret: dict) -> None:
    response = auth.post(
        "/v1/exec",
        json={
            "project_id": project["id"],
            "environment": "dev",
            "command": ["python3", "-c", "import sys;sys.exit(7)"],
        },
    )
    events = sse_events(response.text)
    assert events[-1]["code"] == 7


def test_session_exec_rejects_cwd_outside_project(
    auth: ApiClient, project: dict, secret: dict
) -> None:
    response = auth.post(
        "/v1/exec",
        json={
            "project_id": project["id"],
            "environment": "dev",
            "command": ["echo", "hi"],
            "cwd": "/tmp",
        },
    )
    assert response.status_code == 400


def test_audit_chain_is_valid_and_tamper_evident(
    auth: ApiClient, project: dict, secret: dict, app
) -> None:
    auth.post(
        f"/v1/projects/{project['id']}/secrets/SECRET_KEY/reveal",
        json={"environment": "dev", "passphrase": "correct horse battery staple"},
    )
    assert auth.get("/v1/audit/verify").json() == {"valid": True, "first_bad_id": None}

    with app.state.session_factory() as db:
        entry = db.scalars(select(AuditEntry).order_by(AuditEntry.id.asc())).first()
        assert entry is not None
        entry.detail = '{"tampered":true}'
        db.commit()

    result = auth.get("/v1/audit/verify").json()
    assert result["valid"] is False
    assert result["first_bad_id"] is not None


def test_audit_never_contains_secret_values(auth: ApiClient, project: dict, secret: dict) -> None:
    text = auth.get("/v1/audit").text
    assert SECRET_VALUE not in text
    entries = auth.get("/v1/audit").json()["items"]
    assert any(entry["action"] == "secret.create" for entry in entries)
    assert all(entry["key_names"] == ["SECRET_KEY"] for entry in entries if entry["key_names"])
