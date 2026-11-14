"""Concurrent execution limit: rejected requests must never start a process (B3)."""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest
from sqlalchemy import select

from envvault.config import Settings
from envvault.models import AuditEntry
from envvault.runtime import ExecLimitReached, Runtime
from envvault.services import runner
from tests.conftest import ApiClient


@pytest.fixture()
def settings(settings: Settings) -> Settings:
    """Same isolated settings, with no execution slot available."""
    return dataclasses.replace(settings, max_concurrent_execs=0)


@pytest.fixture()
def popen_calls(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """Record Popen calls instead of starting real processes."""
    calls: list[Any] = []

    def fake_popen(*args: Any, **kwargs: Any) -> None:
        calls.append((args, kwargs))
        raise AssertionError("Popen must not be called when the limit is reached")

    monkeypatch.setattr(runner.subprocess, "Popen", fake_popen)
    return calls


def _exec_start_entries(app) -> list[AuditEntry]:  # type: ignore[no-untyped-def]
    with app.state.session_factory() as db:
        return list(db.scalars(select(AuditEntry).where(AuditEntry.action == "exec.start")).all())


def test_session_exec_over_limit_returns_429_without_spawning(
    app, auth: ApiClient, project: dict, secret: dict, popen_calls: list[Any]
) -> None:
    response = auth.post(
        "/v1/exec",
        json={"project_id": project["id"], "environment": "dev", "command": ["echo", "hi"]},
    )
    assert response.status_code == 429
    assert "concurrent" in response.json()["detail"]
    assert popen_calls == []
    assert _exec_start_entries(app) == []


def test_agent_exec_over_limit_returns_429_without_spawning(
    app, auth: ApiClient, agent: dict, secret: dict, popen_calls: list[Any]
) -> None:
    response = auth.client.post(
        "/v1/agent/exec",
        headers=agent["headers"],
        json={"environment": "dev", "command": ["echo", "hi"]},
    )
    assert response.status_code == 429
    assert popen_calls == []
    assert _exec_start_entries(app) == []


def test_reserved_slots_count_towards_the_limit(settings: Settings) -> None:
    state = Runtime(dataclasses.replace(settings, max_concurrent_execs=1))
    slot = state.reserve_exec_slot()
    with pytest.raises(ExecLimitReached):
        state.reserve_exec_slot()
    state.release_exec_slot(slot)
    assert state.reserve_exec_slot()


def test_failed_spawn_releases_its_slot(
    auth: ApiClient, app, project: dict, secret: dict, settings: Settings
) -> None:
    app.state.runtime.settings = dataclasses.replace(settings, max_concurrent_execs=1)
    for _ in range(2):
        response = auth.post(
            "/v1/exec",
            json={
                "project_id": project["id"],
                "environment": "dev",
                "command": ["/nonexistent/binary-for-envvault-test"],
            },
        )
        assert response.status_code == 400
    assert app.state.runtime.reserved_exec_slots == 0
