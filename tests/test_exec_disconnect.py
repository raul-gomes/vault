"""Cleanup when the client disconnects before the stream is consumed (B4)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import anyio
import pytest
from sqlalchemy import select
from starlette.requests import ClientDisconnect

from envvault.models import AuditEntry, Project
from envvault.services import runner
from tests.conftest import ApiClient

PROCESS_EXIT_WAIT_SECONDS = 5


def _spawn_sleeper(app, project: dict[str, Any]) -> tuple[runner.ExecRecord, Any]:  # type: ignore[no-untyped-def]
    """Start a long-running child through the real runner."""
    state = app.state.runtime
    with app.state.session_factory() as db:
        row = db.get(Project, project["id"])
        assert row is not None
        exec_id = state.reserve_exec_slot()
        record, redactor = runner.spawn(
            state,
            exec_id=exec_id,
            project=row,
            environment="dev",
            secrets={},
            command=["sleep", "30"],
            cwd=Path(row.path),
            actor_type="user",
            actor_name="user",
        )
    response = runner.exec_response(app.state.session_factory, state, record, redactor)
    return record, response


def _actions(app) -> list[str]:  # type: ignore[no-untyped-def]
    with app.state.session_factory() as db:
        return [
            entry.action
            for entry in db.scalars(select(AuditEntry).order_by(AuditEntry.id)).all()
            if entry.action.startswith("exec.")
        ]


def _assert_cleaned_up(app, record: runner.ExecRecord) -> None:  # type: ignore[no-untyped-def]
    assert record.process.wait(timeout=PROCESS_EXIT_WAIT_SECONDS) is not None
    assert app.state.runtime.execs == {}
    assert app.state.runtime.reserved_exec_slots == 0
    assert _actions(app) == ["exec.cancel"]


async def _disconnected_receive() -> dict[str, Any]:
    return {"type": "http.disconnect"}


async def _discard(message: dict[str, Any]) -> None:
    return None


async def _broken_send(message: dict[str, Any]) -> None:
    raise OSError("client went away")


def test_disconnect_before_first_byte_cleans_up(
    app, auth: ApiClient, project: dict[str, Any]
) -> None:
    record, response = _spawn_sleeper(app, project)
    scope = {"type": "http", "asgi": {"spec_version": "2.3"}}

    anyio.run(response, scope, _disconnected_receive, _discard)

    _assert_cleaned_up(app, record)


def test_send_failure_before_first_byte_cleans_up(
    app, auth: ApiClient, project: dict[str, Any]
) -> None:
    record, response = _spawn_sleeper(app, project)
    scope = {"type": "http", "asgi": {"spec_version": "2.4"}}

    with pytest.raises(ClientDisconnect):
        anyio.run(response, scope, _disconnected_receive, _broken_send)

    _assert_cleaned_up(app, record)


def test_completed_stream_is_audited_once(
    auth: ApiClient, app, project: dict[str, Any], secret: dict[str, Any]
) -> None:
    response = auth.post(
        "/v1/exec",
        json={"project_id": project["id"], "environment": "dev", "command": ["true"]},
    )
    assert response.status_code == 200
    assert _actions(app) == ["exec.start", "exec.finish"]
