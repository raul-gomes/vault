"""Agent tokens need an explicit command list or an explicit any-command (S2, ADR 0003)."""

from __future__ import annotations

from typing import Any

from sqlalchemy import update

from envvault.models import ApiToken
from tests.conftest import ApiClient


def _create(auth: ApiClient, project: dict, **overrides: Any):  # type: ignore[no-untyped-def]
    body = {
        "name": "t",
        "project_id": project["id"],
        "environments": ["dev"],
        "can_list": True,
        "can_inject": True,
        "allowed_commands": [],
        **overrides,
    }
    return auth.post("/v1/tokens", json=body)


def test_inject_token_without_commands_is_rejected(auth: ApiClient, project: dict) -> None:
    response = _create(auth, project)
    assert response.status_code == 400
    assert "command" in response.json()["detail"]


def test_list_only_token_needs_no_commands(auth: ApiClient, project: dict) -> None:
    response = _create(auth, project, can_inject=False)
    assert response.status_code == 201, response.text
    assert response.json()["item"]["any_command"] is False


def test_any_command_must_be_explicit_and_is_exposed(auth: ApiClient, project: dict) -> None:
    response = _create(auth, project, any_command=True)
    assert response.status_code == 201, response.text
    assert response.json()["item"]["any_command"] is True


def test_any_command_and_a_list_together_are_rejected(auth: ApiClient, project: dict) -> None:
    response = _create(auth, project, any_command=True, allowed_commands=["pytest"])
    assert response.status_code == 400


def test_any_command_token_runs_any_argv(auth: ApiClient, project: dict) -> None:
    token = _create(auth, project, any_command=True).json()["token"]
    response = auth.client.post(
        "/v1/agent/exec",
        headers={"authorization": f"Bearer {token}"},
        json={"environment": "dev", "command": ["python3", "-c", "print(1)"]},
    )
    assert response.status_code == 200


def test_legacy_token_without_list_is_rejected_until_recreated(
    app, auth: ApiClient, project: dict
) -> None:
    created = _create(auth, project, allowed_commands=["echo"]).json()
    with app.state.session_factory() as db:
        db.execute(
            update(ApiToken)
            .where(ApiToken.id == created["item"]["id"])
            .values(allowed_commands="[]", any_command=False)
        )
        db.commit()
    response = auth.client.post(
        "/v1/agent/exec",
        headers={"authorization": f"Bearer {created['token']}"},
        json={"environment": "dev", "command": ["echo", "hi"]},
    )
    assert response.status_code == 403
    assert "recreate" in response.json()["detail"]


def test_cli_token_create_requires_allow_or_any_command() -> None:
    from typer.testing import CliRunner

    from envvault.cli import app as cli_app

    result = CliRunner().invoke(cli_app, ["token", "create", "-n", "t", "-p", "sample"])
    assert result.exit_code != 0
    assert "--allow" in result.output

    both = CliRunner().invoke(
        cli_app, ["token", "create", "-n", "t", "-p", "s", "--allow", "pytest", "--any-command"]
    )
    assert both.exit_code != 0
