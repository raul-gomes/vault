"""Agent token scope and injection tests."""

from __future__ import annotations

from tests.conftest import SECRET_VALUE, ApiClient, sse_events


def test_agent_context(auth: ApiClient, agent: dict) -> None:
    response = auth.client.get("/v1/agent/context", headers=agent["headers"])
    assert response.status_code == 200
    payload = response.json()
    assert payload["project"]["slug"] == "sample"
    assert payload["environments"] == ["dev"]
    assert payload["can_inject"] is True


def test_agent_can_list_key_names(
    auth: ApiClient, agent: dict, project: dict, secret: dict
) -> None:
    response = auth.client.get(
        "/v1/agent/keys",
        params={"environment": "dev"},
        headers=agent["headers"],
    )
    assert response.status_code == 200
    assert [item["key"] for item in response.json()["items"]] == ["SECRET_KEY"]
    assert SECRET_VALUE not in response.text

    forbidden_env = auth.client.get(
        "/v1/agent/keys",
        params={"environment": "prod"},
        headers=agent["headers"],
    )
    assert forbidden_env.status_code == 403


def test_agent_cannot_use_session_endpoints(auth: ApiClient, agent: dict, project: dict) -> None:
    auth.client.cookies.clear()
    assert auth.client.get("/v1/projects", headers=agent["headers"]).status_code == 401
    reveal = auth.client.post(
        f"/v1/projects/{project['id']}/secrets/SECRET_KEY/reveal",
        headers=agent["headers"],
        json={"environment": "dev", "passphrase": "anything"},
    )
    assert reveal.status_code == 401


def test_agent_exec_redacts_output(
    auth: ApiClient, agent: dict, project: dict, secret: dict
) -> None:
    response = auth.client.post(
        "/v1/agent/exec",
        headers=agent["headers"],
        json={
            "environment": "dev",
            "command": ["python3", "-c", "import os;print('value=' + os.environ['SECRET_KEY'])"],
        },
    )
    assert response.status_code == 200
    events = sse_events(response.text)
    assert events[0]["type"] == "start"
    output = "".join(event.get("text", "") for event in events if event["type"] == "output")
    assert "value=[REDACTED:SECRET_KEY]" in output
    assert SECRET_VALUE not in response.text
    assert events[-1]["type"] == "exit"
    assert events[-1]["code"] == 0


def test_agent_exec_assembles_env_overrides(
    auth: ApiClient, agent: dict, project: dict, secret: dict
) -> None:
    command = [
        "python3",
        "-c",
        "import os;print('port=' + os.environ['PORT']);print('secret=' + os.environ['SECRET_KEY'])",
    ]
    response = auth.client.post(
        "/v1/agent/exec",
        headers=agent["headers"],
        json={
            "environment": "dev",
            "command": command,
            "env": {"PORT": "3001", "NODE_ENV": "development"},
            "timeout_seconds": 30,
        },
    )
    assert response.status_code == 200, response.text
    events = sse_events(response.text)
    assert events[0]["env_keys"] == ["NODE_ENV", "PORT"]
    assert events[0]["timeout_seconds"] == 30
    output = "".join(event.get("text", "") for event in events if event["type"] == "output")
    assert "port=3001" in output
    assert "secret=[REDACTED:SECRET_KEY]" in output
    assert SECRET_VALUE not in response.text
    assert events[-1]["timed_out"] is False

    audit_text = auth.get("/v1/audit").text
    assert "PORT" in audit_text
    assert "3001" not in audit_text


def test_agent_cannot_override_vault_keys(auth: ApiClient, agent: dict, secret: dict) -> None:
    response = auth.client.post(
        "/v1/agent/exec",
        headers=agent["headers"],
        json={
            "environment": "dev",
            "command": ["echo", "hi"],
            "env": {"SECRET_KEY": "shadow"},
        },
    )
    assert response.status_code == 400
    assert "SECRET_KEY" in response.json()["detail"]


def test_agent_rejects_reserved_and_invalid_env_keys(
    auth: ApiClient, agent: dict, secret: dict
) -> None:
    reserved = auth.client.post(
        "/v1/agent/exec",
        headers=agent["headers"],
        json={
            "environment": "dev",
            "command": ["echo", "hi"],
            "env": {"ENVVAULT_HOME": "/tmp"},
        },
    )
    assert reserved.status_code == 400

    invalid = auth.client.post(
        "/v1/agent/exec",
        headers=agent["headers"],
        json={"environment": "dev", "command": ["echo", "hi"], "env": {"bad-key": "x"}},
    )
    assert invalid.status_code == 400


def test_agent_exec_timeout_stops_process(auth: ApiClient, agent: dict, secret: dict) -> None:
    response = auth.client.post(
        "/v1/agent/exec",
        headers=agent["headers"],
        json={
            "environment": "dev",
            "command": ["python3", "-c", "import time;time.sleep(30)"],
            "timeout_seconds": 1,
        },
    )
    assert response.status_code == 200
    events = sse_events(response.text)
    assert events[-1]["type"] == "exit"
    assert events[-1]["timed_out"] is True
    assert events[-1]["code"] != 0
    assert events[-1]["duration_ms"] < 15000


def test_agent_command_prefix_is_enforced(auth: ApiClient, project: dict) -> None:
    restricted = auth.post(
        "/v1/tokens",
        json={
            "name": "restricted",
            "project_id": project["id"],
            "environments": ["dev"],
            "can_list": True,
            "can_inject": True,
            "allowed_commands": ["echo"],
        },
    ).json()
    headers = {"authorization": f"Bearer {restricted['token']}"}

    allowed = auth.client.post(
        "/v1/agent/exec",
        headers=headers,
        json={"environment": "dev", "command": ["echo", "hello"]},
    )
    assert allowed.status_code == 200

    denied = auth.client.post(
        "/v1/agent/exec",
        headers=headers,
        json={"environment": "dev", "command": ["python3", "-c", "print(1)"]},
    )
    assert denied.status_code == 403


def test_agent_environment_scope(auth: ApiClient, project: dict) -> None:
    prod_only = auth.post(
        "/v1/tokens",
        json={
            "name": "prod-only",
            "project_id": project["id"],
            "environments": ["prod"],
            "can_list": False,
            "can_inject": True,
            "allowed_commands": ["echo"],
        },
    ).json()
    headers = {"authorization": f"Bearer {prod_only['token']}"}

    denied = auth.client.post(
        "/v1/agent/exec",
        headers=headers,
        json={"environment": "dev", "command": ["echo", "hi"]},
    )
    assert denied.status_code == 403


def test_agent_cwd_must_stay_inside_project(auth: ApiClient, agent: dict, project: dict) -> None:
    response = auth.client.post(
        "/v1/agent/exec",
        headers=agent["headers"],
        json={"environment": "dev", "command": ["echo", "hi"], "cwd": "/tmp"},
    )
    assert response.status_code == 400


def test_revoked_token_is_rejected(auth: ApiClient, agent: dict) -> None:
    token_id = agent["item"]["id"]
    assert auth.delete(f"/v1/tokens/{token_id}").status_code == 204
    response = auth.client.get("/v1/agent/context", headers=agent["headers"])
    assert response.status_code == 401


def test_agent_exec_requires_unlocked_vault(auth: ApiClient, agent: dict, project: dict) -> None:
    auth.post("/v1/auth/lock")
    response = auth.client.post(
        "/v1/agent/exec",
        headers=agent["headers"],
        json={"environment": "dev", "command": ["echo", "hi"]},
    )
    assert response.status_code == 423
