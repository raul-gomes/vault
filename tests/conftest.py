"""Shared pytest fixtures: isolated vault homes and authenticated clients."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from envvault.app import create_app
from envvault.config import Settings
from envvault.services import vault

PASSPHRASE = "correct horse battery staple"
SECRET_VALUE = "s3cr3t-value-12345"


@dataclass(slots=True)
class ApiClient:
    """Test client that adds the CSRF header on mutations."""

    client: TestClient
    csrf: str

    def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        headers = dict(kwargs.pop("headers", {}))
        if method not in {"GET", "HEAD", "OPTIONS"}:
            headers["x-csrf-token"] = self.csrf
        return self.client.request(method, path, headers=headers, **kwargs)

    def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("POST", path, **kwargs)

    def put(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("PUT", path, **kwargs)

    def patch(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("PATCH", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("DELETE", path, **kwargs)


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    """Fast KDF and no host guard so TestClient works."""
    return Settings(
        home=tmp_path / "home",
        kdf_time_cost=1,
        kdf_memory_kib=8192,
        kdf_parallelism=1,
        enforce_host=False,
    )


@pytest.fixture()
def app(settings: Settings):
    return create_app(settings)


@pytest.fixture()
def client(app) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def vault_ready(client: TestClient, app, settings: Settings) -> TestClient:
    """Initialize the database without creating a session."""
    with app.state.session_factory() as db:
        vault.initialize(db, settings, PASSPHRASE)
        db.commit()
    return client


@pytest.fixture()
def auth(vault_ready: TestClient) -> ApiClient:
    """Unlock, log in and return a CSRF-aware client."""
    response = vault_ready.post("/v1/auth/login", json={"passphrase": PASSPHRASE})
    assert response.status_code == 200, response.text
    return ApiClient(client=vault_ready, csrf=response.json()["csrf_token"])


@pytest.fixture()
def project_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "sample-project"
    directory.mkdir()
    return directory


@pytest.fixture()
def project(auth: ApiClient, project_dir: Path) -> dict[str, Any]:
    response = auth.post(
        "/v1/projects",
        json={"slug": "sample", "name": "Sample", "path": str(project_dir)},
    )
    assert response.status_code == 201, response.text
    return response.json()


@pytest.fixture()
def secret(auth: ApiClient, project: dict[str, Any]) -> dict[str, Any]:
    response = auth.put(
        f"/v1/projects/{project['id']}/secrets",
        json={"environment": "dev", "key": "SECRET_KEY", "value": SECRET_VALUE},
    )
    assert response.status_code == 200, response.text
    return response.json()["item"]


@pytest.fixture()
def agent(auth: ApiClient, project: dict[str, Any]) -> dict[str, Any]:
    response = auth.post(
        "/v1/tokens",
        json={
            "name": "claude-test",
            "project_id": project["id"],
            "environments": ["dev"],
            "can_list": True,
            "can_inject": True,
            "allowed_commands": [],
        },
    )
    assert response.status_code == 201, response.text
    payload = response.json()
    return {
        "token": payload["token"],
        "item": payload["item"],
        "headers": {"authorization": f"Bearer {payload['token']}"},
        "project": project,
    }


def sse_events(text: str) -> list[dict[str, Any]]:
    """Parse SSE frames into JSON events."""
    events = []
    for line in text.splitlines():
        if line.startswith("data: "):
            events.append(json.loads(line[6:]))
    return events
