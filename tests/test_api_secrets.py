"""Project and secret API tests, including encryption at rest."""

from __future__ import annotations

from pathlib import Path

from envvault.config import Settings
from tests.conftest import PASSPHRASE, SECRET_VALUE, ApiClient


def _db_bytes(db_path: Path) -> bytes:
    """Read the SQLite database plus its WAL/SHM sidecars."""
    data = b""
    for suffix in ("", "-wal", "-shm"):
        candidate = db_path.with_name(db_path.name + suffix)
        if candidate.exists():
            data += candidate.read_bytes()
    return data


def test_project_crud_and_validation(auth: ApiClient, project_dir: Path) -> None:
    created = auth.post(
        "/v1/projects",
        json={"slug": "demo", "name": "Demo", "path": str(project_dir)},
    )
    assert created.status_code == 201
    project = created.json()
    assert project["slug"] == "demo"

    duplicate = auth.post(
        "/v1/projects",
        json={"slug": "demo", "name": "Demo 2", "path": str(project_dir)},
    )
    assert duplicate.status_code == 400

    bad_path = auth.post(
        "/v1/projects",
        json={"slug": "missing", "name": "Missing", "path": "/does/not/exist"},
    )
    assert bad_path.status_code == 400

    updated = auth.patch(f"/v1/projects/{project['id']}", json={"name": "Renamed"})
    assert updated.status_code == 200
    assert updated.json()["name"] == "Renamed"

    wrong_confirm = auth.delete(f"/v1/projects/{project['id']}", json={"confirm_slug": "nope"})
    assert wrong_confirm.status_code == 400

    deleted = auth.delete(f"/v1/projects/{project['id']}", json={"confirm_slug": "demo"})
    assert deleted.status_code == 204
    assert auth.get("/v1/projects").json()["total"] == 0


def test_secret_metadata_never_contains_value(auth: ApiClient, project: dict, secret: dict) -> None:
    response = auth.get(f"/v1/projects/{project['id']}/secrets", params={"environment": "dev"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["items"][0]["key"] == "SECRET_KEY"
    assert "value" not in payload["items"][0]
    assert SECRET_VALUE not in response.text


def test_secret_is_encrypted_at_rest(
    auth: ApiClient, project: dict, secret: dict, settings: Settings
) -> None:
    raw = _db_bytes(settings.db_path)
    assert SECRET_VALUE.encode() not in raw
    assert b"SECRET_KEY" in raw  # the key name is metadata, not the value


def test_update_increments_version(auth: ApiClient, project: dict, secret: dict) -> None:
    response = auth.put(
        f"/v1/projects/{project['id']}/secrets",
        json={"environment": "dev", "key": "SECRET_KEY", "value": "new-value-999"},
    )
    assert response.status_code == 200
    assert response.json()["created"] is False
    assert response.json()["item"]["version"] == 2


def test_reveal_requires_passphrase_and_is_audited(
    auth: ApiClient, project: dict, secret: dict
) -> None:
    denied = auth.post(
        f"/v1/projects/{project['id']}/secrets/SECRET_KEY/reveal",
        json={"environment": "dev", "passphrase": "wrong passphrase"},
    )
    assert denied.status_code == 401

    revealed = auth.post(
        f"/v1/projects/{project['id']}/secrets/SECRET_KEY/reveal",
        json={"environment": "dev", "passphrase": PASSPHRASE},
    )
    assert revealed.status_code == 200
    assert revealed.json()["value"] == SECRET_VALUE

    entries = auth.get("/v1/audit", params={"action": "secret.reveal"}).json()["items"]
    assert [entry["result"] for entry in entries] == ["ok", "denied"]
    assert all(entry["key_names"] == ["SECRET_KEY"] for entry in entries)


def test_export_returns_dotenv_after_passphrase(
    auth: ApiClient, project: dict, secret: dict
) -> None:
    response = auth.post(
        f"/v1/projects/{project['id']}/export",
        json={"environment": "dev", "passphrase": PASSPHRASE},
    )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert "SECRET_KEY=" in response.text
    assert SECRET_VALUE in response.text

    denied = auth.post(
        f"/v1/projects/{project['id']}/export",
        json={"environment": "dev", "passphrase": "wrong passphrase"},
    )
    assert denied.status_code == 401


def test_import_create_skip_and_replace(auth: ApiClient, project: dict) -> None:
    content = "# comment\nALPHA=one\nexport BETA='two words'\nBAD LINE\n"
    first = auth.post(
        f"/v1/projects/{project['id']}/import",
        json={"environment": "dev", "content": content, "replace": False},
    )
    assert first.status_code == 200
    assert first.json()["created"] == 2
    assert first.json()["issues"][0]["line"] == 4

    skipped = auth.post(
        f"/v1/projects/{project['id']}/import",
        json={"environment": "dev", "content": "ALPHA=changed\n", "replace": False},
    )
    assert skipped.json()["skipped"] == 1

    replaced = auth.post(
        f"/v1/projects/{project['id']}/import",
        json={"environment": "dev", "content": "ALPHA=changed\n", "replace": True},
    )
    assert replaced.json()["updated"] == 1
    assert replaced.json()["created"] == 0

    listed = auth.get(
        f"/v1/projects/{project['id']}/secrets", params={"environment": "dev"}
    ).json()["items"]
    assert {item["key"] for item in listed} == {"ALPHA", "BETA"}


def test_environment_discovery_and_delete_secret(
    auth: ApiClient, project: dict, secret: dict
) -> None:
    environments = auth.get(f"/v1/projects/{project['id']}/environments").json()
    assert environments["items"][0]["environment"] == "dev"
    assert environments["items"][0]["count"] == 1

    auth.put(
        f"/v1/projects/{project['id']}/secrets",
        json={"environment": "prod", "key": "PROD_KEY", "value": "prod-value"},
    )
    environments = auth.get(f"/v1/projects/{project['id']}/environments").json()
    assert [item["environment"] for item in environments["items"]] == ["dev", "prod"]

    deleted = auth.delete(
        f"/v1/projects/{project['id']}/secrets/PROD_KEY",
        params={"environment": "prod"},
    )
    assert deleted.status_code == 204
    listed = auth.get(
        f"/v1/projects/{project['id']}/secrets", params={"environment": "prod"}
    ).json()["items"]
    assert listed == []


def test_generate_endpoint(auth: ApiClient) -> None:
    response = auth.post(
        "/v1/generate",
        json={"length": 40, "symbols": False},
    )
    assert response.status_code == 200
    payload = response.json()
    assert len(payload["password"]) == 40
    assert payload["entropy_bits"] > 0
    assert not set("!@%^*-_=+.:?") & set(payload["password"])


def test_settings_timeout_update(auth: ApiClient) -> None:
    response = auth.put("/v1/settings", json={"lock_timeout_minutes": 45})
    assert response.status_code == 200
    assert response.json()["lock_timeout_minutes"] == 45
    assert auth.get("/v1/settings").json()["lock_timeout_minutes"] == 45


def test_create_empty_environment_persists(auth: ApiClient, project: dict) -> None:
    created = auth.post(f"/v1/projects/{project['id']}/environments", json={"name": "staging"})
    assert created.status_code == 201
    assert created.json() == {"environment": "staging", "created": True}

    again = auth.post(f"/v1/projects/{project['id']}/environments", json={"name": "staging"})
    assert again.status_code == 200
    assert again.json()["created"] is False

    payload = auth.get(f"/v1/projects/{project['id']}").json()
    by_name = {item["environment"]: item for item in payload["environments"]}
    assert set(by_name) == {"staging"}
    assert by_name["staging"]["count"] == 0


def test_invalid_environment_name_is_rejected(auth: ApiClient, project: dict) -> None:
    response = auth.post(f"/v1/projects/{project['id']}/environments", json={"name": "Not Valid!"})
    assert response.status_code == 400


def test_import_registers_environment(auth: ApiClient, project: dict) -> None:
    auth.post(
        f"/v1/projects/{project['id']}/import",
        json={"environment": "qa", "content": "QA_KEY=value-qa\n", "replace": False},
    )
    payload = auth.get(f"/v1/projects/{project['id']}").json()
    by_name = {item["environment"]: item for item in payload["environments"]}
    assert by_name["qa"]["count"] == 1


def test_delete_environment_requires_it_to_be_empty(
    auth: ApiClient, project: dict, secret: dict
) -> None:
    in_use = auth.delete(f"/v1/projects/{project['id']}/environments/dev")
    assert in_use.status_code == 400

    auth.post(f"/v1/projects/{project['id']}/environments", json={"name": "staging"})
    removed = auth.delete(f"/v1/projects/{project['id']}/environments/staging")
    assert removed.status_code == 204
    payload = auth.get(f"/v1/projects/{project['id']}").json()
    assert "staging" not in [item["environment"] for item in payload["environments"]]
