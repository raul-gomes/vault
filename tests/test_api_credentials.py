"""Credentials API tests: metadata-only responses, encryption, reveal and audit."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from envvault.config import Settings
from tests.conftest import PASSPHRASE, ApiClient

CREDENTIAL = {
    "name": "Hostinger principal",
    "category": "hosting",
    "username": "painel-user-7788",
    "password": "sup3r-secret-hostinger",
    "url": "https://painel.example.test/conta",
    "notes": "conta 7788 · plano Business",
}


def _create(auth: ApiClient, **overrides: Any) -> dict[str, Any]:
    """Create a credential with the test defaults."""
    body = {**CREDENTIAL, **overrides}
    response = auth.post("/v1/credentials", json=body)
    assert response.status_code == 201, response.text
    return response.json()["item"]


def _db_bytes(db_path: Path) -> bytes:
    """Read the SQLite database plus its WAL/SHM sidecars."""
    data = b""
    for suffix in ("", "-wal", "-shm"):
        candidate = db_path.with_name(db_path.name + suffix)
        if candidate.exists():
            data += candidate.read_bytes()
    return data


def test_create_returns_metadata_only(auth: ApiClient) -> None:
    item = _create(auth)
    assert item["name"] == CREDENTIAL["name"]
    assert item["category"] == "hosting"
    assert item["version"] == 1
    assert item["scope"] == "global"
    assert item["project"] is None
    assert "password" not in item
    assert "username" not in item

    listed = auth.get("/v1/credentials")
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert "Hostinger principal" in listed.text
    for field in ("username", "password", "url", "notes"):
        assert CREDENTIAL[field] not in listed.text


def test_credential_can_belong_to_a_project(auth: ApiClient, project: dict) -> None:
    scoped = _create(auth, name="Cloudflare do cliente", project_id=project["id"])
    assert scoped["scope"] == "project"
    assert scoped["project"]["slug"] == project["slug"]

    global_item = _create(auth, name="Cloudflare pessoal")

    all_items = auth.get("/v1/credentials").json()["items"]
    assert {item["name"] for item in all_items} == {
        scoped["name"],
        global_item["name"],
    }

    only_global = auth.get("/v1/credentials", params={"global_only": True}).json()["items"]
    assert [item["name"] for item in only_global] == [global_item["name"]]

    only_project = auth.get("/v1/credentials", params={"project_id": project["id"]}).json()["items"]
    assert [item["name"] for item in only_project] == [scoped["name"]]

    revealed = auth.post(
        f"/v1/credentials/{scoped['id']}/reveal", json={"passphrase": PASSPHRASE}
    ).json()
    assert revealed["scope"] == "project"
    assert revealed["project"]["id"] == project["id"]
    assert revealed["password"] == CREDENTIAL["password"]


def test_update_can_move_credential_to_project_and_back(auth: ApiClient, project: dict) -> None:
    item = _create(auth)
    moved = auth.put(
        f"/v1/credentials/{item['id']}",
        json={**CREDENTIAL, "project_id": project["id"]},
    )
    assert moved.status_code == 200
    assert moved.json()["item"]["scope"] == "project"
    assert moved.json()["item"]["project"]["slug"] == project["slug"]

    back = auth.put(
        f"/v1/credentials/{item['id']}",
        json={**CREDENTIAL, "project_id": None},
    )
    assert back.status_code == 200
    assert back.json()["item"]["scope"] == "global"

    invalid = auth.post("/v1/credentials", json={**CREDENTIAL, "project_id": "missing"})
    assert invalid.status_code == 400


def test_credential_is_encrypted_at_rest(auth: ApiClient, settings: Settings) -> None:
    _create(auth)
    raw = _db_bytes(settings.db_path)
    for field in ("username", "password", "url", "notes"):
        assert CREDENTIAL[field].encode() not in raw
    assert CREDENTIAL["name"].encode() in raw
    assert CREDENTIAL["category"].encode() in raw


def test_update_increments_version_and_replaces_payload(auth: ApiClient) -> None:
    item = _create(auth)
    updated = auth.put(
        f"/v1/credentials/{item['id']}",
        json={
            **CREDENTIAL,
            "name": "Hostinger secondary",
            "category": "dns",
            "username": "novo-usuario-9900",
            "password": "new-password-9900",
            "notes": "rotacionada",
        },
    )
    assert updated.status_code == 200
    assert updated.json()["item"]["version"] == 2
    assert updated.json()["item"]["name"] == "Hostinger secondary"

    revealed = auth.post(
        f"/v1/credentials/{item['id']}/reveal",
        json={"passphrase": PASSPHRASE},
    )
    assert revealed.status_code == 200
    payload = revealed.json()
    assert payload["username"] == "novo-usuario-9900"
    assert payload["password"] == "new-password-9900"
    assert payload["notes"] == "rotacionada"


def test_reveal_requires_passphrase_and_is_audited(auth: ApiClient) -> None:
    item = _create(auth)
    denied = auth.post(
        f"/v1/credentials/{item['id']}/reveal",
        json={"passphrase": "wrong passphrase"},
    )
    assert denied.status_code == 401

    revealed = auth.post(
        f"/v1/credentials/{item['id']}/reveal",
        json={"passphrase": PASSPHRASE},
    )
    assert revealed.status_code == 200
    assert revealed.json()["password"] == CREDENTIAL["password"]
    assert revealed.json()["username"] == CREDENTIAL["username"]

    entries = auth.get("/v1/audit", params={"action": "credential.reveal"}).json()["items"]
    assert [entry["result"] for entry in entries] == ["ok", "denied"]
    assert all(entry["key_names"] == [CREDENTIAL["name"]] for entry in entries)
    assert all(entry["actor_type"] == "user" for entry in entries)


def test_delete_and_missing_credential(auth: ApiClient) -> None:
    item = _create(auth)
    deleted = auth.delete(f"/v1/credentials/{item['id']}")
    assert deleted.status_code == 204
    assert auth.get("/v1/credentials").json()["total"] == 0
    assert auth.get(f"/v1/credentials/{item['id']}").status_code == 404
    assert (
        auth.post(
            f"/v1/credentials/{item['id']}/reveal", json={"passphrase": PASSPHRASE}
        ).status_code
        == 404
    )


def test_agent_token_cannot_access_credentials(auth: ApiClient, agent: dict) -> None:
    _create(auth)
    auth.client.cookies.clear()
    response = auth.client.get("/v1/credentials", headers=agent["headers"])
    assert response.status_code == 401


def test_search_and_category_filter(auth: ApiClient) -> None:
    _create(auth)
    _create(
        auth,
        name="Cloudflare DNS",
        category="dns",
        username="cf-user",
        password="cf-token",
    )
    by_query = auth.get("/v1/credentials", params={"query": "cloud"}).json()
    assert [item["name"] for item in by_query["items"]] == ["Cloudflare DNS"]

    by_category = auth.get("/v1/credentials", params={"category": "hosting"}).json()
    assert [item["name"] for item in by_category["items"]] == [CREDENTIAL["name"]]

    invalid = auth.get("/v1/credentials", params={"category": "Not Valid!"})
    assert invalid.status_code == 400


def test_overview_counts_credentials(auth: ApiClient) -> None:
    _create(auth)
    overview = auth.get("/v1/overview").json()
    assert overview["credentials"] == 1


def test_deleting_project_removes_only_its_credentials(auth: ApiClient, project: dict) -> None:
    scoped = _create(auth, name="Client credential", project_id=project["id"])
    _create(auth, name="Global credential")

    deleted = auth.delete(f"/v1/projects/{project['id']}", json={"confirm_slug": project["slug"]})
    assert deleted.status_code == 204

    remaining = auth.get("/v1/credentials").json()["items"]
    assert [item["name"] for item in remaining] == ["Global credential"]
    assert scoped["id"] not in {item["id"] for item in remaining}


def test_credential_audit_chain_stays_valid(auth: ApiClient) -> None:
    item = _create(auth)
    auth.post(f"/v1/credentials/{item['id']}/reveal", json={"passphrase": PASSPHRASE})
    auth.put(f"/v1/credentials/{item['id']}", json=CREDENTIAL)
    auth.delete(f"/v1/credentials/{item['id']}")
    assert auth.get("/v1/audit/verify").json() == {"valid": True, "first_bad_id": None}
