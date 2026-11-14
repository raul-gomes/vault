"""Keyed audit chain: rewriting or truncating it needs the vault key (S3)."""

from __future__ import annotations

import hashlib

from sqlalchemy import delete, select, update

from envvault.models import AuditEntry
from envvault.services import audit
from tests.conftest import PASSPHRASE, ApiClient


def _verify(auth: ApiClient) -> dict:
    return auth.get("/v1/audit/verify").json()


def _entries(app) -> list[AuditEntry]:  # type: ignore[no-untyped-def]
    with app.state.session_factory() as db:
        return list(db.scalars(select(AuditEntry).order_by(AuditEntry.id)).all())


def test_entries_written_while_unlocked_are_keyed(app, auth: ApiClient, project: dict) -> None:
    keyed = [entry for entry in _entries(app) if entry.action == "project.create"]
    assert keyed and all(entry.mac == "hmac" for entry in keyed)
    assert _verify(auth) == {"valid": True, "first_bad_id": None}


def test_rewriting_the_chain_without_the_key_is_detected(
    app, auth: ApiClient, project: dict
) -> None:
    """An attacker with write access rewrites one entry and re-hashes the rest
    with plain SHA-256 (all they can compute without the key)."""
    with app.state.session_factory() as db:
        rows = list(db.scalars(select(AuditEntry).order_by(AuditEntry.id)).all())
        prev = audit.GENESIS_HASH
        for row in rows:
            if row.action == "project.create":
                row.actor_name = "someone-else"
            row.prev_hash = prev
            row.mac = "sha256"
            row.hash = hashlib.sha256(audit._canonical(audit._payload(row))).hexdigest()
            prev = row.hash
        db.commit()
    assert _verify(auth)["valid"] is False


def test_truncating_the_tail_is_detected(app, auth: ApiClient, project: dict) -> None:
    last = _entries(app)[-1]
    with app.state.session_factory() as db:
        db.execute(delete(AuditEntry).where(AuditEntry.id == last.id))
        db.commit()
    assert _verify(auth)["valid"] is False


def test_failed_unlock_before_any_key_is_recorded_unkeyed(app, vault_ready) -> None:  # type: ignore[no-untyped-def]
    denied = vault_ready.post("/v1/auth/login", json={"passphrase": "wrong passphrase!!"})
    assert denied.status_code == 401
    ok = vault_ready.post("/v1/auth/login", json={"passphrase": PASSPHRASE})
    client = ApiClient(client=vault_ready, csrf=ok.json()["csrf_token"])
    entries = _entries(app)
    assert entries[0].action == "vault.unlock" and entries[0].mac == "sha256"
    assert entries[-1].mac == "hmac"
    assert _verify(client) == {"valid": True, "first_bad_id": None}


def test_unkeyed_entry_of_another_kind_is_rejected(app, auth: ApiClient, project: dict) -> None:
    target = next(entry for entry in _entries(app) if entry.action == "project.create")
    with app.state.session_factory() as db:
        db.execute(update(AuditEntry).where(AuditEntry.id == target.id).values(mac="sha256"))
        db.commit()
    assert _verify(auth)["first_bad_id"] == target.id


def test_lock_and_later_entries_stay_keyed(app, auth: ApiClient) -> None:
    assert auth.post("/v1/auth/lock").status_code == 200
    lock_entry = _entries(app)[-1]
    assert lock_entry.action == "vault.lock" and lock_entry.mac == "hmac"
