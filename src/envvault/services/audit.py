"""Append-only audit log, chained and keyed by the vault (S3).

Each entry stores ``hash`` = MAC over its fields and the previous hash:

* ``hmac``: HMAC-SHA256 with a key derived from the DEK. Rewriting these
  entries requires the DEK, which only exists in the daemon after unlock.
* ``sha256``: plain hash, only for failed unlock attempts written before any
  key exists in this daemon run.
* ``legacy``: plain hash written before revision 0005; allowed only as the
  oldest part of the chain.

The last keyed entry is pinned in ``meta`` with its own HMAC tag, so deleting
the tail is detected too.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from envvault.models import AuditEntry, Meta

if TYPE_CHECKING:
    from envvault.runtime import Runtime

GENESIS_HASH = "0" * 64
MAC_HMAC = "hmac"
MAC_SHA256 = "sha256"
MAC_LEGACY = "legacy"
META_AUDIT_HEAD = "audit_head"
# The only action that may be recorded before the vault key exists.
UNKEYED_ACTIONS = {("vault.unlock", "denied")}


def _canonical(payload: dict[str, Any]) -> bytes:
    """Serialize an audit payload deterministically."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def append(
    db: Session,
    *,
    actor_type: str,
    actor_name: str,
    action: str,
    project_slug: str | None = None,
    environment: str | None = None,
    key_names: Iterable[str] = (),
    command: str | None = None,
    result: str = "ok",
    detail: dict[str, Any] | None = None,
    state: Runtime | None = None,
) -> AuditEntry:
    """Append one entry, chaining and (when the key exists) keying its hash.

    The caller owns the transaction and must commit. ``state`` supplies the
    runtime lock, so concurrent requests cannot fork the chain, and the audit
    key.
    """
    lock = state.lock if state is not None else None
    key = state.audit_key if state is not None else None
    if lock is not None:
        lock.acquire()
    try:
        previous = db.scalars(select(AuditEntry).order_by(AuditEntry.id.desc()).limit(1)).first()
        entry = AuditEntry(
            ts=datetime.now(UTC).isoformat(timespec="microseconds"),
            actor_type=actor_type,
            actor_name=actor_name,
            action=action,
            project_slug=project_slug,
            environment=environment,
            key_names=json.dumps(sorted(set(key_names))),
            command=command,
            result=result,
            detail=json.dumps(detail or {}, sort_keys=True, ensure_ascii=False),
            prev_hash=previous.hash if previous else GENESIS_HASH,
            mac=MAC_HMAC if key is not None else MAC_SHA256,
            hash="",
        )
        entry.hash = _mac(entry, key)
        db.add(entry)
        db.flush()
        if key is not None:
            _pin_head(db, entry, key)
        return entry
    finally:
        if lock is not None:
            lock.release()


def _payload(entry: AuditEntry) -> dict[str, Any]:
    """Fields that are covered by the entry hash."""
    payload: dict[str, Any] = {
        "ts": entry.ts,
        "actor_type": entry.actor_type,
        "actor_name": entry.actor_name,
        "action": entry.action,
        "project_slug": entry.project_slug,
        "environment": entry.environment,
        "key_names": entry.key_names,
        "command": entry.command,
        "result": entry.result,
        "detail": entry.detail,
        "prev_hash": entry.prev_hash,
    }
    if entry.mac != MAC_LEGACY:
        payload["mac"] = entry.mac
    return payload


def _mac(entry: AuditEntry, key: bytes | None) -> str:
    """Compute the entry hash for its MAC kind."""
    data = _canonical(_payload(entry))
    if entry.mac == MAC_HMAC:
        if key is None:
            raise ValueError("keyed audit entry needs the audit key")
        return hmac.new(key, data, hashlib.sha256).hexdigest()
    return hashlib.sha256(data).hexdigest()


def _head_tag(key: bytes, entry_id: int, entry_hash: str) -> str:
    """HMAC that pins the last keyed entry (detects tail deletion)."""
    return hmac.new(key, f"head:{entry_id}:{entry_hash}".encode(), hashlib.sha256).hexdigest()


def _pin_head(db: Session, entry: AuditEntry, key: bytes) -> None:
    """Store the newest keyed entry and its tag in ``meta``."""
    value = json.dumps(
        {"id": entry.id, "hash": entry.hash, "tag": _head_tag(key, entry.id, entry.hash)}
    )
    row = db.get(Meta, META_AUDIT_HEAD)
    if row is None:
        db.add(Meta(key=META_AUDIT_HEAD, value=value))
    else:
        row.value = value


def verify_chain(db: Session, key: bytes | None) -> tuple[bool, int | None]:
    """Recompute the chain. Returns ``(valid, first_bad_id)``.

    ``key`` is the audit key (vault unlocked). Without it, keyed entries
    cannot be checked and the chain is reported invalid at the first one.
    """
    prev_hash = GENESIS_HASH
    seen_non_legacy = False
    last_keyed: AuditEntry | None = None
    entries = db.scalars(select(AuditEntry).order_by(AuditEntry.id.asc())).all()
    for entry in entries:
        if not _entry_allowed(entry, seen_non_legacy) or entry.prev_hash != prev_hash:
            return False, entry.id
        if entry.mac == MAC_HMAC and key is None:
            return False, entry.id
        if not hmac.compare_digest(entry.hash, _mac(entry, key)):
            return False, entry.id
        seen_non_legacy = seen_non_legacy or entry.mac != MAC_LEGACY
        if entry.mac == MAC_HMAC:
            last_keyed = entry
        prev_hash = entry.hash
    if not _head_matches(db, last_keyed, key):
        return False, last_keyed.id if last_keyed else None
    return True, None


def _entry_allowed(entry: AuditEntry, seen_non_legacy: bool) -> bool:
    """Whether the entry's MAC kind is acceptable at this point of the chain."""
    if entry.mac == MAC_HMAC:
        return True
    if entry.mac == MAC_LEGACY:
        return not seen_non_legacy
    if entry.mac == MAC_SHA256:
        return (entry.action, entry.result) in UNKEYED_ACTIONS
    return False


def _head_matches(db: Session, last_keyed: AuditEntry | None, key: bytes | None) -> bool:
    """The pinned head must name the newest keyed entry, with a valid tag."""
    row = db.get(Meta, META_AUDIT_HEAD)
    if last_keyed is None:
        return row is None
    if row is None or key is None:
        return False
    head = json.loads(row.value)
    expected = _head_tag(key, last_keyed.id, last_keyed.hash)
    return (
        head.get("id") == last_keyed.id
        and head.get("hash") == last_keyed.hash
        and hmac.compare_digest(str(head.get("tag", "")), expected)
    )
