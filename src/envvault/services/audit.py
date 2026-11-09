"""Append-only, hash-chained audit log."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from envvault.models import AuditEntry

GENESIS_HASH = "0" * 64


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
    lock: Any = None,
) -> AuditEntry:
    """Append one entry, chaining its hash to the previous one.

    The caller owns the transaction and must commit. ``lock`` should be the
    runtime lock so concurrent requests cannot fork the chain.
    """
    if lock is not None:
        lock.acquire()
    try:
        previous = db.scalars(select(AuditEntry).order_by(AuditEntry.id.desc()).limit(1)).first()
        prev_hash = previous.hash if previous else GENESIS_HASH
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
            prev_hash=prev_hash,
            hash="",
        )
        payload = _payload(entry)
        entry.hash = hashlib.sha256(_canonical(payload)).hexdigest()
        db.add(entry)
        db.flush()
        return entry
    finally:
        if lock is not None:
            lock.release()


def _payload(entry: AuditEntry) -> dict[str, Any]:
    """Fields that are covered by the entry hash."""
    return {
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


def verify_chain(db: Session) -> tuple[bool, int | None]:
    """Recompute the chain. Returns ``(valid, first_bad_id)``."""
    prev_hash = GENESIS_HASH
    entries = db.scalars(select(AuditEntry).order_by(AuditEntry.id.asc())).all()
    for entry in entries:
        expected = hashlib.sha256(_canonical(_payload(entry))).hexdigest()
        if entry.prev_hash != prev_hash or entry.hash != expected:
            return False, entry.id
        prev_hash = entry.hash
    return True, None
