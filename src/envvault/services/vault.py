"""Vault lifecycle: initialize, unlock, verify passphrase, lock and idle expiry."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from envvault import crypto
from envvault.config import MIN_PASSPHRASE_LENGTH, Settings
from envvault.models import Meta
from envvault.runtime import (
    LockedError,
    Runtime,
    VaultNotInitialized,
    constant_time_equals,
)
from envvault.services import audit

META_KDF = "kdf"
META_DEK_WRAPPED = "dek_wrapped"
META_DEK_NONCE = "dek_nonce"
META_LOCK_TIMEOUT = "lock_timeout_minutes"
META_CREATED_AT = "created_at"


@dataclass(frozen=True, slots=True)
class VaultStatus:
    """Public daemon/vault status."""

    initialized: bool
    unlocked: bool
    lock_timeout_minutes: int


def get_meta(db: Session, key: str) -> str | None:
    """Read one metadata value."""
    row = db.get(Meta, key)
    return row.value if row else None


def set_meta(db: Session, key: str, value: str) -> None:
    """Upsert one metadata value."""
    row = db.get(Meta, key)
    if row is None:
        db.add(Meta(key=key, value=value))
    else:
        row.value = value


def is_initialized(db: Session) -> bool:
    """Return whether the vault has KDF metadata."""
    return get_meta(db, META_KDF) is not None


def kdf_params(db: Session) -> crypto.KdfParams:
    """Load the persisted Argon2id parameters."""
    raw = get_meta(db, META_KDF)
    if raw is None:
        raise VaultNotInitialized("vault is not initialized")
    payload = json.loads(raw)
    return crypto.KdfParams(
        salt=bytes.fromhex(payload["salt"]),
        time_cost=int(payload["time_cost"]),
        memory_kib=int(payload["memory_kib"]),
        parallelism=int(payload["parallelism"]),
    )


def timeout_minutes(db: Session, settings: Settings) -> int:
    """Effective idle-lock timeout, from metadata with a settings fallback."""
    raw = get_meta(db, META_LOCK_TIMEOUT)
    return int(raw) if raw else settings.lock_timeout_minutes


def initialize(db: Session, settings: Settings, passphrase: str) -> bytes:
    """Create KDF metadata and a random data key. Returns the DEK."""
    if is_initialized(db):
        raise ValueError("vault is already initialized")
    if len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise ValueError(f"passphrase must have at least {MIN_PASSPHRASE_LENGTH} characters")

    params = crypto.KdfParams(
        salt=crypto.new_salt(),
        time_cost=settings.kdf_time_cost,
        memory_kib=settings.kdf_memory_kib,
        parallelism=settings.kdf_parallelism,
    )
    kek = crypto.derive_kek(passphrase, params)
    dek = crypto.new_data_key()
    nonce, wrapped = crypto.wrap_data_key(kek, dek)

    set_meta(
        db,
        META_KDF,
        json.dumps(
            {
                "salt": params.salt.hex(),
                "time_cost": params.time_cost,
                "memory_kib": params.memory_kib,
                "parallelism": params.parallelism,
            }
        ),
    )
    db.add(Meta(key=META_DEK_NONCE, value=nonce.hex()))
    db.add(Meta(key=META_DEK_WRAPPED, value=wrapped.hex()))
    set_meta(db, META_LOCK_TIMEOUT, str(settings.lock_timeout_minutes))
    set_meta(db, META_CREATED_AT, datetime.now(UTC).isoformat())
    return dek


def unlock(db: Session, state: Runtime, passphrase: str, client: str) -> None:
    """Verify the passphrase and keep the DEK in memory."""
    if not is_initialized(db):
        raise VaultNotInitialized("vault is not initialized")
    state.check_login_allowed(client)
    try:
        kek = crypto.derive_kek(passphrase, kdf_params(db))
        nonce = bytes.fromhex(get_meta(db, META_DEK_NONCE) or "")
        wrapped = bytes.fromhex(get_meta(db, META_DEK_WRAPPED) or "")
        dek = crypto.unwrap_data_key(kek, nonce, wrapped)
    except (crypto.InvalidPassphrase, ValueError):
        state.record_login_failure(client)
        audit.append(
            db,
            actor_type="user",
            actor_name="user",
            action="vault.unlock",
            result="denied",
            detail={"client": client},
            lock=state.lock,
        )
        db.commit()
        raise
    state.unlock_with(dek)
    state.clear_login_failures(client)
    audit.append(
        db,
        actor_type="user",
        actor_name="user",
        action="vault.unlock",
        result="ok",
        detail={"client": client},
        lock=state.lock,
    )
    db.commit()


def verify_passphrase(db: Session, state: Runtime, passphrase: str) -> None:
    """Re-verify the passphrase of an unlocked vault (for reveal/export)."""
    if state.dek is None:
        raise LockedError("vault is locked")
    kek = crypto.derive_kek(passphrase, kdf_params(db))
    nonce = bytes.fromhex(get_meta(db, META_DEK_NONCE) or "")
    wrapped = bytes.fromhex(get_meta(db, META_DEK_WRAPPED) or "")
    candidate = crypto.unwrap_data_key(kek, nonce, wrapped)
    if not constant_time_equals(candidate, state.dek):
        raise crypto.InvalidPassphrase("invalid passphrase")


def lock(db: Session, state: Runtime, actor_type: str = "user", actor_name: str = "user") -> None:
    """Drop the DEK, invalidate sessions and stop child processes."""
    state.terminate_all()
    state.clear_key()
    audit.append(
        db,
        actor_type=actor_type,
        actor_name=actor_name,
        action="vault.lock",
        lock=state.lock,
    )
    db.commit()


def enforce_idle(db: Session, settings: Settings, state: Runtime) -> None:
    """Lock the vault if the idle timeout elapsed, then require unlocked state."""
    if state.dek is None:
        raise LockedError("vault is locked")
    timeout = timeout_minutes(db, settings) * 60
    last = state.last_activity
    if last is None or time.monotonic() - last > timeout:
        lock(db, state, actor_type="system", actor_name="system")
        raise LockedError("vault locked after inactivity")
    state.touch()


def status(db: Session, settings: Settings, state: Runtime) -> VaultStatus:
    """Return the current status without exposing key material."""
    unlocked = state.dek is not None
    if (
        unlocked
        and state.last_activity is not None
        and time.monotonic() - state.last_activity > timeout_minutes(db, settings) * 60
    ):
        unlocked = False
    return VaultStatus(
        initialized=is_initialized(db),
        unlocked=unlocked,
        lock_timeout_minutes=timeout_minutes(db, settings),
    )


def change_passphrase(db: Session, state: Runtime, current: str, new: str, *, client: str) -> None:
    """Re-wrap the DEK with a new passphrase-derived key."""
    if not is_initialized(db):
        raise VaultNotInitialized("vault is not initialized")
    if state.dek is None:
        raise LockedError("vault is locked")
    if len(new) < MIN_PASSPHRASE_LENGTH:
        raise ValueError(f"new passphrase must have at least {MIN_PASSPHRASE_LENGTH} characters")
    state.check_login_allowed(client)
    try:
        verify_passphrase(db, state, current)
    except crypto.InvalidPassphrase:
        state.record_login_failure(client)
        raise
    params = kdf_params(db)
    new_params = crypto.KdfParams(
        salt=crypto.new_salt(),
        time_cost=params.time_cost,
        memory_kib=params.memory_kib,
        parallelism=params.parallelism,
    )
    kek = crypto.derive_kek(new, new_params)
    nonce, wrapped = crypto.wrap_data_key(kek, state.dek)
    set_meta(
        db,
        META_KDF,
        json.dumps(
            {
                "salt": new_params.salt.hex(),
                "time_cost": new_params.time_cost,
                "memory_kib": new_params.memory_kib,
                "parallelism": new_params.parallelism,
            }
        ),
    )
    set_meta(db, META_DEK_NONCE, nonce.hex())
    set_meta(db, META_DEK_WRAPPED, wrapped.hex())
    state.clear_login_failures(client)
    audit.append(
        db,
        actor_type="user",
        actor_name="user",
        action="vault.passphrase.change",
        lock=state.lock,
    )
    db.commit()
