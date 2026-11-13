"""Vault lifecycle: initialize, unlock, verify passphrase, lock and idle expiry."""

from __future__ import annotations

import json
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
META_MAX_UNLOCK_HOURS = "max_unlock_hours"
SECONDS_PER_MINUTE = 60
SECONDS_PER_HOUR = 3600
META_CREATED_AT = "created_at"


@dataclass(frozen=True, slots=True)
class VaultStatus:
    """Public daemon/vault status."""

    initialized: bool
    unlocked: bool
    lock_timeout_minutes: int
    max_unlock_hours: int


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


def max_unlock_hours(db: Session, settings: Settings) -> int:
    """Effective absolute unlock limit, from metadata with a settings fallback."""
    raw = get_meta(db, META_MAX_UNLOCK_HOURS)
    return int(raw) if raw else settings.max_unlock_hours


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
    """Apply the idle and absolute limits, then require unlocked state.

    Called on every authenticated request; a request that finds the vault
    within its limits counts as activity.
    """
    if state.dek is None:
        raise LockedError("vault is locked")
    reason = _expired(db, settings, state)
    if reason is not None:
        lock(db, state, actor_type="system", actor_name="system")
        raise LockedError(reason)
    state.touch()


def enforce_limits(db: Session, settings: Settings, state: Runtime) -> bool:
    """Lock the vault when a limit expired, without counting as activity.

    Used by the daemon watchdog so limits apply even with no requests (a
    long-running command would otherwise keep its secrets indefinitely).
    Returns whether the vault was locked by this call.
    """
    if state.dek is None:
        return False
    if _expired(db, settings, state) is None:
        return False
    lock(db, state, actor_type="system", actor_name="system")
    return True


def _expired(db: Session, settings: Settings, state: Runtime) -> str | None:
    """Return why the unlocked vault must lock now, or ``None``."""
    now = state.clock()
    last = state.last_activity
    if last is None or now - last > timeout_minutes(db, settings) * SECONDS_PER_MINUTE:
        return "vault locked after inactivity"
    started = state.unlocked_at
    if started is None or now - started > max_unlock_hours(db, settings) * SECONDS_PER_HOUR:
        return "vault locked after the maximum unlock time; unlock it again"
    return None


def status(db: Session, settings: Settings, state: Runtime) -> VaultStatus:
    """Return the current status without exposing key material."""
    unlocked = state.dek is not None and _expired(db, settings, state) is None
    return VaultStatus(
        initialized=is_initialized(db),
        unlocked=unlocked,
        lock_timeout_minutes=timeout_minutes(db, settings),
        max_unlock_hours=max_unlock_hours(db, settings),
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
