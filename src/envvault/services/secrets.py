"""Encrypted secret CRUD, import/export, reveal and exec materialization."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from envvault import crypto
from envvault.models import Project, Secret
from envvault.runtime import LockedError, Runtime
from envvault.services import audit, envfile, vault
from envvault.services.projects import validate_environment

KEY_MAX_LENGTH = 120
VALUE_MAX_BYTES = 64 * 1024
MAX_IMPORT_BYTES = 1024 * 1024


class SecretError(ValueError):
    """Raised for invalid secret data or a missing secret."""


class SecretCorruption(RuntimeError):
    """Raised when stored ciphertext cannot be decrypted."""


@dataclass(frozen=True, slots=True)
class ImportResult:
    """Counts and warnings produced by a .env import."""

    created: int
    updated: int
    skipped: int
    names: list[str]
    issues: list[envfile.ParseIssue]


@dataclass(frozen=True, slots=True)
class SecretView:
    """Metadata for a secret; never includes the value."""

    id: str
    key: str
    environment: str
    version: int
    created_at: datetime
    updated_at: datetime


def _dek(state: Runtime) -> bytes:
    """Return the in-memory data key or fail loudly."""
    if state.dek is None:
        raise LockedError("vault is locked")
    return state.dek


def _validate_key(key: str) -> str:
    """Validate an environment variable name."""
    key = key.strip()
    if not key:
        raise SecretError("key is required")
    if len(key) > KEY_MAX_LENGTH or not envfile.KEY_PATTERN.match(key):
        raise SecretError("key must match [A-Za-z_][A-Za-z0-9_]*")
    return key


def _validate_value(value: str) -> str:
    """Reject values that exceed the storage limit."""
    if len(value.encode("utf-8")) > VALUE_MAX_BYTES:
        raise SecretError(f"value exceeds {VALUE_MAX_BYTES} bytes")
    return value


def list_names(db: Session, project: Project, environment: str) -> list[Secret]:
    """List secret metadata (no plaintext) for one project/environment."""
    environment = validate_environment(environment)
    return list(
        db.scalars(
            select(Secret)
            .where(Secret.project_id == project.id, Secret.environment == environment)
            .order_by(Secret.key)
        ).all()
    )


def get(db: Session, project: Project, environment: str, key: str) -> Secret | None:
    """Find one secret row."""
    return db.scalars(
        select(Secret).where(
            Secret.project_id == project.id,
            Secret.environment == environment,
            Secret.key == key,
        )
    ).first()


def upsert(
    db: Session,
    state: Runtime,
    project: Project,
    *,
    environment: str,
    key: str,
    value: str,
    actor_type: str = "user",
    actor_name: str = "user",
) -> tuple[Secret, bool]:
    """Create or replace a secret. Returns ``(row, created)``."""
    environment = validate_environment(environment)
    key = _validate_key(key)
    value = _validate_value(value)
    dek = _dek(state)
    existing = get(db, project, environment, key)
    created = existing is None
    version = 1 if existing is None else existing.version + 1
    aad = crypto.secret_aad(project.id, environment, key, version)
    nonce, ciphertext = crypto.encrypt_secret(dek, value, aad)
    if existing is None:
        existing = Secret(
            project_id=project.id,
            environment=environment,
            key=key,
            nonce=nonce,
            ciphertext=ciphertext,
            version=version,
        )
        db.add(existing)
    else:
        existing.nonce = nonce
        existing.ciphertext = ciphertext
        existing.version = version
    audit.append(
        db,
        actor_type=actor_type,
        actor_name=actor_name,
        action="secret.create" if created else "secret.update",
        project_slug=project.slug,
        environment=environment,
        key_names=[key],
        detail={"version": version},
        lock=state.lock,
    )
    db.commit()
    db.refresh(existing)
    return existing, created


def delete(
    db: Session,
    state: Runtime,
    project: Project,
    *,
    environment: str,
    key: str,
    actor_type: str = "user",
    actor_name: str = "user",
) -> None:
    """Delete a secret by name."""
    environment = validate_environment(environment)
    secret = get(db, project, environment, key)
    if secret is None:
        raise SecretError(f"secret not found: {key}")
    db.delete(secret)
    audit.append(
        db,
        actor_type=actor_type,
        actor_name=actor_name,
        action="secret.delete",
        project_slug=project.slug,
        environment=environment,
        key_names=[key],
        lock=state.lock,
    )
    db.commit()


def reveal(
    db: Session,
    state: Runtime,
    project: Project,
    *,
    environment: str,
    key: str,
    passphrase: str,
    actor_name: str = "user",
) -> str:
    """Decrypt one value after re-verifying the passphrase."""
    environment = validate_environment(environment)
    try:
        vault.verify_passphrase(db, state, passphrase)
    except crypto.InvalidPassphrase:
        audit.append(
            db,
            actor_type="user",
            actor_name=actor_name,
            action="secret.reveal",
            project_slug=project.slug,
            environment=environment,
            key_names=[key],
            result="denied",
            lock=state.lock,
        )
        db.commit()
        raise
    secret = get(db, project, environment, key)
    if secret is None:
        raise SecretError(f"secret not found: {key}")
    value = _decrypt(secret, state)
    audit.append(
        db,
        actor_type="user",
        actor_name=actor_name,
        action="secret.reveal",
        project_slug=project.slug,
        environment=environment,
        key_names=[key],
        lock=state.lock,
    )
    db.commit()
    return value


def import_values(
    db: Session,
    state: Runtime,
    project: Project,
    *,
    environment: str,
    values: dict[str, str],
    replace: bool,
    issues: list[envfile.ParseIssue] | None = None,
    actor_type: str = "user",
    actor_name: str = "user",
) -> ImportResult:
    """Import parsed .env values, optionally overwriting existing keys."""
    environment = validate_environment(environment)
    if not values:
        raise SecretError("no valid keys found in .env")
    dek = _dek(state)
    created = updated = skipped = 0
    names: list[str] = []
    for key, value in values.items():
        key = _validate_key(key)
        value = _validate_value(value)
        existing = get(db, project, environment, key)
        if existing is not None and not replace:
            skipped += 1
            continue
        version = 1 if existing is None else existing.version + 1
        aad = crypto.secret_aad(project.id, environment, key, version)
        nonce, ciphertext = crypto.encrypt_secret(dek, value, aad)
        if existing is None:
            db.add(
                Secret(
                    project_id=project.id,
                    environment=environment,
                    key=key,
                    nonce=nonce,
                    ciphertext=ciphertext,
                    version=version,
                )
            )
            created += 1
        else:
            existing.nonce = nonce
            existing.ciphertext = ciphertext
            existing.version = version
            updated += 1
        names.append(key)
    audit.append(
        db,
        actor_type=actor_type,
        actor_name=actor_name,
        action="secret.import",
        project_slug=project.slug,
        environment=environment,
        key_names=names,
        detail={"created": created, "updated": updated, "skipped": skipped},
        lock=state.lock,
    )
    db.commit()
    return ImportResult(
        created=created,
        updated=updated,
        skipped=skipped,
        names=names,
        issues=issues or [],
    )


def export_text(
    db: Session,
    state: Runtime,
    project: Project,
    *,
    environment: str,
    passphrase: str,
    actor_name: str = "user",
) -> str:
    """Render a project's environment as .env text after re-authentication."""
    environment = validate_environment(environment)
    try:
        vault.verify_passphrase(db, state, passphrase)
    except crypto.InvalidPassphrase:
        audit.append(
            db,
            actor_type="user",
            actor_name=actor_name,
            action="secret.export",
            project_slug=project.slug,
            environment=environment,
            result="denied",
            lock=state.lock,
        )
        db.commit()
        raise
    rows = list_names(db, project, environment)
    values = {row.key: _decrypt(row, state) for row in rows}
    audit.append(
        db,
        actor_type="user",
        actor_name=actor_name,
        action="secret.export",
        project_slug=project.slug,
        environment=environment,
        key_names=values.keys(),
        lock=state.lock,
    )
    db.commit()
    return envfile.render_env(values)


def values_for_exec(
    db: Session, state: Runtime, project: Project, environment: str
) -> dict[str, str]:
    """Decrypt every secret needed to launch a child process.

    The caller must not serialize the return value to an API response; it is
    consumed only by the process runner inside the daemon.
    """
    environment = validate_environment(environment)
    return {row.key: _decrypt(row, state) for row in list_names(db, project, environment)}


def counts(db: Session) -> dict[str, int]:
    """Total secrets and distinct environments for the dashboard."""
    secrets_total = db.scalar(select(func.count(Secret.id))) or 0
    environments_total = db.scalar(select(func.count(func.distinct(Secret.environment)))) or 0
    return {"secrets": int(secrets_total), "environments": int(environments_total)}


def _decrypt(secret: Secret, state: Runtime) -> str:
    """Decrypt one stored secret with its bound associated data."""
    aad = crypto.secret_aad(secret.project_id, secret.environment, secret.key, secret.version)
    try:
        return crypto.decrypt_secret(_dek(state), secret.nonce, secret.ciphertext, aad)
    except Exception as exc:
        raise SecretCorruption(f"could not decrypt secret {secret.key}") from exc
