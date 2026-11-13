"""Service credentials: encrypted CRUD, search and audited reveal.

A credential can be **global** (shared across the vault) or belong to one
project (a client). Only ``name``, ``category`` and the project association are
plaintext metadata; username, password, URL and notes are stored together as one
AES-GCM encrypted JSON payload bound to the credential id and version.
"""

from __future__ import annotations

import json
import re

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from envvault import crypto
from envvault.models import Credential, Project, new_id
from envvault.runtime import LockedError, Runtime
from envvault.services import audit, vault

NAME_MAX_LENGTH = 200
CATEGORY_MAX_LENGTH = 40
CATEGORY_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
DEFAULT_CATEGORY = "other"
FIELD_LIMITS = {
    "username": 500,
    "password": 8192,
    "url": 2000,
    "notes": 65536,
}
PAYLOAD_MAX_BYTES = 128 * 1024


class CredentialError(ValueError):
    """Raised for invalid credential data or a missing credential."""


class CredentialCorruption(RuntimeError):
    """Raised when stored credential ciphertext cannot be decrypted."""


def _dek(state: Runtime) -> bytes:
    """Return the in-memory data key or fail loudly."""
    if state.dek is None:
        raise LockedError("vault is locked")
    return state.dek


def _validate_name(name: str) -> str:
    """Normalize and validate the visible credential name."""
    name = name.strip()
    if not name:
        raise CredentialError("name is required")
    if len(name) > NAME_MAX_LENGTH:
        raise CredentialError(f"name exceeds {NAME_MAX_LENGTH} chars")
    return name


def _validate_category(category: str) -> str:
    """Normalize a category slug; an empty value means ``other``."""
    category = (category or "").strip().lower()
    if not category:
        return DEFAULT_CATEGORY
    if len(category) > CATEGORY_MAX_LENGTH or not CATEGORY_PATTERN.match(category):
        raise CredentialError("category must be 1-40 chars: a-z, 0-9, '-' or '_'")
    return category


def _build_payload(
    *,
    username: str,
    password: str,
    url: str,
    notes: str,
) -> dict[str, str]:
    """Validate the encrypted fields and return the payload to serialize."""
    values = {
        "username": username or "",
        "password": password or "",
        "url": url or "",
        "notes": notes or "",
    }
    for field, limit in FIELD_LIMITS.items():
        if len(values[field]) > limit:
            raise CredentialError(f"{field} exceeds {limit} chars")
    if len(json.dumps(values, ensure_ascii=False).encode("utf-8")) > PAYLOAD_MAX_BYTES:
        raise CredentialError(f"credential payload exceeds {PAYLOAD_MAX_BYTES} bytes")
    return values


def _encrypt(
    dek: bytes, credential_id: str, version: int, payload: dict[str, str]
) -> tuple[bytes, bytes]:
    """Serialize and encrypt one credential payload."""
    plaintext = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    aad = crypto.credential_aad(credential_id, version)
    return crypto.encrypt_secret(dek, plaintext, aad)


def _decrypt(credential: Credential, state: Runtime) -> dict[str, str]:
    """Decrypt and validate one credential payload."""
    aad = crypto.credential_aad(credential.id, credential.version)
    try:
        raw = crypto.decrypt_secret(_dek(state), credential.nonce, credential.ciphertext, aad)
    except Exception as exc:
        raise CredentialCorruption(f"could not decrypt credential {credential.name}") from exc
    try:
        payload = json.loads(raw)
    except ValueError as exc:
        raise CredentialCorruption(f"could not decode credential {credential.name}") from exc
    if not isinstance(payload, dict):
        raise CredentialCorruption(f"could not decode credential {credential.name}")
    return {field: str(payload.get(field, "") or "") for field in FIELD_LIMITS}


def _resolve_project(db: Session, project_id: str | None) -> Project | None:
    """Validate an optional project association (None means global)."""
    if project_id is None or not project_id.strip():
        return None
    project = db.get(Project, project_id.strip())
    if project is None:
        raise CredentialError(f"project not found: {project_id}")
    return project


def list_credentials(
    db: Session,
    *,
    query: str | None = None,
    category: str | None = None,
    project_id: str | None = None,
    global_only: bool = False,
) -> list[Credential]:
    """List credentials ordered by category and name, optionally filtered.

    ``project_id`` returns only that project's credentials. ``global_only``
    returns only shared credentials. With neither, everything is returned.
    """
    statement = select(Credential)
    if global_only:
        statement = statement.where(Credential.project_id.is_(None))
    elif project_id and project_id.strip():
        project = _resolve_project(db, project_id)
        statement = statement.where(Credential.project_id == project.id)
    if category:
        statement = statement.where(Credential.category == _validate_category(category))
    if query and query.strip():
        pattern = f"%{query.strip()}%"
        statement = statement.where(
            or_(Credential.name.ilike(pattern), Credential.category.ilike(pattern))
        )
    statement = statement.order_by(Credential.category, func.lower(Credential.name))
    return list(db.scalars(statement).all())


def get(db: Session, credential_id: str) -> Credential | None:
    """Find one credential by id."""
    return db.get(Credential, credential_id)


def create(
    db: Session,
    state: Runtime,
    *,
    name: str,
    category: str = DEFAULT_CATEGORY,
    username: str = "",
    password: str = "",
    url: str = "",
    notes: str = "",
    project_id: str | None = None,
    actor_type: str = "user",
    actor_name: str = "user",
) -> Credential:
    """Create an encrypted credential record and audit it."""
    dek = _dek(state)
    name = _validate_name(name)
    category = _validate_category(category)
    project = _resolve_project(db, project_id)
    payload = _build_payload(username=username, password=password, url=url, notes=notes)
    credential_id = new_id()
    nonce, ciphertext = _encrypt(dek, credential_id, 1, payload)
    credential = Credential(
        id=credential_id,
        project_id=project.id if project else None,
        name=name,
        category=category,
        nonce=nonce,
        ciphertext=ciphertext,
        version=1,
    )
    db.add(credential)
    audit.append(
        db,
        actor_type=actor_type,
        actor_name=actor_name,
        action="credential.create",
        project_slug=project.slug if project else None,
        key_names=[name],
        detail={
            "category": category,
            "version": 1,
            "scope": project.slug if project else "global",
        },
        state=state,
    )
    db.commit()
    db.refresh(credential)
    return credential


def update(
    db: Session,
    state: Runtime,
    credential: Credential,
    *,
    name: str,
    category: str,
    username: str,
    password: str,
    url: str,
    notes: str,
    project_id: str | None = None,
    actor_type: str = "user",
    actor_name: str = "user",
) -> Credential:
    """Replace the encrypted payload and scope, incrementing the version."""
    dek = _dek(state)
    name = _validate_name(name)
    category = _validate_category(category)
    project = _resolve_project(db, project_id)
    payload = _build_payload(username=username, password=password, url=url, notes=notes)
    version = credential.version + 1
    nonce, ciphertext = _encrypt(dek, credential.id, version, payload)
    credential.project_id = project.id if project else None
    credential.name = name
    credential.category = category
    credential.nonce = nonce
    credential.ciphertext = ciphertext
    credential.version = version
    audit.append(
        db,
        actor_type=actor_type,
        actor_name=actor_name,
        action="credential.update",
        project_slug=project.slug if project else None,
        key_names=[name],
        detail={
            "category": category,
            "version": version,
            "scope": project.slug if project else "global",
        },
        state=state,
    )
    db.commit()
    db.refresh(credential)
    return credential


def delete(
    db: Session,
    state: Runtime,
    credential: Credential,
    *,
    actor_type: str = "user",
    actor_name: str = "user",
) -> None:
    """Delete a credential record and audit the action."""
    name = credential.name
    category = credential.category
    project_slug = credential.project.slug if credential.project else None
    db.delete(credential)
    audit.append(
        db,
        actor_type=actor_type,
        actor_name=actor_name,
        action="credential.delete",
        project_slug=project_slug,
        key_names=[name],
        detail={
            "category": category,
            "scope": project_slug or "global",
        },
        state=state,
    )
    db.commit()


def reveal(
    db: Session,
    state: Runtime,
    credential: Credential,
    *,
    passphrase: str,
    actor_name: str = "user",
) -> dict[str, str]:
    """Decrypt every field after re-verifying the master passphrase."""
    project_slug = credential.project.slug if credential.project else None
    try:
        vault.verify_passphrase(db, state, passphrase)
    except crypto.InvalidPassphrase:
        audit.append(
            db,
            actor_type="user",
            actor_name=actor_name,
            action="credential.reveal",
            project_slug=project_slug,
            key_names=[credential.name],
            result="denied",
            detail={
                "category": credential.category,
                "scope": project_slug or "global",
            },
            state=state,
        )
        db.commit()
        raise
    payload = _decrypt(credential, state)
    audit.append(
        db,
        actor_type="user",
        actor_name=actor_name,
        action="credential.reveal",
        project_slug=project_slug,
        key_names=[credential.name],
        detail={
            "category": credential.category,
            "scope": project_slug or "global",
        },
        state=state,
    )
    db.commit()
    return payload


def counts(db: Session) -> dict[str, int]:
    """Total credentials for the dashboard."""
    total = db.scalar(select(func.count(Credential.id))) or 0
    return {"credentials": int(total)}
