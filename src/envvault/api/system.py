"""Dashboard, audit, settings and password generation endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from envvault import __version__
from envvault.api.deps import get_db, get_runtime, get_settings, require_session
from envvault.api.serializers import audit_payload, status_payload
from envvault.config import Settings
from envvault.models import AuditEntry, Project
from envvault.passwords import PasswordOptions, entropy_bits, generate_password
from envvault.runtime import Runtime
from envvault.schemas import GenerateRequest, SettingsRequest
from envvault.services import audit, vault
from envvault.services import credentials as credential_service
from envvault.services import secrets as secret_service
from envvault.services import tokens as token_service
from envvault.services.vault import (
    META_LOCK_TIMEOUT,
    META_MAX_UNLOCK_HOURS,
    get_meta,
    set_meta,
)

router = APIRouter(tags=["system"], dependencies=[Depends(require_session)])


@router.get("/v1/overview")
def overview(
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, object]:
    """Aggregate counters and recent activity for the dashboard."""
    project_total = db.scalar(select(func.count(Project.id))) or 0
    token_items = token_service.list_tokens(db)
    recent = db.scalars(select(AuditEntry).order_by(AuditEntry.id.desc()).limit(8)).all()
    return {
        "projects": int(project_total),
        **secret_service.counts(db),
        **credential_service.counts(db),
        "active_tokens": sum(1 for token in token_items if token.revoked_at is None),
        "recent_audit": [audit_payload(entry) for entry in recent],
        "status": status_payload(vault.status(db, settings, state)),
        "paths": {"home": str(settings.home), "database": str(settings.db_path)},
        "version": __version__,
    }


@router.get("/v1/audit")
def list_audit(
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    project_slug: str | None = None,
    action: str | None = None,
) -> dict[str, object]:
    """List audit entries newest first, optionally filtered."""
    statement = select(AuditEntry)
    counter = select(func.count(AuditEntry.id))
    if project_slug:
        statement = statement.where(AuditEntry.project_slug == project_slug)
        counter = counter.where(AuditEntry.project_slug == project_slug)
    if action:
        statement = statement.where(AuditEntry.action.like(f"{action}%"))
        counter = counter.where(AuditEntry.action.like(f"{action}%"))
    total = db.scalar(counter) or 0
    rows = db.scalars(statement.order_by(AuditEntry.id.desc()).limit(limit).offset(offset)).all()
    return {
        "items": [audit_payload(entry) for entry in rows],
        "total": int(total),
        "limit": limit,
        "offset": offset,
    }


@router.get("/v1/audit/verify")
def verify_audit(
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
) -> dict[str, object]:
    """Recompute the hash chain and report the first bad entry, if any."""
    valid, first_bad_id = audit.verify_chain(db, state.audit_key)
    return {"valid": valid, "first_bad_id": first_bad_id}


@router.get("/v1/settings")
def get_settings_payload(
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, object]:
    """Return mutable settings and safe instance information."""
    return {
        "lock_timeout_minutes": vault.timeout_minutes(db, settings),
        "max_unlock_hours": vault.max_unlock_hours(db, settings),
        "host": settings.host,
        "port": settings.port,
        "home": str(settings.home),
        "database": str(settings.db_path),
        "version": __version__,
        "status": status_payload(vault.status(db, settings, state)),
    }


@router.put("/v1/settings")
def update_settings(
    payload: SettingsRequest,
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, object]:
    """Update the idle-lock timeout and, when given, the absolute unlock limit."""
    previous = get_meta(db, META_LOCK_TIMEOUT)
    set_meta(db, META_LOCK_TIMEOUT, str(payload.lock_timeout_minutes))
    previous_max = get_meta(db, META_MAX_UNLOCK_HOURS)
    if payload.max_unlock_hours is not None:
        set_meta(db, META_MAX_UNLOCK_HOURS, str(payload.max_unlock_hours))
    audit.append(
        db,
        actor_type="user",
        actor_name="user",
        action="settings.update",
        detail={
            "lock_timeout_minutes": payload.lock_timeout_minutes,
            "previous": previous,
            "max_unlock_hours": payload.max_unlock_hours,
            "previous_max_unlock_hours": previous_max,
        },
        state=state,
    )
    db.commit()
    return {
        "lock_timeout_minutes": vault.timeout_minutes(db, settings),
        "max_unlock_hours": vault.max_unlock_hours(db, settings),
    }


@router.post("/v1/generate")
def generate(
    payload: GenerateRequest,
    _session: Annotated[object, Depends(require_session)],
) -> dict[str, object]:
    """Generate a strong password without storing it."""
    options = PasswordOptions(
        length=payload.length,
        upper=payload.upper,
        lower=payload.lower,
        digits=payload.digits,
        symbols=payload.symbols,
    )
    return {
        "password": generate_password(options),
        "entropy_bits": round(entropy_bits(options), 1),
        "length": payload.length,
        "alphabet_size": len(options.alphabet()),
    }
