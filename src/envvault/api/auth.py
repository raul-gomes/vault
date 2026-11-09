"""Authentication endpoints: unlock/login, session, lock and passphrase change."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from envvault import __version__
from envvault.api.deps import (
    check_origin,
    get_client,
    get_db,
    get_runtime,
    get_settings,
    require_session,
)
from envvault.api.serializers import status_payload
from envvault.config import Settings
from envvault.runtime import SESSION_COOKIE, Runtime, hash_token
from envvault.schemas import ChangePassphraseRequest, LoginRequest
from envvault.services import vault

router = APIRouter(tags=["auth"])


@router.get("/v1/health")
def health(
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, object]:
    """Unauthenticated liveness probe used by the CLI to auto-start the daemon."""
    current = vault.status(db, settings, state)
    return {
        "status": "ok",
        "version": __version__,
        **status_payload(current),
    }


@router.get("/v1/session")
def session_info(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, object]:
    """Return session state without requiring authentication."""
    current = vault.status(db, settings, state)
    session = state.get_session(request.cookies.get(SESSION_COOKIE))
    authenticated = session is not None and current.unlocked
    return {
        "authenticated": authenticated,
        "csrf_token": session.csrf if authenticated and session else None,
        "version": __version__,
        **status_payload(current),
    }


@router.post("/v1/auth/login")
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, object]:
    """Unlock the vault and create a short-lived browser session."""
    check_origin(request, settings)
    vault.unlock(db, state, payload.passphrase, get_client(request))
    raw, session = state.create_session()
    response.set_cookie(
        key=SESSION_COOKIE,
        value=raw,
        max_age=settings.session_idle_minutes * 60,
        httponly=True,
        samesite="strict",
        secure=False,
        path="/",
    )
    current = vault.status(db, settings, state)
    return {
        "csrf_token": session.csrf,
        "expires_in": settings.session_idle_minutes * 60,
        **status_payload(current),
    }


@router.post("/v1/auth/logout")
def logout(
    request: Request,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, bool]:
    """Drop the current session cookie (does not lock the vault)."""
    check_origin(request, settings)
    raw = request.cookies.get(SESSION_COOKIE)
    if raw:
        state.sessions.pop(hash_token(raw), None)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@router.post("/v1/auth/lock")
def lock(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
    settings: Annotated[Settings, Depends(get_settings)],
    _session: Annotated[object, Depends(require_session)],
) -> dict[str, object]:
    """Forget the data key, invalidate sessions and stop running commands."""
    vault.lock(db, state)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return status_payload(vault.status(db, settings, state))


@router.post("/v1/auth/passphrase")
def change_passphrase(
    payload: ChangePassphraseRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
    _session: Annotated[object, Depends(require_session)],
) -> dict[str, bool]:
    """Re-wrap the data key with a new passphrase."""
    vault.change_passphrase(
        db,
        state,
        payload.current,
        payload.new,
        client=get_client(request),
    )
    return {"ok": True}
