"""FastAPI dependencies: database session, auth planes, CSRF and origin checks."""

from __future__ import annotations

import hmac
from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from envvault.config import Settings
from envvault.models import ApiToken, Project
from envvault.runtime import CSRF_HEADER, SESSION_COOKIE, LockedError, Runtime
from envvault.services import tokens, vault

MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def get_db(request: Request) -> Iterator[Session]:
    """Yield a request-scoped SQLAlchemy session."""
    factory = request.app.state.session_factory
    with factory() as db:
        yield db


def get_runtime(request: Request) -> Runtime:
    """Return the daemon runtime state."""
    return request.app.state.runtime


def get_settings(request: Request) -> Settings:
    """Return the immutable settings."""
    return request.app.state.settings


def get_client(request: Request) -> str:
    """Return a stable client key for the login throttle."""
    return request.client.host if request.client else "local"


def allowed_origins(settings: Settings) -> set[str]:
    """Origins accepted for browser state-changing requests."""
    hosts = {
        settings.host,
        "127.0.0.1",
        "localhost",
        "[::1]",
    }
    return {f"http://{host}:{settings.port}" for host in hosts}


def check_origin(request: Request, settings: Settings) -> None:
    """Reject cross-site state-changing requests from obscure origins."""
    origin = request.headers.get("origin")
    if origin and origin not in allowed_origins(settings):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "origin not allowed")


def require_session(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> object:
    """Validate the session cookie and, for mutations, the CSRF header."""
    check_origin(request, settings)
    session = state.get_session(request.cookies.get(SESSION_COOKIE))
    if session is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")
    if request.method in MUTATING_METHODS:
        header = request.headers.get(CSRF_HEADER, "")
        if not header or not hmac.compare_digest(header, session.csrf):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "invalid CSRF token")
    try:
        vault.enforce_idle(db, settings, state)
    except LockedError as exc:
        raise HTTPException(status.HTTP_423_LOCKED, str(exc)) from exc
    return session


def require_agent(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ApiToken:
    """Validate a bearer agent token; tokens can never use session endpoints."""
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    token = tokens.authenticate(db, header.split(" ", 1)[1].strip())
    if token is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token")
    try:
        vault.enforce_idle(db, settings, state)
    except LockedError as exc:
        raise HTTPException(status.HTTP_423_LOCKED, str(exc)) from exc
    return token


def project_or_404(db: Session, project_id: str) -> Project:
    """Load a project by id or raise 404."""
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    return project


def authorize_agent(
    token: ApiToken,
    *,
    project_slug: str,
    environment: str,
    command: list[str] | None = None,
) -> None:
    """Map a token authorization failure to HTTP 403."""
    try:
        tokens.authorize(
            token,
            project_slug=project_slug,
            environment=environment,
            command=command,
        )
    except tokens.AgentForbidden as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
