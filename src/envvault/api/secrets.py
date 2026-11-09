"""Secrets API: metadata listing, upsert/delete, reveal, import and export."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from envvault.api.deps import get_db, get_runtime, project_or_404, require_session
from envvault.api.serializers import secret_payload
from envvault.runtime import Runtime
from envvault.schemas import (
    ExportRequest,
    ImportRequest,
    RevealRequest,
    SecretUpsertRequest,
)
from envvault.services import envfile
from envvault.services import secrets as secret_service

router = APIRouter(tags=["secrets"], dependencies=[Depends(require_session)])


@router.get("/v1/projects/{project_id}/secrets")
def list_secrets(
    project_id: str,
    db: Annotated[Session, Depends(get_db)],
    environment: Annotated[str, Query(min_length=1, max_length=40)],
) -> dict[str, object]:
    """List key names and metadata; values are never included."""
    project = project_or_404(db, project_id)
    rows = secret_service.list_names(db, project, environment)
    return {"items": [secret_payload(row) for row in rows], "environment": environment}


@router.put("/v1/projects/{project_id}/secrets")
def upsert_secret(
    project_id: str,
    payload: SecretUpsertRequest,
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
) -> dict[str, object]:
    """Create or replace one secret (encrypted before storage)."""
    project = project_or_404(db, project_id)
    secret, created = secret_service.upsert(
        db,
        state,
        project,
        environment=payload.environment,
        key=payload.key,
        value=payload.value,
    )
    return {"item": secret_payload(secret), "created": created}


@router.delete("/v1/projects/{project_id}/secrets/{key}", status_code=status.HTTP_204_NO_CONTENT)
def delete_secret(
    project_id: str,
    key: str,
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
    environment: Annotated[str, Query(min_length=1, max_length=40)],
) -> None:
    """Delete one secret."""
    project = project_or_404(db, project_id)
    secret_service.delete(db, state, project, environment=environment, key=key)


@router.post("/v1/projects/{project_id}/secrets/{key}/reveal")
def reveal_secret(
    project_id: str,
    key: str,
    payload: RevealRequest,
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
) -> dict[str, object]:
    """Reveal one value after re-verifying the master passphrase."""
    project = project_or_404(db, project_id)
    value = secret_service.reveal(
        db,
        state,
        project,
        environment=payload.environment,
        key=key,
        passphrase=payload.passphrase,
    )
    return {"key": key, "value": value}


@router.post("/v1/projects/{project_id}/import")
def import_env(
    project_id: str,
    payload: ImportRequest,
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
) -> dict[str, object]:
    """Parse .env content and import it, reporting invalid lines."""
    project = project_or_404(db, project_id)
    parsed = envfile.parse_env(payload.content)
    result = secret_service.import_values(
        db,
        state,
        project,
        environment=payload.environment,
        values=parsed.values,
        replace=payload.replace,
        issues=parsed.issues,
    )
    return {
        "created": result.created,
        "updated": result.updated,
        "skipped": result.skipped,
        "names": result.names,
        "issues": [
            {"line": issue.line, "message": issue.message, "level": issue.level}
            for issue in result.issues
        ],
    }


@router.post("/v1/projects/{project_id}/export", response_class=PlainTextResponse)
def export_env(
    project_id: str,
    payload: ExportRequest,
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
) -> PlainTextResponse:
    """Export one environment as .env text after re-authentication."""
    project = project_or_404(db, project_id)
    text = secret_service.export_text(
        db,
        state,
        project,
        environment=payload.environment,
        passphrase=payload.passphrase,
    )
    filename = f"{project.slug}.{payload.environment}.env"
    return PlainTextResponse(
        text,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
