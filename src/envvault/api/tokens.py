"""Token management API (human session only)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from envvault.api.deps import get_db, get_runtime, project_or_404, require_session
from envvault.api.serializers import token_payload
from envvault.models import ApiToken
from envvault.runtime import Runtime
from envvault.schemas import TokenCreateRequest
from envvault.services import tokens as token_service

router = APIRouter(tags=["tokens"], dependencies=[Depends(require_session)])


@router.get("/v1/tokens")
def list_tokens(db: Annotated[Session, Depends(get_db)]) -> dict[str, object]:
    """List token metadata (hashes are never returned)."""
    items = [token_payload(token) for token in token_service.list_tokens(db)]
    return {"items": items, "total": len(items)}


@router.post("/v1/tokens", status_code=status.HTTP_201_CREATED)
def create_token(
    payload: TokenCreateRequest,
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
) -> dict[str, object]:
    """Create an agent token; the raw value is shown exactly once."""
    project = project_or_404(db, payload.project_id)
    token, raw = token_service.create(
        db,
        state,
        name=payload.name,
        project=project,
        environments=payload.environments,
        can_list=payload.can_list,
        can_inject=payload.can_inject,
        allowed_commands=payload.allowed_commands,
    )
    return {"token": raw, "item": token_payload(token)}


@router.delete("/v1/tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_token(
    token_id: str,
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
) -> None:
    """Revoke a token immediately."""
    token = db.get(ApiToken, token_id)
    if token is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "token not found")
    if token.revoked_at is None:
        token_service.revoke(db, state, token)
