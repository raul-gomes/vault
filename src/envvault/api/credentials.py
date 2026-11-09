"""Credentials API: global service logins stored encrypted, human-only."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from envvault.api.deps import get_db, get_runtime, require_session
from envvault.api.serializers import credential_payload
from envvault.models import Credential
from envvault.runtime import Runtime
from envvault.schemas import CredentialRevealRequest, CredentialUpsertRequest
from envvault.services import credentials as credential_service

router = APIRouter(
    tags=["credentials"],
    dependencies=[Depends(require_session)],
)


def credential_or_404(db: Session, credential_id: str) -> Credential:
    """Load a credential by id or raise 404."""
    credential = credential_service.get(db, credential_id)
    if credential is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "credential not found")
    return credential


@router.get("/v1/credentials")
def list_credentials(
    db: Annotated[Session, Depends(get_db)],
    query: Annotated[str | None, Query(max_length=200)] = None,
    category: Annotated[str | None, Query(max_length=40)] = None,
    project_id: Annotated[str | None, Query(max_length=36)] = None,
    global_only: bool = False,
) -> dict[str, object]:
    """List credential metadata; encrypted fields are never included."""
    rows = credential_service.list_credentials(
        db,
        query=query,
        category=category,
        project_id=project_id,
        global_only=global_only,
    )
    return {"items": [credential_payload(row) for row in rows], "total": len(rows)}


@router.post("/v1/credentials", status_code=status.HTTP_201_CREATED)
def create_credential(
    payload: CredentialUpsertRequest,
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
) -> dict[str, object]:
    """Create a credential after encrypting its sensitive fields."""
    credential = credential_service.create(
        db,
        state,
        name=payload.name,
        category=payload.category,
        username=payload.username,
        password=payload.password,
        url=payload.url,
        notes=payload.notes,
        project_id=payload.project_id,
    )
    return {"item": credential_payload(credential)}


@router.get("/v1/credentials/{credential_id}")
def get_credential(
    credential_id: str,
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, object]:
    """Return one credential's metadata."""
    return {"item": credential_payload(credential_or_404(db, credential_id))}


@router.put("/v1/credentials/{credential_id}")
def update_credential(
    credential_id: str,
    payload: CredentialUpsertRequest,
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
) -> dict[str, object]:
    """Replace the encrypted credential payload and bump its version."""
    credential = credential_or_404(db, credential_id)
    updated = credential_service.update(
        db,
        state,
        credential,
        name=payload.name,
        category=payload.category,
        username=payload.username,
        password=payload.password,
        url=payload.url,
        notes=payload.notes,
        project_id=payload.project_id,
    )
    return {"item": credential_payload(updated)}


@router.delete("/v1/credentials/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_credential(
    credential_id: str,
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
) -> None:
    """Delete a credential."""
    credential_service.delete(db, state, credential_or_404(db, credential_id))


@router.post("/v1/credentials/{credential_id}/reveal")
def reveal_credential(
    credential_id: str,
    payload: CredentialRevealRequest,
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
) -> dict[str, object]:
    """Reveal every encrypted field after re-verifying the passphrase."""
    credential = credential_or_404(db, credential_id)
    values = credential_service.reveal(
        db,
        state,
        credential,
        passphrase=payload.passphrase,
    )
    return {
        "id": credential.id,
        "name": credential.name,
        "category": credential.category,
        "version": credential.version,
        "scope": "project" if credential.project else "global",
        "project": (
            {
                "id": credential.project.id,
                "slug": credential.project.slug,
                "name": credential.project.name,
            }
            if credential.project
            else None
        ),
        **values,
    }


__all__ = ["Credential", "router"]
