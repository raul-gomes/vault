"""Projects API: create, list, update, delete and environment discovery."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from envvault.api.deps import get_db, get_runtime, project_or_404, require_session
from envvault.api.serializers import project_payload
from envvault.models import Project
from envvault.runtime import Runtime
from envvault.schemas import (
    EnvironmentCreateRequest,
    ProjectCreateRequest,
    ProjectDeleteRequest,
    ProjectUpdateRequest,
)
from envvault.services import projects as project_service

router = APIRouter(tags=["projects"], dependencies=[Depends(require_session)])


@router.get("/v1/projects")
def list_projects(db: Annotated[Session, Depends(get_db)]) -> dict[str, object]:
    """List every registered project with secret counts."""
    items = [project_payload(db, project) for project in project_service.list_projects(db)]
    return {"items": items, "total": len(items)}


@router.post("/v1/projects", status_code=status.HTTP_201_CREATED)
def create_project(
    payload: ProjectCreateRequest,
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
) -> dict[str, object]:
    """Register a local directory as a project."""
    project = project_service.create(
        db, state, slug=payload.slug, name=payload.name, path=payload.path
    )
    return project_payload(db, project)


@router.get("/v1/projects/{project_id}")
def get_project(
    project_id: str,
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, object]:
    """Return one project with its environments."""
    return project_payload(db, project_or_404(db, project_id))


@router.patch("/v1/projects/{project_id}")
def update_project(
    project_id: str,
    payload: ProjectUpdateRequest,
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
) -> dict[str, object]:
    """Update a project's name or path."""
    project = project_or_404(db, project_id)
    updated = project_service.update(db, state, project, name=payload.name, path=payload.path)
    return project_payload(db, updated)


@router.delete("/v1/projects/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(
    project_id: str,
    payload: ProjectDeleteRequest,
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
) -> None:
    """Delete a project after the caller echoes its slug."""
    project = project_or_404(db, project_id)
    if payload.confirm_slug != project.slug:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "confirmation slug does not match")
    project_service.delete(db, state, project)


@router.get("/v1/projects/{project_id}/environments")
def list_environments(
    project_id: str,
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, object]:
    """Return environments for the project with counts."""
    project = project_or_404(db, project_id)
    return {"items": project_service.environments(db, project)}


@router.post("/v1/projects/{project_id}/environments", status_code=status.HTTP_201_CREATED)
def create_environment(
    project_id: str,
    payload: EnvironmentCreateRequest,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
) -> dict[str, object]:
    """Create an empty environment so it persists in the dashboard."""
    project = project_or_404(db, project_id)
    row, created = project_service.create_environment(db, state, project, payload.name)
    if not created:
        response.status_code = status.HTTP_200_OK
    return {"environment": row.name, "created": created}


@router.delete(
    "/v1/projects/{project_id}/environments/{name}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_environment(
    project_id: str,
    name: str,
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
) -> None:
    """Remove an environment only when it has no secrets left."""
    project = project_or_404(db, project_id)
    project_service.delete_environment(db, state, project, name)


__all__ = ["Project", "router"]
