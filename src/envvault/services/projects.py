"""Project CRUD and environment discovery."""

from __future__ import annotations

import re
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from envvault.models import Environment, Project, Secret
from envvault.runtime import Runtime
from envvault.services import audit

SLUG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
ENVIRONMENT_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")


class ProjectError(ValueError):
    """Raised for invalid or conflicting project data."""


def validate_slug(slug: str) -> str:
    """Validate and normalize a project slug."""
    slug = slug.strip().lower()
    if not SLUG_PATTERN.match(slug):
        raise ProjectError("slug must be 2-64 chars: a-z, 0-9, '-' or '_'")
    return slug


def validate_environment(environment: str) -> str:
    """Validate and normalize an environment name."""
    environment = environment.strip().lower()
    if not ENVIRONMENT_PATTERN.match(environment):
        raise ProjectError("environment must be 1-40 chars: a-z, 0-9, '-' or '_'")
    return environment


def create(
    db: Session,
    state: Runtime,
    *,
    slug: str,
    name: str,
    path: str,
    actor_type: str = "user",
    actor_name: str = "user",
) -> Project:
    """Register a project. The path must exist and be a directory."""
    slug = validate_slug(slug)
    name = name.strip()
    if not name:
        raise ProjectError("name is required")
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_dir():
        raise ProjectError(f"project path does not exist or is not a directory: {resolved}")
    if db.scalars(select(Project).where(Project.slug == slug)).first():
        raise ProjectError(f"project slug already exists: {slug}")
    project = Project(slug=slug, name=name, path=str(resolved))
    db.add(project)
    db.flush()
    audit.append(
        db,
        actor_type=actor_type,
        actor_name=actor_name,
        action="project.create",
        project_slug=project.slug,
        detail={"path": str(resolved)},
        lock=state.lock,
    )
    db.commit()
    return project


def list_projects(db: Session) -> list[Project]:
    """Return projects ordered by name."""
    return list(db.scalars(select(Project).order_by(func.lower(Project.name))).all())


def get_by_slug(db: Session, slug: str) -> Project | None:
    """Find a project by slug."""
    return db.scalars(select(Project).where(Project.slug == slug)).first()


def get_by_id(db: Session, project_id: str) -> Project | None:
    """Find a project by id."""
    return db.get(Project, project_id)


def update(
    db: Session,
    state: Runtime,
    project: Project,
    *,
    name: str | None = None,
    path: str | None = None,
    actor_type: str = "user",
    actor_name: str = "user",
) -> Project:
    """Update a project's display name and/or path."""
    if name is not None:
        name = name.strip()
        if not name:
            raise ProjectError("name is required")
        project.name = name
    if path is not None:
        resolved = Path(path).expanduser().resolve()
        if not resolved.is_dir():
            raise ProjectError(f"project path does not exist or is not a directory: {resolved}")
        project.path = str(resolved)
    audit.append(
        db,
        actor_type=actor_type,
        actor_name=actor_name,
        action="project.update",
        project_slug=project.slug,
        lock=state.lock,
    )
    db.commit()
    return project


def delete(
    db: Session,
    state: Runtime,
    project: Project,
    *,
    actor_type: str = "user",
    actor_name: str = "user",
) -> None:
    """Delete a project and cascade its secrets/tokens."""
    slug = project.slug
    db.delete(project)
    audit.append(
        db,
        actor_type=actor_type,
        actor_name=actor_name,
        action="project.delete",
        project_slug=slug,
        lock=state.lock,
    )
    db.commit()


def environments(db: Session, project: Project) -> list[dict[str, object]]:
    """Return every named environment with secret counts and last update.

    Environments come from both the registry (so empty ones persist) and the
    secrets table (defensive, for rows written before the registry existed).
    """
    rows = db.execute(
        select(
            Secret.environment,
            func.count(Secret.id),
            func.max(Secret.updated_at),
        )
        .where(Secret.project_id == project.id)
        .group_by(Secret.environment)
    ).all()
    counts = {environment: (int(count), updated) for environment, count, updated in rows}
    registered = set(
        db.scalars(select(Environment.name).where(Environment.project_id == project.id)).all()
    )
    result: list[dict[str, object]] = []
    for name in sorted(registered | set(counts)):
        count, updated = counts.get(name, (0, None))
        result.append(
            {
                "environment": name,
                "count": count,
                "updated_at": updated,
            }
        )
    return result


def ensure_environment(db: Session, project: Project, name: str) -> Environment:
    """Register an environment name, returning the existing row if present."""
    name = validate_environment(name)
    existing = db.scalars(
        select(Environment).where(Environment.project_id == project.id, Environment.name == name)
    ).first()
    if existing is not None:
        return existing
    environment = Environment(project_id=project.id, name=name)
    db.add(environment)
    db.flush()
    return environment


def create_environment(
    db: Session,
    state: Runtime,
    project: Project,
    name: str,
    *,
    actor_type: str = "user",
    actor_name: str = "user",
) -> tuple[Environment, bool]:
    """Register an environment and audit the action. Returns ``(row, created)``."""
    name = validate_environment(name)
    existing = db.scalars(
        select(Environment).where(Environment.project_id == project.id, Environment.name == name)
    ).first()
    if existing is not None:
        return existing, False
    row = Environment(project_id=project.id, name=name)
    db.add(row)
    db.flush()
    audit.append(
        db,
        actor_type=actor_type,
        actor_name=actor_name,
        action="environment.create",
        project_slug=project.slug,
        environment=name,
        lock=state.lock,
    )
    db.commit()
    return row, True


def delete_environment(
    db: Session,
    state: Runtime,
    project: Project,
    name: str,
    *,
    actor_type: str = "user",
    actor_name: str = "user",
) -> None:
    """Remove an empty environment; refuse if it still has secrets."""
    name = validate_environment(name)
    has_secrets = db.scalars(
        select(Secret.id)
        .where(Secret.project_id == project.id, Secret.environment == name)
        .limit(1)
    ).first()
    if has_secrets is not None:
        raise ProjectError("environment still has secrets; delete them first")
    row = db.scalars(
        select(Environment).where(Environment.project_id == project.id, Environment.name == name)
    ).first()
    if row is None:
        raise ProjectError(f"environment not found: {name}")
    db.delete(row)
    audit.append(
        db,
        actor_type=actor_type,
        actor_name=actor_name,
        action="environment.delete",
        project_slug=project.slug,
        environment=name,
        lock=state.lock,
    )
    db.commit()
