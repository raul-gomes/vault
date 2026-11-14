"""JSON serializers for API responses (never include secret plaintext)."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from envvault.models import ApiToken, AuditEntry, Credential, Project, Secret
from envvault.services.projects import environments
from envvault.services.tokens import command_list, environment_list
from envvault.services.vault import VaultStatus


def _iso(value: datetime | None) -> str | None:
    """Serialize a datetime, tolerating naive SQLite values."""
    return value.isoformat() if value is not None else None


def project_payload(db: Session, project: Project) -> dict[str, Any]:
    """Project metadata plus per-environment counts."""
    return {
        "id": project.id,
        "slug": project.slug,
        "name": project.name,
        "path": project.path,
        "created_at": _iso(project.created_at),
        "updated_at": _iso(project.updated_at),
        "secret_count": len(project.secrets),
        "environments": [
            {
                "environment": item["environment"],
                "count": item["count"],
                "updated_at": _iso(item["updated_at"]),
            }
            for item in environments(db, project)
        ],
    }


def secret_payload(secret: Secret) -> dict[str, Any]:
    """Secret metadata; plaintext is only returned by the reveal endpoint."""
    return {
        "id": secret.id,
        "key": secret.key,
        "environment": secret.environment,
        "version": secret.version,
        "created_at": _iso(secret.created_at),
        "updated_at": _iso(secret.updated_at),
    }


def credential_payload(credential: Credential) -> dict[str, Any]:
    """Credential metadata; the encrypted fields only appear on reveal."""
    project = credential.project
    return {
        "id": credential.id,
        "name": credential.name,
        "category": credential.category,
        "version": credential.version,
        "scope": "project" if project is not None else "global",
        "project": (
            {"id": project.id, "slug": project.slug, "name": project.name}
            if project is not None
            else None
        ),
        "created_at": _iso(credential.created_at),
        "updated_at": _iso(credential.updated_at),
    }


def token_payload(token: ApiToken) -> dict[str, Any]:
    """Token metadata with parsed scope JSON."""
    return {
        "id": token.id,
        "name": token.name,
        "prefix": token.prefix,
        "project": {
            "id": token.project.id,
            "slug": token.project.slug,
            "name": token.project.name,
        },
        "environments": environment_list(token),
        "can_list": token.can_list,
        "can_inject": token.can_inject,
        "allowed_commands": command_list(token),
        "any_command": token.any_command,
        "created_at": _iso(token.created_at),
        "last_used_at": _iso(token.last_used_at),
        "revoked_at": _iso(token.revoked_at),
        "active": token.revoked_at is None,
    }


def audit_payload(entry: AuditEntry) -> dict[str, Any]:
    """Audit entry with parsed JSON columns."""
    return {
        "id": entry.id,
        "ts": entry.ts,
        "actor_type": entry.actor_type,
        "actor_name": entry.actor_name,
        "action": entry.action,
        "project_slug": entry.project_slug,
        "environment": entry.environment,
        "key_names": _loads(entry.key_names),
        "command": entry.command,
        "result": entry.result,
        "detail": _loads(entry.detail),
        "prev_hash": entry.prev_hash,
        "hash": entry.hash,
    }


def status_payload(status: VaultStatus) -> dict[str, Any]:
    """Public vault status."""
    return {
        "initialized": status.initialized,
        "unlocked": status.unlocked,
        "lock_timeout_minutes": status.lock_timeout_minutes,
        "max_unlock_hours": status.max_unlock_hours,
    }


def _loads(raw: str) -> Any:
    """Decode a JSON column, falling back to the raw string."""
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return raw
