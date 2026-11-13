"""Scoped agent tokens and their authorization rules."""

from __future__ import annotations

import json
import shlex
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from envvault.models import ApiToken, Project
from envvault.runtime import Runtime, hash_token, new_bearer_token
from envvault.services import audit
from envvault.services.projects import validate_environment

MAX_COMMAND_PREFIXES = 20
MAX_COMMAND_LENGTH = 200


class TokenError(ValueError):
    """Raised for invalid token configuration."""


class AgentForbidden(PermissionError):
    """Raised when a token is not allowed to perform an action."""


def create(
    db: Session,
    state: Runtime,
    *,
    name: str,
    project: Project,
    environments: list[str],
    can_list: bool = True,
    can_inject: bool = True,
    allowed_commands: list[str] | None = None,
    any_command: bool = False,
    actor_name: str = "user",
) -> tuple[ApiToken, str]:
    """Create a token. The raw value is returned once and never stored."""
    name = name.strip()
    if not name:
        raise TokenError("token name is required")
    normalized: list[str] = []
    for environment in environments:
        environment = validate_environment(environment)
        if environment not in normalized:
            normalized.append(environment)
    if not normalized:
        raise TokenError("select at least one environment")
    if not can_list and not can_inject:
        raise TokenError("token must allow listing keys or injecting secrets")
    commands = _normalize_commands(allowed_commands or [])
    if any_command and commands:
        raise TokenError("choose either a command list or any command, not both")
    if can_inject and not commands and not any_command:
        raise TokenError(
            "a token that injects secrets needs at least one allowed command "
            "(or an explicit any-command choice)"
        )
    raw = new_bearer_token()
    token = ApiToken(
        name=name,
        token_hash=hash_token(raw),
        prefix=raw[:11],
        project_id=project.id,
        environments=json.dumps(normalized),
        can_list=can_list,
        can_inject=can_inject,
        allowed_commands=json.dumps(commands),
        any_command=any_command,
    )
    db.add(token)
    db.flush()
    audit.append(
        db,
        actor_type="user",
        actor_name=actor_name,
        action="token.create",
        project_slug=project.slug,
        detail={
            "token_name": name,
            "environments": normalized,
            "can_list": can_list,
            "can_inject": can_inject,
            "allowed_commands": commands,
            "any_command": any_command,
        },
        state=state,
    )
    db.commit()
    db.refresh(token)
    return token, raw


def _normalize_commands(commands: list[str]) -> list[str]:
    """Validate command prefixes used as an extra guard on injection.

    Each prefix is stored as typed but must split into argv with shell quoting
    rules (``shlex``), because matching compares argv elements.
    """
    normalized = [command.strip() for command in commands if command.strip()]
    if len(normalized) > MAX_COMMAND_PREFIXES:
        raise TokenError(f"at most {MAX_COMMAND_PREFIXES} command prefixes")
    for command in normalized:
        if len(command) > MAX_COMMAND_LENGTH:
            raise TokenError(f"command prefix too long: {command[:40]}...")
        try:
            shlex.split(command)
        except ValueError as exc:
            raise TokenError(f"invalid command prefix {command!r}: {exc}") from exc
    return normalized


def list_tokens(db: Session) -> list[ApiToken]:
    """Return tokens newest first."""
    return list(db.scalars(select(ApiToken).order_by(ApiToken.created_at.desc())).all())


def revoke(db: Session, state: Runtime, token: ApiToken, *, actor_name: str = "user") -> None:
    """Revoke a token immediately."""
    token.revoked_at = datetime.now(UTC)
    audit.append(
        db,
        actor_type="user",
        actor_name=actor_name,
        action="token.revoke",
        project_slug=token.project.slug,
        detail={"token_name": token.name},
        state=state,
    )
    db.commit()


def authenticate(db: Session, raw: str) -> ApiToken | None:
    """Look up a bearer token hash; revoked tokens never authenticate."""
    if not raw.startswith("ev_"):
        return None
    token = db.scalars(select(ApiToken).where(ApiToken.token_hash == hash_token(raw))).first()
    if token is None or token.revoked_at is not None:
        return None
    return token


def authorize_scope(token: ApiToken, *, project_slug: str, environment: str) -> None:
    """Enforce only the project/environment boundary."""
    if token.project.slug != project_slug:
        raise AgentForbidden("token is not allowed for this project")
    if environment not in environment_list(token):
        raise AgentForbidden("token is not allowed for this environment")


def authorize(
    token: ApiToken,
    *,
    project_slug: str,
    environment: str,
    command: list[str] | None = None,
) -> None:
    """Enforce project, environment, capability and command-prefix scope."""
    authorize_scope(token, project_slug=project_slug, environment=environment)
    if not token.can_inject:
        raise AgentForbidden("token cannot inject secrets")
    if command is not None and not token.any_command:
        prefixes = command_list(token)
        if not prefixes:
            raise AgentForbidden(
                "token has no allowed commands (created before they became required); "
                "recreate it with --allow or --any-command"
            )
        if not any(_argv_starts_with(command, prefix) for prefix in prefixes):
            raise AgentForbidden("command is not allowed by this token")


def _argv_starts_with(command: list[str], prefix: str) -> bool:
    """Whether ``command`` begins with the argv elements of ``prefix``.

    ``"npm run"`` allows ``["npm", "run", "dev"]`` but not ``["npm", "run-script"]``
    nor ``["npm run", "dev"]``; ``"bun"`` does not allow ``["bunx", ...]``.
    """
    try:
        expected = shlex.split(prefix)
    except ValueError:
        # Stored before prefixes were validated: deny rather than guess.
        return False
    return bool(expected) and command[: len(expected)] == expected


def environment_list(token: ApiToken) -> list[str]:
    """Decode the JSON environments column."""
    return list(json.loads(token.environments))


def command_list(token: ApiToken) -> list[str]:
    """Decode the JSON command-prefix column."""
    return list(json.loads(token.allowed_commands))


def touch_usage(db: Session, token: ApiToken) -> None:
    """Record last usage without exposing any secret."""
    token.last_used_at = datetime.now(UTC)
    db.commit()
