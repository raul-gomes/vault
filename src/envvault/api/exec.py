"""Command execution endpoints: one for the human session, one for agents."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from envvault.api.deps import (
    authorize_agent,
    get_db,
    get_runtime,
    project_or_404,
    require_agent,
    require_session,
)
from envvault.models import ApiToken, Project
from envvault.runtime import Runtime
from envvault.schemas import AgentExecRequest, ExecRequest
from envvault.services import audit, runner, tokens
from envvault.services import secrets as secret_service

session_router = APIRouter(tags=["exec"], dependencies=[Depends(require_session)])
agent_router = APIRouter(tags=["agent"])

SSE_HEADERS = {
    "Cache-Control": "no-store",
    "X-Accel-Buffering": "no",
    "Connection": "keep-alive",
}


@session_router.post("/v1/exec")
def exec_as_user(
    payload: ExecRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
) -> StreamingResponse:
    """Run a command with secrets injected, authenticated by the web session."""
    project = project_or_404(db, payload.project_id)
    return _start_exec(
        request,
        db,
        state,
        project=project,
        environment=payload.environment,
        command=payload.command,
        cwd=payload.cwd,
        invocation_dir=payload.invocation_dir,
        env=payload.env,
        timeout_seconds=payload.timeout_seconds,
        actor_type="user",
        actor_name="user",
        audit_detail={},
    )


@agent_router.get("/v1/agent/context")
def agent_context(
    token: Annotated[ApiToken, Depends(require_agent)],
) -> dict[str, object]:
    """Describe the token scope so the agent knows what it can ask for."""
    return {
        "token_name": token.name,
        "project": {"slug": token.project.slug, "name": token.project.name},
        "environments": tokens.environment_list(token),
        "can_list": token.can_list,
        "can_inject": token.can_inject,
        "allowed_commands": tokens.command_list(token),
        "any_command": token.any_command,
        "usage": (
            "Call POST /v1/agent/exec with {'environment': ..., 'command': [...], "
            "'env': {...}, 'timeout_seconds': ...}. The daemon injects the vault "
            "secrets, assembles the extra env vars and redacts the output; there is "
            "no endpoint that returns plaintext. Env keys already stored in the "
            "vault cannot be overridden. 'cwd' is relative to the project root; "
            "without it, 'invocation_dir' (the caller's directory) is used when it "
            "is inside the project, else the project root."
        ),
        "request_example": {
            "environment": "dev",
            "command": ["npm", "run", "dev"],
            "cwd": "frontend",
            "env": {"PORT": "3001", "NODE_ENV": "development"},
            "timeout_seconds": 120,
        },
        "limits": {
            "max_env_overrides": 64,
            "max_env_value_bytes": 64 * 1024,
            "max_timeout_seconds": 3600,
        },
    }


@agent_router.get("/v1/agent/keys")
def agent_keys(
    db: Annotated[Session, Depends(get_db)],
    token: Annotated[ApiToken, Depends(require_agent)],
    environment: str,
) -> dict[str, object]:
    """List key names (never values) for one allowed environment."""
    if not token.can_list:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "token cannot list keys")
    try:
        tokens.authorize_scope(token, project_slug=token.project.slug, environment=environment)
    except tokens.AgentForbidden as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    rows = secret_service.list_names(db, token.project, environment)
    return {
        "environment": environment,
        "items": [
            {
                "key": row.key,
                "version": row.version,
                "updated_at": row.updated_at.isoformat(),
            }
            for row in rows
        ],
    }


@agent_router.post("/v1/agent/exec")
def exec_as_agent(
    payload: AgentExecRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    state: Annotated[Runtime, Depends(get_runtime)],
    token: Annotated[ApiToken, Depends(require_agent)],
) -> StreamingResponse:
    """Run a command with secrets injected, authenticated by a scoped token."""
    project = token.project
    authorize_agent(
        token,
        project_slug=project.slug,
        environment=payload.environment,
        command=payload.command,
    )
    tokens.touch_usage(db, token)
    return _start_exec(
        request,
        db,
        state,
        project=project,
        environment=payload.environment,
        command=payload.command,
        cwd=payload.cwd,
        invocation_dir=payload.invocation_dir,
        env=payload.env,
        timeout_seconds=payload.timeout_seconds,
        actor_type="agent",
        actor_name=token.name,
        audit_detail={"token_prefix": token.prefix},
    )


def _start_exec(
    request: Request,
    db: Session,
    state: Runtime,
    *,
    project: Project,
    environment: str,
    command: list[str],
    cwd: str | None,
    invocation_dir: str | None,
    env: dict[str, str] | None,
    timeout_seconds: int | None,
    actor_type: str,
    actor_name: str,
    audit_detail: dict[str, object],
) -> StreamingResponse:
    """Validate, reserve a slot, audit and spawn; release the slot on any failure.

    The slot is reserved before anything is audited or started, so a request
    over the concurrency limit gets 429 and never creates a child process.
    """
    resolved_cwd = runner.resolve_cwd(project, cwd, invocation_dir=invocation_dir)
    argv = runner.validate_command(command)
    values = secret_service.values_for_exec(db, state, project, environment)
    extra_env = runner.validate_env(env, vault_keys=set(values))
    exec_id = state.reserve_exec_slot()
    try:
        audit.append(
            db,
            actor_type=actor_type,
            actor_name=actor_name,
            action="exec.start",
            project_slug=project.slug,
            environment=environment,
            command=" ".join(argv),
            detail={
                **audit_detail,
                "cwd": str(resolved_cwd),
                "env_keys": sorted(extra_env),
                "timeout_seconds": timeout_seconds,
            },
            state=state,
        )
        db.commit()
        record, redactor = runner.spawn(
            state,
            exec_id=exec_id,
            project=project,
            environment=environment,
            secrets=values,
            command=argv,
            cwd=resolved_cwd,
            actor_type=actor_type,
            actor_name=actor_name,
            extra_env=extra_env,
            timeout_seconds=timeout_seconds,
        )
    except BaseException:
        state.release_exec_slot(exec_id)
        raise
    return runner.exec_response(
        request.app.state.session_factory, state, record, redactor, headers=SSE_HEADERS
    )
