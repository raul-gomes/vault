"""Execution commands: run, context, keys, and agent-token helpers."""

from __future__ import annotations

import json
import os
from typing import Any

import httpx
import typer

from envvault import tokenstore
from envvault.cli._common import (
    _env_overrides,
    _fail,
    _find_project,
    _login,
    _project_config,
    _raise_for_status,
    _stream_exec,
    _table,
    _target,
    app,
    console,
)
from envvault.config import Settings


# --------------------------------------------------------------------------- #
# execution
# --------------------------------------------------------------------------- #
def _token_client(settings: Settings, token: str) -> httpx.Client:
    """HTTP client authenticated with an agent token (no cookies)."""
    return httpx.Client(
        base_url=settings.base_url,
        timeout=httpx.Timeout(connect=10, read=None, write=30, pool=10),
        headers={"authorization": f"Bearer {token}"},
    )


def _token_json(client: httpx.Client, path: str, params: dict[str, Any] | None = None) -> Any:
    """GET a token endpoint with a friendly error when the daemon is down."""
    try:
        response = client.get(path, params=params)
    except httpx.HTTPError as exc:
        _fail(f"could not reach the daemon: {exc}")
    _raise_for_status(response)
    return response.json()


def _agent_token(settings: Settings, slug: str) -> tokenstore.TokenRef | None:
    """Resolve an agent token from ENVVAULT_TOKEN or the project token file."""
    try:
        return tokenstore.resolve(settings.home, slug, os.environ.get("ENVVAULT_TOKEN"))
    except tokenstore.TokenStoreError as exc:
        _fail(str(exc))


@app.command(
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
    add_help_option=True,
)
def run(
    ctx: typer.Context,
    project: str | None = typer.Option(None, "--project", "-p"),
    environment: str | None = typer.Option(None, "--environment", "-e"),
    cwd: str | None = typer.Option(
        None, "--cwd", help="Execution directory, relative to the project directory"
    ),
    env: list[str] = typer.Option(
        [], "--env", "-E", help="Extra variable KEY=VALUE (repeatable, does not override secrets)"
    ),
    timeout: int | None = typer.Option(
        None, "--timeout", help="Seconds before killing the process"
    ),
) -> None:
    """Run a command with secrets injected by the daemon.

    Example: envvault run --env PORT=3001 --timeout 120 -- npm run dev
    """
    command = list(ctx.args)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        _fail("provide the command after --, e.g.: envvault run -- npm run dev")
    slug, env_name = _target(project, environment)
    overrides = _env_overrides(env)
    settings = Settings.from_env()
    auth = _agent_token(settings, slug)
    if auth:
        client = _token_client(settings, auth.value)
        try:
            code = _stream_exec(
                client,
                "/v1/agent/exec",
                {
                    "environment": env_name,
                    "command": command,
                    "cwd": cwd,
                    "invocation_dir": os.getcwd(),
                    "env": overrides,
                    "timeout_seconds": timeout,
                },
                None,
            )
        finally:
            client.close()
    else:
        session = _login(settings)
        try:
            item = _find_project(session, slug)
            code = _stream_exec(
                session.client,
                "/v1/exec",
                {
                    "project_id": item["id"],
                    "environment": env_name,
                    "command": command,
                    "cwd": cwd,
                    "invocation_dir": os.getcwd(),
                    "env": overrides,
                    "timeout_seconds": timeout,
                },
                session.csrf,
            )
        finally:
            session.close()
    raise typer.Exit(code)


@app.command()
def context(
    project: str | None = typer.Option(None, "--project", "-p", help="Project of the local token"),
) -> None:
    """Show the agent token scope (project, environment, commands)."""
    settings = Settings.from_env()
    env_token = os.environ.get("ENVVAULT_TOKEN")
    if env_token:
        token = env_token
    else:
        slug = project or (_project_config() or {}).get("project")
        if not slug:
            _fail("provide --project (or set ENVVAULT_TOKEN / .envvault.toml)")
        auth = _agent_token(settings, slug)
        if auth is None:
            _fail(
                f"no local token for {slug}; "
                f"create one with `envvault token create -p {slug} --save`"
            )
        token = auth.value
    client = _token_client(settings, token)
    try:
        console.print_json(json.dumps(_token_json(client, "/v1/agent/context")))
    finally:
        client.close()


@app.command()
def keys(
    project: str | None = typer.Option(None, "--project", "-p", help="Project of the local token"),
    environment: str | None = typer.Option(
        None, "--environment", "-e", help="Environment (default: from .envvault.toml)"
    ),
) -> None:
    """List key names for the project token (never the values)."""
    slug, resolved = _target(project, environment)
    settings = Settings.from_env()
    auth = _agent_token(settings, slug)
    if auth is None:
        _fail(
            f"no token for {slug}; create one with `envvault token create -p {slug} --save` "
            "(como humano, use `envvault list`)"
        )
    client = _token_client(settings, auth.value)
    try:
        items = _token_json(client, "/v1/agent/keys", params={"environment": resolved})["items"]
        _table(
            f"chaves/{resolved}",
            ["key", "version", "updated at"],
            [[item["key"], str(item["version"]), item["updated_at"]] for item in items],
        )
    finally:
        client.close()
