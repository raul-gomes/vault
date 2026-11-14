"""Agent token commands (`envvault token ...`)."""

from __future__ import annotations

import os

import typer

from envvault import tokenstore
from envvault.cli._common import (
    _fail,
    _find_project,
    _login,
    _table,
    console,
    token_app,
)
from envvault.config import Settings


# --------------------------------------------------------------------------- #
# tokens
# --------------------------------------------------------------------------- #
@token_app.command("create")
def token_create(
    name: str = typer.Option(..., "--name", "-n", help="Token name"),
    project: str = typer.Option(..., "--project", "-p"),
    environment: list[str] = typer.Option(
        ["dev"], "--environment", "-e", help="Allowed environment (repeatable)"
    ),
    allow: list[str] = typer.Option(
        [], "--allow", help="Allowed command, matched word by word (repeatable)"
    ),
    any_command: bool = typer.Option(
        False, "--any-command", help="Allow any command (not recommended)"
    ),
    no_list: bool = typer.Option(False, "--no-list", help="Do not allow listing keys"),
    no_inject: bool = typer.Option(False, "--no-inject", help="Do not allow execution"),
    save: bool = typer.Option(
        True,
        "--save/--no-save",
        help="Write to ~/.envvault/agent-tokens/<project>.token (0600) instead of printing",
    ),
) -> None:
    """Create an agent token and, by default, save it to a 0600 file."""
    if not no_inject and not allow and not any_command:
        _fail('provide at least one --allow "<command>" or, if you really mean it, --any-command')
    if allow and any_command:
        _fail("use --allow or --any-command, not both")
    settings = Settings.from_env()
    session = _login(settings)
    try:
        item = _find_project(session, project)
        response = session.request(
            "POST",
            "/v1/tokens",
            json={
                "name": name,
                "project_id": item["id"],
                "environments": environment,
                "can_list": not no_list,
                "can_inject": not no_inject,
                "allowed_commands": allow,
                "any_command": any_command,
            },
        )
        created = response.json()
        raw = created["token"]
        if save:
            try:
                path = tokenstore.save(
                    settings.home,
                    item["slug"],
                    raw,
                    token_id=created["item"]["id"],
                    name=name,
                )
            except tokenstore.TokenStoreError as exc:
                _fail(str(exc))
            console.print(f"[bold green]Token created and saved:[/bold green] {path} (0600)")
            console.print(f"Use from any directory: envvault run -p {item['slug']} -- <command>")
            if os.environ.get("ENVVAULT_TOKEN"):
                console.print(
                    "[yellow]ENVVAULT_TOKEN is set in this shell and takes precedence; "
                    "run `unset ENVVAULT_TOKEN` to use the project file.[/yellow]"
                )
        else:
            console.print("[bold green]Token created.[/bold green] It will not be shown again:")
            console.print(raw)
            console.print("\nUse in the agent environment:")
            console.print(f"  export ENVVAULT_TOKEN={raw}")
        if allow:
            console.print(f"Allowed commands: {', '.join(allow)}")
        elif any_command:
            console.print(
                "[yellow]Any command is accepted for this token (--any-command).[/yellow]"
            )
    finally:
        session.close()


@token_app.command("list")
def token_list() -> None:
    """List tokens (without revealing the value)."""
    settings = Settings.from_env()
    session = _login(settings)
    try:
        items = session.request("GET", "/v1/tokens").json()["items"]
        rows = []
        for item in items:
            slug = item["project"]["slug"]
            local_id = tokenstore.local_token_id(settings.home, slug)
            has_file = tokenstore.exists(settings.home, slug)
            local = item["active"] and (local_id == item["id"] if local_id else has_file)
            rows.append(
                [
                    item["name"],
                    slug,
                    ", ".join(item["environments"]),
                    ("listar " if item["can_list"] else "")
                    + ("executar" if item["can_inject"] else ""),
                    item["last_used_at"] or "nunca",
                    "ativo" if item["active"] else "revogado",
                    "sim" if local else "—",
                ]
            )
        _table(
            "Tokens",
            ["name", "project", "environments", "permissions", "last used", "status", "local"],
            rows,
        )
    finally:
        session.close()


@token_app.command("revoke")
def token_revoke(
    name: str = typer.Argument(..., help="Token name"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """Revoke a token by name."""
    settings = Settings.from_env()
    session = _login(settings)
    try:
        items = session.request("GET", "/v1/tokens").json()["items"]
        matches = [item for item in items if item["name"] == name and item["active"]]
        if not matches:
            _fail(f"active token not found: {name}")
        if len(matches) > 1 and not yes:
            _fail("there is more than one active token with that name; revoke it in the dashboard")
        if not yes and not typer.confirm(f"Revoke the token {name}?"):
            raise typer.Exit(1)
        session.request("DELETE", f"/v1/tokens/{matches[0]['id']}")
        console.print(f"[yellow]Token revoked:[/yellow] {name}")
        slug = matches[0]["project"]["slug"]
        remaining = [
            item
            for item in items
            if item["active"] and item["id"] != matches[0]["id"] and item["project"]["slug"] == slug
        ]
        local_id = tokenstore.local_token_id(settings.home, slug)
        should_remove = local_id == matches[0]["id"] or (local_id is None and not remaining)
        if should_remove and tokenstore.remove(settings.home, slug):
            console.print(f"[yellow]Local token removed:[/yellow] {slug}")
    finally:
        session.close()
