"""Service credential commands (`envvault credential ...`)."""

from __future__ import annotations

from typing import Any

import typer

from envvault.cli._common import (
    _copy_to_clipboard,
    _fail,
    _find_credential,
    _find_project,
    _login,
    _table,
    console,
    credential_app,
)
from envvault.config import Settings
from envvault.passwords import (
    DEFAULT_LENGTH,
    PasswordOptions,
    generate_password,
)


# --------------------------------------------------------------------------- #
# credentials
# --------------------------------------------------------------------------- #
@credential_app.command("add")
def credential_add(
    name: str = typer.Argument(..., help="Display name, e.g. Hostinger"),
    category: str = typer.Option(
        "other", "--category", "-c", help="hosting, dns, email, smtp, api, database…"
    ),
    username: str = typer.Option("", "--username", "-u", help="Username or email"),
    url: str = typer.Option("", "--url", help="Dashboard/service URL"),
    notes: str = typer.Option("", "--notes", "-n", help="Notes (stored encrypted)"),
    password: str | None = typer.Option(
        None, "--password", help="Literal password (avoid: stays in shell history)"
    ),
    generate: bool = typer.Option(False, "--generate", help="Generate a strong password"),
    length: int = typer.Option(DEFAULT_LENGTH, "--length", help="Length when generating"),
    project: str | None = typer.Option(
        None, "--project", "-p", help="Project slug (omit for a global credential)"
    ),
) -> None:
    """Add a service credential (sensitive fields encrypted)."""
    if generate:
        secret_value = generate_password(PasswordOptions(length=length))
        console.print(
            "[yellow]Password generated and saved in the vault. Use "
            "`envvault credential show` to view it.[/yellow]"
        )
    elif password is not None:
        secret_value = password
    else:
        secret_value = typer.prompt(f"Password for {name}", hide_input=True)
    settings = Settings.from_env()
    session = _login(settings)
    try:
        project_id = _find_project(session, project)["id"] if project else None
        item = session.request(
            "POST",
            "/v1/credentials",
            json={
                "name": name,
                "category": category,
                "username": username,
                "password": secret_value,
                "url": url,
                "notes": notes,
                "project_id": project_id,
            },
        ).json()["item"]
        console.print(
            f"[green]Credential created:[/green] {item['name']} "
            f"({item['category']}, {item['project']['slug'] if item['project'] else 'global'}) "
            f"· id {item['id']}"
        )
    finally:
        session.close()


@credential_app.command("list")
def credential_list(
    query: str | None = typer.Option(None, "--query", "-q", help="Search by name/category"),
    category: str | None = typer.Option(None, "--category", "-c"),
    project: str | None = typer.Option(None, "--project", "-p", help="Filter by project"),
    only_global: bool = typer.Option(False, "--global", help="Only global credentials"),
) -> None:
    """List credentials (metadata only, never the values)."""
    if project and only_global:
        _fail("use --project or --global, not both")
    settings = Settings.from_env()
    session = _login(settings)
    try:
        params: dict[str, Any] = {}
        if query:
            params["query"] = query
        if category:
            params["category"] = category
        if project:
            params["project_id"] = _find_project(session, project)["id"]
        if only_global:
            params["global_only"] = "true"
        items = session.request("GET", "/v1/credentials", params=params).json()["items"]
        rows = [
            [
                item["name"],
                item["category"],
                item["project"]["slug"] if item["project"] else "global",
                f"v{item['version']}",
                item["id"],
            ]
            for item in items
        ]
        _table("Credentials", ["name", "category", "scope", "version", "id"], rows)
    finally:
        session.close()


@credential_app.command("show")
def credential_show(
    identifier: str = typer.Argument(..., help="Credential name or id"),
    copy: bool = typer.Option(False, "--copy", help="Copy the password to the clipboard"),
) -> None:
    """Show the fields of a credential (audited reveal)."""
    settings = Settings.from_env()
    session = _login(settings)
    try:
        item = _find_credential(session, identifier)
        data = session.request(
            "POST",
            f"/v1/credentials/{item['id']}/reveal",
            json={"passphrase": session.passphrase},
        ).json()
        if copy:
            if not data.get("password"):
                _fail("this credential has no saved password")
            if not _copy_to_clipboard(data["password"]):
                _fail("no clipboard utility found (wl-copy/xclip/pbcopy)")
            console.print("[green]Password copied to the clipboard.[/green]")
            return
        rows = [
            ["nome", data["name"]],
            ["categoria", data["category"]],
            ["escopo", data["project"]["slug"] if data.get("project") else "global"],
            ["username", data.get("username") or "—"],
            ["password", data.get("password") or "—"],
            ["url", data.get("url") or "—"],
            ["notas", data.get("notes") or "—"],
        ]
        _table(f"Credencial · {data['name']}", ["campo", "valor"], rows)
    finally:
        session.close()


@credential_app.command("update")
def credential_update(
    identifier: str = typer.Argument(..., help="Credential name or id"),
    name: str | None = typer.Option(None, "--name"),
    category: str | None = typer.Option(None, "--category", "-c"),
    username: str | None = typer.Option(None, "--username", "-u"),
    url: str | None = typer.Option(None, "--url"),
    notes: str | None = typer.Option(None, "--notes", "-n"),
    password: str | None = typer.Option(
        None, "--password", help="New literal password (avoid shell history)"
    ),
    generate: bool = typer.Option(False, "--generate", help="Generate a new strong password"),
    length: int = typer.Option(DEFAULT_LENGTH, "--length", help="Length when generating"),
    project: str | None = typer.Option(
        None, "--project", "-p", help="Move the credential to this project"
    ),
    global_scope: bool = typer.Option(
        False, "--global", help="Move the credential to the global scope"
    ),
) -> None:
    """Update credential fields, keeping the ones not provided."""
    if project and global_scope:
        _fail("use --project or --global, not both")
    settings = Settings.from_env()
    session = _login(settings)
    try:
        item = _find_credential(session, identifier)
        current = session.request(
            "POST",
            f"/v1/credentials/{item['id']}/reveal",
            json={"passphrase": session.passphrase},
        ).json()
        new_password = current.get("password", "")
        if generate:
            new_password = generate_password(PasswordOptions(length=length))
            console.print("[yellow]New password generated and saved.[/yellow]")
        elif password is not None:
            new_password = password
        if project:
            project_id = _find_project(session, project)["id"]
        elif global_scope:
            project_id = None
        else:
            project_id = current["project"]["id"] if current.get("project") else None
        payload = {
            "name": name if name is not None else current["name"],
            "category": category if category is not None else current["category"],
            "username": username if username is not None else current.get("username", ""),
            "password": new_password,
            "url": url if url is not None else current.get("url", ""),
            "notes": notes if notes is not None else current.get("notes", ""),
            "project_id": project_id,
        }
        updated = session.request("PUT", f"/v1/credentials/{item['id']}", json=payload).json()[
            "item"
        ]
        scope = updated["project"]["slug"] if updated["project"] else "global"
        console.print(
            f"[green]Credential updated:[/green] {updated['name']} ({scope}, v{updated['version']})"
        )
    finally:
        session.close()


@credential_app.command("remove")
def credential_remove(
    identifier: str = typer.Argument(..., help="Credential name or id"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not ask for confirmation"),
) -> None:
    """Remove a credential."""
    settings = Settings.from_env()
    session = _login(settings)
    try:
        item = _find_credential(session, identifier)
        if not yes and not typer.confirm(
            f"Remove the credential {item['name']}? This cannot be undone"
        ):
            raise typer.Exit(1)
        session.request("DELETE", f"/v1/credentials/{item['id']}")
        console.print(f"[yellow]Credential removed:[/yellow] {item['name']}")
    finally:
        session.close()
