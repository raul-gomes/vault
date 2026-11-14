"""Project management commands (`envvault project ...`)."""

from __future__ import annotations

from typing import Any

import typer

from envvault.cli._common import (
    _fail,
    _find_project,
    _login,
    _table,
    console,
    project_app,
)
from envvault.config import Settings


# --------------------------------------------------------------------------- #
# projects
# --------------------------------------------------------------------------- #
@project_app.command("add")
def project_add(
    slug: str = typer.Argument(..., help="Short identifier, e.g. my-app"),
    name: str | None = typer.Option(None, "--name", "-n", help="Display name"),
    path: str = typer.Option(".", "--path", "-p", help="Project directory"),
) -> None:
    """Register a local project."""
    settings = Settings.from_env()
    session = _login(settings)
    try:
        response = session.request(
            "POST",
            "/v1/projects",
            json={"slug": slug, "name": name or slug, "path": path},
        )
        project = response.json()
        console.print(f"[green]Project created:[/green] {project['slug']} → {project['path']}")
    finally:
        session.close()


@project_app.command("update")
def project_update(
    slug: str = typer.Argument(..., help="Project slug"),
    name: str | None = typer.Option(None, "--name", "-n", help="New display name"),
    path: str | None = typer.Option(None, "--path", "-p", help="New project directory"),
) -> None:
    """Update the name and/or directory of a registered project."""
    if name is None and path is None:
        _fail("provide --name and/or --path")
    settings = Settings.from_env()
    session = _login(settings)
    try:
        project = _find_project(session, slug)
        payload: dict[str, Any] = {}
        if name is not None:
            payload["name"] = name
        if path is not None:
            payload["path"] = path
        updated = session.request("PATCH", f"/v1/projects/{project['id']}", json=payload).json()
        console.print(f"[green]Project updated:[/green] {updated['slug']} → {updated['path']}")
    finally:
        session.close()


@project_app.command("list")
def project_list() -> None:
    """List registered projects."""
    settings = Settings.from_env()
    session = _login(settings)
    try:
        items = session.request("GET", "/v1/projects").json()["items"]
        rows = [
            [
                item["slug"],
                item["name"],
                item["path"],
                str(item["secret_count"]),
                ", ".join(env["environment"] for env in item["environments"]) or "—",
            ]
            for item in items
        ]
        _table("Projetos", ["slug", "nome", "path", "segredos", "ambientes"], rows)
    finally:
        session.close()


@project_app.command("remove")
def project_remove(
    slug: str = typer.Argument(...),
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not ask for confirmation"),
) -> None:
    """Remove a project and all its secrets/tokens."""
    settings = Settings.from_env()
    session = _login(settings)
    try:
        project = _find_project(session, slug)
        if not yes and not typer.confirm(
            f"Delete {slug} and ALL secrets/tokens? This cannot be undone"
        ):
            raise typer.Exit(1)
        session.request(
            "DELETE",
            f"/v1/projects/{project['id']}",
            json={"confirm_slug": slug},
        )
        console.print(f"[yellow]Project removed:[/yellow] {slug}")
    finally:
        session.close()
