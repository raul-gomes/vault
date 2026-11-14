"""Maintenance commands: audit, backup, verify, passwd."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer

from envvault.cli._common import (
    _fail,
    _login,
    _table,
    app,
    console,
)
from envvault.config import Settings
from envvault.services.backup import BackupError, create_backup


# --------------------------------------------------------------------------- #
# audit / misc
# --------------------------------------------------------------------------- #
@app.command()
def audit(
    limit: int = typer.Option(30, "--limit", "-l", min=1, max=500),
    project: str | None = typer.Option(None, "--project", "-p"),
) -> None:
    """Show the latest audit log events."""
    settings = Settings.from_env()
    session = _login(settings)
    try:
        params: dict[str, Any] = {"limit": limit}
        if project:
            params["project_slug"] = project
        items = session.request("GET", "/v1/audit", params=params).json()["items"]
        rows = [
            [
                item["ts"][:19].replace("T", " "),
                item["actor_type"],
                item["action"],
                item["project_slug"] or "—",
                item["environment"] or "—",
                item["result"],
            ]
            for item in items
        ]
        _table("Audit log", ["when", "actor", "action", "project", "environment", "result"], rows)
    finally:
        session.close()


@app.command()
def backup(
    destination: Path = typer.Argument(..., help="New file or existing directory"),
) -> None:
    """Copy the still-encrypted database (needs neither the daemon nor the passphrase)."""
    settings = Settings.from_env()
    try:
        path = create_backup(settings.db_path, destination)
    except BackupError as exc:
        _fail(str(exc))
    console.print(f"[bold green]Backup created:[/bold green] {path} (0600, encrypted)")
    console.print(
        "To restore you need the passphrase that was in use when the backup was made. "
        "Step by step: README, Backup and restore section."
    )


@app.command()
def verify() -> None:
    """Verify the integrity of the audit log chain."""
    settings = Settings.from_env()
    session = _login(settings)
    try:
        result = session.request("GET", "/v1/audit/verify").json()
        if result["valid"]:
            console.print("[green]Audit log chain intact.[/green]")
        else:
            _fail(f"chain broken at id {result['first_bad_id']}")
    finally:
        session.close()


@app.command()
def passwd() -> None:
    """Change the master passphrase (re-wraps the data key)."""
    settings = Settings.from_env()
    session = _login(settings)
    try:
        current = session.passphrase
        new = typer.prompt("New passphrase", hide_input=True, confirmation_prompt=True)
        if len(new) < 10:
            _fail("the new passphrase must be at least 10 characters")
        session.request(
            "POST",
            "/v1/auth/passphrase",
            json={"current": current, "new": new},
        )
        console.print("[green]Passphrase changed.[/green]")
    finally:
        session.close()
