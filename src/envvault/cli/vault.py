"""Vault lifecycle commands: init, serve, stop, status, unlock, lock."""

from __future__ import annotations

import os
import signal
import time

import typer

from envvault import __version__
from envvault.cli._common import (
    _fail,
    _health,
    _login,
    app,
    console,
    ensure_daemon,
)
from envvault.config import Settings
from envvault.db import build_engine, build_session_factory, secure_database_files
from envvault.services import vault


# --------------------------------------------------------------------------- #
# lifecycle
# --------------------------------------------------------------------------- #
@app.command()
def init() -> None:
    """Create the vault, ask for the master passphrase and start the daemon."""
    settings = Settings.from_env()
    settings.ensure_home()
    if settings.db_path.exists():
        engine = build_engine(settings.db_path)
        factory = build_session_factory(engine)
        with factory() as db:
            already = vault.is_initialized(db)
        engine.dispose()
        if already:
            _fail(f"a vault already exists at {settings.db_path}")
    passphrase = typer.prompt("New master passphrase", hide_input=True, confirmation_prompt=True)
    if len(passphrase) < 10:
        _fail("the passphrase must be at least 10 characters")
    from envvault import migrate

    migrate.upgrade(settings)
    engine = build_engine(settings.db_path)
    factory = build_session_factory(engine)
    with factory() as db:
        vault.initialize(db, settings, passphrase)
        db.commit()
    engine.dispose()
    secure_database_files(settings.db_path)
    ensure_daemon(settings)
    session = _login(settings, passphrase)
    session.close()
    console.print(f"[bold green]Vault created[/bold green] at {settings.home}")
    console.print("[yellow]There is no passphrase recovery.[/yellow] Keep it safe.")
    console.print(f"Dashboard: [bold]{settings.base_url}[/bold]")
    console.print("Next step: [bold]envvault project add <slug> --path .[/bold]")


@app.command()
def serve() -> None:
    """Run the daemon in the foreground (use the log to debug)."""
    from envvault.daemon import main as daemon_main

    daemon_main()


@app.command()
def stop() -> None:
    """Stop the background daemon."""
    settings = Settings.from_env()
    if not settings.pid_path.exists():
        _fail("daemon is not running (no PID file)")
    try:
        pid = int(settings.pid_path.read_text(encoding="utf-8").strip())
    except ValueError:
        _fail(f"invalid PID in {settings.pid_path}")
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        settings.pid_path.unlink(missing_ok=True)
        console.print("daemon was already stopped")
        return
    for _ in range(50):
        time.sleep(0.1)
        if _health(settings, timeout=0.2) is None:
            settings.pid_path.unlink(missing_ok=True)
            console.print("daemon stopped")
            return
    _fail("the daemon did not respond to SIGTERM")


@app.command()
def status() -> None:
    """Show the daemon and vault status."""
    settings = Settings.from_env()
    health = _health(settings)
    console.print(f"EnvVault [bold]{__version__}[/bold]")
    console.print(f"home:   {settings.home}")
    console.print(f"database: {settings.db_path}")
    if health is None:
        console.print("daemon: [red]not running[/red]")
        return
    state = "unlocked" if health.get("unlocked") else "locked"
    color = "green" if health.get("unlocked") else "yellow"
    console.print(f"daemon: [green]ok[/green] at {settings.base_url}")
    console.print(f"vault:  [{color}]{state}[/{color}]")
    console.print(f"inactivity timeout: {health.get('lock_timeout_minutes')} min")


@app.command()
def unlock() -> None:
    """Unlock the vault in memory (the CLI session is not persisted)."""
    settings = Settings.from_env()
    session = _login(settings)
    session.close()
    console.print("[green]Vault unlocked.[/green]")


@app.command()
def lock() -> None:
    """Discard the key from memory, end sessions and kill running commands."""
    settings = Settings.from_env()
    session = _login(settings)
    try:
        session.request("POST", "/v1/auth/lock")
        console.print("[yellow]Vault locked.[/yellow]")
    finally:
        session.client.close()
