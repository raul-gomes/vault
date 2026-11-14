"""Secret commands: link, set, list, remove, reveal, import, export."""

from __future__ import annotations

import sys
from pathlib import Path

import typer

from envvault.cli._common import (
    PROJECT_FILE,
    CliError,
    _copy_to_clipboard,
    _fail,
    _find_project,
    _login,
    _print_issues,
    _table,
    _target,
    app,
    console,
)
from envvault.config import Settings
from envvault.passwords import (
    DEFAULT_LENGTH,
    PasswordOptions,
    entropy_bits,
    generate_password,
)


# --------------------------------------------------------------------------- #
# secrets
# --------------------------------------------------------------------------- #
@app.command()
def link(
    project: str | None = typer.Option(
        None, "--project", "-p", help="Project slug (default: current directory name)"
    ),
    environment: str = typer.Option("dev", "--environment", "-e", help="Default environment"),
    force: bool = typer.Option(False, "--force", help="Overwrite existing file"),
) -> None:
    """Create .envvault.toml in the current directory (no secrets)."""
    target = Path.cwd() / PROJECT_FILE
    if target.exists() and not force:
        _fail(f"{target} already exists (use --force)")
    slug = project or typer.prompt("Project slug", default=Path.cwd().name)
    target.write_text(
        f'project = "{slug}"\nenvironment = "{environment}"\n',
        encoding="utf-8",
    )
    console.print(f"[green]Created[/green] {target}")


@app.command()
def set(
    key: str = typer.Argument(..., help="Variable name, e.g. DATABASE_URL"),
    project: str | None = typer.Option(None, "--project", "-p"),
    environment: str | None = typer.Option(None, "--environment", "-e"),
    value: str | None = typer.Option(
        None, "--value", help="Literal value (avoid: stays in shell history)"
    ),
    generate: bool = typer.Option(False, "--generate", help="Generate a strong password"),
    length: int = typer.Option(DEFAULT_LENGTH, "--length", help="Length when generating"),
) -> None:
    """Create or replace a secret (value is prompted hidden by default)."""
    slug, env = _target(project, environment)
    settings = Settings.from_env()
    session = _login(settings)
    try:
        if generate:
            options = PasswordOptions(length=length)
            secret_value = generate_password(options)
            console.print(
                f"[yellow]Password generated ({entropy_bits(options):.0f} bits):[/yellow] "
                f"[bold]{secret_value}[/bold]"
            )
        elif value is not None:
            secret_value = value
        else:
            secret_value = typer.prompt(f"Value of {key}", hide_input=True)
        item = _find_project(session, slug)
        response = session.request(
            "PUT",
            f"/v1/projects/{item['id']}/secrets",
            json={"environment": env, "key": key, "value": secret_value},
        )
        payload = response.json()
        action = "created" if payload["created"] else "updated"
        console.print(f"[green]Secret {action}:[/green] {slug}/{env}/{key}")
    finally:
        session.close()


@app.command("list")
def list_secrets(
    project: str | None = typer.Option(None, "--project", "-p"),
    environment: str | None = typer.Option(None, "--environment", "-e"),
) -> None:
    """List secret names and versions (never the values)."""
    slug, env = _target(project, environment)
    settings = Settings.from_env()
    session = _login(settings)
    try:
        item = _find_project(session, slug)
        rows_data = session.request(
            "GET",
            f"/v1/projects/{item['id']}/secrets",
            params={"environment": env},
        ).json()["items"]
        rows = [[row["key"], str(row["version"]), str(row["updated_at"])] for row in rows_data]
        _table(f"{slug}/{env}", ["key", "version", "updated at"], rows)
    finally:
        session.close()


@app.command()
def remove(
    key: str = typer.Argument(...),
    project: str | None = typer.Option(None, "--project", "-p"),
    environment: str | None = typer.Option(None, "--environment", "-e"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """Remove a secret."""
    slug, env = _target(project, environment)
    if not yes and not typer.confirm(f"Remove {key} from {slug}/{env}?"):
        raise typer.Exit(1)
    settings = Settings.from_env()
    session = _login(settings)
    try:
        item = _find_project(session, slug)
        session.request(
            "DELETE",
            f"/v1/projects/{item['id']}/secrets/{key}",
            params={"environment": env},
        )
        console.print(f"[yellow]Secret removed:[/yellow] {key}")
    finally:
        session.close()


@app.command()
def reveal(
    key: str = typer.Argument(...),
    project: str | None = typer.Option(None, "--project", "-p"),
    environment: str | None = typer.Option(None, "--environment", "-e"),
    copy: bool = typer.Option(False, "--copy", help="Copy to the clipboard"),
) -> None:
    """Show a value (audited) after re-validating the passphrase."""
    slug, env = _target(project, environment)
    settings = Settings.from_env()
    session = _login(settings)
    try:
        item = _find_project(session, slug)
        response = session.request(
            "POST",
            f"/v1/projects/{item['id']}/secrets/{key}/reveal",
            json={"environment": env, "passphrase": session.passphrase},
        )
        secret = response.json()["value"]
        if copy:
            if not _copy_to_clipboard(secret):
                _fail("no clipboard utility found (wl-copy/xclip/pbcopy)")
            console.print("[green]Value copied to the clipboard.[/green]")
        else:
            console.print(secret)
    finally:
        session.close()


@app.command("import")
def import_env(
    file: str = typer.Argument(".env", help="Source .env file"),
    project: str | None = typer.Option(None, "--project", "-p"),
    environment: str | None = typer.Option(None, "--environment", "-e"),
    replace: bool = typer.Option(False, "--replace", help="Overwrite existing keys"),
    delete_file: bool = typer.Option(
        False,
        "--delete-file",
        help="Delete the .env after importing (the vault becomes the source)",
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Do not ask for confirmation when deleting"
    ),
    create: bool = typer.Option(False, "--create", help="Create the project if it does not exist"),
    path: str = typer.Option(".", "--path", help="Project directory when using --create"),
) -> None:
    """Import a .env into the vault (validates and never executes the content)."""
    source = Path(file).expanduser()
    if not source.is_file():
        _fail(f"file not found: {source}")
    content = source.read_text(encoding="utf-8")
    slug, env = _target(project, environment)
    settings = Settings.from_env()
    session = _login(settings)
    try:
        try:
            item = _find_project(session, slug)
        except CliError:
            if not create:
                raise
            item = session.request(
                "POST",
                "/v1/projects",
                json={"slug": slug, "name": slug, "path": path},
            ).json()
            console.print(f"[green]Project created:[/green] {slug}")
        response = session.request(
            "POST",
            f"/v1/projects/{item['id']}/import",
            json={"environment": env, "content": content, "replace": replace},
        )
        result = response.json()
        console.print(
            f"[green]Imported[/green] into {slug}/{env}: "
            f"{result['created']} created, {result['updated']} updated, "
            f"{result['skipped']} skipped"
        )
        _print_issues(result["issues"])
        if delete_file:
            if not yes and not typer.confirm(f"Delete {source} now?"):
                return
            source.unlink()
            console.print(f"[yellow]File removed:[/yellow] {source}")
    finally:
        session.close()


@app.command()
def export(
    project: str | None = typer.Option(None, "--project", "-p"),
    environment: str | None = typer.Option(None, "--environment", "-e"),
    out: str | None = typer.Option(None, "--out", "-o", help="Destination file"),
    force: bool = typer.Option(False, "--force", help="Overwrite destination"),
) -> None:
    """Export an environment to .env (temporary) or to stdout."""
    slug, env = _target(project, environment)
    settings = Settings.from_env()
    session = _login(settings)
    try:
        item = _find_project(session, slug)
        text = session.request(
            "POST",
            f"/v1/projects/{item['id']}/export",
            json={"environment": env, "passphrase": session.passphrase},
        ).text
        if not out:
            sys.stdout.write(text)
            return
        destination = Path(out).expanduser()
        if destination.exists() and not force:
            _fail(f"{destination} already exists (use --force)")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
        destination.chmod(0o600)
        console.print(f"[yellow]Exported to {destination}[/yellow] (mode 0600)")
        console.print("Delete the file after use; prefer `envvault run`.")
    finally:
        session.close()
