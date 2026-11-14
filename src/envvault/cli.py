"""Command-line interface for EnvVault."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

import httpx
import typer
from rich.console import Console
from rich.table import Table

from envvault import __version__, tokenstore
from envvault.config import Settings
from envvault.db import build_engine, build_session_factory, secure_database_files
from envvault.passwords import (
    DEFAULT_LENGTH,
    InvalidLength,
    PasswordOptions,
    entropy_bits,
    generate_password,
)
from envvault.services import vault
from envvault.services.backup import BackupError, create_backup

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Local .env vault: injects secrets without exposing values to the agent.",
)
project_app = typer.Typer(help="Manage registered projects.", no_args_is_help=True)
token_app = typer.Typer(help="Manage agent tokens.", no_args_is_help=True)
credential_app = typer.Typer(
    help="Manage service credentials (hosting, DNS, email…).",
    no_args_is_help=True,
)
app.add_typer(project_app, name="project")
app.add_typer(token_app, name="token")
app.add_typer(credential_app, name="credential")

console = Console()
PROJECT_FILE = ".envvault.toml"


class CliError(Exception):
    """Fatal CLI error with a user-facing message."""


@dataclass(slots=True)
class UserSession:
    """Authenticated CLI session; the passphrase stays only in memory."""

    client: httpx.Client
    csrf: str
    passphrase: str

    def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """Send a request with the CSRF header on mutations and raise on error."""
        headers = dict(kwargs.pop("headers", {}))
        if method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            headers["x-csrf-token"] = self.csrf
        response = self.client.request(method, path, headers=headers, **kwargs)
        _raise_for_status(response)
        return response

    def close(self) -> None:
        """Log out server-side (hygiene) and close the HTTP client."""
        with contextlib.suppress(httpx.HTTPError):
            self.client.post("/v1/auth/logout")
        self.client.close()


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _fail(message: str, code: int = 1) -> NoReturn:
    """Print an error and exit non-zero."""
    typer.secho(f"erro: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code)


def _detail(response: httpx.Response) -> str:
    """Extract a safe error message from an API response."""
    try:
        payload = response.json()
    except ValueError:
        return response.text.strip() or response.reason_phrase
    detail = payload.get("detail") if isinstance(payload, dict) else None
    if isinstance(detail, list):
        return "; ".join(str(item.get("msg", item)) for item in detail)
    return str(detail or response.reason_phrase)


def _raise_for_status(response: httpx.Response) -> None:
    """Turn an HTTP error into a :class:`CliError` with context."""
    if response.status_code < 400:
        return
    detail = _detail(response)
    if response.status_code == 401:
        raise CliError(f"not authenticated: {detail}")
    if response.status_code == 423:
        raise CliError("vault locked; run `envvault unlock` or provide the passphrase")
    if response.status_code == 409:
        raise CliError(f"{detail}; run `envvault init`")
    raise CliError(f"HTTP {response.status_code}: {detail}")


def _health(settings: Settings, timeout: float = 1.0) -> dict[str, Any] | None:
    """Return the daemon health payload, or None when it is not reachable."""
    try:
        response = httpx.get(f"{settings.base_url}/v1/health", timeout=timeout)
    except httpx.HTTPError:
        return None
    if response.status_code != 200:
        return None
    payload = response.json()
    return payload if isinstance(payload, dict) else None


def ensure_daemon(settings: Settings) -> None:
    """Start the daemon in the background when it is not already running."""
    if _health(settings) is not None:
        return
    settings.ensure_home()
    log = settings.open_log()
    subprocess.Popen(
        [sys.executable, "-m", "envvault.daemon"],
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=log,
        start_new_session=True,
        env=os.environ.copy(),
    )
    for _ in range(60):
        time.sleep(0.2)
        if _health(settings) is not None:
            return
    _fail(f"the daemon did not start; see {settings.log_path}")


def _login(settings: Settings, passphrase: str | None = None) -> UserSession:
    """Unlock the vault and return an in-memory CLI session."""
    ensure_daemon(settings)
    secret = passphrase or typer.prompt("Passphrase", hide_input=True)
    client = httpx.Client(base_url=settings.base_url, timeout=30.0)
    try:
        response = client.post("/v1/auth/login", json={"passphrase": secret})
        _raise_for_status(response)
        csrf = response.json()["csrf_token"]
    except Exception:
        client.close()
        raise
    return UserSession(client=client, csrf=csrf, passphrase=secret)


def _find_project(session: UserSession, slug: str) -> dict[str, Any]:
    """Resolve a project payload by slug."""
    response = session.request("GET", "/v1/projects")
    for item in response.json()["items"]:
        if item["slug"] == slug:
            return item
    raise CliError(f"project not found: {slug} (use `envvault project add`)")


def _find_credential(session: UserSession, identifier: str) -> dict[str, Any]:
    """Resolve a credential by id first, then by exact name."""
    items = session.request("GET", "/v1/credentials").json()["items"]
    for item in items:
        if item["id"] == identifier:
            return item
    matches = [item for item in items if item["name"] == identifier]
    if not matches:
        raise CliError(f"credential not found: {identifier}")
    if len(matches) > 1:
        raise CliError(
            f"there is more than one credential named {identifier}; use the id "
            "(see `envvault credential list`)"
        )
    return matches[0]


def _project_config() -> dict[str, str] | None:
    """Read the nearest ``.envvault.toml`` walking up from the current dir."""
    for directory in [Path.cwd(), *Path.cwd().parents]:
        candidate = directory / PROJECT_FILE
        if candidate.exists():
            data = tomllib.loads(candidate.read_text(encoding="utf-8"))
            config = {}
            if isinstance(data.get("project"), str):
                config["project"] = data["project"]
            if isinstance(data.get("environment"), str):
                config["environment"] = data["environment"]
            return config or None
    return None


def _target(project: str | None, environment: str | None) -> tuple[str, str]:
    """Resolve project/environment from flags, then from .envvault.toml."""
    config = _project_config() or {}
    resolved_project = project or config.get("project")
    resolved_environment = environment or config.get("environment")
    if not resolved_project:
        raise CliError("provide --project (or create a .envvault.toml with `envvault link`)")
    if not resolved_environment:
        raise CliError("provide --environment (or set environment in .envvault.toml)")
    return resolved_project, resolved_environment


def _env_overrides(values: list[str]) -> dict[str, str]:
    """Parse repeated ``KEY=VALUE`` flags into an environment map."""
    overrides: dict[str, str] = {}
    for item in values:
        key, separator, value = item.partition("=")
        if not separator or not key:
            raise CliError(f"use KEY=VALUE in --env (got: {item!r})")
        overrides[key] = value
    return overrides


def _table(title: str, columns: list[str], rows: list[list[str]]) -> None:
    """Render a compact table."""
    table = Table(title=title, header_style="bold cyan", title_style="bold")
    for column in columns:
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(*row)
    console.print(table)


def _print_issues(issues: list[dict[str, Any]]) -> None:
    """Print .env parse issues."""
    for issue in issues:
        color = "yellow" if issue.get("level") == "warning" else "red"
        console.print(f"[{color}]line {issue.get('line')}: {issue.get('message')}[/{color}]")


def _copy_to_clipboard(value: str) -> bool:
    """Copy to the system clipboard when a helper is available."""
    for command in (["wl-copy"], ["xclip", "-selection", "clipboard"], ["pbcopy"]):
        executable = shutil.which(command[0])
        if executable:
            try:
                subprocess.run(
                    [executable, *command[1:]],
                    input=value.encode("utf-8"),
                    check=True,
                    timeout=5,
                )
                return True
            except (subprocess.SubprocessError, OSError):
                continue
    return False


def _stream_exec(client: httpx.Client, path: str, payload: dict[str, Any], csrf: str | None) -> int:
    """Stream SSE events from the daemon and print output as it arrives."""
    headers = {"x-csrf-token": csrf} if csrf else {}
    try:
        with client.stream("POST", path, json=payload, headers=headers) as response:
            if response.status_code >= 400:
                response.read()
                _raise_for_status(response)
            exit_code = 0
            for line in response.iter_lines():
                if not line.startswith("data: "):
                    continue
                event = json.loads(line[6:])
                kind = event.get("type")
                if kind == "output":
                    sys.stdout.write(event.get("text", ""))
                    sys.stdout.flush()
                elif kind == "exit":
                    exit_code = int(event.get("code") or 0)
            return exit_code
    except KeyboardInterrupt:
        return 130
    except httpx.HTTPError as exc:
        _fail(f"could not reach the daemon: {exc}")


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
    state = "desbloqueado" if health.get("unlocked") else "bloqueado"
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


# --------------------------------------------------------------------------- #
# secrets
# --------------------------------------------------------------------------- #
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


@app.command()
def generate(
    length: int = typer.Option(DEFAULT_LENGTH, "--length", "-l", min=8, max=256),
    upper: bool = typer.Option(True, "--upper/--no-upper"),
    lower: bool = typer.Option(True, "--lower/--no-lower"),
    digits: bool = typer.Option(True, "--digits/--no-digits"),
    symbols: bool = typer.Option(True, "--symbols/--no-symbols"),
    count: int = typer.Option(1, "--count", "-c", min=1, max=100),
    as_json: bool = typer.Option(False, "--json", help="JSON output"),
    copy: bool = typer.Option(False, "--copy", help="Copy the first one to the clipboard"),
) -> None:
    """Generate strong passwords locally (system CSPRNG)."""
    options = PasswordOptions(
        length=length, upper=upper, lower=lower, digits=digits, symbols=symbols
    )
    try:
        passwords = [generate_password(options) for _ in range(count)]
    except InvalidLength as exc:
        _fail(str(exc))
        return
    bits = round(entropy_bits(options), 1)
    if as_json:
        console.print_json(
            json.dumps(
                {
                    "passwords": passwords,
                    "length": length,
                    "entropy_bits": bits,
                    "alphabet_size": len(options.alphabet()),
                }
            )
        )
        return
    if copy and not _copy_to_clipboard(passwords[0]):
        _fail("no clipboard utility found (wl-copy/xclip/pbcopy)")
    for password in passwords:
        console.print(password)
    console.print(
        f"[dim]{length} characters · ~{bits} bits of entropy · "
        f"{len(options.alphabet())} possible symbols[/dim]",
        err=True,
    )


def main() -> None:
    """Console entry point with friendly errors instead of tracebacks."""
    try:
        app()
    except CliError as exc:
        typer.secho(f"erro: {exc}", fg=typer.colors.RED, err=True)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
