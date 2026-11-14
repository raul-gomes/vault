"""Shared CLI state and helpers: apps, console, errors, daemon and session helpers."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
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

from envvault.config import Settings

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
HTTP_TIMEOUT_SECONDS = 30.0


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
    typer.secho(f"error: {message}", fg=typer.colors.RED, err=True)
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


def _http_client(
    settings: Settings,
    *,
    timeout: float | httpx.Timeout = HTTP_TIMEOUT_SECONDS,
    headers: dict[str, str] | None = None,
) -> httpx.Client:
    """Every HTTP client the CLI uses to reach the daemon (seam for tests)."""
    return httpx.Client(base_url=settings.base_url, timeout=timeout, headers=headers)


def _health(settings: Settings, timeout: float = 1.0) -> dict[str, Any] | None:
    """Return the daemon health payload, or None when it is not reachable."""
    try:
        with _http_client(settings, timeout=timeout) as client:
            response = client.get("/v1/health")
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
    client = _http_client(settings)
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
