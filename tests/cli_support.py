"""Run the real CLI against an in-process daemon (no network, no subprocess daemon).

Every HTTP client the CLI creates goes through ``_common._http_client``. The
``cli`` fixture swaps it for a Starlette ``TestClient`` bound to a FastAPI app
that uses an isolated ``ENVVAULT_HOME`` with a fast KDF, so commands exercise
the CLI, the API and the services together.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from typer.testing import CliRunner, Result

from envvault.app import create_app
from envvault.cli import CliError, _common, app
from envvault.config import Settings

PASSPHRASE = "cli-test-passphrase-123"
FAST_KDF_ENV = {
    "ENVVAULT_KDF_TIME_COST": "1",
    "ENVVAULT_KDF_MEMORY_KIB": "8192",
    "ENVVAULT_KDF_PARALLELISM": "1",
}


class _ClientWithoutLifespan(TestClient):
    """TestClient whose ``with`` block does not run app startup/shutdown.

    The CLI opens short-lived clients with ``with``; a plain TestClient would
    run the lifespan each time, and shutdown locks the vault.
    """

    def __enter__(self) -> _ClientWithoutLifespan:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


@dataclass
class Outcome:
    """Exit code and combined output of a CLI run that ended in a ``CliError``."""

    exit_code: int
    output: str


@dataclass
class Cli:
    """Invoke CLI commands against the in-process daemon."""

    runner: CliRunner
    app: FastAPI
    settings: Settings

    def __call__(self, *args: str, input: str | None = None) -> Result | Outcome:
        """Run ``envvault <args>`` and return the result.

        A ``CliError`` is turned into exit code 1 plus the ``error:`` line, the
        way :func:`envvault.cli.main` reports it.
        """
        try:
            return self.runner.invoke(app, list(args), input=input, catch_exceptions=False)
        except CliError as exc:
            return Outcome(exit_code=1, output=f"error: {exc}\n")

    def ok(self, *args: str, input: str | None = None) -> Result | Outcome:
        """Run a command that must exit 0."""
        result = self(*args, input=input)
        assert result.exit_code == 0, result.output
        return result

    def init(self) -> None:
        """Create the vault with :data:`PASSPHRASE`."""
        self.ok("init", input=f"{PASSPHRASE}\n{PASSPHRASE}\n")

    def add_project(self, slug: str, path: Path) -> None:
        """Register a project (the CLI asks for the passphrase)."""
        self.ok("project", "add", slug, "--path", str(path), input=f"{PASSPHRASE}\n")


@pytest.fixture()
def cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Cli]:
    """CLI wired to an in-process daemon on an isolated home."""
    home = tmp_path / "home"
    monkeypatch.setenv("ENVVAULT_HOME", str(home))
    for key, value in FAST_KDF_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("ENVVAULT_TOKEN", raising=False)
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    settings = Settings.from_env()
    settings.ensure_home()
    daemon_app = create_app(settings)

    def fake_http_client(
        settings: Settings,
        *,
        timeout: Any = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Client:
        return _ClientWithoutLifespan(
            daemon_app,
            base_url=settings.base_url,
            headers=headers,
            raise_server_exceptions=False,
        )

    with TestClient(daemon_app):
        monkeypatch.setattr(_common, "_http_client", fake_http_client)
        yield Cli(runner=CliRunner(), app=daemon_app, settings=settings)
