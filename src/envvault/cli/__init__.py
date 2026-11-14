"""Command-line interface for EnvVault.

Importing this package registers every command on the shared ``app``.
"""

from __future__ import annotations

import typer

# Import order sets the command order shown by `envvault --help`; keep it.
# isort: off
from envvault.cli import vault  # noqa: F401
from envvault.cli import secrets  # noqa: F401
from envvault.cli import runtime  # noqa: F401
from envvault.cli import maintenance  # noqa: F401
from envvault.cli import pwgen  # noqa: F401
from envvault.cli import projects  # noqa: F401
from envvault.cli import tokens  # noqa: F401
from envvault.cli import credentials  # noqa: F401

# isort: on
from envvault.cli._common import CliError, app, console, ensure_daemon

__all__ = ["CliError", "app", "console", "ensure_daemon", "main"]


def main() -> None:
    """Console entry point with friendly errors instead of tracebacks."""
    try:
        app()
    except CliError as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise SystemExit(1) from None
