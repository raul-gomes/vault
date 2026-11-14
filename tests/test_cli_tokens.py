"""CLI agent token commands."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from envvault import tokenstore
from tests.cli_support import PASSPHRASE, Cli

PASS = f"{PASSPHRASE}\n"


@pytest.fixture()
def demo(cli: Cli, tmp_path: Path) -> Cli:
    """CLI with an initialised vault and a ``demo`` project."""
    cli.init()
    cli.add_project("demo", tmp_path / "work")
    return cli


def _token_file(cli: Cli, slug: str = "demo") -> Path:
    return cli.settings.home / "agent-tokens" / f"{slug}.token"


def test_token_create_saves_0600_file_and_does_not_print_value(demo: Cli) -> None:
    result = demo.ok("token", "create", "-n", "agent", "-p", "demo", "--allow", "echo", input=PASS)
    path = _token_file(demo)
    assert "Token created and saved" in result.output
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    stored = tokenstore.load(demo.settings.home, "demo")
    assert stored is not None
    assert stored.value not in result.output
    assert "Allowed commands: echo" in result.output


def test_token_create_no_save_prints_value_once(demo: Cli) -> None:
    result = demo.ok(
        "token", "create", "-n", "agent", "-p", "demo", "--allow", "echo", "--no-save", input=PASS
    )
    assert "will not be shown again" in result.output
    assert "ENVVAULT_TOKEN=" in result.output
    assert not _token_file(demo).exists()


def test_token_create_any_command_warns(demo: Cli) -> None:
    result = demo.ok("token", "create", "-n", "agent", "-p", "demo", "--any-command", input=PASS)
    assert "--any-command" in result.output


def test_token_create_warns_when_env_token_shadows_file(
    demo: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ENVVAULT_TOKEN", "evt_dummy")
    result = demo.ok("token", "create", "-n", "agent", "-p", "demo", "--any-command", input=PASS)
    assert "takes precedence" in result.output


def test_token_create_requires_allow_or_any_command(demo: Cli) -> None:
    result = demo("token", "create", "-n", "agent", "-p", "demo")
    assert result.exit_code == 1
    assert "--allow" in result.output


def test_token_create_rejects_allow_with_any_command(demo: Cli) -> None:
    result = demo(
        "token", "create", "-n", "agent", "-p", "demo", "--allow", "echo", "--any-command"
    )
    assert result.exit_code == 1
    assert "not both" in result.output


def test_token_create_without_inject_needs_no_command(demo: Cli) -> None:
    demo.ok("token", "create", "-n", "reader", "-p", "demo", "--no-inject", input=PASS)
    assert _token_file(demo).exists()


def test_token_create_for_unknown_project_fails(demo: Cli) -> None:
    result = demo("token", "create", "-n", "a", "-p", "ghost", "--any-command", input=PASS)
    assert result.exit_code == 1
    assert "project not found: ghost" in result.output


def test_token_list_shows_permissions_and_local_copy(demo: Cli) -> None:
    demo.ok("token", "create", "-n", "agent", "-p", "demo", "--allow", "echo", input=PASS)
    result = demo.ok("token", "list", input=PASS)
    assert "agent" in result.output
    assert "active" in result.output
    assert "yes" in result.output
    stored = tokenstore.load(demo.settings.home, "demo")
    assert stored is not None
    assert stored.value not in result.output


def test_token_list_shows_read_only_token_without_run_permission(demo: Cli) -> None:
    demo.ok("token", "create", "-n", "reader", "-p", "demo", "--no-inject", "--no-save", input=PASS)
    result = demo.ok("token", "list", input=PASS)
    assert "reader" in result.output
    assert "list" in result.output


def test_token_revoke_removes_local_file(demo: Cli) -> None:
    demo.ok("token", "create", "-n", "agent", "-p", "demo", "--allow", "echo", input=PASS)
    result = demo.ok("token", "revoke", "agent", "-y", input=PASS)
    assert "Token revoked" in result.output
    assert "Local token removed" in result.output
    assert not _token_file(demo).exists()
    assert "revoked" in demo.ok("token", "list", input=PASS).output


def test_token_revoke_asks_for_confirmation(demo: Cli) -> None:
    demo.ok("token", "create", "-n", "agent", "-p", "demo", "--allow", "echo", input=PASS)
    declined = demo("token", "revoke", "agent", input=f"{PASS}n\n")
    assert declined.exit_code == 1
    assert _token_file(demo).exists()
    demo.ok("token", "revoke", "agent", input=f"{PASS}y\n")
    assert not _token_file(demo).exists()


def test_token_revoke_unknown_name_fails(demo: Cli) -> None:
    result = demo("token", "revoke", "ghost", "-y", input=PASS)
    assert result.exit_code == 1
    assert "active token not found: ghost" in result.output


def test_token_revoke_refuses_duplicate_names_without_yes(demo: Cli) -> None:
    for _ in range(2):
        demo.ok(
            "token", "create", "-n", "dup", "-p", "demo", "--any-command", "--no-save", input=PASS
        )
    result = demo("token", "revoke", "dup", input=PASS)
    assert result.exit_code == 1
    assert "more than one active token" in result.output
