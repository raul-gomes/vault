"""CLI runtime commands: run, context, keys (user session and agent token)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from envvault import tokenstore
from envvault.cli import _common
from tests.cli_support import PASSPHRASE, Cli

PASS = f"{PASSPHRASE}\n"
VALUE = "inject-me-4242"


@pytest.fixture()
def demo(cli: Cli, tmp_path: Path) -> Cli:
    """CLI with a ``demo`` project holding one dev secret."""
    cli.init()
    cli.add_project("demo", tmp_path / "work")
    cli.ok("set", "API_KEY", "-p", "demo", "-e", "dev", "--value", VALUE, input=PASS)
    return cli


def _agent_token(cli: Cli, *extra: str) -> str:
    """Create a token file for ``demo`` and return the raw token."""
    cli.ok("token", "create", "-n", "agent", "-p", "demo", *extra, input=PASS)
    stored = tokenstore.load(cli.settings.home, "demo")
    assert stored is not None
    return stored.value


def test_run_requires_a_command(cli: Cli) -> None:
    result = cli("run", "-p", "demo", "-e", "dev")
    assert result.exit_code == 1
    assert "provide the command after --" in result.output


def test_run_with_invalid_env_flag_fails(cli: Cli) -> None:
    result = cli("run", "-p", "demo", "-e", "dev", "--env", "NOEQUALS", "--", "true")
    assert result.exit_code == 1
    assert "use KEY=VALUE in --env" in result.output


def test_run_without_project_fails(cli: Cli) -> None:
    result = cli("run", "--", "true")
    assert result.exit_code == 1
    assert "provide --project" in result.output


def test_run_as_user_propagates_exit_code(demo: Cli) -> None:
    result = demo("run", "-p", "demo", "-e", "dev", "--", "sh", "-c", "exit 3", input=PASS)
    assert result.exit_code == 3


def test_run_as_user_passes_extra_env_to_process(demo: Cli) -> None:
    result = demo.ok(
        "run", "-p", "demo", "-e", "dev", "-E", "PORT=3001", "--timeout", "30",
        "--", "sh", "-c", "echo port=$PORT", input=PASS,
    )  # fmt: skip
    assert "port=3001" in result.output


def test_run_as_user_with_unknown_project_fails(demo: Cli) -> None:
    result = demo("run", "-p", "ghost", "-e", "dev", "--", "true", input=PASS)
    assert result.exit_code == 1
    assert "project not found: ghost" in result.output


def test_run_with_agent_token_file_injects_and_redacts(demo: Cli) -> None:
    _agent_token(demo, "--any-command")
    result = demo.ok("run", "-p", "demo", "-e", "dev", "--", "sh", "-c", "echo $API_KEY")
    assert "[REDACTED:API_KEY]" in result.output
    assert VALUE not in result.output


def test_run_with_allowed_command_list_rejects_other_commands(demo: Cli) -> None:
    _agent_token(demo, "--allow", "echo")
    allowed = demo("run", "-p", "demo", "-e", "dev", "--", "echo", "hi")
    denied = demo("run", "-p", "demo", "-e", "dev", "--", "sh", "-c", "true")
    assert allowed.exit_code == 0
    assert denied.exit_code == 1
    assert "HTTP 403" in denied.output


def test_run_with_env_token_uses_it_over_files(demo: Cli, monkeypatch: pytest.MonkeyPatch) -> None:
    token = _agent_token(demo, "--any-command")
    tokenstore.remove(demo.settings.home, "demo")
    monkeypatch.setenv("ENVVAULT_TOKEN", token)
    result = demo.ok("run", "-p", "demo", "-e", "dev", "--", "echo", "ok")
    assert "ok" in result.output


def test_run_fails_when_token_file_has_wide_permissions(demo: Cli) -> None:
    _agent_token(demo, "--any-command")
    tokenstore.path_for(demo.settings.home, "demo").chmod(0o644)
    result = demo("run", "-p", "demo", "-e", "dev", "--", "echo", "ok")
    assert result.exit_code == 1
    assert "error:" in result.output


def test_run_reports_unreachable_daemon_for_streaming(
    demo: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    _agent_token(demo, "--any-command")

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    def broken_client(*args: object, **kwargs: object) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(refuse), base_url="http://127.0.0.1:1")

    monkeypatch.setattr(_common, "_http_client", broken_client)
    result = demo("run", "-p", "demo", "-e", "dev", "--", "echo", "ok")
    assert result.exit_code == 1
    assert "could not reach the daemon" in result.output


def test_context_with_token_file_prints_scope_json(demo: Cli) -> None:
    _agent_token(demo, "--allow", "echo")
    result = demo.ok("context", "-p", "demo")
    payload = json.loads(result.output)
    assert payload["project"]["slug"] == "demo"


def test_context_with_env_token(demo: Cli, monkeypatch: pytest.MonkeyPatch) -> None:
    token = _agent_token(demo, "--allow", "echo")
    monkeypatch.setenv("ENVVAULT_TOKEN", token)
    assert json.loads(demo.ok("context").output)["project"]["slug"] == "demo"


def test_context_uses_project_from_envvault_toml(demo: Cli) -> None:
    _agent_token(demo, "--allow", "echo")
    demo.ok("link", "-p", "demo", "-e", "dev")
    assert json.loads(demo.ok("context").output)["project"]["slug"] == "demo"


def test_context_without_project_or_token_fails(cli: Cli) -> None:
    result = cli("context")
    assert result.exit_code == 1
    assert "provide --project" in result.output


def test_context_without_local_token_fails(demo: Cli) -> None:
    result = demo("context", "-p", "demo")
    assert result.exit_code == 1
    assert "no local token for demo" in result.output


def test_context_with_revoked_token_fails(demo: Cli) -> None:
    _agent_token(demo, "--allow", "echo")
    stored = tokenstore.load(demo.settings.home, "demo")
    assert stored is not None
    demo.ok("token", "revoke", "agent", "-y", input=PASS)
    tokenstore.save(demo.settings.home, "demo", stored.value)
    result = demo("context", "-p", "demo")
    assert result.exit_code == 1
    assert "not authenticated" in result.output


def test_keys_lists_names_and_never_values(demo: Cli) -> None:
    _agent_token(demo, "--allow", "echo")
    result = demo.ok("keys", "-p", "demo", "-e", "dev")
    assert "API_KEY" in result.output
    assert "keys/dev" in result.output
    assert VALUE not in result.output


def test_keys_without_token_fails_in_english(demo: Cli) -> None:
    result = demo("keys", "-p", "demo", "-e", "dev")
    assert result.exit_code == 1
    assert "no token for demo" in result.output
    assert "as a human" in result.output


def test_keys_with_no_list_permission_fails(demo: Cli) -> None:
    _agent_token(demo, "--allow", "echo", "--no-list")
    result = demo("keys", "-p", "demo", "-e", "dev")
    assert result.exit_code == 1
    assert "HTTP 403" in result.output
