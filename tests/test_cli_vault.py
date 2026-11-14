"""CLI vault lifecycle commands: init, serve, stop, status, unlock, lock."""

from __future__ import annotations

import os
import signal
from pathlib import Path

import httpx
import pytest

from envvault.cli import _common, vault
from tests.cli_support import PASSPHRASE, Cli


def _unreachable_client(*args: object, **kwargs: object) -> httpx.Client:
    """HTTP client whose every request fails to connect."""

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    return httpx.Client(transport=httpx.MockTransport(refuse), base_url="http://127.0.0.1:1")


def test_init_creates_vault_and_reports_next_step(cli: Cli) -> None:
    result = cli.ok("init", input=f"{PASSPHRASE}\n{PASSPHRASE}\n")
    assert "Vault created" in result.output
    assert cli.settings.db_path.exists()


def test_init_refuses_when_vault_already_exists(cli: Cli) -> None:
    cli.init()
    result = cli("init", input=f"{PASSPHRASE}\n{PASSPHRASE}\n")
    assert result.exit_code == 1
    assert "already exists" in result.output


def test_init_rejects_short_passphrase(cli: Cli) -> None:
    result = cli("init", input="short\nshort\n")
    assert result.exit_code == 1
    assert "at least 10 characters" in result.output


def test_status_reports_locked_vault_after_lock(cli: Cli) -> None:
    cli.init()
    cli.ok("lock", input=f"{PASSPHRASE}\n")
    assert "locked" in cli.ok("status").output


def test_status_reports_daemon_not_running_when_unreachable(
    cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_common, "_http_client", _unreachable_client)
    result = cli.ok("status")
    assert "not running" in result.output


def test_unlock_succeeds_with_correct_passphrase(cli: Cli) -> None:
    cli.init()
    assert "unlocked" in cli.ok("unlock", input=f"{PASSPHRASE}\n").output.lower()


def test_unlock_fails_with_wrong_passphrase(cli: Cli) -> None:
    cli.init()
    result = cli("unlock", input="wrong-passphrase-xyz\n")
    assert result.exit_code != 0


def test_lock_reports_vault_locked(cli: Cli) -> None:
    cli.init()
    assert "locked" in cli.ok("lock", input=f"{PASSPHRASE}\n").output.lower()


def test_serve_delegates_to_daemon_main(cli: Cli, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr("envvault.daemon.main", lambda: calls.append("main"))
    cli.ok("serve")
    assert calls == ["main"]


def test_stop_fails_without_pid_file(cli: Cli) -> None:
    # The in-process daemon writes its own PID (the pytest process) on startup.
    cli.settings.pid_path.unlink(missing_ok=True)
    result = cli("stop")
    assert result.exit_code == 1
    assert "no PID file" in result.output


def test_stop_fails_on_invalid_pid(cli: Cli) -> None:
    cli.settings.pid_path.write_text("not-a-number", encoding="utf-8")
    result = cli("stop")
    assert result.exit_code == 1
    assert "invalid PID" in result.output


def test_stop_handles_process_that_is_already_gone(
    cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    cli.settings.pid_path.write_text("4242", encoding="utf-8")

    def gone(pid: int, sig: int) -> None:
        raise ProcessLookupError

    monkeypatch.setattr(os, "kill", gone)
    result = cli.ok("stop")
    assert "already stopped" in result.output
    assert not cli.settings.pid_path.exists()


def test_stop_signals_daemon_and_removes_pid_file(
    cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    cli.settings.pid_path.write_text("4242", encoding="utf-8")
    sent: list[tuple[int, int]] = []
    monkeypatch.setattr(os, "kill", lambda pid, sig: sent.append((pid, sig)))
    monkeypatch.setattr(vault, "_health", lambda settings, timeout=1.0: None)
    monkeypatch.setattr(vault.time, "sleep", lambda seconds: None)
    result = cli.ok("stop")
    assert sent == [(4242, signal.SIGTERM)]
    assert "daemon stopped" in result.output
    assert not cli.settings.pid_path.exists()


def test_stop_fails_when_daemon_keeps_answering(cli: Cli, monkeypatch: pytest.MonkeyPatch) -> None:
    cli.settings.pid_path.write_text("4242", encoding="utf-8")
    monkeypatch.setattr(os, "kill", lambda pid, sig: None)
    monkeypatch.setattr(vault, "_health", lambda settings, timeout=1.0: {"ok": True})
    monkeypatch.setattr(vault.time, "sleep", lambda seconds: None)
    result = cli("stop")
    assert result.exit_code == 1
    assert "did not respond" in result.output


def test_pid_path_fixture_is_inside_home(cli: Cli, tmp_path: Path) -> None:
    assert str(cli.settings.pid_path).startswith(str(tmp_path / "home"))
