"""CLI maintenance commands: audit, backup, verify, passwd, generate."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from envvault.cli import _common, pwgen
from tests.cli_support import PASSPHRASE, Cli

PASS = f"{PASSPHRASE}\n"


def test_audit_lists_recent_events(cli: Cli, tmp_path: Path) -> None:
    cli.init()
    cli.add_project("demo", tmp_path / "work")
    result = cli.ok("audit", "-l", "10", input=PASS)
    assert "Audit log" in result.output
    assert "project" in result.output


def test_audit_filters_by_project(cli: Cli, tmp_path: Path) -> None:
    cli.init()
    cli.add_project("demo", tmp_path / "work")
    result = cli.ok("audit", "-p", "demo", input=PASS)
    assert "demo" in result.output


def test_audit_rejects_out_of_range_limit(cli: Cli) -> None:
    result = cli("audit", "--limit", "0")
    assert result.exit_code == 2


def test_verify_reports_intact_chain(cli: Cli) -> None:
    cli.init()
    assert "intact" in cli.ok("verify", input=PASS).output


def test_backup_to_directory_creates_0600_copy(cli: Cli, tmp_path: Path) -> None:
    cli.init()
    target = tmp_path / "backups"
    target.mkdir()
    result = cli.ok("backup", str(target))
    assert "Backup created" in result.output
    copies = list(target.iterdir())
    assert len(copies) == 1
    assert stat.S_IMODE(copies[0].stat().st_mode) == 0o600


def test_backup_fails_when_database_is_missing(cli: Cli, tmp_path: Path) -> None:
    cli.settings.db_path.unlink()
    result = cli("backup", str(tmp_path / "x.db"))
    assert result.exit_code == 1
    assert "error:" in result.output


def test_passwd_changes_the_passphrase(cli: Cli) -> None:
    cli.init()
    new = "brand-new-passphrase-456"
    result = cli.ok("passwd", input=f"{PASS}{new}\n{new}\n")
    assert "Passphrase changed" in result.output
    assert cli("unlock", input=PASS).exit_code != 0
    cli.ok("unlock", input=f"{new}\n")


def test_passwd_rejects_short_new_passphrase(cli: Cli) -> None:
    cli.init()
    result = cli("passwd", input=f"{PASS}short\nshort\n")
    assert result.exit_code == 1
    assert "at least 10 characters" in result.output


def test_generate_prints_requested_count_of_passwords(cli: Cli) -> None:
    result = cli.ok("generate", "-l", "20", "-c", "3")
    lines = [line for line in result.output.splitlines() if len(line) == 20]
    assert len(lines) == 3


def test_generate_json_reports_entropy(cli: Cli) -> None:
    result = cli.ok("generate", "--json", "-l", "16", "-c", "2")
    payload = json.loads(result.output)
    assert len(payload["passwords"]) == 2
    assert payload["length"] == 16
    assert payload["entropy_bits"] > 0


def test_generate_without_any_character_class_fails(cli: Cli) -> None:
    result = cli("generate", "--no-upper", "--no-lower", "--no-digits", "--no-symbols")
    assert result.exit_code == 1
    assert "error:" in result.output


def test_generate_copy_uses_clipboard(cli: Cli, monkeypatch: pytest.MonkeyPatch) -> None:
    copied: list[str] = []
    monkeypatch.setattr(pwgen, "_copy_to_clipboard", lambda value: copied.append(value) or True)
    cli.ok("generate", "--copy")
    assert len(copied) == 1


def test_generate_copy_fails_without_clipboard(cli: Cli, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pwgen, "_copy_to_clipboard", lambda value: False)
    result = cli("generate", "--copy")
    assert result.exit_code == 1
    assert "no clipboard utility" in result.output


def test_copy_to_clipboard_returns_false_when_no_helper_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_common.shutil, "which", lambda name: None)
    assert _common._copy_to_clipboard("x") is False


def test_copy_to_clipboard_pipes_value_to_first_available_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], bytes]] = []
    monkeypatch.setattr(_common.shutil, "which", lambda name: f"/bin/{name}")

    def fake_run(command: list[str], input: bytes, **kwargs: object) -> None:
        calls.append((command, input))

    monkeypatch.setattr(_common.subprocess, "run", fake_run)
    assert _common._copy_to_clipboard("hello") is True
    assert calls == [(["/bin/wl-copy"], b"hello")]


def test_copy_to_clipboard_falls_through_failing_helpers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_common.shutil, "which", lambda name: f"/bin/{name}")

    def failing_run(command: list[str], **kwargs: object) -> None:
        raise OSError("boom")

    monkeypatch.setattr(_common.subprocess, "run", failing_run)
    assert _common._copy_to_clipboard("hello") is False
