"""End-to-end CLI flows against the in-process daemon."""

from __future__ import annotations

from pathlib import Path

import pytest

from envvault import cli as cli_pkg
from envvault.cli import CliError

from tests.cli_support import PASSPHRASE, Cli


def test_init_then_status_reports_unlocked_vault(cli: Cli) -> None:
    cli.init()
    result = cli.ok("status")
    assert "unlocked" in result.output.lower()


def test_secret_round_trip_never_prints_the_value(cli: Cli, tmp_path: Path) -> None:
    cli.init()
    project_dir = tmp_path / "work"
    cli.add_project("demo", project_dir)
    cli.ok("set", "API_KEY", "-p", "demo", "-e", "dev", input=f"{PASSPHRASE}\nsuper-secret-value\n")
    listed = cli.ok("list", "-p", "demo", "-e", "dev", input=f"{PASSPHRASE}\n")
    assert "API_KEY" in listed.output
    assert "super-secret-value" not in listed.output


def test_run_injects_and_redacts(cli: Cli, tmp_path: Path) -> None:
    cli.init()
    cli.add_project("demo", tmp_path / "work")
    cli.ok("set", "API_KEY", "-p", "demo", "-e", "dev", input=f"{PASSPHRASE}\nsuper-secret-value\n")
    result = cli(
        "run", "-p", "demo", "-e", "dev", "--", "sh", "-c", "echo $API_KEY", input=f"{PASSPHRASE}\n"
    )
    assert result.exit_code == 0, result.output
    assert "[REDACTED:API_KEY]" in result.output
    assert "super-secret-value" not in result.output


def test_main_reports_cli_errors_in_english_without_traceback(
    cli: Cli, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom() -> None:
        raise CliError("something broke")

    monkeypatch.setattr(cli_pkg, "app", boom)
    with pytest.raises(SystemExit) as exit_info:
        cli_pkg.main()
    assert exit_info.value.code == 1
    assert capsys.readouterr().err.startswith("error: something broke")


def test_fail_prefixes_message_with_english_error_label(cli: Cli) -> None:
    cli.settings.pid_path.unlink(missing_ok=True)
    result = cli("stop")
    assert result.exit_code == 1
    assert "error:" in result.output
    assert "erro:" not in result.output
