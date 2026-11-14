"""End-to-end CLI flows against the in-process daemon."""

from __future__ import annotations

from pathlib import Path

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
