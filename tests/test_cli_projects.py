"""CLI project commands."""

from __future__ import annotations

from pathlib import Path

from tests.cli_support import PASSPHRASE, Cli

PASS = f"{PASSPHRASE}\n"


def test_project_add_and_list_show_the_project(cli: Cli, tmp_path: Path) -> None:
    cli.init()
    added = cli.ok("project", "add", "demo", "-n", "Demo App", "-p", str(tmp_path / "work"), input=PASS)
    assert "Project created" in added.output
    listed = cli.ok("project", "list", input=PASS)
    assert "demo" in listed.output
    assert "Demo App" in listed.output


def test_project_add_duplicate_slug_fails(cli: Cli, tmp_path: Path) -> None:
    cli.init()
    cli.add_project("demo", tmp_path / "work")
    result = cli("project", "add", "demo", "-p", str(tmp_path / "work"), input=PASS)
    assert result.exit_code != 0


def test_project_update_requires_a_field(cli: Cli) -> None:
    result = cli("project", "update", "demo")
    assert result.exit_code == 1
    assert "provide --name and/or --path" in result.output


def test_project_update_changes_name_and_path(cli: Cli, tmp_path: Path) -> None:
    cli.init()
    cli.add_project("demo", tmp_path / "work")
    new_dir = tmp_path / "other"
    new_dir.mkdir()
    result = cli.ok("project", "update", "demo", "-n", "Renamed", "-p", str(new_dir), input=PASS)
    assert "Project updated" in result.output
    listed = cli.ok("project", "list", input=PASS)
    assert "Renamed" in listed.output


def test_project_update_unknown_project_fails(cli: Cli) -> None:
    cli.init()
    result = cli("project", "update", "ghost", "-n", "X", input=PASS)
    assert result.exit_code != 0


def test_project_remove_with_yes_deletes_project(cli: Cli, tmp_path: Path) -> None:
    cli.init()
    cli.add_project("demo", tmp_path / "work")
    result = cli.ok("project", "remove", "demo", "--yes", input=PASS)
    assert "Project removed" in result.output
    assert "demo" not in cli.ok("project", "list", input=PASS).output


def test_project_remove_declined_confirmation_keeps_project(cli: Cli, tmp_path: Path) -> None:
    cli.init()
    cli.add_project("demo", tmp_path / "work")
    result = cli("project", "remove", "demo", input=f"{PASS}n\n")
    assert result.exit_code == 1
    assert "demo" in cli.ok("project", "list", input=PASS).output


def test_project_remove_unknown_project_fails(cli: Cli) -> None:
    cli.init()
    result = cli("project", "remove", "ghost", "-y", input=PASS)
    assert result.exit_code != 0
    assert "project not found" in result.output
