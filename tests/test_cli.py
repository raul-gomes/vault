"""CLI smoke tests that do not need a daemon."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from envvault.cli import app

runner = CliRunner()


def test_help_lists_core_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "init" in result.output
    assert "run" in result.output
    assert "generate" in result.output


def test_generate_json() -> None:
    result = runner.invoke(
        app, ["generate", "--length", "24", "--count", "3", "--json", "--no-symbols"]
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["length"] == 24
    assert len(payload["passwords"]) == 3
    assert all(len(password) == 24 for password in payload["passwords"])
    assert payload["entropy_bits"] > 0


def test_generate_rejects_invalid_setup() -> None:
    result = runner.invoke(
        app,
        ["generate", "--no-upper", "--no-lower", "--no-digits", "--no-symbols"],
    )
    assert result.exit_code != 0
    assert "caractere" in result.output or "character" in result.output


def test_link_writes_project_file(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["link", "--project", "sample", "--environment", "dev"])
    assert result.exit_code == 0
    content = (tmp_path / ".envvault.toml").read_text(encoding="utf-8")
    assert 'project = "sample"' in content
    assert 'environment = "dev"' in content

    again = runner.invoke(app, ["link", "--project", "other"])
    assert again.exit_code != 0
