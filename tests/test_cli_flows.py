"""End-to-end CLI flows against the in-process daemon."""

from __future__ import annotations

import runpy
from pathlib import Path

import httpx
import pytest
import typer

from envvault import cli as cli_pkg
from envvault.cli import CliError, _common
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


def test_ensure_daemon_spawns_process_and_returns_once_healthy(
    cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    health = iter([None, {"ok": True}])
    spawned: list[list[str]] = []
    monkeypatch.setattr(_common, "_health", lambda settings, timeout=1.0: next(health))
    monkeypatch.setattr(_common.subprocess, "Popen", lambda cmd, **kw: spawned.append(cmd))
    monkeypatch.setattr(_common.time, "sleep", lambda seconds: None)
    _common.ensure_daemon(cli.settings)
    assert len(spawned) == 1
    assert spawned[0][-2:] == ["-m", "envvault.daemon"]


def test_ensure_daemon_fails_when_daemon_never_answers(
    cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_common, "_health", lambda settings, timeout=1.0: None)
    monkeypatch.setattr(_common.subprocess, "Popen", lambda cmd, **kw: None)
    monkeypatch.setattr(_common.time, "sleep", lambda seconds: None)
    with pytest.raises(typer.Exit) as exit_info:
        _common.ensure_daemon(cli.settings)
    assert exit_info.value.exit_code == 1


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (401, {"detail": "nope"}, "not authenticated: nope"),
        (423, {"detail": "locked"}, "vault locked"),
        (409, {"detail": "conflict"}, "conflict; run `envvault init`"),
        (422, {"detail": [{"msg": "bad field"}]}, "HTTP 422: bad field"),
        (500, {"other": 1}, "HTTP 500: Internal Server Error"),
    ],
)
def test_raise_for_status_maps_http_errors_to_messages(
    status: int, body: dict[str, object], expected: str
) -> None:
    response = httpx.Response(status, json=body)
    with pytest.raises(CliError, match=expected):
        _common._raise_for_status(response)


def test_raise_for_status_uses_plain_text_when_body_is_not_json() -> None:
    with pytest.raises(CliError, match="HTTP 502: bad gateway"):
        _common._raise_for_status(httpx.Response(502, text="bad gateway"))


def test_python_dash_m_entry_point_runs_main(monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[str] = []
    monkeypatch.setattr(cli_pkg, "main", lambda: called.append("main"))
    runpy.run_module("envvault.cli", run_name="__main__")
    assert called == ["main"]
