"""Working directory resolution for executions (B1)."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from envvault import cli
from envvault.services.runner import ExecError, resolve_cwd
from tests.conftest import ApiClient, sse_events


@pytest.fixture()
def project_tree(tmp_path: Path) -> SimpleNamespace:
    """A project with a subfolder, plus a folder outside it."""
    root = tmp_path / "proj"
    (root / "admin").mkdir(parents=True)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    return SimpleNamespace(root=root, outside=outside, project=SimpleNamespace(path=str(root)))


def test_relative_cwd_resolves_from_the_project_not_the_daemon(
    project_tree: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(project_tree.outside)
    assert resolve_cwd(project_tree.project, "admin") == project_tree.root / "admin"


def test_relative_cwd_cannot_escape_the_project(project_tree: SimpleNamespace) -> None:
    with pytest.raises(ExecError):
        resolve_cwd(project_tree.project, "../elsewhere")


def test_invocation_dir_inside_the_project_is_used(project_tree: SimpleNamespace) -> None:
    resolved = resolve_cwd(
        project_tree.project, None, invocation_dir=str(project_tree.root / "admin")
    )
    assert resolved == project_tree.root / "admin"


def test_invocation_dir_outside_the_project_falls_back_to_the_root(
    project_tree: SimpleNamespace,
) -> None:
    resolved = resolve_cwd(project_tree.project, None, invocation_dir=str(project_tree.outside))
    assert resolved == project_tree.root


def test_explicit_cwd_wins_over_invocation_dir(project_tree: SimpleNamespace) -> None:
    resolved = resolve_cwd(
        project_tree.project, ".", invocation_dir=str(project_tree.root / "admin")
    )
    assert resolved == project_tree.root


def test_explicit_cwd_outside_the_project_is_still_rejected(project_tree: SimpleNamespace) -> None:
    with pytest.raises(ExecError):
        resolve_cwd(project_tree.project, str(project_tree.outside))


def test_agent_exec_runs_in_the_relative_subfolder(
    auth: ApiClient, agent: dict, project_dir: Path
) -> None:
    (project_dir / "admin").mkdir()
    response = auth.client.post(
        "/v1/agent/exec",
        headers=agent["headers"],
        json={
            "environment": "dev",
            "command": ["python3", "-c", "import os;print(os.getcwd())"],
            "cwd": "admin",
        },
    )
    assert response.status_code == 200, response.text
    output = "".join(e.get("text", "") for e in sse_events(response.text) if e["type"] == "output")
    assert output.strip() == str((project_dir / "admin").resolve())


def test_cli_run_sends_the_invocation_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sent: dict[str, Any] = {}

    def fake_stream(_client: Any, _path: str, payload: dict[str, Any], _csrf: str | None) -> int:
        sent.update(payload)
        return 0

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "_target", lambda _p, _e: ("sample", "dev"))
    monkeypatch.setattr(cli, "_agent_token", lambda _s, _slug: SimpleNamespace(value="ev_x"))
    monkeypatch.setattr(cli, "_token_client", lambda _s, _t: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(cli, "_stream_exec", fake_stream)
    result = CliRunner().invoke(cli.app, ["run", "-p", "sample", "--", "echo", "hi"])
    assert result.exit_code == 0, result.output
    assert sent["invocation_dir"] == os.getcwd()
    assert sent["cwd"] is None
