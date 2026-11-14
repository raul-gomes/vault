"""``envvault.daemon.main`` starts uvicorn with the configured loopback address."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from envvault import daemon


def test_main_runs_uvicorn_factory_on_configured_host_and_port(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ENVVAULT_HOME", str(tmp_path / "home"))
    calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    monkeypatch.setattr(daemon.uvicorn, "run", lambda *a, **k: calls.append((a, k)))
    daemon.main()
    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args == ("envvault.app:create_app",)
    assert kwargs["factory"] is True
    assert kwargs["host"] == "127.0.0.1"
    assert kwargs["access_log"] is False
