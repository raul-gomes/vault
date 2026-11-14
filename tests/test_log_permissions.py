"""Daemon log must be owner-only, whatever the umask or the existing mode (S6)."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from envvault.app import create_app
from envvault.config import Settings

PRIVATE_MODE = 0o600
GROUP_READABLE_MODE = 0o664
PERMISSIVE_UMASK = 0o002


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.fixture()
def permissive_umask() -> Iterator[None]:
    """Use the common desktop umask (files 0664) and restore it afterwards."""
    previous = os.umask(PERMISSIVE_UMASK)
    try:
        yield
    finally:
        os.umask(previous)


def test_open_log_creates_owner_only_file(settings: Settings, permissive_umask: None) -> None:
    settings.ensure_home()
    with settings.open_log() as log:
        log.write(b"started\n")
    assert _mode(settings.log_path) == PRIVATE_MODE


def test_open_log_tightens_an_existing_readable_file(settings: Settings) -> None:
    settings.ensure_home()
    settings.log_path.write_bytes(b"old\n")
    settings.log_path.chmod(GROUP_READABLE_MODE)
    with settings.open_log() as log:
        log.write(b"new\n")
    assert _mode(settings.log_path) == PRIVATE_MODE
    assert settings.log_path.read_bytes() == b"old\nnew\n"


def test_daemon_start_tightens_an_existing_log(settings: Settings) -> None:
    settings.ensure_home()
    settings.log_path.write_bytes(b"old\n")
    settings.log_path.chmod(GROUP_READABLE_MODE)
    with TestClient(create_app(settings)):
        pass
    assert _mode(settings.log_path) == PRIVATE_MODE
