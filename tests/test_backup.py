"""Encrypted backup of the vault database (S5)."""

from __future__ import annotations

import sqlite3
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from envvault.cli import app as cli_app
from envvault.config import Settings
from envvault.services.backup import BackupError, create_backup
from tests.conftest import SECRET_VALUE

FIXED_NOW = datetime(2026, 11, 13, 21, 30, 5, tzinfo=UTC)


def _tables(path: Path) -> set[str]:
    with sqlite3.connect(path) as conn:
        rows = conn.execute("select name from sqlite_master where type = 'table'").fetchall()
    return {row[0] for row in rows}


def test_backup_copies_the_encrypted_database(
    settings: Settings, secret: dict, tmp_path: Path
) -> None:
    target = tmp_path / "copy.db"
    result = create_backup(settings.db_path, target)
    assert result == target
    assert {"secrets", "meta", "audit_log"} <= _tables(target)
    with sqlite3.connect(target) as conn:
        assert conn.execute("select count(*) from secrets").fetchone()[0] == 1
    assert SECRET_VALUE.encode() not in target.read_bytes()
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_backup_refuses_to_overwrite(settings: Settings, secret: dict, tmp_path: Path) -> None:
    target = tmp_path / "copy.db"
    target.write_bytes(b"keep me")
    with pytest.raises(BackupError, match="exists"):
        create_backup(settings.db_path, target)
    assert target.read_bytes() == b"keep me"


def test_backup_into_a_directory_uses_a_timestamped_name(
    settings: Settings, secret: dict, tmp_path: Path
) -> None:
    result = create_backup(settings.db_path, tmp_path, now=FIXED_NOW)
    assert result == tmp_path / "envvault-backup-20261113T213005Z.db"


def test_backup_without_a_vault_fails(tmp_path: Path) -> None:
    with pytest.raises(BackupError, match="no vault"):
        create_backup(tmp_path / "missing.db", tmp_path / "copy.db")


def test_cli_backup(settings: Settings, secret: dict, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ENVVAULT_HOME", str(settings.home))
    target = tmp_path / "cli-copy.db"
    result = CliRunner().invoke(cli_app, ["backup", str(target)])
    assert result.exit_code == 0, result.output
    assert target.exists()
    assert "passphrase" in result.output
