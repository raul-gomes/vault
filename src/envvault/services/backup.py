"""Consistent copy of the still-encrypted vault database (S5).

The copy holds ciphertext and the DEK wrapped by the passphrase in use at
backup time, so it is safe to keep on an external disk or cloud storage and
useless without that passphrase. No plaintext is ever produced.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from envvault.config import PRIVATE_FILE_MODE

BACKUP_NAME_FORMAT = "envvault-backup-%Y%m%dT%H%M%SZ.db"


class BackupError(ValueError):
    """Raised when a backup cannot be created safely."""


def create_backup(db_path: Path, destination: Path, *, now: datetime | None = None) -> Path:
    """Copy the vault database to ``destination`` and return the file written.

    ``destination`` may be a file path (must not exist) or an existing
    directory (a timestamped file name is used). Uses SQLite's online backup
    API, so it is consistent even while the daemon is writing.
    """
    if not db_path.is_file():
        raise BackupError(f"no vault database at {db_path}")
    destination = destination.expanduser()
    if destination.is_dir():
        stamp = (now or datetime.now(UTC)).astimezone(UTC)
        destination = destination / stamp.strftime(BACKUP_NAME_FORMAT)
    if destination.exists():
        raise BackupError(f"{destination} already exists; choose another name")
    # Create the file owner-only before SQLite writes any page into it.
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, PRIVATE_FILE_MODE)
    os.close(fd)
    try:
        source = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        target = sqlite3.connect(destination)
        try:
            source.backup(target)
        finally:
            target.close()
            source.close()
    except sqlite3.Error as exc:
        destination.unlink(missing_ok=True)
        raise BackupError(f"backup failed: {exc}") from exc
    os.chmod(destination, PRIVATE_FILE_MODE)
    return destination
