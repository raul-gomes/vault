"""Runtime configuration (paths, bind address and KDF cost)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8787
DEFAULT_LOCK_TIMEOUT_MINUTES = 30

# Argon2id defaults. Tests lower these to keep the suite fast.
DEFAULT_KDF_TIME_COST = 3
DEFAULT_KDF_MEMORY_KIB = 64 * 1024
DEFAULT_KDF_PARALLELISM = 4

MIN_PASSPHRASE_LENGTH = 10

# Owner-only mode for every file the vault writes (database, log, tokens).
PRIVATE_FILE_MODE = 0o600


def _env_int(name: str, fallback: int) -> int:
    """Read an integer environment variable, failing loudly on bad input."""
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return fallback
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc


@dataclass(frozen=True, slots=True)
class Settings:
    """Immutable settings resolved once per process."""

    home: Path
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    lock_timeout_minutes: int = DEFAULT_LOCK_TIMEOUT_MINUTES
    kdf_time_cost: int = DEFAULT_KDF_TIME_COST
    kdf_memory_kib: int = DEFAULT_KDF_MEMORY_KIB
    kdf_parallelism: int = DEFAULT_KDF_PARALLELISM
    session_idle_minutes: int = 30
    max_concurrent_execs: int = 8
    enforce_host: bool = True

    @classmethod
    def from_env(cls) -> Settings:
        """Build settings from ``ENVVAULT_*`` variables."""
        home = Path(os.environ.get("ENVVAULT_HOME", "~/.envvault")).expanduser()
        return cls(
            home=home,
            host=os.environ.get("ENVVAULT_HOST", DEFAULT_HOST),
            port=_env_int("ENVVAULT_PORT", DEFAULT_PORT),
            lock_timeout_minutes=_env_int(
                "ENVVAULT_LOCK_TIMEOUT_MINUTES", DEFAULT_LOCK_TIMEOUT_MINUTES
            ),
            kdf_time_cost=_env_int("ENVVAULT_KDF_TIME_COST", DEFAULT_KDF_TIME_COST),
            kdf_memory_kib=_env_int("ENVVAULT_KDF_MEMORY_KIB", DEFAULT_KDF_MEMORY_KIB),
            kdf_parallelism=_env_int("ENVVAULT_KDF_PARALLELISM", DEFAULT_KDF_PARALLELISM),
            session_idle_minutes=_env_int("ENVVAULT_SESSION_IDLE_MINUTES", 30),
            max_concurrent_execs=_env_int("ENVVAULT_MAX_EXECS", 8),
        )

    @property
    def db_path(self) -> Path:
        """SQLite database file."""
        return self.home / "vault.db"

    @property
    def log_path(self) -> Path:
        """Daemon log file."""
        return self.home / "daemon.log"

    @property
    def pid_path(self) -> Path:
        """Daemon PID file."""
        return self.home / "daemon.pid"

    @property
    def base_url(self) -> str:
        """Loopback URL used by the CLI and the web UI."""
        return f"http://{self.host}:{self.port}"

    def open_log(self) -> BinaryIO:
        """Open the daemon log for appending, owner-only whatever the umask.

        The file is created with mode 0600 and an existing file is tightened,
        so a log written under a permissive umask (0664) stops being readable
        by other users.
        """
        fd = os.open(self.log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, PRIVATE_FILE_MODE)
        os.fchmod(fd, PRIVATE_FILE_MODE)
        return os.fdopen(fd, "ab", buffering=0)

    def secure_log(self) -> None:
        """Tighten an existing daemon log to owner-only (no-op when absent)."""
        if self.log_path.exists():
            self.log_path.chmod(PRIVATE_FILE_MODE)

    def ensure_home(self) -> None:
        """Create the vault directory with owner-only permissions."""
        self.home.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.home.chmod(0o700)
