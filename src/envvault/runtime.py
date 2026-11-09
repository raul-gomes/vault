"""In-process runtime state: data key, sessions, login throttle and executions."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import signal
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from envvault.config import Settings

if TYPE_CHECKING:
    import subprocess

SESSION_COOKIE = "envvault_session"
CSRF_HEADER = "x-csrf-token"
TOKEN_PREFIX = "ev_"


class LockedError(Exception):
    """Raised when an operation needs the vault to be unlocked."""


class VaultNotInitialized(Exception):
    """Raised when the database has no KDF metadata yet."""


class RateLimited(Exception):
    """Raised when too many passphrase attempts happened in a short window."""


def hash_token(raw: str) -> str:
    """Hash a bearer/session token before storing or comparing it."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def constant_time_equals(left: bytes, right: bytes) -> bool:
    """Compare two byte strings without early exit."""
    return hmac.compare_digest(left, right)


def new_bearer_token() -> str:
    """Return a new prefixed bearer token (shown to the user exactly once)."""
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def new_session_token() -> str:
    """Return a new opaque session token for the web UI/CLI."""
    return secrets.token_urlsafe(32)


@dataclass(slots=True)
class Session:
    """Server-side session record; only its hash is stored."""

    token_hash: str
    csrf: str
    created_at: float
    last_seen: float


@dataclass(slots=True)
class ExecRecord:
    """A running child process started by the broker."""

    exec_id: str
    process: subprocess.Popen[bytes]
    actor_type: str
    actor_name: str
    project_slug: str
    environment: str
    command: str
    started_at: float = field(default_factory=time.monotonic)
    env_keys: tuple[str, ...] = ()
    timeout_seconds: int | None = None


class Runtime:
    """Mutable state that lives for the lifetime of the daemon."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.dek: bytes | None = None
        self.last_activity: float | None = None
        self.sessions: dict[str, Session] = {}
        self.login_failures: dict[str, list[float]] = {}
        self.execs: dict[str, ExecRecord] = {}
        self.lock = threading.RLock()

    # -- lifecycle ---------------------------------------------------------
    def unlock_with(self, dek: bytes) -> None:
        """Install the data key in memory and start the idle clock."""
        with self.lock:
            self.dek = dek
            self.last_activity = time.monotonic()

    def locked(self) -> bool:
        """Return whether the vault is locked in memory."""
        return self.dek is None

    def touch(self) -> None:
        """Record authenticated activity."""
        with self.lock:
            self.last_activity = time.monotonic()

    def clear_key(self) -> None:
        """Drop the data key and every server-side session."""
        with self.lock:
            self.dek = None
            self.last_activity = None
            self.sessions.clear()

    # -- sessions ----------------------------------------------------------
    def create_session(self) -> tuple[str, Session]:
        """Create a session and return ``(raw_token, session)``."""
        raw = new_session_token()
        now = time.monotonic()
        session = Session(
            token_hash=hash_token(raw),
            csrf=secrets.token_urlsafe(24),
            created_at=now,
            last_seen=now,
        )
        with self.lock:
            self.sessions[session.token_hash] = session
        return raw, session

    def get_session(self, raw: str | None) -> Session | None:
        """Return a valid session for a raw cookie token, refreshing its clock."""
        if not raw:
            return None
        with self.lock:
            session = self.sessions.get(hash_token(raw))
            if session is None:
                return None
            now = time.monotonic()
            if now - session.last_seen > self.settings.session_idle_minutes * 60:
                del self.sessions[session.token_hash]
                return None
            session.last_seen = now
            return session

    # -- login throttle ----------------------------------------------------
    def check_login_allowed(self, client: str, limit: int = 5, window: float = 60.0) -> None:
        """Raise :class:`RateLimited` after ``limit`` failures inside ``window``."""
        now = time.monotonic()
        with self.lock:
            recent = [ts for ts in self.login_failures.get(client, []) if now - ts < window]
            self.login_failures[client] = recent
            if len(recent) >= limit:
                raise RateLimited("too many failed attempts; wait a minute")

    def record_login_failure(self, client: str) -> None:
        """Record one failed passphrase attempt."""
        with self.lock:
            self.login_failures.setdefault(client, []).append(time.monotonic())

    def clear_login_failures(self, client: str) -> None:
        """Reset the throttle after a successful authentication."""
        with self.lock:
            self.login_failures.pop(client, None)

    # -- executions --------------------------------------------------------
    def add_exec(self, record: ExecRecord) -> None:
        """Register a running child process, enforcing the concurrency cap."""
        with self.lock:
            if len(self.execs) >= self.settings.max_concurrent_execs:
                raise RuntimeError("too many concurrent executions")
            self.execs[record.exec_id] = record

    def remove_exec(self, exec_id: str) -> ExecRecord | None:
        """Remove and return an execution record."""
        with self.lock:
            return self.execs.pop(exec_id, None)

    def terminate_exec(self, exec_id: str) -> bool:
        """Terminate a running execution's whole process group."""
        record = self.remove_exec(exec_id)
        if record is None:
            return False
        _terminate_process_group(record.process)
        return True

    def terminate_all(self) -> None:
        """Terminate every running execution (used when locking the vault)."""
        with self.lock:
            records = list(self.execs.values())
            self.execs.clear()
        for record in records:
            _terminate_process_group(record.process)


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    """SIGTERM the child's process group, escalating to SIGKILL after 3s."""
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
