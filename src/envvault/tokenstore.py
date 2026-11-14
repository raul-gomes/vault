"""Per-project agent token files used by the CLI.

Agent tokens are bearer credentials, not vault secrets: they authorize the
daemon to inject one project's secrets into a child process. Keeping one file
per project lets a shell run commands for any registered project from any
directory, without exporting a token per project.

The file stores the token id and name next to the value so revocation can
remove exactly the right local copy. Plain-text files from older versions are
still accepted.

Security rules:

- the directory is ``0700`` and the file is ``0600``;
- symlinks are refused;
- a file with wider permissions fails to load instead of being trusted;
- the value is never printed when it is saved.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from envvault.services.projects import ProjectError, validate_slug

DIR_NAME = "agent-tokens"
FILE_SUFFIX = ".token"


class TokenStoreError(ValueError):
    """Raised when a local token file cannot be used safely."""


@dataclass(frozen=True, slots=True)
class StoredToken:
    """A token value plus the metadata needed to manage the local copy."""

    value: str
    token_id: str | None = None
    name: str | None = None
    saved_at: str | None = None


@dataclass(frozen=True, slots=True)
class TokenRef:
    """A token value plus where it came from (for diagnostics)."""

    value: str
    source: str
    token_id: str | None = None


def _slug(value: str) -> str:
    """Validate a slug before it becomes part of a file name."""
    try:
        return validate_slug(value)
    except ProjectError as exc:
        raise TokenStoreError(f"invalid slug: {value!r}") from exc


def directory(home: Path) -> Path:
    """Directory that holds one token file per project."""
    return Path(home) / DIR_NAME


def path_for(home: Path, slug: str) -> Path:
    """Token file path for a project slug."""
    return directory(home) / f"{_slug(slug)}{FILE_SUFFIX}"


def _ensure_directory(home: Path) -> Path:
    """Create the home and token directory with owner-only permissions."""
    home = Path(home)
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    home.chmod(0o700)
    target = directory(home)
    target.mkdir(mode=0o700, exist_ok=True)
    target.chmod(0o700)
    return target


def _check_secure(path: Path) -> None:
    """Refuse symlinks and files readable by group or others."""
    if path.is_symlink():
        raise TokenStoreError(f"{path} is a symlink; refusing to use it")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise TokenStoreError(f"{path} has permissions {mode:04o}; run `chmod 600 {path}`")


def save(
    home: Path,
    slug: str,
    token: str,
    *,
    token_id: str | None = None,
    name: str | None = None,
) -> Path:
    """Write a project token with ``0600`` and return its path."""
    value = token.strip()
    if not value or any(character.isspace() for character in value):
        raise TokenStoreError("token is empty or contains whitespace")
    path = _ensure_directory(home) / f"{_slug(slug)}{FILE_SUFFIX}"
    if path.is_symlink():
        raise TokenStoreError(f"{path} is a symlink; refusing to use it")
    payload: dict[str, Any] = {
        "token": value,
        "token_id": token_id,
        "name": name,
        "saved_at": datetime.now(UTC).isoformat(),
    }
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise TokenStoreError(f"could not write {path}: {exc}") from exc
    try:
        os.write(descriptor, json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(0o600)
    return path


def load(home: Path, slug: str) -> StoredToken | None:
    """Read a project token, or ``None`` when no file exists."""
    path = path_for(home, slug)
    if not os.path.lexists(path):
        return None
    _check_secure(path)
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        raise TokenStoreError(f"{path} is empty; recreate the token")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return StoredToken(value=raw)
    if not isinstance(data, dict) or not isinstance(data.get("token"), str):
        raise TokenStoreError(f"{path} is corrupted; recreate the token")
    value = data["token"].strip()
    if not value:
        raise TokenStoreError(f"{path} is corrupted; recreate the token")
    return StoredToken(
        value=value,
        token_id=data.get("token_id") if isinstance(data.get("token_id"), str) else None,
        name=data.get("name") if isinstance(data.get("name"), str) else None,
        saved_at=data.get("saved_at") if isinstance(data.get("saved_at"), str) else None,
    )


def exists(home: Path, slug: str) -> bool:
    """Whether a local token file exists for the project."""
    return os.path.lexists(path_for(home, slug))


def remove(home: Path, slug: str) -> bool:
    """Delete a project token file; return whether something was removed."""
    path = path_for(home, slug)
    if not os.path.lexists(path):
        return False
    path.unlink()
    return True


def local_token_id(home: Path, slug: str) -> str | None:
    """Token id stored for the project, or ``None`` if absent/unreadable."""
    try:
        stored = load(home, slug)
    except TokenStoreError:
        return None
    return stored.token_id if stored else None


def resolve(home: Path, slug: str, override: str | None = None) -> TokenRef | None:
    """Prefer an explicit ``ENVVAULT_TOKEN``, then the project token file."""
    explicit = (override or "").strip()
    if explicit:
        return TokenRef(value=explicit, source="ENVVAULT_TOKEN")
    stored = load(home, slug)
    if stored is None:
        return None
    return TokenRef(
        value=stored.value,
        source=str(path_for(home, slug)),
        token_id=stored.token_id,
    )
