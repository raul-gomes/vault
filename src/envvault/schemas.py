"""Pydantic request models. Validation happens at the boundary."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from envvault.config import MAX_UNLOCK_HOURS_LIMIT


class LoginRequest(BaseModel):
    """Passphrase used to unlock the vault and create a session."""

    passphrase: str = Field(min_length=1, max_length=1024)


class ChangePassphraseRequest(BaseModel):
    """Current and new master passphrase."""

    current: str = Field(min_length=1, max_length=1024)
    new: str = Field(min_length=10, max_length=1024)


class ProjectCreateRequest(BaseModel):
    """Register a local project."""

    slug: str = Field(min_length=2, max_length=64)
    name: str = Field(min_length=1, max_length=200)
    path: str = Field(min_length=1, max_length=500)


class ProjectUpdateRequest(BaseModel):
    """Partial project update."""

    name: str | None = Field(default=None, min_length=1, max_length=200)
    path: str | None = Field(default=None, min_length=1, max_length=500)


class ProjectDeleteRequest(BaseModel):
    """Explicit confirmation to avoid deleting the wrong project."""

    confirm_slug: str = Field(min_length=1, max_length=64)


class EnvironmentCreateRequest(BaseModel):
    """Create an environment name, even before it has secrets."""

    name: str = Field(min_length=1, max_length=40)


class CredentialUpsertRequest(BaseModel):
    """Create or replace one service credential (global or project-scoped)."""

    name: str = Field(min_length=1, max_length=200)
    category: str = Field(default="other", max_length=40)
    username: str = Field(default="", max_length=500)
    password: str = Field(default="", max_length=8192)
    url: str = Field(default="", max_length=2000)
    notes: str = Field(default="", max_length=65536)
    project_id: str | None = Field(default=None, max_length=36)


class CredentialRevealRequest(BaseModel):
    """Re-authentication payload for revealing a credential."""

    passphrase: str = Field(min_length=1, max_length=1024)


class SecretUpsertRequest(BaseModel):
    """Create or replace one environment variable."""

    environment: str = Field(min_length=1, max_length=40)
    key: str = Field(min_length=1, max_length=120)
    value: str = Field(max_length=65536)


class RevealRequest(BaseModel):
    """Re-authentication payload for revealing one value."""

    environment: str = Field(min_length=1, max_length=40)
    passphrase: str = Field(min_length=1, max_length=1024)


class ExportRequest(BaseModel):
    """Re-authentication payload for exporting an environment."""

    environment: str = Field(min_length=1, max_length=40)
    passphrase: str = Field(min_length=1, max_length=1024)


class ImportRequest(BaseModel):
    """Raw .env content to import server-side."""

    environment: str = Field(min_length=1, max_length=40)
    content: str = Field(max_length=1024 * 1024)
    replace: bool = False


class TokenCreateRequest(BaseModel):
    """Scoped agent token configuration."""

    name: str = Field(min_length=1, max_length=120)
    project_id: str = Field(min_length=1, max_length=36)
    environments: list[str] = Field(min_length=1)
    can_list: bool = True
    can_inject: bool = True
    allowed_commands: list[str] = Field(default_factory=list)
    any_command: bool = False


class ExecRequest(BaseModel):
    """Run a command with secrets injected (session-authenticated)."""

    project_id: str = Field(min_length=1, max_length=36)
    environment: str = Field(min_length=1, max_length=40)
    command: list[str] = Field(min_length=1, max_length=64)
    cwd: str | None = Field(default=None, max_length=500)
    invocation_dir: str | None = Field(default=None, max_length=500)
    env: dict[str, str] = Field(default_factory=dict, max_length=64)
    timeout_seconds: int | None = Field(default=None, ge=1, le=3600)


class AgentExecRequest(BaseModel):
    """Run a command with secrets injected (agent-token-authenticated).

    ``env`` carries non-secret overrides assembled by the daemon. Keys that
    already exist in the vault are rejected so the agent cannot shadow a
    stored secret.
    """

    environment: str = Field(min_length=1, max_length=40)
    command: list[str] = Field(min_length=1, max_length=64)
    cwd: str | None = Field(default=None, max_length=500)
    invocation_dir: str | None = Field(default=None, max_length=500)
    env: dict[str, str] = Field(default_factory=dict, max_length=64)
    timeout_seconds: int | None = Field(default=None, ge=1, le=3600)


class GenerateRequest(BaseModel):
    """Password generator options."""

    length: int = Field(default=32, ge=8, le=256)
    upper: bool = True
    lower: bool = True
    digits: bool = True
    symbols: bool = True

    @field_validator("length")
    @classmethod
    def _length(cls, value: int) -> int:
        if value < 8:
            raise ValueError("length must be at least 8")
        return value


class SettingsRequest(BaseModel):
    """Mutable settings."""

    lock_timeout_minutes: int = Field(ge=1, le=1440)
    max_unlock_hours: int | None = Field(default=None, ge=1, le=MAX_UNLOCK_HOURS_LIMIT)
