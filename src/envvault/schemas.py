"""Pydantic request models. Validation happens at the boundary."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


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


class ExecRequest(BaseModel):
    """Run a command with secrets injected (session-authenticated)."""

    project_id: str = Field(min_length=1, max_length=36)
    environment: str = Field(min_length=1, max_length=40)
    command: list[str] = Field(min_length=1, max_length=64)
    cwd: str | None = Field(default=None, max_length=500)


class AgentExecRequest(BaseModel):
    """Run a command with secrets injected (agent-token-authenticated)."""

    environment: str = Field(min_length=1, max_length=40)
    command: list[str] = Field(min_length=1, max_length=64)
    cwd: str | None = Field(default=None, max_length=500)


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
