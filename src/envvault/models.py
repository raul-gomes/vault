"""Persistent models. Secret values are stored only as AES-GCM ciphertext."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    """Timezone-aware UTC timestamp."""
    return datetime.now(UTC)


def new_id() -> str:
    """Random UUID usable as a primary key."""
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    """Declarative base for every table."""


class Meta(Base):
    """Key/value metadata: KDF parameters, wrapped DEK and settings."""

    __tablename__ = "meta"

    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)


class Project(Base):
    """A local repository whose secrets are managed by the vault."""

    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    path: Mapped[str] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)

    secrets: Mapped[list[Secret]] = relationship(
        back_populates="project", cascade="all, delete-orphan", passive_deletes=True
    )
    tokens: Mapped[list[ApiToken]] = relationship(
        back_populates="project", cascade="all, delete-orphan", passive_deletes=True
    )
    environment_rows: Mapped[list[Environment]] = relationship(
        back_populates="project", cascade="all, delete-orphan", passive_deletes=True
    )
    credentials: Mapped[list[Credential]] = relationship(
        back_populates="project", cascade="all, delete-orphan", passive_deletes=True
    )


class Environment(Base):
    """A named environment (dev, staging, prod) that exists even while empty.

    Environments used to be inferred from the secrets table, so an environment
    without secrets could not be shown or selected. This table makes them
    first-class.
    """

    __tablename__ = "environments"
    __table_args__ = (UniqueConstraint("project_id", "name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)

    project: Mapped[Project] = relationship(back_populates="environment_rows")


class Secret(Base):
    """One encrypted environment variable inside a project/environment."""

    __tablename__ = "secrets"
    __table_args__ = (UniqueConstraint("project_id", "environment", "key"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    environment: Mapped[str] = mapped_column(String(40), index=True)
    key: Mapped[str] = mapped_column(String(120))
    nonce: Mapped[bytes] = mapped_column(LargeBinary)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)

    project: Mapped[Project] = relationship(back_populates="secrets")


class Credential(Base):
    """A service credential (hosting, DNS, email…) global or per project.

    ``project_id`` is null for shared/global credentials and set when the login
    belongs to a specific client project. Name and category are searchable
    metadata; the remaining fields live in an encrypted JSON payload so
    usernames and notes never touch plaintext columns.
    """

    __tablename__ = "credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str | None] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True, nullable=True
    )
    name: Mapped[str] = mapped_column(String(200), index=True)
    category: Mapped[str] = mapped_column(String(40), index=True, default="other")
    nonce: Mapped[bytes] = mapped_column(LargeBinary)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)

    project: Mapped[Project | None] = relationship(back_populates="credentials")


class ApiToken(Base):
    """Scoped bearer token usable by agents (Claude) — cannot reveal values."""

    __tablename__ = "api_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    prefix: Mapped[str] = mapped_column(String(16))
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    environments: Mapped[str] = mapped_column(Text)  # JSON list
    can_list: Mapped[bool] = mapped_column(Boolean, default=True)
    can_inject: Mapped[bool] = mapped_column(Boolean, default=True)
    allowed_commands: Mapped[str] = mapped_column(Text, default="[]")  # JSON list
    any_command: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(nullable=True)

    project: Mapped[Project] = relationship(back_populates="tokens")


class AuditEntry(Base):
    """Append-only, hash-chained audit record. Never contains secret values."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[str] = mapped_column(String(40), index=True)
    actor_type: Mapped[str] = mapped_column(String(20))
    actor_name: Mapped[str] = mapped_column(String(120))
    action: Mapped[str] = mapped_column(String(60), index=True)
    project_slug: Mapped[str | None] = mapped_column(String(80), nullable=True)
    environment: Mapped[str | None] = mapped_column(String(40), nullable=True)
    key_names: Mapped[str] = mapped_column(Text, default="[]")
    command: Mapped[str | None] = mapped_column(Text, nullable=True)
    result: Mapped[str] = mapped_column(String(20), default="ok")
    detail: Mapped[str] = mapped_column(Text, default="{}")
    prev_hash: Mapped[str] = mapped_column(String(64))
    # "hmac" (keyed by the vault), "sha256" (written before any unlock) or
    # "legacy" (written before revision 0005).
    mac: Mapped[str] = mapped_column(String(10), default="sha256")
    hash: Mapped[str] = mapped_column(String(64), index=True)
