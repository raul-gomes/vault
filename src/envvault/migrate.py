"""Programmatic Alembic upgrade used by ``envvault init`` and the daemon."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config

from envvault.config import Settings
from envvault.db import secure_database_files


def upgrade(settings: Settings) -> None:
    """Apply all migrations to the configured SQLite database."""
    settings.ensure_home()
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{settings.db_path}")
    command.upgrade(config, "head")
    secure_database_files(settings.db_path)
