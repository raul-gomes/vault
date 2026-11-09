"""SQLAlchemy engine/session setup for the local SQLite database."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from envvault.config import Settings


def _set_sqlite_pragmas(dbapi_connection: object, _record: object) -> None:
    """Enable foreign keys, WAL and a busy timeout on every connection."""
    cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


def build_engine(db_path: Path) -> Engine:
    """Create a SQLite engine with the project's required pragmas."""
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
        future=True,
    )
    event.listen(engine, "connect", _set_sqlite_pragmas)
    return engine


def build_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Return a session factory bound to ``engine``."""
    return sessionmaker(bind=engine, expire_on_commit=False, class_=Session)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Open a session and commit/rollback around the block."""
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def secure_database_files(db_path: Path) -> None:
    """Restrict the database, WAL and SHM files to the current user."""
    for suffix in ("", "-wal", "-shm"):
        candidate = db_path.with_name(db_path.name + suffix)
        if candidate.exists():
            candidate.chmod(0o600)


def ensure_private_home(settings: Settings) -> None:
    """Create the vault home and database directory with mode 0700."""
    settings.ensure_home()
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    settings.db_path.parent.chmod(0o700)
