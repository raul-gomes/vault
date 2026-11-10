"""Tests for per-project agent token files."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from envvault import tokenstore

SLUG = "meu-app"
TOKEN = "ev_test_1234567890"


def test_save_and_load_roundtrip(tmp_path: Path) -> None:
    home = tmp_path / "home"
    path = tokenstore.save(home, SLUG, TOKEN, token_id="tok-1", name="claude-meu-app")

    assert path == home / "agent-tokens" / f"{SLUG}.token"
    stored = tokenstore.load(home, SLUG)
    assert stored is not None
    assert stored.value == TOKEN
    assert stored.token_id == "tok-1"
    assert stored.name == "claude-meu-app"
    assert tokenstore.local_token_id(home, SLUG) == "tok-1"
    assert tokenstore.resolve(home, SLUG) == tokenstore.TokenRef(TOKEN, str(path), "tok-1")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_legacy_plain_text_file_is_accepted(tmp_path: Path) -> None:
    home = tmp_path / "home"
    directory = home / "agent-tokens"
    directory.mkdir(parents=True)
    directory.chmod(0o700)
    path = directory / f"{SLUG}.token"
    path.write_text(TOKEN, encoding="utf-8")
    path.chmod(0o600)

    stored = tokenstore.load(home, SLUG)
    assert stored is not None
    assert stored.value == TOKEN
    assert stored.token_id is None


def test_load_missing_returns_none(tmp_path: Path) -> None:
    assert tokenstore.load(tmp_path / "home", SLUG) is None
    assert tokenstore.resolve(tmp_path / "home", SLUG) is None


def test_env_override_wins(tmp_path: Path) -> None:
    tokenstore.save(tmp_path / "home", SLUG, TOKEN)
    assert tokenstore.resolve(tmp_path / "home", SLUG, "ev_from_env") == tokenstore.TokenRef(
        "ev_from_env", "ENVVAULT_TOKEN"
    )


def test_loose_permissions_are_rejected(tmp_path: Path) -> None:
    path = tokenstore.save(tmp_path / "home", SLUG, TOKEN)
    path.chmod(0o644)
    with pytest.raises(tokenstore.TokenStoreError, match="permissões"):
        tokenstore.load(tmp_path / "home", SLUG)


def test_symlink_is_rejected(tmp_path: Path) -> None:
    home = tmp_path / "home"
    directory = home / "agent-tokens"
    directory.mkdir(parents=True)
    target = tmp_path / "elsewhere"
    target.write_text(TOKEN, encoding="utf-8")
    os.symlink(target, directory / f"{SLUG}.token")

    with pytest.raises(tokenstore.TokenStoreError, match="symlink"):
        tokenstore.load(home, SLUG)
    with pytest.raises(tokenstore.TokenStoreError, match="symlink"):
        tokenstore.save(home, SLUG, TOKEN)


def test_remove_and_exists(tmp_path: Path) -> None:
    home = tmp_path / "home"
    tokenstore.save(home, SLUG, TOKEN)
    assert tokenstore.exists(home, SLUG)
    assert tokenstore.remove(home, SLUG)
    assert not tokenstore.exists(home, SLUG)
    assert not tokenstore.remove(home, SLUG)


def test_rejects_path_traversal(tmp_path: Path) -> None:
    with pytest.raises(tokenstore.TokenStoreError, match="slug"):
        tokenstore.save(tmp_path / "home", "../escape", TOKEN)


def test_rejects_empty_token(tmp_path: Path) -> None:
    with pytest.raises(tokenstore.TokenStoreError, match="vazio"):
        tokenstore.save(tmp_path / "home", SLUG, "   ")
    with pytest.raises(tokenstore.TokenStoreError, match="vazio"):
        tokenstore.save(tmp_path / "home", SLUG, "ev_with space")
