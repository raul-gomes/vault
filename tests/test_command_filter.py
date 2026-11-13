"""Allowed commands match argv element by element, never as a text prefix (B2)."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from envvault.services.tokens import AgentForbidden, TokenError, _normalize_commands, authorize


def _token(*allowed: str) -> SimpleNamespace:
    return SimpleNamespace(
        project=SimpleNamespace(slug="sample"),
        environments=json.dumps(["dev"]),
        can_inject=True,
        allowed_commands=json.dumps(list(allowed)),
    )


def _check(token: SimpleNamespace, argv: list[str]) -> None:
    authorize(token, project_slug="sample", environment="dev", command=argv)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("allowed", "argv"),
    [
        ("bun", ["bunx", "evil"]),
        ("npm run", ["npm", "run-script", "x"]),
        ("npm run dev", ["npm", "run", "develop"]),
        ("echo", ["echo-secrets"]),
        ("npm run", ["npm run", "dev"]),
    ],
)
def test_text_prefix_tricks_are_denied(allowed: str, argv: list[str]) -> None:
    with pytest.raises(AgentForbidden):
        _check(_token(allowed), argv)


@pytest.mark.parametrize(
    ("allowed", "argv"),
    [
        ("bun", ["bun", "test"]),
        ("npm run", ["npm", "run", "dev"]),
        ("npm run dev", ["npm", "run", "dev"]),
        ("pytest", ["pytest"]),
        ("python -m pytest", ["python", "-m", "pytest", "-q"]),
    ],
)
def test_argv_prefixes_are_allowed(allowed: str, argv: list[str]) -> None:
    _check(_token(allowed), argv)


def test_quoted_prefix_keeps_its_argument_together() -> None:
    _check(_token('python -c "print(1)"'), ["python", "-c", "print(1)"])
    with pytest.raises(AgentForbidden):
        _check(_token('python -c "print(1)"'), ["python", "-c", "print(2)"])


def test_unparseable_prefix_is_rejected_on_creation() -> None:
    with pytest.raises(TokenError):
        _normalize_commands(['npm run "unterminated'])


def test_stored_unparseable_prefix_denies_instead_of_crashing() -> None:
    with pytest.raises(AgentForbidden):
        _check(_token('npm run "unterminated'), ["npm", "run", "dev"])
