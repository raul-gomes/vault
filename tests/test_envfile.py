"""Dotenv parser/serializer tests."""

from __future__ import annotations

import pytest

from envvault.services.envfile import EnvFileTooLarge, parse_env, render_env


def test_parses_comments_export_quotes_and_inline_comments() -> None:
    parsed = parse_env(
        """
        # comment
        export FOO=bar
        SPACED = value with spaces
        SINGLE='literal $VALUE'
        DOUBLE="line\\nbreak \\"quoted\\""
        INLINE=abc # trailing comment
        HASH=abc#not-a-comment
        EMPTY=
        """
    )
    assert parsed.values["FOO"] == "bar"
    assert parsed.values["SPACED"] == "value with spaces"
    assert parsed.values["SINGLE"] == "literal $VALUE"
    assert parsed.values["DOUBLE"] == 'line\nbreak "quoted"'
    assert parsed.values["INLINE"] == "abc"
    assert parsed.values["HASH"] == "abc#not-a-comment"
    assert parsed.values["EMPTY"] == ""
    assert parsed.issues == []


def test_reports_invalid_lines_without_executing_them() -> None:
    parsed = parse_env(
        """
        GOOD=1
        no_equals
        BAD-KEY=1
        UNTERMINATED="abc
        """
    )
    assert parsed.values == {"GOOD": "1"}
    messages = [issue.message for issue in parsed.issues]
    assert any("missing '='" in message for message in messages)
    assert any("invalid key" in message for message in messages)
    assert any("unterminated" in message for message in messages)


def test_duplicate_key_is_a_warning_and_last_wins() -> None:
    parsed = parse_env("KEY=first\nKEY=second\n")
    assert parsed.values["KEY"] == "second"
    assert parsed.issues[0].level == "warning"


def test_render_roundtrip_keeps_literal_values() -> None:
    values = {
        "PLAIN": "abc-123",
        "SPACES": "hello world",
        "DOLLAR": "pa$$word",
        "QUOTE": "it's",
        "NEWLINE": "line1\nline2",
        "EMPTY": "",
    }
    rendered = render_env(values)
    assert parse_env(rendered).values == values


def test_dollar_values_are_not_expanded() -> None:
    rendered = render_env({"SECRET": "$HOME"})
    assert "\\$HOME" in rendered
    assert parse_env(rendered).values["SECRET"] == "$HOME"


def test_rejects_oversized_input() -> None:
    with pytest.raises(EnvFileTooLarge):
        parse_env("A=" + "x" * (1024 * 1024 + 1))
