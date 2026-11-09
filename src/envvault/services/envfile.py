"""Parser and serializer for ``.env`` files (strict, no code execution)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

MAX_ENV_BYTES = 1024 * 1024
MAX_ENV_KEYS = 2000
KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SAFE_UNQUOTED = re.compile(r"^[A-Za-z0-9_./:@%+,\-]+$")
_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\", "$": "$"}


class EnvFileTooLarge(ValueError):
    """Raised when the input exceeds the parser safety limits."""


@dataclass(frozen=True, slots=True)
class ParseIssue:
    """One line-level problem found while parsing."""

    line: int
    message: str
    level: str = "error"


@dataclass(slots=True)
class ParsedEnv:
    """Parsed values plus non-fatal issues."""

    values: dict[str, str] = field(default_factory=dict)
    issues: list[ParseIssue] = field(default_factory=list)


def parse_env(text: str) -> ParsedEnv:
    """Parse dotenv text into a dict, reporting invalid lines instead of raising.

    Supports comments, blank lines, ``export`` prefixes, single quotes,
    double quotes with ``\\n``/``\\t``/``\\"``/``\\\\`` escapes, and inline
    comments after whitespace. Values are never expanded or executed.
    """
    if len(text.encode("utf-8")) > MAX_ENV_BYTES:
        raise EnvFileTooLarge(f".env content exceeds {MAX_ENV_BYTES} bytes")
    result = ParsedEnv()
    lines = text.lstrip("\ufeff").splitlines()
    for number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export") and (len(line) == 6 or line[6] in " \t"):
            line = line[6:].lstrip()
        if "=" not in line:
            result.issues.append(ParseIssue(number, "missing '='"))
            continue
        raw_key, raw_value = line.split("=", 1)
        key = raw_key.strip()
        if not KEY_PATTERN.match(key):
            result.issues.append(ParseIssue(number, f"invalid key {key!r}"))
            continue
        value = _parse_value(raw_value, number, result.issues)
        if value is None:
            continue
        if key in result.values:
            result.issues.append(
                ParseIssue(number, f"duplicate key {key!r}; last value wins", level="warning")
            )
        result.values[key] = value
        if len(result.values) > MAX_ENV_KEYS:
            raise EnvFileTooLarge(f".env has more than {MAX_ENV_KEYS} keys")
    return result


def _parse_value(raw: str, number: int, issues: list[ParseIssue]) -> str | None:
    """Parse the right-hand side of a dotenv assignment."""
    raw = raw.lstrip()
    if raw.startswith("'"):
        end = raw.find("'", 1)
        if end == -1:
            issues.append(ParseIssue(number, "unterminated single quote"))
            return None
        _check_trailing(raw[end + 1 :], number, issues)
        return raw[1:end]
    if raw.startswith('"'):
        out: list[str] = []
        index = 1
        while index < len(raw):
            char = raw[index]
            if char == "\\" and index + 1 < len(raw):
                following = raw[index + 1]
                out.append(_ESCAPES.get(following, "\\" + following))
                index += 2
                continue
            if char == '"':
                _check_trailing(raw[index + 1 :], number, issues)
                return "".join(out)
            out.append(char)
            index += 1
        issues.append(ParseIssue(number, "unterminated double quote"))
        return None
    value = raw
    for marker in (" #", "\t#"):
        cut = value.find(marker)
        if cut != -1:
            value = value[:cut]
    return value.strip()


def _check_trailing(rest: str, number: int, issues: list[ParseIssue]) -> None:
    """Allow only whitespace or a comment after a closing quote."""
    stripped = rest.strip()
    if stripped and not stripped.startswith("#"):
        issues.append(
            ParseIssue(number, "unexpected characters after quoted value", level="warning")
        )


def render_env(values: dict[str, str]) -> str:
    """Serialize values to dotenv text, sorted, without variable expansion."""
    lines = [f"{key}={_quote(value)}" for key, value in sorted(values.items())]
    return "\n".join(lines) + ("\n" if lines else "")


def _quote(value: str) -> str:
    """Quote a value so common dotenv loaders keep it literally."""
    if value == "":
        return ""
    if SAFE_UNQUOTED.match(value):
        return value
    if "\n" not in value and "\r" not in value and "'" not in value and not value.startswith("$"):
        return f"'{value}'"
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
        .replace("$", "\\$")
    )
    return f'"{escaped}"'
