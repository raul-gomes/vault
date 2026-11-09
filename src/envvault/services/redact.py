"""Best-effort output redaction for values injected into a child process.

Redaction stops accidental leaks (a framework printing its config). It is not
a hard boundary against a deliberately malicious command: a program can encode,
encrypt or exfiltrate a secret in ways a string replacer cannot follow.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from urllib.parse import quote, quote_plus

MIN_REDACT_LENGTH = 6
MIN_ENCODED_LENGTH = 8


class Redactor:
    """Replace secret values and their common encodings with a marker."""

    def __init__(self, secrets: Mapping[str, str]) -> None:
        patterns: dict[str, str] = {}
        for key, value in secrets.items():
            if len(value) < MIN_REDACT_LENGTH:
                continue
            candidates = {value, quote(value, safe=""), quote_plus(value)}
            if len(value) >= MIN_ENCODED_LENGTH:
                raw = value.encode("utf-8")
                candidates.add(base64.b64encode(raw).decode("ascii"))
                candidates.add(base64.urlsafe_b64encode(raw).decode("ascii"))
            for candidate in candidates:
                if len(candidate) >= MIN_REDACT_LENGTH:
                    patterns.setdefault(candidate, key)
        self._patterns = sorted(patterns.items(), key=lambda item: len(item[0]), reverse=True)

    def redact(self, text: str) -> str:
        """Return ``text`` with every known secret occurrence replaced."""
        for pattern, key in self._patterns:
            if pattern in text:
                text = text.replace(pattern, f"[REDACTED:{key}]")
        return text

    @property
    def pattern_count(self) -> int:
        """Number of distinct strings watched (useful for diagnostics)."""
        return len(self._patterns)

    @property
    def max_pattern_length(self) -> int:
        """Length of the longest watched string, used to avoid split leaks."""
        return max((len(pattern) for pattern, _ in self._patterns), default=0)
