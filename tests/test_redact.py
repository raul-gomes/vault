"""Output redaction tests."""

from __future__ import annotations

import base64
from urllib.parse import quote

from envvault.services.redact import Redactor


def test_redacts_raw_value() -> None:
    redactor = Redactor({"TOKEN": "abcdef-123456"})
    assert "abcdef-123456" not in redactor.redact("token=abcdef-123456 fim")


def test_redacts_url_encoded_and_base64_variants() -> None:
    value = "p@ss word/123"
    redactor = Redactor({"PASSWORD": value})
    encoded_url = quote(value, safe="")
    encoded_b64 = base64.b64encode(value.encode()).decode()
    text = f"{encoded_url} {encoded_b64}"
    result = redactor.redact(text)
    assert encoded_url not in result
    assert encoded_b64 not in result
    assert result.count("[REDACTED:PASSWORD]") == 2


def test_short_values_are_not_redacted_to_avoid_noise() -> None:
    redactor = Redactor({"PORT": "8080"})
    assert "8080" in redactor.redact("porta 8080")


def test_max_pattern_length_is_exposed() -> None:
    redactor = Redactor({"A": "long-secret-value"})
    assert redactor.max_pattern_length >= len("long-secret-value")
