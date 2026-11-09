"""Password generator tests."""

from __future__ import annotations

import pytest

from envvault.passwords import (
    DIGITS,
    LOWER,
    SYMBOLS,
    UPPER,
    InvalidLength,
    PasswordOptions,
    entropy_bits,
    generate_password,
)


def test_generated_password_has_requested_length_and_sets() -> None:
    password = generate_password(PasswordOptions(length=48))
    assert len(password) == 48
    assert any(char in UPPER for char in password)
    assert any(char in LOWER for char in password)
    assert any(char in DIGITS for char in password)
    assert any(char in SYMBOLS for char in password)


def test_ambiguous_characters_are_absent() -> None:
    password = generate_password(PasswordOptions(length=256))
    assert not set("Il1O0o") & set(password)


def test_can_disable_character_sets() -> None:
    password = generate_password(
        PasswordOptions(length=32, upper=False, digits=False, symbols=False)
    )
    assert all(char in LOWER for char in password)


def test_rejects_invalid_length_and_empty_alphabet() -> None:
    with pytest.raises(InvalidLength):
        generate_password(PasswordOptions(length=4))
    with pytest.raises(InvalidLength):
        generate_password(
            PasswordOptions(length=32, upper=False, lower=False, digits=False, symbols=False)
        )


def test_entropy_grows_with_length() -> None:
    short = entropy_bits(PasswordOptions(length=16))
    long = entropy_bits(PasswordOptions(length=64))
    assert long > short > 0


def test_passwords_are_unique() -> None:
    passwords = {generate_password(PasswordOptions(length=32)) for _ in range(50)}
    assert len(passwords) == 50
