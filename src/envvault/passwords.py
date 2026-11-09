"""Strong password generation using the ``secrets`` CSPRNG."""

from __future__ import annotations

import math
import secrets
from dataclasses import dataclass

# Ambiguous glyphs are removed by default: they cause support tickets when a
# password is read from a screen or copied by hand.
UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"  # no I, O
LOWER = "abcdefghijkmnpqrstuvwxyz"  # no l, o
DIGITS = "23456789"  # no 0, 1
SYMBOLS = "!@%^*-_=+.:?"

DEFAULT_LENGTH = 32
MIN_LENGTH = 8
MAX_LENGTH = 256


class InvalidLength(ValueError):
    """Raised when the requested length cannot satisfy the character sets."""


@dataclass(frozen=True, slots=True)
class PasswordOptions:
    """Character-set selection for a generated password."""

    length: int = DEFAULT_LENGTH
    upper: bool = True
    lower: bool = True
    digits: bool = True
    symbols: bool = True

    def alphabet(self) -> str:
        """Return the union of the selected character sets."""
        parts = []
        if self.upper:
            parts.append(UPPER)
        if self.lower:
            parts.append(LOWER)
        if self.digits:
            parts.append(DIGITS)
        if self.symbols:
            parts.append(SYMBOLS)
        return "".join(parts)

    def required_sets(self) -> list[str]:
        """Return each selected set, used to guarantee at least one char each."""
        sets = []
        if self.upper:
            sets.append(UPPER)
        if self.lower:
            sets.append(LOWER)
        if self.digits:
            sets.append(DIGITS)
        if self.symbols:
            sets.append(SYMBOLS)
        return sets


def generate_password(options: PasswordOptions | None = None) -> str:
    """Generate a password guaranteed to contain every selected character set.

    Uses :mod:`secrets` (``os.urandom``) and unbiased ``choice``. The result is
    shuffled with ``secrets.SystemRandom`` so the guaranteed characters are not
    predictably placed at the start.
    """
    opts = options or PasswordOptions()
    alphabet = opts.alphabet()
    if not alphabet:
        raise InvalidLength("select at least one character set")
    if opts.length < MIN_LENGTH or opts.length > MAX_LENGTH:
        raise InvalidLength(f"length must be between {MIN_LENGTH} and {MAX_LENGTH}")
    if opts.length < len(opts.required_sets()):
        raise InvalidLength("length is shorter than the number of selected sets")

    chars = [secrets.choice(char_set) for char_set in opts.required_sets()]
    chars.extend(secrets.choice(alphabet) for _ in range(opts.length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def entropy_bits(options: PasswordOptions | None = None) -> float:
    """Return the theoretical entropy of the generator configuration."""
    opts = options or PasswordOptions()
    alphabet = opts.alphabet()
    if not alphabet:
        return 0.0
    return opts.length * math.log2(len(alphabet))
