"""Cryptographic primitives: Argon2id KDF and AES-256-GCM envelope encryption.

The design is a two-layer envelope:

* a passphrase-derived key (KEK) wraps a random data key (DEK);
* the DEK encrypts each secret, with associated data binding the ciphertext
  to project, environment, key name and version.

Changing the passphrase only re-wraps the DEK; secrets are untouched.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LENGTH = 32
NONCE_LENGTH = 12
SALT_LENGTH = 16
DEK_AAD = b"envvault:dek:v1"
SECRET_AAD_PREFIX = "envvault:secret:v1"


class InvalidPassphrase(Exception):
    """Raised when the passphrase cannot unwrap the data key."""


@dataclass(frozen=True, slots=True)
class KdfParams:
    """Argon2id parameters persisted alongside the wrapped key."""

    salt: bytes
    time_cost: int
    memory_kib: int
    parallelism: int


def new_salt() -> bytes:
    """Return a fresh random KDF salt."""
    return os.urandom(SALT_LENGTH)


def new_data_key() -> bytes:
    """Return a fresh random 256-bit data encryption key."""
    return os.urandom(KEY_LENGTH)


def derive_kek(passphrase: str, params: KdfParams) -> bytes:
    """Derive the key-encryption key from a passphrase with Argon2id."""
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=params.salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_kib,
        parallelism=params.parallelism,
        hash_len=KEY_LENGTH,
        type=Type.ID,
    )


def wrap_data_key(kek: bytes, data_key: bytes) -> tuple[bytes, bytes]:
    """Encrypt the data key with the KEK. Returns ``(nonce, ciphertext)``."""
    nonce = os.urandom(NONCE_LENGTH)
    ciphertext = AESGCM(kek).encrypt(nonce, data_key, DEK_AAD)
    return nonce, ciphertext


def unwrap_data_key(kek: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt the data key, raising :class:`InvalidPassphrase` on failure."""
    try:
        return AESGCM(kek).decrypt(nonce, ciphertext, DEK_AAD)
    except InvalidTag as exc:
        raise InvalidPassphrase("invalid passphrase") from exc


def secret_aad(project_id: str, environment: str, key: str, version: int) -> bytes:
    """Build the associated data that binds a ciphertext to its slot."""
    return f"{SECRET_AAD_PREFIX}:{project_id}:{environment}:{key}:{version}".encode()


def encrypt_secret(data_key: bytes, plaintext: str, aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt a secret value. Returns ``(nonce, ciphertext)``."""
    nonce = os.urandom(NONCE_LENGTH)
    ciphertext = AESGCM(data_key).encrypt(nonce, plaintext.encode("utf-8"), aad)
    return nonce, ciphertext


def decrypt_secret(data_key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> str:
    """Decrypt a secret value, raising :class:`InvalidTag` if it was moved."""
    return AESGCM(data_key).decrypt(nonce, ciphertext, aad).decode("utf-8")
