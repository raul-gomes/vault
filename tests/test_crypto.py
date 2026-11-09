"""Cryptographic envelope tests."""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

from envvault import crypto


def test_wrap_unwrap_roundtrip() -> None:
    params = crypto.KdfParams(salt=crypto.new_salt(), time_cost=1, memory_kib=8192, parallelism=1)
    kek = crypto.derive_kek("passphrase forte 123", params)
    dek = crypto.new_data_key()
    nonce, wrapped = crypto.wrap_data_key(kek, dek)
    assert crypto.unwrap_data_key(kek, nonce, wrapped) == dek


def test_wrong_passphrase_cannot_unwrap() -> None:
    params = crypto.KdfParams(salt=crypto.new_salt(), time_cost=1, memory_kib=8192, parallelism=1)
    kek = crypto.derive_kek("passphrase forte 123", params)
    nonce, wrapped = crypto.wrap_data_key(kek, crypto.new_data_key())
    wrong = crypto.derive_kek("outra passphrase", params)
    with pytest.raises(crypto.InvalidPassphrase):
        crypto.unwrap_data_key(wrong, nonce, wrapped)


def test_secret_aad_binds_ciphertext_to_slot() -> None:
    dek = crypto.new_data_key()
    aad = crypto.secret_aad("project", "dev", "KEY", 1)
    nonce, ciphertext = crypto.encrypt_secret(dek, "value", aad)
    assert crypto.decrypt_secret(dek, nonce, ciphertext, aad) == "value"
    moved = crypto.secret_aad("project", "prod", "KEY", 1)
    with pytest.raises(InvalidTag):
        crypto.decrypt_secret(dek, nonce, ciphertext, moved)


def test_secret_ciphertext_differs_each_time() -> None:
    dek = crypto.new_data_key()
    aad = crypto.secret_aad("project", "dev", "KEY", 1)
    first = crypto.encrypt_secret(dek, "same", aad)
    second = crypto.encrypt_secret(dek, "same", aad)
    assert first != second
