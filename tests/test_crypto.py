from __future__ import annotations

import base64
import os
import stat
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from custos_protocol.crypto import (
    b64_to_public_key,
    generate_hmac_key,
    generate_keypair,
    hmac_sign,
    hmac_verify,
    load_private_key,
    load_public_key,
    public_key_to_b64,
    save_private_key,
    save_public_key,
    sign_data,
    verify_signature,
)


def test_sign_and_verify_round_trip():
    private_key, public_key = generate_keypair()
    signature = sign_data(private_key, b"payload")
    assert verify_signature(public_key, b"payload", signature) is True


def test_verify_rejects_tampered_payload():
    private_key, public_key = generate_keypair()
    signature = sign_data(private_key, b"payload")
    assert verify_signature(public_key, b"payload-tampered", signature) is False


def test_verify_rejects_foreign_key():
    private_key, _ = generate_keypair()
    _, other_public = generate_keypair()
    signature = sign_data(private_key, b"payload")
    assert verify_signature(other_public, b"payload", signature) is False


def test_verify_returns_false_instead_of_raising_on_garbage():
    _, public_key = generate_keypair()
    assert verify_signature(public_key, b"payload", "not-base64!!") is False
    assert verify_signature(public_key, b"payload", "") is False


def test_signature_encoding_is_base64url():
    """The URL-safe alphabet is pinned; a second implementation must match byte for byte."""
    private_key, _ = generate_keypair()
    signature = sign_data(private_key, b"payload")
    assert base64.urlsafe_b64decode(signature.encode("ascii"))
    assert "+" not in signature and "/" not in signature


def test_public_key_b64_round_trip_is_32_raw_bytes():
    _, public_key = generate_keypair()
    encoded = public_key_to_b64(public_key)
    assert len(base64.urlsafe_b64decode(encoded.encode("ascii"))) == 32
    restored = b64_to_public_key(encoded)
    assert public_key_to_b64(restored) == encoded


def test_private_key_pem_round_trip(tmp_path):
    private_key, public_key = generate_keypair()
    path = tmp_path / "private.pem"
    save_private_key(private_key, path)
    loaded = load_private_key(path)
    signature = sign_data(loaded, b"payload")
    assert verify_signature(public_key, b"payload", signature) is True


def test_private_key_supports_encryption_at_rest(tmp_path):
    """The blueprint writes NoEncryption(); Custos supports a passphrase."""
    private_key, _ = generate_keypair()
    path = tmp_path / "private.pem"
    save_private_key(private_key, path, passphrase=b"correct-horse")
    assert b"ENCRYPTED" in path.read_bytes()
    with pytest.raises(Exception):
        load_private_key(path)
    assert isinstance(load_private_key(path, passphrase=b"correct-horse"), Ed25519PrivateKey)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes are not meaningful on Windows")
def test_private_key_file_mode_is_owner_only(tmp_path):
    private_key, _ = generate_keypair()
    path = tmp_path / "private.pem"
    save_private_key(private_key, path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_public_key_pem_round_trip(tmp_path):
    _, public_key = generate_keypair()
    path = tmp_path / "public.pem"
    save_public_key(public_key, path)
    assert public_key_to_b64(load_public_key(path)) == public_key_to_b64(public_key)


def test_hmac_round_trip_and_rejection():
    key = generate_hmac_key()
    assert len(key) == 32
    signature = hmac_sign(key, b"payload")
    assert hmac_verify(key, b"payload", signature) is True
    assert hmac_verify(key, b"other", signature) is False
    assert hmac_verify(generate_hmac_key(), b"payload", signature) is False
