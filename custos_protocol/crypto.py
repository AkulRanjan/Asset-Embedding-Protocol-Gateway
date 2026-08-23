"""Ed25519 and HMAC-SHA256 primitives. No custom cryptography is implemented here.

Encoding is base64url everywhere (padding retained). Any second implementation
must match this alphabet or every signature comparison fails.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def sign_data(private_key: Ed25519PrivateKey, data: bytes) -> str:
    return _b64encode(private_key.sign(data))


def verify_signature(public_key: Ed25519PublicKey, data: bytes, signature: str) -> bool:
    """Never raises. A verifier that throws on malformed input is a denial-of-service surface."""
    try:
        public_key.verify(_b64decode(signature), data)
    except (InvalidSignature, ValueError, TypeError, base64.binascii.Error):
        return False
    return True


def public_key_to_b64(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _b64encode(raw)


def b64_to_public_key(value: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(_b64decode(value))


def save_private_key(key: Ed25519PrivateKey, path: Path, passphrase: bytes | None = None) -> None:
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    path = Path(path)
    path.write_bytes(pem)
    try:
        os.chmod(path, 0o600)
    except (OSError, NotImplementedError):  # pragma: no cover - Windows
        pass


def load_private_key(path: Path, passphrase: bytes | None = None) -> Ed25519PrivateKey:
    loaded = serialization.load_pem_private_key(Path(path).read_bytes(), password=passphrase)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise TypeError("Custos private keys must be Ed25519")
    return loaded


def save_public_key(key: Ed25519PublicKey, path: Path) -> None:
    Path(path).write_bytes(
        key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def load_public_key(path: Path) -> Ed25519PublicKey:
    loaded = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(loaded, Ed25519PublicKey):
        raise TypeError("Custos public keys must be Ed25519")
    return loaded


def generate_hmac_key() -> bytes:
    return os.urandom(32)


def hmac_sign(key: bytes, data: bytes) -> str:
    return _b64encode(hmac.new(key, data, hashlib.sha256).digest())


def hmac_verify(key: bytes, data: bytes, signature: str) -> bool:
    try:
        expected = hmac.new(key, data, hashlib.sha256).digest()
        return hmac.compare_digest(expected, _b64decode(signature))
    except (ValueError, TypeError, base64.binascii.Error):
        return False
