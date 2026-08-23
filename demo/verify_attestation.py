"""Standalone verifier: intentionally imports no Custos modules.

Verifies against a key supplied OUT OF BAND, not the one embedded in the record.
Trusting the embedded key authenticates nothing: an attacker can re-sign forged
content with their own key and update that field to match.
"""

from __future__ import annotations

import argparse
import base64
import json
import math
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def normalize_numbers(obj):
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise ValueError("non-finite number")
        return int(obj) if obj.is_integer() else obj
    if isinstance(obj, dict):
        return {key: normalize_numbers(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [normalize_numbers(item) for item in obj]
    return obj


def canonical_bytes(record: dict) -> bytes:
    filtered = {key: value for key, value in record.items() if key != "proof"}
    return json.dumps(normalize_numbers(filtered), sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify(record: dict, public_key_b64: str) -> None:
    key = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(public_key_b64.encode("ascii")))
    key.verify(base64.urlsafe_b64decode(record["proof"]["proof_value"].encode("ascii")),
               canonical_bytes(record))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify a Custos record independently.")
    parser.add_argument("record", type=Path)
    parser.add_argument("--public-key", required=True,
                        help="base64url key from GET /v1/pubkey — supplied out of band, on purpose")
    args = parser.parse_args()
    verify(json.loads(args.record.read_text(encoding="utf-8")), args.public_key)
    print("VALID: Ed25519 signature matches the canonical payload.")
