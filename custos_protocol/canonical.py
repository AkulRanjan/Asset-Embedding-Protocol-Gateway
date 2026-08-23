"""Canonical serialization — the interop core.

Eight rules produce byte-stable output across languages and runs:

1. Exclude the proof field        — you cannot sign your own signature
2. Whole floats become ints       — Python emits 500.0, JavaScript emits 500
3. Keys sorted recursively        — dict ordering differs across languages
4. No whitespace                  — pretty-printing differences
5. UTF-8 bytes                    — encoding ambiguity
6. Datetimes ISO-8601 with Z      — handled by Pydantic mode="json"
7. Nulls emitted, never omitted   — presence ambiguity
8. Array order preserved          — never sorted

Decimal values are serialized by Pydantic as JSON *strings* before reaching this
module, which preserves exactness. A second implementation must do the same.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

from pydantic import BaseModel


class NonFiniteNumberError(ValueError):
    """Raised for NaN or +/-Infinity, which have no valid JSON representation."""


def normalize_numbers(obj: Any) -> Any:
    """Rule 2: collapse whole floats to ints; reject non-finite values.

    ``bool`` is deliberately checked before ``int``/``float`` because ``bool`` is a
    subclass of ``int`` and must survive as ``true``/``false``.
    """
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise NonFiniteNumberError(f"{obj!r} has no valid JSON representation")
        return int(obj) if obj.is_integer() else obj
    if isinstance(obj, dict):
        return {key: normalize_numbers(value) for key, value in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [normalize_numbers(item) for item in obj]
    return obj


def canonical_bytes(data: dict[str, Any], *, exclude: set[str]) -> bytes:
    """Canonicalize an already-serialized mapping.

    This is the verifier's entry point: a relying party receives JSON off the wire,
    not a model. ``get_signable_payload`` delegates here so signer and verifier
    provably share one implementation.
    """
    filtered = {key: value for key, value in data.items() if key not in exclude}
    return json.dumps(normalize_numbers(filtered), sort_keys=True, separators=(",", ":")).encode("utf-8")


def get_signable_payload(model: BaseModel, *, exclude: set[str]) -> bytes:
    return canonical_bytes(model.model_dump(mode="json", by_alias=True), exclude=exclude)


def payload_hash(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()
