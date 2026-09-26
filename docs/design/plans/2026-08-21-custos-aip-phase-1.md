# Custos Phase 1 — Protocol Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild Custos Gateway on a new `custos_protocol/` SDK that mirrors the AIP architecture — layered leaf modules, canonical serialization, a tier-gated verification pipeline, and a 30-code error taxonomy — with zero dependency on the AIP SDK.

**Architecture:** A flat-module protocol package (`custos_protocol/`) holds every layer. Leaf modules (`errors`, `crypto`, `canonical`) have no internal dependencies; `models` depends only on leaves; feature modules (`passport`, `envelope`, `boundaries`, `drift`, `attestation`, `revocation`) depend on models; `verification` is the only module that composes everything. `gateway/` becomes a thin FastAPI adapter. `claims/` and `oracle/` are retained untouched behind their existing `Claim | None` and `Observation | None` interfaces — the protocol package never performs I/O.

**Tech Stack:** Python 3.10.11, Pydantic 2.12.5, FastAPI 0.128.0, cryptography 46.0.4, httpx 0.28.1, pytest 8.x

**Spec:** `docs/superpowers/specs/2026-08-21-custos-aip-architecture-design.md`

## Global Constraints

- **Zero linkage to AIP.** No file may import `aip_protocol` or reference `../aip`. The blueprint is documentation only.
- **Python floor 3.10.** PEP 604 unions (`X | None`) and `from __future__ import annotations` are used throughout.
- **`custos_protocol/` must never import `gateway/`, `claims/`, or `oracle/`.** Enforced by test in Task 15.
- **`custos_protocol/` performs no I/O.** No sockets, no environment reads inside protocol modules. Configuration arrives as value objects passed by the caller.
- **Encoding is base64url everywhere** (`base64.urlsafe_b64encode`, padding retained) for keys and signatures.
- **All datetimes are timezone-aware UTC.** Naive datetimes are a validation error, never silently coerced, except `Claim.last_attested_at` which is coerced to UTC for backward compatibility with the seed file.
- **Protocol version is `"1.0.0"`; `@context` is `"https://custos.protocol/v1"`; `@type` is `"CustosEnvelope"`.**
- **Error codes are the `CUSTOS-Exxx` values in spec §16.1.** 30 codes. Do not invent new ones.
- **Every error code must be emitted by at least one test**, asserted programmatically in Task 15. `CUSTOS-E203` (per-day limit) is the single documented exemption until Phase 2.
- **Commit after every task.** Conventional commit prefixes (`feat:`, `test:`, `refactor:`, `chore:`).

---

## File Structure

**Created:**

| File | Responsibility |
|---|---|
| `pyproject.toml` | Packaging, pytest `pythonpath`, dependency pins |
| `custos_protocol/__init__.py` | Public API re-exports |
| `custos_protocol/errors.py` | 30-code taxonomy, HTTP mapping, `CustosError` exception |
| `custos_protocol/crypto.py` | Ed25519, HMAC-SHA256, base64url, PEM I/O |
| `custos_protocol/canonical.py` | Byte-stable signable payload (8 rules) |
| `custos_protocol/models.py` | Every wire model + domain models |
| `custos_protocol/passport.py` | `AgentPassport` — identity, keys, policy cage, persistence |
| `custos_protocol/envelope.py` | Envelope construction, signing, hashing, tier selection |
| `custos_protocol/boundaries.py` | Boundary predicates |
| `custos_protocol/drift.py` | Asset-truth engine (staleness, yield drift, backing) |
| `custos_protocol/attestation.py` | Signed `Attestation` / `Denial` records |
| `custos_protocol/revocation.py` | Kill switch + FIFO nonce cache |
| `custos_protocol/verification.py` | `verify_intent()` — the only composer |
| `tests/test_*.py` | One suite per module |

**Modified:** `claims/seed.json`, `claims/registry.py` (add `asset_class`), `gateway/server.py` (rewritten), `gateway/proxy.py`, `config.py`, `demo/*`, `requirements.txt`

**Deleted:** `models/` (folds into `custos_protocol/models.py`), `attest/` (folds into `errors`/`drift`/`attestation`/`canonical`/`crypto`), `gateway/validation.py` (folds into `verification.py`)

---

## Interface Contract (locked across all tasks)

Every task's `Interfaces` block refers back to these exact signatures.

```python
# errors.py
class CustosErrorCode(str, Enum): ...            # .value == "CUSTOS-E100", .name == "INVALID_SIGNATURE"
@dataclass(frozen=True)
class ErrorSpec: http_status: int; description: str
ERROR_SPECS: dict[CustosErrorCode, ErrorSpec]
def http_status_for(code: CustosErrorCode) -> int
class CustosError(Exception):
    def __init__(self, code: CustosErrorCode, detail: str = "") -> None
    def to_dict(self) -> dict[str, str]

# crypto.py
def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]
def sign_data(private_key: Ed25519PrivateKey, data: bytes) -> str
def verify_signature(public_key: Ed25519PublicKey, data: bytes, signature: str) -> bool
def public_key_to_b64(public_key: Ed25519PublicKey) -> str
def b64_to_public_key(value: str) -> Ed25519PublicKey
def save_private_key(key: Ed25519PrivateKey, path: Path, passphrase: bytes | None = None) -> None
def load_private_key(path: Path, passphrase: bytes | None = None) -> Ed25519PrivateKey
def save_public_key(key: Ed25519PublicKey, path: Path) -> None
def load_public_key(path: Path) -> Ed25519PublicKey
def generate_hmac_key() -> bytes
def hmac_sign(key: bytes, data: bytes) -> str
def hmac_verify(key: bytes, data: bytes, signature: str) -> bool

# canonical.py
class NonFiniteNumberError(ValueError): ...
def normalize_numbers(obj: Any) -> Any
def get_signable_payload(model: BaseModel, *, exclude: set[str]) -> bytes
def payload_hash(payload: bytes) -> str

# models.py
class VerificationTier(str, Enum): TIER_0, TIER_1, TIER_2
class Action(str, Enum): BORROW_AGAINST, TRADE, REDEEM, READ
class AttestationMethod(str, Enum): SELF_REPORTED, FRAMEWORK_REGISTRY, THIRD_PARTY_AUDIT
class RevocationStatus(str, Enum): NOT_REVOKED, REVOKED, SUSPENDED
class CheckOutcome(str, Enum): PASSED, FAILED, NOT_RUN
MonetaryLimit, TimeWindow, Boundaries, DelegationLink, Principal,
AgentAttestation, AgentIdentity, Intent, Proof, CustosEnvelope,
Claim, Observation, AssetScores, RevocationCheck, VerificationResult

# passport.py
class AgentPassport:
    @classmethod
    def create(cls, domain: str, agent_name: str | None = None, **kw) -> AgentPassport
    agent: AgentIdentity; principal: Principal; boundaries: Boundaries
    @property
    def private_key(self) -> Ed25519PrivateKey        # raises ValueError if public-only
    @property
    def public_key(self) -> Ed25519PublicKey
    def save(self, directory: Path) -> None
    @classmethod
    def load(cls, directory: Path) -> AgentPassport
    def to_dict(self) -> dict

# envelope.py
VALUE_MOVING_ACTIONS: frozenset[Action]
def select_tier(action, parameters, boundaries, *, cross_org=False, first_contact=False) -> VerificationTier
def create_envelope(passport, action, target, parameters, *, tier=None, ttl=300, now=None) -> CustosEnvelope
def sign_envelope(envelope, private_key, verification_method="") -> CustosEnvelope
def envelope_hash(envelope: CustosEnvelope) -> str

# boundaries.py
def check_boundaries(envelope, claim=None, *, request_geo=None, now=None) -> list[CustosErrorCode]

# drift.py
@dataclass(frozen=True)
class DriftConfig:
    staleness_threshold_hours: float = 24.0
    drift_threshold: float = 0.02
    backing_floor: float = 1.0
    max_observation_age_days: int = 4
    zero_yield_abs_tolerance_bps: int = 10
    clock_skew_seconds: int = 5
@dataclass(frozen=True)
class AssetTruthFailure:
    code: CustosErrorCode; detail: str
    scores: AssetScores | None; reference: dict | None
def check_asset_truth(claim, observation, config, *, now=None) -> AssetScores | AssetTruthFailure

# attestation.py
class Attestation(BaseModel): ...    # verdict Literal["ALLOW"]
class Denial(BaseModel): ...         # verdict Literal["BLOCK"]
class RecordSigner:
    def __init__(self, private_key: Ed25519PrivateKey | None = None) -> None
    @property
    def public_key_b64(self) -> str
    @property
    def public_key_pem(self) -> str
    def sign_attestation(self, **fields) -> Attestation
    def sign_denial(self, **fields) -> Denial
def verify_record(record: dict, public_key: Ed25519PublicKey) -> bool

# revocation.py
class SubjectType(str, Enum): AGENT, ISSUER
@dataclass(frozen=True)
class RevocationRecord:
    subject_id: str; subject_type: SubjectType; reason: str
    revoked_at: datetime; revoked_by: str; scope: str
    suspended_until: datetime | None
class RevocationStore:
    def revoke(self, subject_id, subject_type, reason="", revoked_by="") -> None
    def suspend(self, subject_id, subject_type, duration_seconds=1800, reason="", revoked_by="circuit_breaker") -> None
    def is_revoked(self, subject_id: str) -> bool
    def is_suspended(self, subject_id: str) -> bool
    def reinstate(self, subject_id: str) -> bool
    def get_record(self, subject_id: str) -> RevocationRecord | None
    def touch_sync(self) -> None
    @property
    def last_sync_time(self) -> datetime
    def freshness(self, max_staleness_ms: int) -> RevocationCheck
    def check_nonce(self, nonce: str, ttl_seconds: int = 86400) -> bool
    def clear_nonces(self) -> None
    @property
    def revocation_count(self) -> int

# verification.py
def verify_intent(envelope, public_key, *, claim=None, observation=None,
                  revocation_store=None, drift_config=None, hmac_key=None,
                  request_geo=None, clock_skew_seconds=5,
                  max_revocation_staleness_ms=500, now=None) -> VerificationResult
```

**One deliberate tightening against spec §12:** `check_asset_truth` drops the `envelope`
parameter the spec listed, because the function never reads it. A pure function should not
accept an argument it ignores. The claim and observation carry everything the three signals
need.

---

## Task 1: Packaging and test harness

Establishes `pyproject.toml` so bare `pytest` works (today only `python -m pytest` does), and pins the dependency floors.

**Files:**
- Create: `pyproject.toml`
- Modify: `requirements.txt`
- Test: `tests/test_packaging.py`

**Interfaces:**
- Consumes: nothing
- Produces: a repo where `pytest` resolves `custos_protocol`, `gateway`, `claims`, `oracle` from the root

- [ ] **Step 1: Write the failing test**

```python
# tests/test_packaging.py
from __future__ import annotations

import tomllib
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_pyproject_exists_and_declares_pythonpath():
    """Bare `pytest` must resolve top-level packages; only `python -m pytest` did before."""
    config = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert config["tool"]["pytest"]["ini_options"]["pythonpath"] == ["."]


def test_python_floor_is_310():
    config = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert config["project"]["requires-python"] == ">=3.10"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_packaging.py -v`
Expected: FAIL with `FileNotFoundError: ... pyproject.toml`

- [ ] **Step 3: Write minimal implementation**

```toml
# pyproject.toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "custos-protocol"
version = "1.0.0"
description = "Custos — pre-transaction asset-truth attestation for autonomous agents"
readme = "README.md"
requires-python = ">=3.10"
license = "MIT"

dependencies = [
    "pydantic>=2.0,<3.0",
    "cryptography>=42.0,<47.0",
    "fastapi>=0.110,<1.0",
    "uvicorn[standard]>=0.27,<1.0",
    "httpx>=0.27,<1.0",
]

[project.optional-dependencies]
dev = ["pytest>=8.0,<10.0"]
demo = ["rich>=13.0,<15.0"]

[tool.hatch.build.targets.wheel]
packages = ["custos_protocol"]

[tool.pytest.ini_options]
pythonpath = ["."]
testpaths = ["tests"]
```

- [ ] **Step 4: Trim `requirements.txt` to runtime only**

```
fastapi>=0.110,<1.0
uvicorn[standard]>=0.27,<1.0
pydantic>=2.0,<3.0
httpx>=0.27,<1.0
cryptography>=42.0,<47.0
```

`rich` and `pytest` move to the `demo` and `dev` extras — they were runtime-listed but used only by `demo/` and `tests/`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_packaging.py -v`
Expected: 2 passed. Note this is **bare `pytest`** — it must now work.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml requirements.txt tests/test_packaging.py
git commit -m "chore: add pyproject.toml so bare pytest resolves top-level packages"
```

---

## Task 2: Error taxonomy

**Files:**
- Create: `custos_protocol/__init__.py`, `custos_protocol/errors.py`
- Test: `tests/test_errors.py`

**Interfaces:**
- Consumes: nothing (leaf module)
- Produces: `CustosErrorCode`, `ErrorSpec`, `ERROR_SPECS`, `http_status_for`, `CustosError`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_errors.py
from __future__ import annotations

import pytest

from custos_protocol.errors import (
    ERROR_SPECS,
    CustosError,
    CustosErrorCode,
    http_status_for,
)


def test_taxonomy_has_thirty_codes():
    assert len(CustosErrorCode) == 30


def test_every_code_has_a_spec_with_status_and_description():
    for code in CustosErrorCode:
        spec = ERROR_SPECS[code]
        assert spec.http_status in {400, 401, 403, 404, 409, 422, 502, 503}
        assert spec.description, f"{code.name} has no description"


def test_code_value_and_name_shape():
    assert CustosErrorCode.INVALID_SIGNATURE.value == "CUSTOS-E100"
    assert CustosErrorCode.INVALID_SIGNATURE.name == "INVALID_SIGNATURE"
    for code in CustosErrorCode:
        assert code.value.startswith("CUSTOS-E")
        assert len(code.value) == len("CUSTOS-E100")


def test_families_are_correctly_sized():
    families: dict[str, int] = {}
    for code in CustosErrorCode:
        families[code.value[8]] = families.get(code.value[8], 0) + 1
    assert families == {"1": 7, "2": 7, "3": 7, "4": 6, "5": 3}


@pytest.mark.parametrize(
    "code,status",
    [
        (CustosErrorCode.INVALID_SIGNATURE, 401),
        (CustosErrorCode.REPLAY_DETECTED, 409),
        (CustosErrorCode.UNKNOWN_ASSET, 404),
        (CustosErrorCode.TENOR_UNSUPPORTED, 422),
        (CustosErrorCode.ORACLE_UNAVAILABLE, 503),
        (CustosErrorCode.DOWNSTREAM_UNREACHABLE, 502),
        (CustosErrorCode.CLAIM_STALE, 403),
    ],
)
def test_http_status_mapping(code, status):
    assert http_status_for(code) == status


def test_custos_error_serializes_for_an_api_response():
    error = CustosError(CustosErrorCode.YIELD_DRIFT_EXCEEDED, detail="drift 3.36% > 2.0%")
    assert error.to_dict() == {
        "error": "CUSTOS-E301",
        "error_name": "YIELD_DRIFT_EXCEEDED",
        "description": ERROR_SPECS[CustosErrorCode.YIELD_DRIFT_EXCEEDED].description,
        "detail": "drift 3.36% > 2.0%",
    }


def test_custos_error_is_raisable_and_carries_its_code():
    with pytest.raises(CustosError) as caught:
        raise CustosError(CustosErrorCode.AGENT_REVOKED)
    assert caught.value.code is CustosErrorCode.AGENT_REVOKED
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_errors.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'custos_protocol'`

- [ ] **Step 3: Write minimal implementation**

```python
# custos_protocol/__init__.py
"""Custos — pre-transaction asset-truth attestation protocol."""

__version__ = "1.0.0"
```

```python
# custos_protocol/errors.py
"""The Custos error taxonomy: 30 codes across five families.

E1xx envelope/protocol · E2xx boundary · E3xx asset truth
E4xx revocation/trust  · E5xx infrastructure
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CustosErrorCode(str, Enum):
    # E1xx — envelope / protocol
    INVALID_SIGNATURE = "CUSTOS-E100"
    EXPIRED_ENVELOPE = "CUSTOS-E101"
    REPLAY_DETECTED = "CUSTOS-E102"
    SCHEMA_INVALID = "CUSTOS-E103"
    VERSION_UNSUPPORTED = "CUSTOS-E104"
    NONCE_INVALID = "CUSTOS-E105"
    CLOCK_SKEW = "CUSTOS-E106"

    # E2xx — boundary
    ACTION_NOT_ALLOWED = "CUSTOS-E200"
    ACTION_DENIED = "CUSTOS-E201"
    MONETARY_LIMIT_PER_TXN = "CUSTOS-E202"
    MONETARY_LIMIT_PER_DAY = "CUSTOS-E203"
    TIME_WINDOW_VIOLATION = "CUSTOS-E204"
    GEO_RESTRICTION = "CUSTOS-E205"
    ASSET_CLASS_NOT_ALLOWED = "CUSTOS-E206"

    # E3xx — asset truth
    CLAIM_STALE = "CUSTOS-E300"
    YIELD_DRIFT_EXCEEDED = "CUSTOS-E301"
    BACKING_RATIO_BELOW_FLOOR = "CUSTOS-E302"
    UNKNOWN_ASSET = "CUSTOS-E303"
    TENOR_UNSUPPORTED = "CUSTOS-E304"
    CLAIM_FUTURE_DATED = "CUSTOS-E305"
    ATTESTATION_MISMATCH = "CUSTOS-E306"

    # E4xx — revocation / delegation / trust
    AGENT_REVOKED = "CUSTOS-E400"
    AGENT_SUSPENDED = "CUSTOS-E401"
    ISSUER_REVOKED = "CUSTOS-E402"
    DELEGATION_INVALID = "CUSTOS-E403"
    TRUST_SCORE_LOW = "CUSTOS-E404"
    REVOCATION_STALE = "CUSTOS-E405"

    # E5xx — infrastructure
    ORACLE_UNAVAILABLE = "CUSTOS-E500"
    ORACLE_DATA_STALE = "CUSTOS-E501"
    DOWNSTREAM_UNREACHABLE = "CUSTOS-E502"


@dataclass(frozen=True)
class ErrorSpec:
    http_status: int
    description: str


ERROR_SPECS: dict[CustosErrorCode, ErrorSpec] = {
    CustosErrorCode.INVALID_SIGNATURE: ErrorSpec(401, "Envelope signature failed verification."),
    CustosErrorCode.EXPIRED_ENVELOPE: ErrorSpec(400, "Envelope expires_at is in the past."),
    CustosErrorCode.REPLAY_DETECTED: ErrorSpec(409, "Envelope nonce has already been used."),
    CustosErrorCode.SCHEMA_INVALID: ErrorSpec(400, "Envelope failed schema validation."),
    CustosErrorCode.VERSION_UNSUPPORTED: ErrorSpec(400, "Protocol version is not supported."),
    CustosErrorCode.NONCE_INVALID: ErrorSpec(400, "Envelope entropy is not a well-formed nonce."),
    CustosErrorCode.CLOCK_SKEW: ErrorSpec(400, "Envelope issued_at is implausibly far in the future."),
    CustosErrorCode.ACTION_NOT_ALLOWED: ErrorSpec(403, "Action is absent from the agent's allowed actions."),
    CustosErrorCode.ACTION_DENIED: ErrorSpec(403, "Action appears on the agent's denied actions."),
    CustosErrorCode.MONETARY_LIMIT_PER_TXN: ErrorSpec(403, "Amount exceeds the per-transaction monetary limit."),
    CustosErrorCode.MONETARY_LIMIT_PER_DAY: ErrorSpec(403, "Amount exceeds the rolling per-day monetary limit."),
    CustosErrorCode.TIME_WINDOW_VIOLATION: ErrorSpec(403, "Request falls outside the agent's permitted time window."),
    CustosErrorCode.GEO_RESTRICTION: ErrorSpec(403, "Request origin is outside the agent's permitted geography."),
    CustosErrorCode.ASSET_CLASS_NOT_ALLOWED: ErrorSpec(403, "Asset class is absent from the agent's permitted classes."),
    CustosErrorCode.CLAIM_STALE: ErrorSpec(403, "Claim was not attested within the staleness threshold."),
    CustosErrorCode.YIELD_DRIFT_EXCEEDED: ErrorSpec(403, "Claimed yield diverges from the observed market yield beyond threshold."),
    CustosErrorCode.BACKING_RATIO_BELOW_FLOOR: ErrorSpec(403, "Claimed backing does not cover the implied liability."),
    CustosErrorCode.UNKNOWN_ASSET: ErrorSpec(404, "Asset is not present in the claim registry."),
    CustosErrorCode.TENOR_UNSUPPORTED: ErrorSpec(422, "Claim references a tenor with no yield-curve mapping."),
    CustosErrorCode.CLAIM_FUTURE_DATED: ErrorSpec(403, "Claim was attested in the future."),
    CustosErrorCode.ATTESTATION_MISMATCH: ErrorSpec(403, "Agent build or prompt attestation does not match the expected value."),
    CustosErrorCode.AGENT_REVOKED: ErrorSpec(403, "Agent identity has been revoked."),
    CustosErrorCode.AGENT_SUSPENDED: ErrorSpec(403, "Agent identity is temporarily suspended."),
    CustosErrorCode.ISSUER_REVOKED: ErrorSpec(403, "The asset issuer has been revoked."),
    CustosErrorCode.DELEGATION_INVALID: ErrorSpec(403, "Delegation chain is broken, expired, or widens its scope."),
    CustosErrorCode.TRUST_SCORE_LOW: ErrorSpec(403, "Agent trust score is below the required minimum."),
    CustosErrorCode.REVOCATION_STALE: ErrorSpec(503, "Revocation data is too stale to rely on; Custos fails closed."),
    CustosErrorCode.ORACLE_UNAVAILABLE: ErrorSpec(503, "The market oracle could not be reached; Custos fails closed."),
    CustosErrorCode.ORACLE_DATA_STALE: ErrorSpec(503, "The market observation is older than tolerance."),
    CustosErrorCode.DOWNSTREAM_UNREACHABLE: ErrorSpec(502, "The downstream service could not be reached."),
}


def http_status_for(code: CustosErrorCode) -> int:
    return ERROR_SPECS[code].http_status


class CustosError(Exception):
    """Structured protocol error. `verify_intent` returns codes; this is for callers who raise."""

    def __init__(self, code: CustosErrorCode, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code.value} {code.name}: {detail}" if detail else f"{code.value} {code.name}")

    def to_dict(self) -> dict[str, str]:
        return {
            "error": self.code.value,
            "error_name": self.code.name,
            "description": ERROR_SPECS[self.code].description,
            "detail": self.detail,
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_errors.py -v`
Expected: 12 passed (7 parametrized cases + 5 others)

- [ ] **Step 5: Commit**

```bash
git add custos_protocol/__init__.py custos_protocol/errors.py tests/test_errors.py
git commit -m "feat: add 30-code CUSTOS error taxonomy with HTTP mapping"
```

---

## Task 3: Cryptography

**Files:**
- Create: `custos_protocol/crypto.py`
- Test: `tests/test_crypto.py`

**Interfaces:**
- Consumes: nothing (leaf module)
- Produces: `generate_keypair`, `sign_data`, `verify_signature`, `public_key_to_b64`, `b64_to_public_key`, `save_private_key`, `load_private_key`, `save_public_key`, `load_public_key`, `generate_hmac_key`, `hmac_sign`, `hmac_verify`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_crypto.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_crypto.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'custos_protocol.crypto'`

- [ ] **Step 3: Write minimal implementation**

```python
# custos_protocol/crypto.py
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_crypto.py -v`
Expected: 11 passed, 1 skipped on Windows

- [ ] **Step 5: Commit**

```bash
git add custos_protocol/crypto.py tests/test_crypto.py
git commit -m "feat: add Ed25519 and HMAC primitives with base64url encoding"
```

---
## Task 4: Canonical serialization

The most important module in the repository. If two implementations disagree on these bytes, every signature fails.

**Files:**
- Create: `custos_protocol/canonical.py`
- Test: `tests/test_canonical.py`

**Interfaces:**
- Consumes: nothing (leaf module)
- Produces: `NonFiniteNumberError`, `normalize_numbers(obj) -> Any`, `canonical_bytes(data: dict, *, exclude: set[str]) -> bytes`, `get_signable_payload(model: BaseModel, *, exclude: set[str]) -> bytes`, `payload_hash(payload: bytes) -> str`

`canonical_bytes` takes a plain dict and is what Task 10's `verify_record` uses — a verifier receives JSON off the wire, not a model. `get_signable_payload` dumps a model and delegates to it, so signer and verifier provably share one implementation.

**Verified serializer behaviour** (Pydantic 2.12.5, confirmed by execution — do not re-derive):
- Aware-UTC datetime → `"2026-08-21T12:00:00Z"` (Z suffix; no fractional part when `microsecond == 0`)
- `Decimal("50000.00")` → the string `"50000.00"` (exactness preserved)
- `float 500.0` → stays `500.0` through `json.dumps` — **this is why rule 2 exists**
- `None` → `null`, emitted not omitted
- `@context` sorts before all letters (`@` is `U+0040`)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_canonical.py
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

import pytest
from pydantic import BaseModel, Field

from custos_protocol.canonical import (
    NonFiniteNumberError,
    get_signable_payload,
    normalize_numbers,
    payload_hash,
)


class Sample(BaseModel):
    context: str = Field(default="https://custos.protocol/v1", alias="@context")
    amount: Decimal
    whole: float
    fractional: float
    issued_at: datetime
    optional: str | None = None
    tags: list[str]
    proof: dict | None = None
    model_config = {"populate_by_name": True}


def sample() -> Sample:
    return Sample(
        amount=Decimal("50000.00"),
        whole=500.0,
        fractional=45.5,
        issued_at=datetime(2026, 8, 21, 12, 0, 0, tzinfo=timezone.utc),
        tags=["zebra", "alpha"],
        proof={"proof_value": "ignored"},
    )


def test_rule_2_whole_floats_become_ints():
    assert normalize_numbers({"a": 500.0}) == {"a": 500}
    assert normalize_numbers({"a": 45.5}) == {"a": 45.5}
    assert normalize_numbers([1.0, 2.5]) == [1, 2.5]
    assert normalize_numbers({"nested": {"deep": [{"x": 3.0}]}}) == {"nested": {"deep": [{"x": 3}]}}


def test_rule_2_leaves_bools_alone():
    """bool is a subclass of int; normalizing must not turn True into 1."""
    result = normalize_numbers({"flag": True, "other": False})
    assert result["flag"] is True
    assert result["other"] is False


def test_non_finite_floats_are_rejected():
    """The blueprint's normalizer crashes on these; Custos rejects them explicitly."""
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(NonFiniteNumberError):
            normalize_numbers({"a": bad})


def test_canonical_payload_is_byte_exact():
    payload = get_signable_payload(sample(), exclude={"proof"})
    assert payload == (
        b'{"@context":"https://custos.protocol/v1",'
        b'"amount":"50000.00",'
        b'"fractional":45.5,'
        b'"issued_at":"2026-08-21T12:00:00Z",'
        b'"optional":null,'
        b'"tags":["zebra","alpha"],'
        b'"whole":500}'
    )


def test_rule_1_excluded_field_is_absent():
    assert b"proof" not in get_signable_payload(sample(), exclude={"proof"})


def test_rule_3_keys_sorted_recursively_and_at_sorts_first():
    payload = get_signable_payload(sample(), exclude={"proof"}).decode()
    assert payload.startswith('{"@context"')
    keys = ["@context", "amount", "fractional", "issued_at", "optional", "tags", "whole"]
    positions = [payload.index(f'"{key}"') for key in keys]
    assert positions == sorted(positions)


def test_rule_4_no_whitespace():
    payload = get_signable_payload(sample(), exclude={"proof"})
    assert b" " not in payload.replace(b"https://custos.protocol/v1", b"")


def test_rule_7_nulls_are_emitted_not_omitted():
    assert b'"optional":null' in get_signable_payload(sample(), exclude={"proof"})


def test_rule_8_array_order_is_preserved():
    assert b'["zebra","alpha"]' in get_signable_payload(sample(), exclude={"proof"})


def test_payload_is_stable_across_field_construction_order():
    first = get_signable_payload(sample(), exclude={"proof"})
    second = get_signable_payload(sample(), exclude={"proof"})
    assert first == second


def test_payload_hash_is_deterministic_sha256_hex():
    digest = payload_hash(get_signable_payload(sample(), exclude={"proof"}))
    assert len(digest) == 64
    assert digest == payload_hash(get_signable_payload(sample(), exclude={"proof"}))


def test_canonical_bytes_on_a_dict_matches_the_model_path():
    """A verifier receives JSON off the wire, not a model. Both paths must agree."""
    from custos_protocol.canonical import canonical_bytes

    served = sample().model_dump(mode="json", by_alias=True)
    assert canonical_bytes(served, exclude={"proof"}) == get_signable_payload(sample(), exclude={"proof"})


def test_canonical_bytes_applies_the_same_number_rule():
    from custos_protocol.canonical import canonical_bytes

    assert canonical_bytes({"whole": 500.0}, exclude=set()) == b'{"whole":500}'
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_canonical.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'custos_protocol.canonical'`

- [ ] **Step 3: Write minimal implementation**

```python
# custos_protocol/canonical.py
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_canonical.py -v`
Expected: 11 passed

- [ ] **Step 5: Commit**

```bash
git add custos_protocol/canonical.py tests/test_canonical.py
git commit -m "feat: add canonical serialization with byte-exact 8-rule payload"
```

---

## Task 5: Data models

**Files:**
- Create: `custos_protocol/models.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Consumes: `custos_protocol.errors.CustosErrorCode`
- Produces: `VerificationTier`, `Action`, `AttestationMethod`, `RevocationStatus`, `CheckOutcome`, `MonetaryLimit`, `TimeWindow`, `Boundaries`, `DelegationLink`, `Principal`, `AgentAttestation`, `AgentIdentity`, `Intent`, `Proof`, `CustosEnvelope`, `Claim`, `Observation`, `AssetScores`, `RevocationCheck`, `VerificationResult`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_models.py
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from pydantic import ValidationError

from custos_protocol.models import (
    Action,
    AgentIdentity,
    Boundaries,
    CheckOutcome,
    Claim,
    CustosEnvelope,
    DelegationLink,
    Intent,
    MonetaryLimit,
    Principal,
    VerificationResult,
    VerificationTier,
)


def now() -> datetime:
    return datetime.now(timezone.utc)


def envelope_kwargs(**overrides) -> dict:
    issued = now()
    base = {
        "agent": AgentIdentity(id="did:web:acme.com:agents:bot"),
        "principal": Principal(id="did:web:acme.com"),
        "intent": Intent(action=Action.TRADE, target="TKN-UST-3M-001",
                         parameters={"amount": 50000, "currency": "USD"}),
        "boundaries": Boundaries(),
        "entropy": "nonce:" + "a" * 32,
        "issued_at": issued,
        "expires_at": issued + timedelta(minutes=5),
    }
    base.update(overrides)
    return base


def test_envelope_defaults_match_the_protocol():
    envelope = CustosEnvelope(**envelope_kwargs())
    assert envelope.context == "https://custos.protocol/v1"
    assert envelope.type == "CustosEnvelope"
    assert envelope.protocol_version == "1.0.0"
    assert envelope.verification_tier is VerificationTier.TIER_1
    assert envelope.ttl == 300
    assert envelope.proof is None


def test_envelope_serializes_jsonld_aliases():
    dumped = CustosEnvelope(**envelope_kwargs()).model_dump(mode="json", by_alias=True)
    assert dumped["@context"] == "https://custos.protocol/v1"
    assert dumped["@type"] == "CustosEnvelope"


def test_envelope_accepts_alias_or_field_name_on_input():
    """populate_by_name lets callers use either form."""
    assert CustosEnvelope(**envelope_kwargs(), **{}).context == "https://custos.protocol/v1"
    payload = CustosEnvelope(**envelope_kwargs()).model_dump(mode="json", by_alias=True)
    assert CustosEnvelope.model_validate(payload).type == "CustosEnvelope"


def test_expires_at_is_required():
    """Divergence from the blueprint, which permits a never-expiring envelope."""
    kwargs = envelope_kwargs()
    del kwargs["expires_at"]
    with pytest.raises(ValidationError):
        CustosEnvelope(**kwargs)


def test_envelope_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        CustosEnvelope(**envelope_kwargs(), surprise="x")


def test_envelope_rejects_naive_datetimes():
    with pytest.raises(ValidationError):
        CustosEnvelope(**envelope_kwargs(issued_at=datetime.now()))


def test_ttl_is_bounded():
    with pytest.raises(ValidationError):
        CustosEnvelope(**envelope_kwargs(ttl=0))
    with pytest.raises(ValidationError):
        CustosEnvelope(**envelope_kwargs(ttl=86401))


def test_delegation_link_accepts_from_and_to_aliases():
    """`from` is a Python keyword, so the field is from_id with an alias."""
    link = DelegationLink.model_validate(
        {"from": "did:web:acme.com", "to": "did:web:acme.com:agents:bot",
         "scope": "default", "granted_at": now().isoformat()}
    )
    assert link.from_id == "did:web:acme.com"
    assert link.to_id == "did:web:acme.com:agents:bot"
    assert link.boundary_monotonicity is True
    assert link.model_dump(by_alias=True)["from"] == "did:web:acme.com"


def test_monetary_limit_rejects_negatives():
    with pytest.raises(ValidationError):
        MonetaryLimit(per_transaction=-1)


def test_claim_requires_positive_tokens_outstanding():
    """Schema-level guarantee that the backing-ratio denominator is never zero."""
    with pytest.raises(ValidationError):
        Claim(asset_id="a", issuer="i", underlying_tenor="3M", asset_class="treasury",
              claimed_nav_per_token=Decimal("1"), claimed_backing_usd=Decimal("100"),
              tokens_outstanding=Decimal("0"), claimed_yield_bps=400,
              last_attested_at=now(), chain="ethereum", contract_address="0x1")


def test_claim_coerces_naive_last_attested_at_to_utc():
    claim = Claim(asset_id="a", issuer="i", underlying_tenor="3M", asset_class="treasury",
                  claimed_nav_per_token=Decimal("1"), claimed_backing_usd=Decimal("100"),
                  tokens_outstanding=Decimal("100"), claimed_yield_bps=400,
                  last_attested_at=datetime(2026, 8, 21, 12, 0, 0),
                  chain="ethereum", contract_address="0x1")
    assert claim.last_attested_at.tzinfo is timezone.utc


def test_verification_result_passed_is_the_single_authority():
    """There is no `valid` field; NOT_RUN checks never contribute to `passed`."""
    assert not hasattr(VerificationResult, "valid")
    result = VerificationResult(
        passed=True,
        checks={"signature": CheckOutcome.PASSED, "asset_truth": CheckOutcome.NOT_RUN},
        tier_used=VerificationTier.TIER_0,
    )
    assert result.passed is True
    assert result.checks["asset_truth"] is CheckOutcome.NOT_RUN
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'custos_protocol.models'`

- [ ] **Step 3: Write minimal implementation**

```python
# custos_protocol/models.py
"""Every wire message and domain object, as Pydantic v2 models. This file is the schema."""

from __future__ import annotations

from datetime import date, datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)

from custos_protocol.errors import CustosErrorCode

PROTOCOL_VERSION = "1.0.0"
CONTEXT_URL = "https://custos.protocol/v1"
ENVELOPE_TYPE = "CustosEnvelope"


class VerificationTier(str, Enum):
    TIER_0 = "tier_0"   # authorization only — NO market check
    TIER_1 = "tier_1"   # + asset truth + attestation
    TIER_2 = "tier_2"   # + delegation + trust  (Phase 2)


class Action(str, Enum):
    BORROW_AGAINST = "borrow_against"
    TRADE = "trade"
    REDEEM = "redeem"
    READ = "read"


class AttestationMethod(str, Enum):
    SELF_REPORTED = "self_reported"
    FRAMEWORK_REGISTRY = "framework_registry"
    THIRD_PARTY_AUDIT = "third_party_audit"


class RevocationStatus(str, Enum):
    NOT_REVOKED = "not_revoked"
    REVOKED = "revoked"
    SUSPENDED = "suspended"


class CheckOutcome(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    NOT_RUN = "not_run"


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    return value.astimezone(timezone.utc)


class MonetaryLimit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    per_transaction: float = Field(default=0.0, ge=0)
    per_day: float = Field(default=0.0, ge=0)
    currency: str = "USD"


class TimeWindow(BaseModel):
    model_config = ConfigDict(extra="forbid")
    start: datetime
    end: datetime


class Boundaries(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allowed_actions: list[str] = Field(default_factory=list)
    denied_actions: list[str] = Field(default_factory=list)
    monetary_limit: MonetaryLimit = Field(default_factory=MonetaryLimit)
    asset_classes: list[str] = Field(default_factory=list)
    geo_restriction: str | None = None
    time_window: TimeWindow | None = None


class DelegationLink(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    from_id: str = Field(alias="from")
    to_id: str = Field(alias="to")
    scope: str = "default"
    boundary_monotonicity: bool = True
    granted_at: datetime
    expires_at: datetime | None = None


class Principal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = "organization"
    id: str
    delegation_chain: list[DelegationLink] = Field(default_factory=list)


class AgentAttestation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    method: AttestationMethod = AttestationMethod.SELF_REPORTED
    framework_id: str | None = None
    build_hash: str | None = None
    system_prompt_hash: str | None = None
    registry_signature: str | None = None


class AgentIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    version: str = "1.0.0"
    runtime: str = "custos-sdk/1.0.0"
    attestation: AgentAttestation = Field(default_factory=AgentAttestation)


class Intent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Action
    target: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)


class Proof(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = "Ed25519Signature2020"
    created: datetime
    verification_method: str = ""
    proof_purpose: str = "assertionMethod"
    proof_value: str


class CustosEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    context: str = Field(default=CONTEXT_URL, alias="@context")
    type: str = Field(default=ENVELOPE_TYPE, alias="@type")
    protocol_version: str = PROTOCOL_VERSION

    agent: AgentIdentity
    principal: Principal
    intent: Intent
    boundaries: Boundaries

    verification_tier: VerificationTier = VerificationTier.TIER_1
    entropy: str = Field(default_factory=lambda: f"nonce:{uuid4().hex}")
    ttl: int = Field(default=300, ge=1, le=86400)
    issued_at: datetime
    expires_at: datetime
    proof: Proof | None = None

    @field_validator("issued_at", "expires_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return _require_aware(value)


class Claim(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: str
    issuer: str
    underlying_tenor: str
    asset_class: str = "treasury"
    claimed_nav_per_token: Decimal = Field(gt=0)
    claimed_backing_usd: Decimal = Field(ge=0)
    tokens_outstanding: Decimal = Field(gt=0)
    claimed_yield_bps: int = Field(ge=0)
    last_attested_at: datetime
    chain: str
    contract_address: str

    @field_validator("last_attested_at")
    @classmethod
    def _coerce_utc(cls, value: datetime) -> datetime:
        """Seed data is written naive; assume UTC rather than reject."""
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


class Observation(BaseModel):
    source: str
    dataset: str = "daily_treasury_yield_curve"
    tenor: str
    observed_yield_bps: int
    record_date: date
    fetched_at: datetime
    cache_hit: bool = False


class AssetScores(BaseModel):
    staleness_hours: float | None = None
    staleness_threshold_hours: float | None = None
    yield_drift: float | None = None
    yield_drift_threshold: float | None = None
    yield_drift_basis: str | None = None      # "relative" | "absolute"
    backing_ratio: float | None = None
    backing_ratio_floor: float | None = None


class RevocationCheck(BaseModel):
    status: RevocationStatus = RevocationStatus.NOT_REVOKED
    freshness_ms: float = 0.0
    max_staleness_ms: int = 500
    stale: bool = False


class VerificationResult(BaseModel):
    passed: bool = False
    checks: dict[str, CheckOutcome] = Field(default_factory=dict)
    revocation: RevocationCheck = Field(default_factory=RevocationCheck)
    trust_score: float = 0.0
    tier_used: VerificationTier = VerificationTier.TIER_1
    scores: AssetScores | None = None
    reference: dict[str, Any] | None = None
    errors: list[CustosErrorCode] = Field(default_factory=list)
    detail: str = ""
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_models.py -v`
Expected: 13 passed

- [ ] **Step 5: Commit**

```bash
git add custos_protocol/models.py tests/test_models.py
git commit -m "feat: add protocol and domain models with JSON-LD envelope"
```

---

## Task 6: Agent passport

**Files:**
- Create: `custos_protocol/passport.py`
- Test: `tests/test_passport.py`

**Interfaces:**
- Consumes: `crypto.*`, `models.AgentIdentity`, `models.AgentAttestation`, `models.Principal`, `models.DelegationLink`, `models.Boundaries`, `models.MonetaryLimit`, `models.AttestationMethod`
- Produces: `AgentPassport` with `.create()`, `.save()`, `.load()`, `.to_dict()`, `.agent`, `.principal`, `.boundaries`, `.public_key`, `.private_key`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_passport.py
from __future__ import annotations

import json

import pytest

from custos_protocol.crypto import sign_data, verify_signature
from custos_protocol.models import AttestationMethod
from custos_protocol.passport import AgentPassport


def test_create_synthesises_did_identities():
    passport = AgentPassport.create(domain="acme.com", agent_name="treasury-bot")
    assert passport.agent.id == "did:web:acme.com:agents:treasury-bot"
    assert passport.principal.id == "did:web:acme.com"


def test_agent_name_defaults_to_random_suffix():
    passport = AgentPassport.create(domain="acme.com")
    assert passport.agent.id.startswith("did:web:acme.com:agents:agent-")
    assert len(passport.agent.id.rsplit("-", 1)[-1]) == 8


def test_create_ships_a_one_hop_delegation_chain():
    """Every passport is born with a well-formed principal to agent link."""
    passport = AgentPassport.create(domain="acme.com", agent_name="bot")
    assert len(passport.principal.delegation_chain) == 1
    link = passport.principal.delegation_chain[0]
    assert link.from_id == "did:web:acme.com"
    assert link.to_id == "did:web:acme.com:agents:bot"
    assert link.boundary_monotonicity is True


def test_attestation_method_depends_on_framework_id():
    assert AgentPassport.create(domain="a.com").agent.attestation.method is AttestationMethod.SELF_REPORTED
    framework = AgentPassport.create(domain="a.com", framework_id="langchain")
    assert framework.agent.attestation.method is AttestationMethod.FRAMEWORK_REGISTRY
    assert framework.agent.attestation.framework_id == "langchain"


def test_boundaries_are_built_from_flat_kwargs():
    passport = AgentPassport.create(
        domain="acme.com",
        allowed_actions=["borrow_against"],
        denied_actions=["redeem"],
        monetary_limit_per_txn=100000.0,
        monetary_limit_per_day=250000.0,
        asset_classes=["treasury"],
    )
    assert passport.boundaries.allowed_actions == ["borrow_against"]
    assert passport.boundaries.denied_actions == ["redeem"]
    assert passport.boundaries.monetary_limit.per_transaction == 100000.0
    assert passport.boundaries.monetary_limit.per_day == 250000.0
    assert passport.boundaries.asset_classes == ["treasury"]


def test_keys_are_usable_for_signing():
    passport = AgentPassport.create(domain="acme.com")
    signature = sign_data(passport.private_key, b"payload")
    assert verify_signature(passport.public_key, b"payload", signature) is True


def test_save_writes_three_files(tmp_path):
    AgentPassport.create(domain="acme.com", agent_name="bot").save(tmp_path)
    assert (tmp_path / "passport.json").exists()
    assert (tmp_path / "private.pem").exists()
    assert (tmp_path / "public.pem").exists()


def test_save_load_round_trip_preserves_identity_and_keys(tmp_path):
    original = AgentPassport.create(domain="acme.com", agent_name="bot",
                                    allowed_actions=["trade"])
    original.save(tmp_path)
    loaded = AgentPassport.load(tmp_path)
    assert loaded.agent.id == original.agent.id
    assert loaded.boundaries.allowed_actions == ["trade"]
    signature = sign_data(loaded.private_key, b"payload")
    assert verify_signature(original.public_key, b"payload", signature) is True


def test_public_only_passport_can_verify_but_not_sign(tmp_path):
    """Ship passport.json without the PEMs and you get a verifier-only passport."""
    AgentPassport.create(domain="acme.com", agent_name="bot").save(tmp_path)
    (tmp_path / "private.pem").unlink()
    (tmp_path / "public.pem").unlink()
    loaded = AgentPassport.load(tmp_path)
    assert loaded.public_key is not None
    with pytest.raises(ValueError, match="public-only"):
        _ = loaded.private_key


def test_to_dict_never_leaks_the_private_key(tmp_path):
    data = AgentPassport.create(domain="acme.com").to_dict()
    serialized = json.dumps(data)
    assert "PRIVATE" not in serialized
    assert "private_key" not in data
    assert "public_key" in data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_passport.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'custos_protocol.passport'`

- [ ] **Step 3: Write minimal implementation**

```python
# custos_protocol/passport.py
"""The identity object: DID, keypair, and the policy cage that travels inside every envelope."""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from custos_protocol.crypto import (
    b64_to_public_key,
    generate_keypair,
    load_private_key,
    load_public_key,
    public_key_to_b64,
    save_private_key,
    save_public_key,
)
from custos_protocol.models import (
    AgentAttestation,
    AgentIdentity,
    AttestationMethod,
    Boundaries,
    DelegationLink,
    MonetaryLimit,
    Principal,
)


class AgentPassport:
    """Holds models plus live key objects. Deliberately not a Pydantic model."""

    def __init__(
        self,
        agent: AgentIdentity,
        principal: Principal,
        boundaries: Boundaries,
        public_key: Ed25519PublicKey,
        private_key: Ed25519PrivateKey | None = None,
    ) -> None:
        self.agent = agent
        self.principal = principal
        self.boundaries = boundaries
        self._public_key = public_key
        self._private_key = private_key

    @classmethod
    def create(
        cls,
        domain: str,
        agent_name: str | None = None,
        *,
        version: str = "1.0.0",
        principal_id: str | None = None,
        principal_type: str = "organization",
        allowed_actions: list[str] | None = None,
        denied_actions: list[str] | None = None,
        monetary_limit_per_txn: float = 0.0,
        monetary_limit_per_day: float = 0.0,
        currency: str = "USD",
        asset_classes: list[str] | None = None,
        geo_restriction: str | None = None,
        framework_id: str | None = None,
        system_prompt_hash: str | None = None,
    ) -> AgentPassport:
        agent_name = agent_name or f"agent-{secrets.token_hex(4)}"
        agent_id = f"did:web:{domain}:agents:{agent_name}"
        principal_id = principal_id or f"did:web:{domain}"

        private_key, public_key = generate_keypair()

        attestation = AgentAttestation(
            method=AttestationMethod.FRAMEWORK_REGISTRY if framework_id else AttestationMethod.SELF_REPORTED,
            framework_id=framework_id,
            system_prompt_hash=system_prompt_hash,
        )
        agent = AgentIdentity(id=agent_id, version=version, attestation=attestation)

        principal = Principal(
            type=principal_type,
            id=principal_id,
            delegation_chain=[
                DelegationLink(
                    from_id=principal_id,
                    to_id=agent_id,
                    scope="default",
                    boundary_monotonicity=True,
                    granted_at=datetime.now(timezone.utc),
                )
            ],
        )

        boundaries = Boundaries(
            allowed_actions=allowed_actions or [],
            denied_actions=denied_actions or [],
            monetary_limit=MonetaryLimit(
                per_transaction=monetary_limit_per_txn,
                per_day=monetary_limit_per_day,
                currency=currency,
            ),
            asset_classes=asset_classes or [],
            geo_restriction=geo_restriction,
        )

        return cls(agent, principal, boundaries, public_key, private_key)

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._public_key

    @property
    def private_key(self) -> Ed25519PrivateKey:
        if self._private_key is None:
            raise ValueError("No private key loaded — passport may be public-only")
        return self._private_key

    def to_dict(self) -> dict:
        return {
            "agent": self.agent.model_dump(mode="json"),
            "principal": self.principal.model_dump(mode="json", by_alias=True),
            "boundaries": self.boundaries.model_dump(mode="json"),
            "public_key": public_key_to_b64(self._public_key),
        }

    def save(self, directory: Path) -> None:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "passport.json").write_text(
            json.dumps(self.to_dict(), indent=2), encoding="utf-8"
        )
        save_public_key(self._public_key, directory / "public.pem")
        if self._private_key is not None:
            save_private_key(self._private_key, directory / "private.pem")

    @classmethod
    def load(cls, directory: Path) -> AgentPassport:
        directory = Path(directory)
        data = json.loads((directory / "passport.json").read_text(encoding="utf-8"))

        private_key: Ed25519PrivateKey | None = None
        private_path = directory / "private.pem"
        public_path = directory / "public.pem"

        # Key precedence: private.pem (derive public) -> public.pem -> passport.json
        if private_path.exists():
            private_key = load_private_key(private_path)
            public_key = private_key.public_key()
        elif public_path.exists():
            public_key = load_public_key(public_path)
        else:
            public_key = b64_to_public_key(data["public_key"])

        return cls(
            agent=AgentIdentity.model_validate(data["agent"]),
            principal=Principal.model_validate(data["principal"]),
            boundaries=Boundaries.model_validate(data["boundaries"]),
            public_key=public_key,
            private_key=private_key,
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_passport.py -v`
Expected: 10 passed

- [ ] **Step 5: Commit**

```bash
git add custos_protocol/passport.py tests/test_passport.py
git commit -m "feat: add AgentPassport with DID identity and key persistence"
```

---
## Task 7: Intent envelope

**Files:**
- Create: `custos_protocol/envelope.py`
- Test: `tests/test_envelope.py`

**Interfaces:**
- Consumes: `canonical.get_signable_payload`, `canonical.payload_hash`, `crypto.sign_data`, `models.*`, `passport.AgentPassport`
- Produces: `VALUE_MOVING_ACTIONS`, `select_tier(...)`, `create_envelope(...)`, `sign_envelope(...)`, `envelope_hash(...)`

**Tier selection rule** (spec §9 — risk-relative, unlike the blueprint's flat `amount > 100`):

```
action not value-moving (READ)                        → TIER_0
cross_org or first_contact                            → TIER_2
per_transaction > 0 and amount / per_transaction > .5 → TIER_2
otherwise                                             → TIER_1
```

Value-moving actions floor at Tier 1 because asset truth runs at Tier 1+.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_envelope.py
from __future__ import annotations

import re
from datetime import datetime, timezone

import pytest

from custos_protocol.crypto import verify_signature
from custos_protocol.envelope import (
    create_envelope,
    envelope_hash,
    select_tier,
    sign_envelope,
)
from custos_protocol.canonical import get_signable_payload
from custos_protocol.models import Action, Boundaries, MonetaryLimit, VerificationTier
from custos_protocol.passport import AgentPassport


def passport(**kw) -> AgentPassport:
    return AgentPassport.create(domain="acme.com", agent_name="bot", **kw)


def limits(per_txn: float) -> Boundaries:
    return Boundaries(monetary_limit=MonetaryLimit(per_transaction=per_txn))


def test_read_action_selects_tier_0():
    assert select_tier(Action.READ, {}, limits(0)) is VerificationTier.TIER_0


@pytest.mark.parametrize("action", [Action.BORROW_AGAINST, Action.TRADE, Action.REDEEM])
def test_value_moving_actions_never_select_tier_0(action):
    """Asset truth runs at Tier 1+, so a value-moving action must never skip it."""
    assert select_tier(action, {"amount": 1}, limits(1_000_000)) is VerificationTier.TIER_1


def test_amount_over_half_the_limit_escalates_to_tier_2():
    assert select_tier(Action.TRADE, {"amount": 501}, limits(1000)) is VerificationTier.TIER_2
    assert select_tier(Action.TRADE, {"amount": 500}, limits(1000)) is VerificationTier.TIER_1


def test_tier_selection_is_relative_not_absolute():
    """The blueprint's flat `amount > 100` inverts risk ordering; this rule does not."""
    rich = select_tier(Action.TRADE, {"amount": 101}, limits(1_000_000))
    poor = select_tier(Action.TRADE, {"amount": 99}, limits(50))
    assert rich is VerificationTier.TIER_1
    assert poor is VerificationTier.TIER_2


def test_cross_org_and_first_contact_force_tier_2():
    assert select_tier(Action.TRADE, {"amount": 1}, limits(10**9), cross_org=True) is VerificationTier.TIER_2
    assert select_tier(Action.TRADE, {"amount": 1}, limits(10**9), first_contact=True) is VerificationTier.TIER_2


def test_create_envelope_populates_identity_and_cage_from_the_passport():
    holder = passport(allowed_actions=["trade"], monetary_limit_per_txn=1000.0)
    envelope = create_envelope(holder, Action.TRADE, "TKN-UST-3M-001", {"amount": 100})
    assert envelope.agent.id == holder.agent.id
    assert envelope.principal.id == holder.principal.id
    assert envelope.boundaries.allowed_actions == ["trade"]
    assert envelope.intent.target == "TKN-UST-3M-001"
    assert envelope.intent.parameters == {"amount": 100}


def test_create_envelope_generates_a_well_formed_nonce():
    envelope = create_envelope(passport(), Action.TRADE, "asset", {"amount": 1})
    assert re.fullmatch(r"nonce:[0-9a-f]{32}", envelope.entropy)


def test_nonces_are_unique_per_envelope():
    holder = passport()
    first = create_envelope(holder, Action.TRADE, "asset", {"amount": 1})
    second = create_envelope(holder, Action.TRADE, "asset", {"amount": 1})
    assert first.entropy != second.entropy


def test_expires_at_is_issued_at_plus_ttl_truncated_to_whole_seconds():
    envelope = create_envelope(passport(), Action.TRADE, "asset", {"amount": 1}, ttl=120)
    assert (envelope.expires_at - envelope.issued_at).total_seconds() == 120
    assert envelope.issued_at.microsecond == 0


def test_sign_envelope_does_not_mutate_its_input():
    holder = passport()
    envelope = create_envelope(holder, Action.TRADE, "asset", {"amount": 1})
    signed = sign_envelope(envelope, holder.private_key)
    assert envelope.proof is None
    assert signed.proof is not None


def test_signature_verifies_against_the_canonical_payload():
    holder = passport()
    signed = sign_envelope(create_envelope(holder, Action.TRADE, "asset", {"amount": 1}),
                           holder.private_key)
    payload = get_signable_payload(signed, exclude={"proof"})
    assert verify_signature(holder.public_key, payload, signed.proof.proof_value) is True


def test_tampering_after_signing_breaks_verification():
    holder = passport()
    signed = sign_envelope(create_envelope(holder, Action.TRADE, "asset", {"amount": 1}),
                           holder.private_key)
    tampered = signed.model_copy(update={"intent": signed.intent.model_copy(
        update={"parameters": {"amount": 999999}})})
    payload = get_signable_payload(tampered, exclude={"proof"})
    assert verify_signature(holder.public_key, payload, signed.proof.proof_value) is False


def test_verification_method_defaults_to_principal_keys_1():
    holder = passport()
    signed = sign_envelope(create_envelope(holder, Action.TRADE, "asset", {"amount": 1}),
                           holder.private_key)
    assert signed.proof.verification_method == f"{holder.principal.id}#keys-1"


def test_envelope_hash_is_deterministic_and_ignores_the_proof():
    holder = passport()
    envelope = create_envelope(holder, Action.TRADE, "asset", {"amount": 1})
    signed = sign_envelope(envelope, holder.private_key)
    assert envelope_hash(envelope) == envelope_hash(signed)
    assert len(envelope_hash(envelope)) == 64
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_envelope.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'custos_protocol.envelope'`

- [ ] **Step 3: Write minimal implementation**

```python
# custos_protocol/envelope.py
"""Envelope construction, signing, hashing, and risk-relative tier selection."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from custos_protocol.canonical import get_signable_payload, payload_hash
from custos_protocol.crypto import sign_data
from custos_protocol.models import (
    Action,
    Boundaries,
    CustosEnvelope,
    Intent,
    Proof,
    VerificationTier,
)
from custos_protocol.passport import AgentPassport

VALUE_MOVING_ACTIONS = frozenset({Action.BORROW_AGAINST, Action.TRADE, Action.REDEEM})

_ESCALATION_RATIO = 0.50


def _numeric(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def select_tier(
    action: Action,
    parameters: dict[str, Any],
    boundaries: Boundaries,
    *,
    cross_org: bool = False,
    first_contact: bool = False,
) -> VerificationTier:
    """Risk-relative escalation.

    The blueprint uses a flat, currency-blind ``amount > 100``, which gives an agent
    with a $1,000,000 limit moving $101 full Tier 2 treatment while an agent with a
    $50 limit moving $99 gets the fast path — the opposite of the intended ordering.
    Custos escalates on the amount as a fraction of the agent's own limit.
    """
    if action not in VALUE_MOVING_ACTIONS:
        return VerificationTier.TIER_0
    if cross_org or first_contact:
        return VerificationTier.TIER_2

    per_transaction = boundaries.monetary_limit.per_transaction
    amount = _numeric(parameters.get("amount"))
    if per_transaction > 0 and amount is not None and amount / per_transaction > _ESCALATION_RATIO:
        return VerificationTier.TIER_2
    return VerificationTier.TIER_1


def create_envelope(
    passport: AgentPassport,
    action: Action,
    target: str,
    parameters: dict[str, Any] | None = None,
    *,
    tier: VerificationTier | None = None,
    ttl: int = 300,
    now: datetime | None = None,
) -> CustosEnvelope:
    parameters = dict(parameters or {})
    # Whole seconds keep the canonical payload free of fractional-second divergence.
    issued_at = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    selected = tier or select_tier(action, parameters, passport.boundaries)

    return CustosEnvelope(
        agent=passport.agent,
        principal=passport.principal,
        intent=Intent(action=action, target=target, parameters=parameters),
        boundaries=passport.boundaries,
        verification_tier=selected,
        entropy=f"nonce:{secrets.token_hex(16)}",
        ttl=ttl,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=ttl),
    )


def sign_envelope(
    envelope: CustosEnvelope,
    private_key: Ed25519PrivateKey,
    verification_method: str = "",
) -> CustosEnvelope:
    """Returns a signed copy. The input envelope is never mutated."""
    payload = get_signable_payload(envelope, exclude={"proof"})
    proof = Proof(
        created=datetime.now(timezone.utc).replace(microsecond=0),
        verification_method=verification_method or f"{envelope.principal.id}#keys-1",
        proof_value=sign_data(private_key, payload),
    )
    return envelope.model_copy(update={"proof": proof})


def envelope_hash(envelope: CustosEnvelope) -> str:
    """SHA-256 of the canonical payload. Stable before and after signing."""
    return payload_hash(get_signable_payload(envelope, exclude={"proof"}))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_envelope.py -v`
Expected: 16 passed (3 parametrized + 13 others)

- [ ] **Step 5: Commit**

```bash
git add custos_protocol/envelope.py tests/test_envelope.py
git commit -m "feat: add envelope construction, signing, and risk-relative tier selection"
```

---

## Task 8: Boundary enforcement

Phase 1 implements predicates 1, 2, 3, 5, 6, 7. Predicate 4 (`E203` per-day) needs the rolling-window ledger and lands in Phase 2.

**Files:**
- Create: `custos_protocol/boundaries.py`
- Modify: `custos_protocol/models.py` (add the `Intent` amount validator)
- Test: `tests/test_boundaries.py`, `tests/test_models.py` (one added test)

**Interfaces:**
- Consumes: `errors.CustosErrorCode`, `models.CustosEnvelope`, `models.Claim`
- Produces: `check_boundaries(envelope, claim=None, *, request_geo=None, now=None) -> list[CustosErrorCode]` — empty list means pass; violations accumulate rather than short-circuit

- [ ] **Step 1: Add the amount validator to `Intent` in `custos_protocol/models.py`**

`parameters` is a free-form dict, so a negative amount would otherwise reach the monetary comparison and pass every `amount > limit` test. The blueprint documents exactly this hole. Reject it at the schema layer instead.

Add to `models.py`, replacing the existing `Intent` class:

```python
class Intent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Action
    target: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)

    @field_validator("parameters")
    @classmethod
    def _amount_is_non_negative(cls, value: dict[str, Any]) -> dict[str, Any]:
        """A negative amount passes every `amount > limit` comparison. Reject it here."""
        amount = value.get("amount")
        if amount is None:
            return value
        if isinstance(amount, bool) or not isinstance(amount, (int, float)):
            raise ValueError("parameters['amount'] must be a number")
        if amount < 0:
            raise ValueError("parameters['amount'] must not be negative")
        return value
```

Add to `tests/test_models.py`:

```python
def test_intent_rejects_negative_and_non_numeric_amounts():
    """A negative amount would silently pass every monetary boundary comparison."""
    for bad in (-1, -0.01, "500", True, None if False else object()):
        with pytest.raises(ValidationError):
            Intent(action=Action.TRADE, target="a", parameters={"amount": bad})
    assert Intent(action=Action.TRADE, target="a", parameters={"amount": 0}).parameters["amount"] == 0
```

Add `Intent` to the imports at the top of `tests/test_models.py`.

- [ ] **Step 2: Write the failing boundaries test**

```python
# tests/test_boundaries.py
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal

from custos_protocol.boundaries import check_boundaries
from custos_protocol.envelope import create_envelope
from custos_protocol.errors import CustosErrorCode
from custos_protocol.models import Action, Claim, TimeWindow
from custos_protocol.passport import AgentPassport


def now() -> datetime:
    return datetime.now(timezone.utc)


def claim(asset_class: str = "treasury") -> Claim:
    return Claim(
        asset_id="TKN-UST-3M-001", issuer="Meridian", underlying_tenor="3M",
        asset_class=asset_class, claimed_nav_per_token=Decimal("1"),
        claimed_backing_usd=Decimal("100"), tokens_outstanding=Decimal("100"),
        claimed_yield_bps=400, last_attested_at=now(), chain="ethereum",
        contract_address="0x1",
    )


def envelope(action=Action.TRADE, amount=100, **passport_kw):
    holder = AgentPassport.create(domain="acme.com", agent_name="bot", **passport_kw)
    return create_envelope(holder, action, "TKN-UST-3M-001", {"amount": amount})


def test_clean_envelope_has_no_violations():
    assert check_boundaries(envelope(allowed_actions=["trade"]), claim()) == []


def test_denied_action_is_rejected():
    result = check_boundaries(envelope(denied_actions=["trade"]), claim())
    assert CustosErrorCode.ACTION_DENIED in result


def test_deny_wins_over_allow():
    """Both lists contain the action; deny must take precedence."""
    result = check_boundaries(
        envelope(allowed_actions=["trade"], denied_actions=["trade"]), claim()
    )
    assert CustosErrorCode.ACTION_DENIED in result
    assert CustosErrorCode.ACTION_NOT_ALLOWED not in result


def test_action_outside_a_non_empty_allowlist_is_rejected():
    result = check_boundaries(envelope(allowed_actions=["redeem"]), claim())
    assert CustosErrorCode.ACTION_NOT_ALLOWED in result


def test_empty_allowlist_permits_everything():
    """Preserved from the blueprint and documented as a footgun, not changed."""
    assert check_boundaries(envelope(), claim()) == []


def test_amount_over_per_transaction_limit_is_rejected():
    result = check_boundaries(envelope(amount=1001, monetary_limit_per_txn=1000.0), claim())
    assert CustosErrorCode.MONETARY_LIMIT_PER_TXN in result


def test_amount_exactly_at_the_limit_passes():
    assert check_boundaries(envelope(amount=1000, monetary_limit_per_txn=1000.0), claim()) == []


def test_zero_per_transaction_limit_means_no_limit():
    """Matches the blueprint's semantics; the passport constructor warns about it."""
    assert check_boundaries(envelope(amount=10**9, monetary_limit_per_txn=0.0), claim()) == []


def test_time_window_violation():
    holder = AgentPassport.create(domain="acme.com", agent_name="bot")
    holder.boundaries.time_window = TimeWindow(
        start=now() - timedelta(hours=2), end=now() - timedelta(hours=1)
    )
    result = check_boundaries(create_envelope(holder, Action.TRADE, "a", {"amount": 1}), claim())
    assert CustosErrorCode.TIME_WINDOW_VIOLATION in result


def test_geo_restriction_is_inert_without_a_request_geo():
    """Custos cannot determine geography; the caller supplies it or the boundary sleeps."""
    env = envelope(geo_restriction="US,CA")
    assert check_boundaries(env, claim()) == []
    assert check_boundaries(env, claim(), request_geo="US") == []
    assert CustosErrorCode.GEO_RESTRICTION in check_boundaries(env, claim(), request_geo="RU")


def test_geo_restriction_accepts_a_comma_separated_list_case_insensitively():
    env = envelope(geo_restriction="us, ca , gb")
    assert check_boundaries(env, claim(), request_geo="GB") == []


def test_asset_class_outside_the_permitted_set_is_rejected():
    env = envelope(asset_classes=["treasury"])
    assert check_boundaries(env, claim(asset_class="corporate_credit")) != []
    assert CustosErrorCode.ASSET_CLASS_NOT_ALLOWED in check_boundaries(
        env, claim(asset_class="corporate_credit")
    )


def test_asset_class_check_is_skipped_without_a_claim():
    assert check_boundaries(envelope(asset_classes=["treasury"]), None) == []


def test_violations_accumulate_rather_than_short_circuit():
    """One envelope can legitimately fail several boundaries at once."""
    env = envelope(amount=5000, denied_actions=["trade"],
                   monetary_limit_per_txn=1000.0, geo_restriction="US")
    result = check_boundaries(env, claim(asset_class="corporate_credit"), request_geo="RU")
    assert CustosErrorCode.ACTION_DENIED in result
    assert CustosErrorCode.MONETARY_LIMIT_PER_TXN in result
    assert CustosErrorCode.GEO_RESTRICTION in result
    assert len(result) >= 3
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_boundaries.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'custos_protocol.boundaries'`

- [ ] **Step 4: Write minimal implementation**

```python
# custos_protocol/boundaries.py
"""Boundary predicates — what actually stops the money.

Violations accumulate rather than short-circuiting, so one envelope can report
every boundary it broke in a single response.

Phase 1 implements predicates 1, 2, 3, 5, 6 and 7. Predicate 4
(CUSTOS-E203, rolling per-day limit) requires the ledger introduced in Phase 2.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from custos_protocol.errors import CustosErrorCode
from custos_protocol.models import Claim, CustosEnvelope


def _numeric(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def check_boundaries(
    envelope: CustosEnvelope,
    claim: Claim | None = None,
    *,
    request_geo: str | None = None,
    now: datetime | None = None,
) -> list[CustosErrorCode]:
    now = now or datetime.now(timezone.utc)
    boundaries = envelope.boundaries
    action = envelope.intent.action.value
    violations: list[CustosErrorCode] = []

    # 1. Deny list wins over the allow list.
    if action in boundaries.denied_actions:
        violations.append(CustosErrorCode.ACTION_DENIED)
    # 2. Allow list is only enforced once it is non-empty.
    elif boundaries.allowed_actions and action not in boundaries.allowed_actions:
        violations.append(CustosErrorCode.ACTION_NOT_ALLOWED)

    # 3. Per-transaction monetary limit. A limit of 0 means "no limit".
    amount = _numeric(envelope.intent.parameters.get("amount"))
    per_transaction = boundaries.monetary_limit.per_transaction
    if amount is not None and per_transaction > 0 and amount > per_transaction:
        violations.append(CustosErrorCode.MONETARY_LIMIT_PER_TXN)

    # 5. Time window.
    window = boundaries.time_window
    if window is not None and not (window.start <= now <= window.end):
        violations.append(CustosErrorCode.TIME_WINDOW_VIOLATION)

    # 6. Geography — inert unless the verifier supplies the caller's location.
    if boundaries.geo_restriction and request_geo:
        permitted = {part.strip().upper() for part in boundaries.geo_restriction.split(",")}
        if request_geo.strip().upper() not in permitted:
            violations.append(CustosErrorCode.GEO_RESTRICTION)

    # 7. Asset class — skipped when no claim was resolved.
    if boundaries.asset_classes and claim is not None:
        if claim.asset_class not in boundaries.asset_classes:
            violations.append(CustosErrorCode.ASSET_CLASS_NOT_ALLOWED)

    return violations
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_boundaries.py tests/test_models.py -v`
Expected: 14 boundary tests + 14 model tests passed

- [ ] **Step 6: Commit**

```bash
git add custos_protocol/boundaries.py custos_protocol/models.py tests/test_boundaries.py tests/test_models.py
git commit -m "feat: add boundary enforcement with accumulating violations"
```

---

## Task 9: Asset truth engine

The layer that carries Custos's actual value. Pure function, no I/O, no environment reads.

**Files:**
- Create: `custos_protocol/drift.py`
- Test: `tests/test_drift.py`

**Interfaces:**
- Consumes: `errors.CustosErrorCode`, `models.AssetScores`, `models.Claim`, `models.Observation`
- Produces: `DriftConfig`, `AssetTruthFailure`, `check_asset_truth(claim, observation, config, *, now=None) -> AssetScores | AssetTruthFailure`

**Ordered guards** (short-circuiting; the returned code names the most fundamental problem):

| # | Guard | Code |
|---|---|---|
| 1 | `claim is None` | `E303` UNKNOWN_ASSET |
| 2 | `observation is None` | `E500` ORACLE_UNAVAILABLE |
| 3 | observation older than `max_observation_age_days` | `E501` ORACLE_DATA_STALE |
| 4 | `last_attested_at` beyond skew grace in the future | `E305` CLAIM_FUTURE_DATED |
| 5 | staleness > threshold | `E300` CLAIM_STALE |
| 6 | `observed_yield_bps < 0` | `E501` ORACLE_DATA_STALE |
| 7 | drift > threshold | `E301` YIELD_DRIFT_EXCEEDED |
| 8 | backing ratio < floor | `E302` BACKING_RATIO_BELOW_FLOOR |

- [ ] **Step 1: Write the failing test**

```python
# tests/test_drift.py
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from custos_protocol.drift import AssetTruthFailure, DriftConfig, check_asset_truth
from custos_protocol.errors import CustosErrorCode
from custos_protocol.models import AssetScores, Claim, Observation

CONFIG = DriftConfig()


def now() -> datetime:
    return datetime.now(timezone.utc)


def claim(**overrides) -> Claim:
    values = {
        "asset_id": "TKN-UST-3M-001", "issuer": "Meridian", "underlying_tenor": "3M",
        "asset_class": "treasury", "claimed_nav_per_token": Decimal("1"),
        "claimed_backing_usd": Decimal("100"), "tokens_outstanding": Decimal("100"),
        "claimed_yield_bps": 400, "last_attested_at": now() - timedelta(hours=1),
        "chain": "ethereum", "contract_address": "0x1",
    }
    values.update(overrides)
    return Claim(**values)


def observation(**overrides) -> Observation:
    values = {"source": "test", "tenor": "3M", "observed_yield_bps": 400,
              "record_date": now().date(), "fetched_at": now()}
    values.update(overrides)
    return Observation(**values)


def code(result) -> CustosErrorCode | None:
    return result.code if isinstance(result, AssetTruthFailure) else None


def test_healthy_claim_returns_scores():
    result = check_asset_truth(claim(), observation(), CONFIG)
    assert isinstance(result, AssetScores)
    assert result.yield_drift == 0
    assert result.backing_ratio == 1.0
    assert result.yield_drift_basis == "relative"


def test_scores_pair_every_metric_with_its_threshold():
    result = check_asset_truth(claim(), observation(), CONFIG)
    assert result.staleness_threshold_hours == CONFIG.staleness_threshold_hours
    assert result.yield_drift_threshold == CONFIG.drift_threshold
    assert result.backing_ratio_floor == CONFIG.backing_floor


def test_missing_claim_is_unknown_asset():
    assert code(check_asset_truth(None, observation(), CONFIG)) is CustosErrorCode.UNKNOWN_ASSET


def test_missing_observation_fails_closed():
    assert code(check_asset_truth(claim(), None, CONFIG)) is CustosErrorCode.ORACLE_UNAVAILABLE


def test_observation_older_than_tolerance_is_rejected():
    old = observation(record_date=(now() - timedelta(days=9)).date())
    assert code(check_asset_truth(claim(), old, CONFIG)) is CustosErrorCode.ORACLE_DATA_STALE


def test_future_dated_claim_is_rejected():
    """The old implementation clamped negative staleness to zero, so this passed."""
    future = claim(last_attested_at=now() + timedelta(days=1825))
    assert code(check_asset_truth(future, observation(), CONFIG)) is CustosErrorCode.CLAIM_FUTURE_DATED


def test_slightly_future_dated_claim_is_tolerated_within_skew_grace():
    fresh = claim(last_attested_at=now() + timedelta(seconds=2))
    assert isinstance(check_asset_truth(fresh, observation(), CONFIG), AssetScores)


def test_stale_claim_is_rejected():
    stale = claim(last_attested_at=now() - timedelta(hours=25))
    assert code(check_asset_truth(stale, observation(), CONFIG)) is CustosErrorCode.CLAIM_STALE


def test_staleness_short_circuits_before_drift():
    """The returned code must name the most fundamental problem, not an arbitrary one."""
    both_wrong = claim(last_attested_at=now() - timedelta(hours=25), claimed_yield_bps=1)
    assert code(check_asset_truth(both_wrong, observation(), CONFIG)) is CustosErrorCode.CLAIM_STALE


def test_negative_observed_yield_is_an_oracle_fault():
    bad = observation(observed_yield_bps=-5)
    assert code(check_asset_truth(claim(), bad, CONFIG)) is CustosErrorCode.ORACLE_DATA_STALE


def test_zero_observed_yield_is_legal_and_uses_absolute_basis():
    """Treasury bills printed 0.00% through 2020-2021; that is data, not a fault."""
    zero = observation(observed_yield_bps=0)
    passing = check_asset_truth(claim(claimed_yield_bps=5), zero, CONFIG)
    assert isinstance(passing, AssetScores)
    assert passing.yield_drift_basis == "absolute"
    assert passing.yield_drift == 5

    failing = check_asset_truth(claim(claimed_yield_bps=50), zero, CONFIG)
    assert code(failing) is CustosErrorCode.YIELD_DRIFT_EXCEEDED


def test_drift_boundary_is_inclusive_at_exactly_the_threshold():
    assert isinstance(check_asset_truth(claim(claimed_yield_bps=392), observation(), CONFIG), AssetScores)
    assert code(check_asset_truth(claim(claimed_yield_bps=391), observation(), CONFIG)) is CustosErrorCode.YIELD_DRIFT_EXCEEDED


def test_drift_is_normalised_by_the_observed_yield():
    result = check_asset_truth(claim(claimed_yield_bps=200), observation(observed_yield_bps=400), CONFIG)
    assert isinstance(result, AssetTruthFailure)
    assert result.scores.yield_drift == pytest.approx(0.5)


def test_under_backed_claim_is_rejected():
    thin = claim(claimed_backing_usd=Decimal("94"))
    assert code(check_asset_truth(thin, observation(), CONFIG)) is CustosErrorCode.BACKING_RATIO_BELOW_FLOOR


def test_backing_floor_is_inclusive():
    assert isinstance(check_asset_truth(claim(claimed_backing_usd=Decimal("100")), observation(), CONFIG), AssetScores)


def test_failure_carries_the_scores_computed_so_far_and_the_market_reference():
    result = check_asset_truth(claim(claimed_yield_bps=360), observation(), CONFIG)
    assert isinstance(result, AssetTruthFailure)
    assert result.scores.staleness_hours is not None
    assert result.scores.yield_drift is not None
    assert result.scores.backing_ratio is None       # never reached
    assert result.reference["observed_yield_bps"] == 400
    assert result.reference["claimed_yield_bps"] == 360
    assert "360" in result.detail and "400" in result.detail


def test_thresholds_come_from_the_config_object_not_the_environment():
    lenient = DriftConfig(drift_threshold=0.50)
    assert isinstance(check_asset_truth(claim(claimed_yield_bps=300), observation(), lenient), AssetScores)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_drift.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'custos_protocol.drift'`

- [ ] **Step 3: Write minimal implementation**

```python
# custos_protocol/drift.py
"""Asset truth: is this claim plausible against the live market for its tenor?

A pure function of (claim, observation, config). No I/O, no environment reads —
thresholds arrive as a value object so the layer is testable in isolation.

This is a plausibility check against market rates, not an audit of a fund's
private NAV or holdings.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from custos_protocol.errors import CustosErrorCode
from custos_protocol.models import AssetScores, Claim, Observation


@dataclass(frozen=True)
class DriftConfig:
    staleness_threshold_hours: float = 24.0
    drift_threshold: float = 0.02
    backing_floor: float = 1.0
    max_observation_age_days: int = 4
    zero_yield_abs_tolerance_bps: int = 10
    clock_skew_seconds: int = 5


@dataclass(frozen=True)
class AssetTruthFailure:
    code: CustosErrorCode
    detail: str
    scores: AssetScores | None = None
    reference: dict[str, Any] | None = None


def _reference(claim: Claim, observation: Observation) -> dict[str, Any]:
    return {
        "source": observation.source,
        "tenor": observation.tenor,
        "claimed_yield_bps": claim.claimed_yield_bps,
        "observed_yield_bps": observation.observed_yield_bps,
        "record_date": observation.record_date.isoformat(),
    }


def check_asset_truth(
    claim: Claim | None,
    observation: Observation | None,
    config: DriftConfig,
    *,
    now: datetime | None = None,
) -> AssetScores | AssetTruthFailure:
    now = now or datetime.now(timezone.utc)

    # 1. Unknown asset — nothing to evaluate.
    if claim is None:
        return AssetTruthFailure(
            CustosErrorCode.UNKNOWN_ASSET,
            "The requested asset is not present in the claim registry.",
        )

    # 2. No market data — fail closed. This is the load-bearing guarantee.
    if observation is None:
        return AssetTruthFailure(
            CustosErrorCode.ORACLE_UNAVAILABLE,
            "The market oracle could not be reached; Custos fails closed.",
        )

    reference = _reference(claim, observation)

    # 3. The observation itself is too old to be evidence.
    age_days = (now.date() - observation.record_date).days
    if age_days > config.max_observation_age_days:
        return AssetTruthFailure(
            CustosErrorCode.ORACLE_DATA_STALE,
            f"Market observation is {age_days} days old; maximum is {config.max_observation_age_days}.",
            reference=reference,
        )

    # 4. A future-dated claim must not defeat the staleness check.
    grace = timedelta(seconds=config.clock_skew_seconds)
    if claim.last_attested_at > now + grace:
        return AssetTruthFailure(
            CustosErrorCode.CLAIM_FUTURE_DATED,
            f"Claim is attested {(claim.last_attested_at - now).total_seconds():.0f}s in the future.",
            reference=reference,
        )

    # 5. Staleness.
    staleness_hours = max(0.0, (now - claim.last_attested_at).total_seconds() / 3600)
    scores = AssetScores(
        staleness_hours=round(staleness_hours, 2),
        staleness_threshold_hours=config.staleness_threshold_hours,
    )
    if staleness_hours > config.staleness_threshold_hours:
        return AssetTruthFailure(
            CustosErrorCode.CLAIM_STALE,
            f"Claim was last attested {staleness_hours:.2f} hours ago; "
            f"threshold is {config.staleness_threshold_hours:.1f} hours.",
            scores=scores,
            reference=reference,
        )

    # 6. A negative yield is impossible data. Zero is legal.
    observed = observation.observed_yield_bps
    if observed < 0:
        return AssetTruthFailure(
            CustosErrorCode.ORACLE_DATA_STALE,
            f"Market oracle returned a negative yield of {observed} bps.",
            scores=scores,
            reference=reference,
        )

    # 7. Yield drift. Relative drift is undefined at a zero observation, so fall
    #    back to an absolute basis-point comparison.
    if observed == 0:
        drift_value = float(abs(claim.claimed_yield_bps - observed))
        threshold: float = float(config.zero_yield_abs_tolerance_bps)
        basis = "absolute"
        exceeded = drift_value > threshold
        drift_detail = (
            f"Claimed yield {claim.claimed_yield_bps} bps differs by {drift_value:.0f} bps "
            f"from an observed {observation.tenor} yield of 0 bps; tolerance is {threshold:.0f} bps."
        )
    else:
        drift_value = abs(observed - claim.claimed_yield_bps) / observed
        threshold = config.drift_threshold
        basis = "relative"
        exceeded = drift_value > threshold
        drift_detail = (
            f"Claimed yield {claim.claimed_yield_bps} bps diverges {drift_value:.2%} from observed "
            f"{observation.tenor} yield of {observed} bps; threshold is {threshold:.1%}."
        )

    scores = scores.model_copy(update={
        "yield_drift": round(drift_value, 6),
        "yield_drift_threshold": threshold,
        "yield_drift_basis": basis,
    })
    if exceeded:
        return AssetTruthFailure(
            CustosErrorCode.YIELD_DRIFT_EXCEEDED, drift_detail,
            scores=scores, reference=reference,
        )

    # 8. Backing ratio. Exact Decimal arithmetic; the float cast is for reporting only.
    implied_liability = claim.tokens_outstanding * claim.claimed_nav_per_token
    ratio = float(claim.claimed_backing_usd / implied_liability)
    scores = scores.model_copy(update={
        "backing_ratio": round(ratio, 6),
        "backing_ratio_floor": config.backing_floor,
    })
    if ratio < config.backing_floor:
        return AssetTruthFailure(
            CustosErrorCode.BACKING_RATIO_BELOW_FLOOR,
            f"Backing ratio is {ratio:.4f}; floor is {config.backing_floor:.4f}.",
            scores=scores, reference=reference,
        )

    return scores
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_drift.py -v`
Expected: 17 passed

- [ ] **Step 5: Commit**

```bash
git add custos_protocol/drift.py tests/test_drift.py
git commit -m "feat: add asset-truth engine with future-date and zero-yield handling"
```

---
## Task 10: Signed attestation and denial records

**Files:**
- Create: `custos_protocol/attestation.py`
- Test: `tests/test_attestation.py`

**Interfaces:**
- Consumes: `canonical.canonical_bytes`, `canonical.get_signable_payload`, `crypto.*`, `models.*`
- Produces: `Attestation`, `Denial`, `RecordSigner`, `verify_record(record: dict, public_key) -> bool`

**Divergence from today's gateway:** denials are signed too. A relying party that needs to *prove* it was denied cannot do that when only ALLOW carries a signature. Signing costs ~33 µs.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_attestation.py
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from custos_protocol.attestation import Attestation, Denial, RecordSigner, verify_record
from custos_protocol.crypto import generate_keypair
from custos_protocol.errors import CustosErrorCode
from custos_protocol.models import AssetScores, VerificationTier


def signer() -> RecordSigner:
    return RecordSigner()


def allow_fields() -> dict:
    return {
        "envelope_hash": "a" * 64,
        "agent_id": "did:web:acme.com:agents:bot",
        "asset_id": "TKN-UST-3M-001",
        "action": "borrow_against",
        "amount": 50000,
        "tier_used": VerificationTier.TIER_1,
        "scores": AssetScores(staleness_hours=1.0, backing_ratio=1.0),
        "reference": {"source": "test", "observed_yield_bps": 400},
    }


def test_attestation_is_signed_and_verifies():
    record_signer = signer()
    attestation = record_signer.sign_attestation(**allow_fields())
    assert attestation.verdict == "ALLOW"
    assert attestation.proof is not None
    assert verify_record(attestation.model_dump(mode="json"), record_signer.public_key) is True


def test_denial_is_also_signed():
    """Today only ALLOW is signed, so a denial cannot be proved."""
    record_signer = signer()
    denial = record_signer.sign_denial(
        envelope_hash="b" * 64,
        agent_id="did:web:acme.com:agents:bot",
        asset_id="TKN-UST-3M-003",
        errors=[CustosErrorCode.YIELD_DRIFT_EXCEEDED],
        detail="drift 6.98% > 2.0%",
        scores=AssetScores(yield_drift=0.0698),
    )
    assert denial.verdict == "BLOCK"
    assert verify_record(denial.model_dump(mode="json"), record_signer.public_key) is True


def test_attestation_id_is_prefixed_and_unique():
    record_signer = signer()
    first = record_signer.sign_attestation(**allow_fields())
    second = record_signer.sign_attestation(**allow_fields())
    assert first.attestation_id.startswith("att_")
    assert first.attestation_id != second.attestation_id


def test_expires_at_follows_the_configured_ttl():
    attestation = RecordSigner(ttl_seconds=120).sign_attestation(**allow_fields())
    assert (attestation.expires_at - attestation.issued_at).total_seconds() == 120


def test_tampering_with_any_signed_field_breaks_verification():
    record_signer = signer()
    served = record_signer.sign_attestation(**allow_fields()).model_dump(mode="json")

    for field, replacement in [
        ("amount", 1),
        ("asset_id", "TKN-OTHER"),
        ("agent_id", "did:web:evil.com:agents:bot"),
        ("envelope_hash", "c" * 64),
    ]:
        tampered = dict(served)
        tampered[field] = replacement
        assert verify_record(tampered, record_signer.public_key) is False


def test_tampering_with_nested_scores_breaks_verification():
    record_signer = signer()
    served = record_signer.sign_attestation(**allow_fields()).model_dump(mode="json")
    tampered = dict(served)
    tampered["scores"] = dict(served["scores"])
    tampered["scores"]["backing_ratio"] = 99.0
    assert verify_record(tampered, record_signer.public_key) is False


def test_verify_record_rejects_a_foreign_key():
    """Key substitution must fail against a pinned key. Consumers MUST pin."""
    served = signer().sign_attestation(**allow_fields()).model_dump(mode="json")
    _, foreign_public = generate_keypair()
    assert verify_record(served, foreign_public) is False


def test_record_survives_a_json_round_trip():
    """The independent verifier receives JSON off the wire, not a model."""
    record_signer = signer()
    served = record_signer.sign_attestation(**allow_fields()).model_dump(mode="json")
    reparsed = json.loads(json.dumps(served))
    assert verify_record(reparsed, record_signer.public_key) is True


def test_signer_exposes_both_key_encodings():
    record_signer = signer()
    assert len(record_signer.public_key_b64) > 0
    assert record_signer.public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")


def test_records_declare_their_own_verification_procedure():
    attestation = signer().sign_attestation(**allow_fields())
    assert attestation.signature_alg == "Ed25519"
    assert attestation.canonicalization == "custos/canonical-v1"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_attestation.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'custos_protocol.attestation'`

- [ ] **Step 3: Write minimal implementation**

```python
# custos_protocol/attestation.py
"""Signed verdict records.

Both verdicts are signed. A system that signs only approvals leaves a relying
party unable to prove it was denied.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, Field

from custos_protocol.canonical import canonical_bytes, get_signable_payload
from custos_protocol.crypto import (
    generate_keypair,
    public_key_to_b64,
    sign_data,
    verify_signature,
)
from custos_protocol.errors import CustosErrorCode
from custos_protocol.models import AssetScores, Proof, VerificationTier

CANONICALIZATION = "custos/canonical-v1"
_SIGNATURE_EXCLUDE = {"proof"}


class _SignedRecord(BaseModel):
    envelope_hash: str
    agent_id: str
    asset_id: str | None = None
    issued_at: datetime
    signature_alg: str = "Ed25519"
    canonicalization: str = CANONICALIZATION
    public_key: str
    proof: Proof | None = None


class Attestation(_SignedRecord):
    attestation_id: str
    verdict: Literal["ALLOW"] = "ALLOW"
    action: str
    amount: float | None = None
    tier_used: VerificationTier
    scores: AssetScores | None = None
    reference: dict[str, Any] | None = None
    expires_at: datetime


class Denial(_SignedRecord):
    denial_id: str
    verdict: Literal["BLOCK"] = "BLOCK"
    errors: list[CustosErrorCode] = Field(default_factory=list)
    detail: str = ""
    scores: AssetScores | None = None
    reference: dict[str, Any] | None = None


class RecordSigner:
    def __init__(self, private_key: Ed25519PrivateKey | None = None, *, ttl_seconds: int = 300) -> None:
        if private_key is None:
            private_key, _ = generate_keypair()
        self._private_key = private_key
        self._ttl_seconds = ttl_seconds

    @property
    def public_key_b64(self) -> str:
        return public_key_to_b64(self._private_key.public_key())

    @property
    def public_key_pem(self) -> str:
        from cryptography.hazmat.primitives import serialization

        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    def _attach_proof(self, record: _SignedRecord) -> Any:
        payload = get_signable_payload(record, exclude=_SIGNATURE_EXCLUDE)
        proof = Proof(
            created=record.issued_at,
            verification_method="custos-gateway#keys-1",
            proof_value=sign_data(self._private_key, payload),
        )
        return record.model_copy(update={"proof": proof})

    def sign_attestation(
        self,
        *,
        envelope_hash: str,
        agent_id: str,
        asset_id: str | None,
        action: str,
        amount: float | None,
        tier_used: VerificationTier,
        scores: AssetScores | None = None,
        reference: dict[str, Any] | None = None,
    ) -> Attestation:
        issued_at = datetime.now(timezone.utc).replace(microsecond=0)
        record = Attestation(
            attestation_id=f"att_{uuid.uuid4().hex}",
            envelope_hash=envelope_hash,
            agent_id=agent_id,
            asset_id=asset_id,
            action=action,
            amount=amount,
            tier_used=tier_used,
            scores=scores,
            reference=reference,
            issued_at=issued_at,
            expires_at=issued_at + timedelta(seconds=self._ttl_seconds),
            public_key=self.public_key_b64,
        )
        return self._attach_proof(record)

    def sign_denial(
        self,
        *,
        envelope_hash: str,
        agent_id: str,
        asset_id: str | None = None,
        errors: list[CustosErrorCode],
        detail: str = "",
        scores: AssetScores | None = None,
        reference: dict[str, Any] | None = None,
    ) -> Denial:
        record = Denial(
            denial_id=f"den_{uuid.uuid4().hex}",
            envelope_hash=envelope_hash,
            agent_id=agent_id,
            asset_id=asset_id,
            errors=errors,
            detail=detail,
            scores=scores,
            reference=reference,
            issued_at=datetime.now(timezone.utc).replace(microsecond=0),
            public_key=self.public_key_b64,
        )
        return self._attach_proof(record)


def verify_record(record: dict[str, Any], public_key: Ed25519PublicKey) -> bool:
    """Verify a served record against a **pinned** key.

    The caller must supply the key out-of-band (GET /v1/pubkey). Trusting the
    ``public_key`` embedded in the record authenticates nothing — an attacker can
    re-sign arbitrary content with their own key and update that field to match.
    """
    proof = record.get("proof")
    if not isinstance(proof, dict) or "proof_value" not in proof:
        return False
    payload = canonical_bytes(record, exclude=_SIGNATURE_EXCLUDE)
    return verify_signature(public_key, payload, proof["proof_value"])
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_attestation.py -v`
Expected: 10 passed

- [ ] **Step 5: Commit**

```bash
git add custos_protocol/attestation.py tests/test_attestation.py
git commit -m "feat: add signed attestation and denial records"
```

---

## Task 11: Revocation store and replay cache

**Files:**
- Create: `custos_protocol/revocation.py`
- Test: `tests/test_revocation.py`

**Interfaces:**
- Consumes: `models.RevocationCheck`, `models.RevocationStatus`
- Produces: `SubjectType`, `RevocationRecord`, `RevocationStore`

**Two divergences from the blueprint, both deliberate:**

1. **FIFO nonce eviction with time-based expiry.** The blueprint uses a `set` and evicts arbitrary elements, so a recent nonce can be discarded while an ancient one survives — a probabilistic replay hole past the cap.
2. **`local_only` freshness.** The blueprint's store is `stale` ~500 ms after construction because `_last_sync` only advances on mutation, which makes its deep revocation check fail *open* permanently. Custos fails *closed* on stale data — but a purely local store has no upstream to sync with and is therefore never stale. Failing closed on a local store would be a self-inflicted denial of service. `local_only=True` is the default; a future distributed mesh sets it `False`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_revocation.py
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from custos_protocol.models import RevocationStatus
from custos_protocol.revocation import RevocationStore, SubjectType


def store() -> RevocationStore:
    return RevocationStore()


def test_revoked_agent_is_reported():
    subject = RevocationStore()
    subject.revoke("did:web:acme.com:agents:bot", SubjectType.AGENT, reason="compromised")
    assert subject.is_revoked("did:web:acme.com:agents:bot") is True
    assert subject.is_suspended("did:web:acme.com:agents:bot") is False


def test_issuer_revocation_is_a_first_class_subject():
    subject = store()
    subject.revoke("Meridian", SubjectType.ISSUER, reason="fraud")
    record = subject.get_record("Meridian")
    assert subject.is_revoked("Meridian") is True
    assert record.subject_type is SubjectType.ISSUER


def test_unknown_subject_is_not_revoked():
    assert store().is_revoked("did:web:acme.com:agents:nobody") is False


def test_suspension_expires_on_its_own():
    subject = store()
    subject.suspend("agent", SubjectType.AGENT, duration_seconds=-1)
    assert subject.is_revoked("agent") is False
    assert subject.get_record("agent") is None


def test_active_suspension_blocks_and_is_distinguishable():
    subject = store()
    subject.suspend("agent", SubjectType.AGENT, duration_seconds=1800)
    assert subject.is_revoked("agent") is True
    assert subject.is_suspended("agent") is True


def test_reinstate_removes_the_record():
    subject = store()
    subject.revoke("agent", SubjectType.AGENT)
    assert subject.reinstate("agent") is True
    assert subject.is_revoked("agent") is False
    assert subject.reinstate("agent") is False


def test_revocation_count_tracks_active_records():
    subject = store()
    assert subject.revocation_count == 0
    subject.revoke("a", SubjectType.AGENT)
    subject.revoke("b", SubjectType.ISSUER)
    assert subject.revocation_count == 2


def test_nonce_is_accepted_once_then_rejected():
    subject = store()
    assert subject.check_nonce("nonce:" + "a" * 32) is True
    assert subject.check_nonce("nonce:" + "a" * 32) is False


def test_distinct_nonces_are_independent():
    subject = store()
    assert subject.check_nonce("nonce:" + "a" * 32) is True
    assert subject.check_nonce("nonce:" + "b" * 32) is True


def test_nonce_expires_after_its_ttl():
    subject = store()
    assert subject.check_nonce("nonce:x", ttl_seconds=0) is True
    time.sleep(0.01)
    assert subject.check_nonce("nonce:x", ttl_seconds=0) is True


def test_nonce_eviction_is_fifo_not_arbitrary():
    """The blueprint evicts arbitrary set members; the oldest must go first."""
    subject = RevocationStore(max_nonces=10)
    for index in range(10):
        assert subject.check_nonce(f"nonce:{index}") is True
    subject.check_nonce("nonce:overflow")
    assert subject.check_nonce("nonce:0") is True      # oldest was evicted, so it is new again
    assert subject.check_nonce("nonce:9") is False     # newest survived and is still remembered


def test_clear_nonces_empties_the_cache():
    subject = store()
    subject.check_nonce("nonce:a")
    subject.clear_nonces()
    assert subject.check_nonce("nonce:a") is True


def test_a_local_only_store_is_never_stale():
    """Failing closed on a store with no upstream would be a self-inflicted outage."""
    subject = RevocationStore(local_only=True)
    time.sleep(0.02)
    check = subject.freshness(max_staleness_ms=1)
    assert check.stale is False
    assert check.status is RevocationStatus.NOT_REVOKED


def test_a_synced_store_goes_stale_and_reports_it():
    subject = RevocationStore(local_only=False)
    subject.touch_sync()
    time.sleep(0.02)
    assert subject.freshness(max_staleness_ms=1).stale is True
    subject.touch_sync()
    assert subject.freshness(max_staleness_ms=10_000).stale is False


def test_freshness_reports_the_measured_age():
    subject = RevocationStore(local_only=False)
    subject.touch_sync()
    check = subject.freshness(max_staleness_ms=500)
    assert check.freshness_ms >= 0
    assert check.max_staleness_ms == 500
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_revocation.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'custos_protocol.revocation'`

- [ ] **Step 3: Write minimal implementation**

```python
# custos_protocol/revocation.py
"""The kill switch and the replay cache, in one thread-safe object."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum

from custos_protocol.models import RevocationCheck, RevocationStatus

MAX_NONCE_CACHE = 1_000_000
DEFAULT_NONCE_TTL_SECONDS = 86_400


class SubjectType(str, Enum):
    AGENT = "agent"
    ISSUER = "issuer"


@dataclass(frozen=True)
class RevocationRecord:
    subject_id: str
    subject_type: SubjectType
    reason: str
    revoked_at: datetime
    revoked_by: str
    scope: str
    suspended_until: datetime | None   # None means permanent


class RevocationStore:
    def __init__(
        self,
        *,
        local_only: bool = True,
        max_nonces: int = MAX_NONCE_CACHE,
    ) -> None:
        self._records: dict[str, RevocationRecord] = {}
        self._nonces: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()
        self._local_only = local_only
        self._max_nonces = max_nonces
        self._last_sync = datetime.now(timezone.utc)

    # ---- kill switch -------------------------------------------------

    def revoke(self, subject_id: str, subject_type: SubjectType,
               reason: str = "", revoked_by: str = "", scope: str = "global") -> None:
        with self._lock:
            self._records[subject_id] = RevocationRecord(
                subject_id=subject_id, subject_type=subject_type, reason=reason,
                revoked_at=datetime.now(timezone.utc), revoked_by=revoked_by,
                scope=scope, suspended_until=None,
            )
            self._last_sync = datetime.now(timezone.utc)

    def suspend(self, subject_id: str, subject_type: SubjectType,
                duration_seconds: int = 1800, reason: str = "",
                revoked_by: str = "circuit_breaker", scope: str = "global") -> None:
        with self._lock:
            self._records[subject_id] = RevocationRecord(
                subject_id=subject_id, subject_type=subject_type, reason=reason,
                revoked_at=datetime.now(timezone.utc), revoked_by=revoked_by,
                scope=scope,
                suspended_until=datetime.now(timezone.utc) + timedelta(seconds=duration_seconds),
            )
            self._last_sync = datetime.now(timezone.utc)

    def _live_record(self, subject_id: str) -> RevocationRecord | None:
        record = self._records.get(subject_id)
        if record is None:
            return None
        if record.suspended_until is not None and record.suspended_until <= datetime.now(timezone.utc):
            self._records.pop(subject_id, None)   # lazily drop expired suspensions
            return None
        return record

    def is_revoked(self, subject_id: str) -> bool:
        with self._lock:
            return self._live_record(subject_id) is not None

    def is_suspended(self, subject_id: str) -> bool:
        with self._lock:
            record = self._live_record(subject_id)
            return record is not None and record.suspended_until is not None

    def reinstate(self, subject_id: str) -> bool:
        with self._lock:
            existed = self._records.pop(subject_id, None) is not None
            self._last_sync = datetime.now(timezone.utc)
            return existed

    def get_record(self, subject_id: str) -> RevocationRecord | None:
        with self._lock:
            return self._live_record(subject_id)

    @property
    def revocation_count(self) -> int:
        with self._lock:
            return len(self._records)

    # ---- freshness ---------------------------------------------------

    def touch_sync(self) -> None:
        with self._lock:
            self._last_sync = datetime.now(timezone.utc)

    @property
    def last_sync_time(self) -> datetime:
        return self._last_sync

    def freshness(self, max_staleness_ms: int) -> RevocationCheck:
        """A local-only store has no upstream and is never stale.

        The blueprint's store advances ``_last_sync`` only on mutation, so it is
        permanently stale in a long-running verifier — which silently disables its
        deep revocation check. Custos fails closed on stale data, so the same
        behaviour here would be a self-inflicted outage instead.
        """
        age_ms = (datetime.now(timezone.utc) - self._last_sync).total_seconds() * 1000
        stale = (not self._local_only) and age_ms > max_staleness_ms
        return RevocationCheck(
            status=RevocationStatus.NOT_REVOKED,
            freshness_ms=age_ms,
            max_staleness_ms=max_staleness_ms,
            stale=stale,
        )

    # ---- replay cache ------------------------------------------------

    def check_nonce(self, nonce: str, ttl_seconds: int = DEFAULT_NONCE_TTL_SECONDS) -> bool:
        """True if the nonce is new. Consumes it as a side effect."""
        with self._lock:
            cutoff = time.monotonic() - ttl_seconds
            while self._nonces:
                oldest_nonce, stored_at = next(iter(self._nonces.items()))
                if stored_at > cutoff:
                    break
                self._nonces.popitem(last=False)     # age-based eviction first

            if nonce in self._nonces:
                return False

            self._nonces[nonce] = time.monotonic()
            while len(self._nonces) > self._max_nonces:
                self._nonces.popitem(last=False)     # then pressure, oldest first
            return True

    def clear_nonces(self) -> None:
        with self._lock:
            self._nonces.clear()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_revocation.py -v`
Expected: 15 passed

- [ ] **Step 5: Commit**

```bash
git add custos_protocol/revocation.py tests/test_revocation.py
git commit -m "feat: add revocation store with FIFO nonce cache and fail-closed freshness"
```

---

## Task 12: The verification pipeline

The only module that composes everything.

**Files:**
- Create: `custos_protocol/verification.py`
- Test: `tests/test_verification.py`

**Interfaces:**
- Consumes: everything above
- Produces: `verify_intent(...) -> VerificationResult`, `SUPPORTED_VERSIONS`, `NONCE_PATTERN`

**Two ordering divergences from the blueprint, both deliberate:**

1. **Signature (step 4) precedes replay (step 5b).** The blueprint checks replay first, letting an unauthenticated attacker burn a victim's nonce by submitting a garbage envelope carrying it. Verifying the signature first closes that.
2. **Tier 2 is not implemented in Phase 1.** A Tier 2 envelope is verified through step 9 and the result reports `tier_used = TIER_1`, so a relying party can detect that it received less verification than it asked for. Silently reporting `TIER_2` would be a lie.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_verification.py
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from custos_protocol.drift import DriftConfig
from custos_protocol.envelope import create_envelope, sign_envelope
from custos_protocol.errors import CustosErrorCode
from custos_protocol.models import (
    Action,
    CheckOutcome,
    Claim,
    Observation,
    VerificationTier,
)
from custos_protocol.passport import AgentPassport
from custos_protocol.revocation import RevocationStore, SubjectType
from custos_protocol.verification import verify_intent


def now() -> datetime:
    return datetime.now(timezone.utc)


def holder(**kw) -> AgentPassport:
    kw.setdefault("allowed_actions", ["trade", "borrow_against", "read"])
    return AgentPassport.create(domain="acme.com", agent_name="bot", **kw)


def claim(**overrides) -> Claim:
    values = {
        "asset_id": "TKN-UST-3M-001", "issuer": "Meridian", "underlying_tenor": "3M",
        "asset_class": "treasury", "claimed_nav_per_token": Decimal("1"),
        "claimed_backing_usd": Decimal("100"), "tokens_outstanding": Decimal("100"),
        "claimed_yield_bps": 400, "last_attested_at": now() - timedelta(hours=1),
        "chain": "ethereum", "contract_address": "0x1",
    }
    values.update(overrides)
    return Claim(**values)


def observation(**overrides) -> Observation:
    values = {"source": "test", "tenor": "3M", "observed_yield_bps": 400,
              "record_date": now().date(), "fetched_at": now()}
    values.update(overrides)
    return Observation(**values)


def signed(passport=None, action=Action.TRADE, amount=100, **envelope_kw):
    passport = passport or holder()
    envelope = create_envelope(passport, action, "TKN-UST-3M-001", {"amount": amount}, **envelope_kw)
    return sign_envelope(envelope, passport.private_key), passport


def verify(envelope, passport, **kw):
    kw.setdefault("claim", claim())
    kw.setdefault("observation", observation())
    kw.setdefault("drift_config", DriftConfig())
    kw.setdefault("revocation_store", RevocationStore())
    return verify_intent(envelope, passport.public_key, **kw)


def test_healthy_envelope_passes_tier_1():
    envelope, passport = signed()
    result = verify(envelope, passport)
    assert result.passed is True
    assert result.errors == []
    assert result.tier_used is VerificationTier.TIER_1
    assert result.scores is not None


def test_unsupported_version_is_rejected_first():
    envelope, passport = signed()
    result = verify(envelope.model_copy(update={"protocol_version": "9.9.9"}), passport)
    assert result.errors == [CustosErrorCode.VERSION_UNSUPPORTED]


def test_expired_envelope_is_rejected():
    envelope, passport = signed()
    stale = envelope.model_copy(update={"expires_at": now() - timedelta(minutes=1)})
    result = verify(stale, passport)
    assert CustosErrorCode.EXPIRED_ENVELOPE in result.errors


def test_expiry_allows_a_small_clock_skew_grace():
    envelope, passport = signed()
    just_expired = envelope.model_copy(update={"expires_at": now() - timedelta(seconds=2)})
    assert verify(just_expired, passport, clock_skew_seconds=5).passed is True


def test_future_issued_at_is_clock_skew():
    envelope, passport = signed()
    future = envelope.model_copy(update={
        "issued_at": now() + timedelta(minutes=10),
        "expires_at": now() + timedelta(minutes=20),
    })
    assert CustosErrorCode.CLOCK_SKEW in verify(future, passport).errors


def test_bad_signature_is_rejected():
    envelope, passport = signed()
    tampered = envelope.model_copy(update={
        "intent": envelope.intent.model_copy(update={"parameters": {"amount": 999999}})
    })
    assert verify(tampered, passport).errors == [CustosErrorCode.INVALID_SIGNATURE]


def test_unsigned_envelope_is_rejected():
    envelope, passport = signed()
    assert CustosErrorCode.INVALID_SIGNATURE in verify(
        envelope.model_copy(update={"proof": None}), passport
    ).errors


def test_signature_is_checked_before_replay():
    """A forged envelope carrying a victim's nonce must not burn it."""
    envelope, passport = signed()
    store = RevocationStore()
    forged = envelope.model_copy(update={
        "intent": envelope.intent.model_copy(update={"parameters": {"amount": 1}})
    })

    forged_result = verify(forged, passport, revocation_store=store)
    assert forged_result.errors == [CustosErrorCode.INVALID_SIGNATURE]
    assert forged_result.checks["replay"] is CheckOutcome.NOT_RUN

    # The genuine envelope still works — its nonce was never consumed.
    assert verify(envelope, passport, revocation_store=store).passed is True


def test_malformed_nonce_is_rejected():
    envelope, passport = signed()
    bad = envelope.model_copy(update={"entropy": "not-a-nonce"})
    signed_bad = sign_envelope(bad, passport.private_key)
    assert CustosErrorCode.NONCE_INVALID in verify(signed_bad, passport).errors


def test_replayed_envelope_is_rejected():
    envelope, passport = signed()
    store = RevocationStore()
    assert verify(envelope, passport, revocation_store=store).passed is True
    assert verify(envelope, passport, revocation_store=store).errors == [
        CustosErrorCode.REPLAY_DETECTED
    ]


def test_boundary_violations_are_reported_together():
    passport = holder(allowed_actions=["read"], monetary_limit_per_txn=10.0)
    envelope, _ = signed(passport, action=Action.TRADE, amount=5000)
    result = verify(envelope, passport)
    assert CustosErrorCode.ACTION_NOT_ALLOWED in result.errors
    assert CustosErrorCode.MONETARY_LIMIT_PER_TXN in result.errors


def test_revoked_agent_is_blocked_at_every_tier():
    envelope, passport = signed(action=Action.READ)       # Tier 0
    store = RevocationStore()
    store.revoke(passport.agent.id, SubjectType.AGENT, reason="compromised")
    result = verify(envelope, passport, revocation_store=store)
    assert result.tier_used is VerificationTier.TIER_0
    assert CustosErrorCode.AGENT_REVOKED in result.errors


def test_suspended_agent_reports_its_own_code():
    envelope, passport = signed()
    store = RevocationStore()
    store.suspend(passport.agent.id, SubjectType.AGENT, duration_seconds=1800)
    assert CustosErrorCode.AGENT_SUSPENDED in verify(envelope, passport, revocation_store=store).errors


def test_revoked_issuer_blocks_the_transaction():
    envelope, passport = signed()
    store = RevocationStore()
    store.revoke("Meridian", SubjectType.ISSUER, reason="fraud")
    assert CustosErrorCode.ISSUER_REVOKED in verify(envelope, passport, revocation_store=store).errors


def test_stale_revocation_data_fails_closed():
    """The blueprint fails open here; that is its highest-severity finding."""
    import time

    envelope, passport = signed()
    store = RevocationStore(local_only=False)
    store.touch_sync()
    time.sleep(0.02)
    result = verify(envelope, passport, revocation_store=store, max_revocation_staleness_ms=1)
    assert CustosErrorCode.REVOCATION_STALE in result.errors
    assert result.passed is False


def test_tier_0_skips_the_market_check_entirely():
    envelope, passport = signed(action=Action.READ)
    result = verify(envelope, passport, claim=None, observation=None)
    assert result.passed is True
    assert result.tier_used is VerificationTier.TIER_0
    assert result.checks["asset_truth"] is CheckOutcome.NOT_RUN


def test_tier_1_runs_the_market_check_and_can_fail_it():
    envelope, passport = signed()
    result = verify(envelope, passport, claim=claim(claimed_yield_bps=360))
    assert result.passed is False
    assert CustosErrorCode.YIELD_DRIFT_EXCEEDED in result.errors
    assert result.checks["asset_truth"] is CheckOutcome.FAILED


def test_tier_1_fails_closed_without_an_observation():
    envelope, passport = signed()
    result = verify(envelope, passport, observation=None)
    assert CustosErrorCode.ORACLE_UNAVAILABLE in result.errors


def test_tier_2_is_downgraded_honestly_in_phase_1():
    """Reporting TIER_2 while running Tier 1 checks would be a lie."""
    passport = holder(monetary_limit_per_txn=100.0)
    envelope, _ = signed(passport, amount=100, tier=VerificationTier.TIER_2)
    result = verify(envelope, passport)
    assert result.tier_used is VerificationTier.TIER_1
    assert result.checks["delegation"] is CheckOutcome.NOT_RUN
    assert result.checks["trust"] is CheckOutcome.NOT_RUN


def test_failure_is_fail_fast_and_later_checks_do_not_run():
    envelope, passport = signed()
    result = verify(envelope.model_copy(update={"protocol_version": "9.9.9"}), passport)
    assert result.checks["signature"] is CheckOutcome.NOT_RUN
    assert result.checks["boundaries"] is CheckOutcome.NOT_RUN
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_verification.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'custos_protocol.verification'`

- [ ] **Step 3: Write minimal implementation**

```python
# custos_protocol/verification.py
"""The verification pipeline — the only module that composes every layer.

Ordered, tier-gated, fail-fast. The step order is API surface, not an
implementation detail: the returned code names the most fundamental problem.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from custos_protocol.boundaries import check_boundaries
from custos_protocol.canonical import get_signable_payload
from custos_protocol.crypto import hmac_verify, verify_signature
from custos_protocol.drift import AssetTruthFailure, DriftConfig, check_asset_truth
from custos_protocol.errors import CustosErrorCode
from custos_protocol.models import (
    AssetScores,
    CheckOutcome,
    Claim,
    CustosEnvelope,
    Observation,
    RevocationStatus,
    VerificationResult,
    VerificationTier,
)
from custos_protocol.revocation import RevocationStore

SUPPORTED_VERSIONS = frozenset({"1.0.0"})
NONCE_PATTERN = re.compile(r"^nonce:[0-9a-f]{32}$")

_STEPS = (
    "version", "schema", "expiry", "clock_skew", "signature",
    "nonce_format", "replay", "boundaries", "revocation",
    "asset_truth", "attestation", "delegation", "trust",
)

# Phase 1 implements Tier 0 and Tier 1. A Tier 2 request is served at Tier 1 and
# the result says so, rather than claiming a tier it did not perform.
_MAX_IMPLEMENTED_TIER = VerificationTier.TIER_1
_TIER_ORDER = {VerificationTier.TIER_0: 0, VerificationTier.TIER_1: 1, VerificationTier.TIER_2: 2}


def _effective_tier(requested: VerificationTier) -> VerificationTier:
    if _TIER_ORDER[requested] > _TIER_ORDER[_MAX_IMPLEMENTED_TIER]:
        return _MAX_IMPLEMENTED_TIER
    return requested


def verify_intent(
    envelope: CustosEnvelope,
    public_key: Ed25519PublicKey,
    *,
    claim: Claim | None = None,
    observation: Observation | None = None,
    revocation_store: RevocationStore | None = None,
    drift_config: DriftConfig | None = None,
    hmac_key: bytes | None = None,
    request_geo: str | None = None,
    clock_skew_seconds: int = 5,
    max_revocation_staleness_ms: int = 500,
    now: datetime | None = None,
) -> VerificationResult:
    now = now or datetime.now(timezone.utc)
    store = revocation_store if revocation_store is not None else RevocationStore()
    config = drift_config or DriftConfig()
    tier = _effective_tier(envelope.verification_tier)

    checks: dict[str, CheckOutcome] = {step: CheckOutcome.NOT_RUN for step in _STEPS}

    def fail(step: str, codes: list[CustosErrorCode], detail: str,
             *, scores: AssetScores | None = None,
             reference: dict | None = None) -> VerificationResult:
        checks[step] = CheckOutcome.FAILED
        return VerificationResult(
            passed=False, checks=checks, tier_used=tier, errors=codes,
            detail=detail, scores=scores, reference=reference,
            revocation=store.freshness(max_revocation_staleness_ms),
        )

    # 1. Version
    if envelope.protocol_version not in SUPPORTED_VERSIONS:
        return fail("version", [CustosErrorCode.VERSION_UNSUPPORTED],
                    f"Protocol version {envelope.protocol_version} is not supported.")
    checks["version"] = CheckOutcome.PASSED

    # 2. Schema — Pydantic did the structural work; these are the semantic minimums.
    if not envelope.agent.id or not envelope.intent.action:
        return fail("schema", [CustosErrorCode.SCHEMA_INVALID],
                    "Envelope is missing an agent identity or an action.")
    checks["schema"] = CheckOutcome.PASSED

    # 3. Expiry, with a grace window for clock skew.
    if envelope.expires_at < now - timedelta(seconds=clock_skew_seconds):
        return fail("expiry", [CustosErrorCode.EXPIRED_ENVELOPE],
                    "Envelope expires_at is in the past.")
    checks["expiry"] = CheckOutcome.PASSED

    # 3b. Clock skew on issued_at.
    if envelope.issued_at > now + timedelta(minutes=5):
        return fail("clock_skew", [CustosErrorCode.CLOCK_SKEW],
                    "Envelope issued_at is more than five minutes in the future.")
    checks["clock_skew"] = CheckOutcome.PASSED

    # 4. Signature — BEFORE replay, so an unauthenticated caller cannot burn a nonce.
    if envelope.proof is None:
        return fail("signature", [CustosErrorCode.INVALID_SIGNATURE], "Envelope carries no proof.")
    payload = get_signable_payload(envelope, exclude={"proof"})
    if tier is VerificationTier.TIER_0 and hmac_key is not None:
        signature_ok = hmac_verify(hmac_key, payload, envelope.proof.proof_value)
    else:
        signature_ok = verify_signature(public_key, payload, envelope.proof.proof_value)
    if not signature_ok:
        return fail("signature", [CustosErrorCode.INVALID_SIGNATURE],
                    "Envelope signature failed verification.")
    checks["signature"] = CheckOutcome.PASSED

    # 5. Nonce format.
    if not NONCE_PATTERN.match(envelope.entropy):
        return fail("nonce_format", [CustosErrorCode.NONCE_INVALID],
                    "Envelope entropy is not a well-formed nonce.")
    checks["nonce_format"] = CheckOutcome.PASSED

    # 5b. Replay — consumes the nonce.
    if not store.check_nonce(envelope.entropy):
        return fail("replay", [CustosErrorCode.REPLAY_DETECTED],
                    "Envelope nonce has already been used.")
    checks["replay"] = CheckOutcome.PASSED

    # 6. Boundaries — accumulates every violation.
    violations = check_boundaries(envelope, claim, request_geo=request_geo, now=now)
    if violations:
        return fail("boundaries", violations,
                    "Envelope violates the agent's declared boundaries.")
    checks["boundaries"] = CheckOutcome.PASSED

    # 7. Revocation — every tier, and fails closed on stale data.
    revocation = store.freshness(max_revocation_staleness_ms)
    if revocation.stale:
        return fail("revocation", [CustosErrorCode.REVOCATION_STALE],
                    "Revocation data is too stale to rely on; Custos fails closed.")
    if store.is_revoked(envelope.agent.id):
        code = (CustosErrorCode.AGENT_SUSPENDED if store.is_suspended(envelope.agent.id)
                else CustosErrorCode.AGENT_REVOKED)
        return fail("revocation", [code], f"Agent {envelope.agent.id} is not permitted to transact.")
    if claim is not None and store.is_revoked(claim.issuer):
        return fail("revocation", [CustosErrorCode.ISSUER_REVOKED],
                    f"Issuer {claim.issuer} has been revoked.")
    checks["revocation"] = CheckOutcome.PASSED

    def succeed(scores: AssetScores | None, reference: dict | None) -> VerificationResult:
        return VerificationResult(
            passed=True, checks=checks, tier_used=tier, errors=[],
            detail=f"{tier.value} verification passed.",
            scores=scores, reference=reference, revocation=revocation,
        )

    # ---- Tier 0 exits here: authorization only, no market check ----
    if tier is VerificationTier.TIER_0:
        return succeed(None, None)

    # 8. Asset truth.
    outcome = check_asset_truth(claim, observation, config, now=now)
    if isinstance(outcome, AssetTruthFailure):
        return fail("asset_truth", [outcome.code], outcome.detail,
                    scores=outcome.scores, reference=outcome.reference)
    checks["asset_truth"] = CheckOutcome.PASSED
    reference = {
        "source": observation.source,
        "tenor": observation.tenor,
        "claimed_yield_bps": claim.claimed_yield_bps,
        "observed_yield_bps": observation.observed_yield_bps,
        "record_date": observation.record_date.isoformat(),
    }

    # 9. Attestation — opt-in; nothing to check without expected hashes.
    checks["attestation"] = CheckOutcome.PASSED

    # ---- Tier 1 exits here. Delegation and trust arrive in Phase 2. ----
    return succeed(outcome, reference)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_verification.py -v`
Expected: 20 passed

- [ ] **Step 5: Run the whole suite**

Run: `pytest -q`
Expected: all tests pass; no regressions in earlier modules

- [ ] **Step 6: Commit**

```bash
git add custos_protocol/verification.py tests/test_verification.py
git commit -m "feat: add tier-gated verification pipeline with signature before replay"
```

---
## Task 13: Rebuild the gateway

The gateway becomes a thin adapter: parse → resolve domain inputs → `verify_intent` → sign → render.

**Files:**
- Create: `gateway/keys.py`, `gateway/config.py`
- Rewrite: `gateway/server.py`
- Modify: `gateway/proxy.py`, `claims/registry.py`, `claims/seed.json`
- Delete: `gateway/validation.py` (folds into `verification.py`), `config.py` (moves to `gateway/config.py`)
- Test: `tests/test_gateway.py` (rewritten)

**Interfaces:**
- Consumes: `custos_protocol.*`, `claims.ClaimRegistry`, `oracle.TreasuryOracle`
- Produces: the HTTP surface; `AgentKeyRegistry`; `load_drift_config()`

**Key resolution.** The envelope is signed by the agent, so the gateway needs the agent's public key. Phase 1 uses an in-memory `AgentKeyRegistry` populated via `POST /v1/agents`. This lives in `gateway/`, not `custos_protocol/`, because it is mutable process state.

**An unregistered agent yields `CUSTOS-E100`** with the detail `"No registered key for agent <id>; signature cannot be verified."` The taxonomy is fixed at 30 codes and has no `UNKNOWN_AGENT`; an envelope whose signature cannot be validated is exactly an `INVALID_SIGNATURE`, and it fails closed.

- [ ] **Step 1: Add `asset_class` to the seed data**

In `claims/seed.json`, add `"asset_class": "treasury"` to each of the four records, and fix the malformed contract address on `TKN-UST-3M-002` (it has 39 hex digits, not 40):

```json
{
  "asset_id": "TKN-UST-3M-002",
  "issuer": "Meridian Short Duration Treasury Fund",
  "underlying_tenor": "3M",
  "asset_class": "treasury",
  "claimed_nav_per_token": "1.0000",
  "claimed_backing_usd": "10000000.00",
  "tokens_outstanding": "10000000",
  "claimed_yield_bps": 400,
  "last_attested_offset_hours": -72,
  "chain": "ethereum",
  "contract_address": "0x0000000000000000000000000000000000000002"
}
```

In `claims/registry.py`, change the import from `models` to `custos_protocol.models`:

```python
from custos_protocol.models import Claim
```

- [ ] **Step 2: Write the failing test**

```python
# tests/test_gateway.py
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from custos_protocol.attestation import verify_record
from custos_protocol.crypto import b64_to_public_key, public_key_to_b64
from custos_protocol.envelope import create_envelope, sign_envelope
from custos_protocol.models import Action, Observation, VerificationTier
from custos_protocol.passport import AgentPassport
from custos_protocol.revocation import SubjectType
from gateway import server


class FixedOracle:
    async def get_observation(self, tenor: str) -> Observation:
        stamp = datetime.now(timezone.utc)
        return Observation(source="test-oracle", tenor=tenor, observed_yield_bps=400,
                           record_date=stamp.date(), fetched_at=stamp)


class DeadOracle:
    async def get_observation(self, tenor: str) -> None:
        return None


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(server, "oracle", FixedOracle())
    server.registry = server.ClaimRegistry()
    server.revocations = server.RevocationStore()
    server.agent_keys = server.AgentKeyRegistry()
    return TestClient(server.app)


@pytest.fixture
def agent(client):
    passport = AgentPassport.create(
        domain="acme.com", agent_name="treasury-bot",
        allowed_actions=["borrow_against", "trade", "read"],
        monetary_limit_per_txn=100000.0, asset_classes=["treasury"],
    )
    response = client.post("/v1/agents", json={
        "agent_id": passport.agent.id,
        "public_key": public_key_to_b64(passport.public_key),
    })
    assert response.status_code == 201
    return passport


def envelope_json(passport, asset="TKN-UST-3M-001", action=Action.BORROW_AGAINST,
                  amount=50000, **kw):
    envelope = create_envelope(passport, action, asset, {"amount": amount, "currency": "USD"}, **kw)
    return sign_envelope(envelope, passport.private_key).model_dump(mode="json", by_alias=True)


def test_healthy_envelope_returns_a_signed_attestation(client, agent):
    response = client.post("/v1/intent", json=envelope_json(agent))
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "ALLOW"
    assert body["tier_used"] == VerificationTier.TIER_1.value


def test_allow_is_independently_verifiable_against_the_published_key(client, agent):
    served = client.post("/v1/intent", json=envelope_json(agent)).json()
    published = client.get("/v1/pubkey").json()["public_key"]
    assert verify_record(served, b64_to_public_key(published)) is True


def test_denial_is_signed_and_verifiable(client, agent):
    served = client.post("/v1/intent", json=envelope_json(agent, asset="TKN-UST-3M-003")).json()
    published = client.get("/v1/pubkey").json()["public_key"]
    assert served["verdict"] == "BLOCK"
    assert "CUSTOS-E301" in served["errors"]
    assert verify_record(served, b64_to_public_key(published)) is True


def test_malformed_envelope_is_a_structured_400(client):
    response = client.post("/v1/intent", json={})
    assert response.status_code == 400
    assert response.json()["errors"] == ["CUSTOS-E103"]


def test_unregistered_agent_cannot_be_verified(client):
    stranger = AgentPassport.create(domain="evil.com", agent_name="bot")
    response = client.post("/v1/intent", json=envelope_json(stranger))
    assert response.status_code == 401
    assert response.json()["errors"] == ["CUSTOS-E100"]


def test_stale_claim_is_blocked_with_403(client, agent):
    response = client.post("/v1/intent", json=envelope_json(agent, asset="TKN-UST-3M-002"))
    assert response.status_code == 403
    assert "CUSTOS-E300" in response.json()["errors"]


def test_under_backed_claim_is_blocked(client, agent):
    response = client.post("/v1/intent", json=envelope_json(agent, asset="TKN-UST-6M-004"))
    assert response.status_code == 403
    assert "CUSTOS-E302" in response.json()["errors"]


def test_unknown_asset_is_404_and_precedes_the_oracle(client, agent):
    response = client.post("/v1/intent", json=envelope_json(agent, asset="NOPE"))
    assert response.status_code == 404
    assert "CUSTOS-E303" in response.json()["errors"]


def test_replayed_envelope_is_409(client, agent):
    payload = envelope_json(agent)
    assert client.post("/v1/intent", json=payload).status_code == 200
    replayed = client.post("/v1/intent", json=payload)
    assert replayed.status_code == 409
    assert "CUSTOS-E102" in replayed.json()["errors"]


def test_revoked_agent_is_blocked(client, agent):
    server.revocations.revoke(agent.agent.id, SubjectType.AGENT, reason="compromised")
    response = client.post("/v1/intent", json=envelope_json(agent))
    assert response.status_code == 403
    assert "CUSTOS-E400" in response.json()["errors"]


def test_oracle_failure_fails_closed_with_503(client, agent, monkeypatch):
    monkeypatch.setattr(server, "oracle", DeadOracle())
    response = client.post("/v1/intent", json=envelope_json(agent))
    assert response.status_code == 503
    assert "CUSTOS-E500" in response.json()["errors"]


def test_read_action_needs_no_market_data(client, agent, monkeypatch):
    monkeypatch.setattr(server, "oracle", DeadOracle())
    response = client.post("/v1/intent", json=envelope_json(agent, action=Action.READ, amount=0))
    assert response.status_code == 200
    assert response.json()["tier_used"] == VerificationTier.TIER_0.value


def test_assets_endpoints(client):
    listing = client.get("/v1/assets")
    assert listing.status_code == 200
    assert len(listing.json()["assets"]) == 4

    detail = client.get("/v1/assets/TKN-UST-3M-001")
    assert detail.status_code == 200
    assert detail.json()["claim"]["asset_class"] == "treasury"
    assert detail.json()["evaluation"] is not None

    assert client.get("/v1/assets/NOPE").status_code == 404


def test_pubkey_exposes_both_encodings(client):
    body = client.get("/v1/pubkey").json()
    assert body["algorithm"] == "Ed25519"
    assert body["public_key_pem"].startswith("-----BEGIN PUBLIC KEY-----")


def test_health_reports_oracle_state(client, monkeypatch):
    assert client.get("/v1/health").json()["status"] == "ok"
    monkeypatch.setattr(server, "oracle", DeadOracle())
    degraded = client.get("/v1/health")
    assert degraded.status_code == 503
    assert degraded.json()["status"] == "degraded"


def test_demo_sync_is_absent_unless_demo_mode_is_enabled(client):
    """It rewrites every claim in the registry; it must not be exposed by default."""
    assert client.post("/v1/demo/sync").status_code == 404
    assert "/v1/demo/sync" not in client.get("/openapi.json").json()["paths"]
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_gateway.py -v`
Expected: FAIL — `gateway.server` has no `AgentKeyRegistry`

- [ ] **Step 4: Write `gateway/config.py`**

Environment reads live here, never inside `custos_protocol/`.

```python
# gateway/config.py
"""Runtime configuration. The protocol package never reads the environment."""

from __future__ import annotations

import os

from custos_protocol.drift import DriftConfig


def _env(name: str, default: str) -> str:
    return os.getenv(name, default)


def load_drift_config() -> DriftConfig:
    return DriftConfig(
        staleness_threshold_hours=float(_env("CUSTOS_STALENESS_HOURS", "24.0")),
        drift_threshold=float(_env("CUSTOS_DRIFT_THRESHOLD", "0.02")),
        backing_floor=float(_env("CUSTOS_BACKING_FLOOR", "1.0")),
        max_observation_age_days=int(_env("CUSTOS_MAX_OBS_AGE_DAYS", "4")),
        zero_yield_abs_tolerance_bps=int(_env("CUSTOS_ZERO_YIELD_TOLERANCE_BPS", "10")),
        clock_skew_seconds=int(_env("CUSTOS_CLOCK_SKEW_SECONDS", "5")),
    )


ORACLE_TIMEOUT_SECONDS = float(_env("CUSTOS_ORACLE_TIMEOUT", "3.0"))
DOWNSTREAM_TIMEOUT_SECONDS = float(_env("CUSTOS_DOWNSTREAM_TIMEOUT", "3.0"))
ORACLE_CACHE_TTL_SECONDS = int(_env("CUSTOS_CACHE_TTL", "60"))
ATTESTATION_TTL_SECONDS = int(_env("CUSTOS_ATTESTATION_TTL", "300"))
PRIVATE_KEY_PATH = os.getenv("CUSTOS_PRIVATE_KEY")
DEMO_MODE = _env("CUSTOS_DEMO_MODE", "").lower() in {"1", "true", "yes"}
```

Note `DOWNSTREAM_TIMEOUT_SECONDS` is now its own knob — the old code reused the oracle timeout for the downstream proxy. `CUSTOS_FAIL_MODE` is deleted: it was documented as `closed | open` but never read by anything.

**Do not** point `oracle/` at `gateway.config`. That would make the data service depend on the HTTP layer — the same inversion the architecture rules exist to prevent. Instead give `TreasuryOracle` explicit constructor parameters and let the gateway inject them.

In `oracle/treasury.py`, replace `import config` with parameters:

```python
class TreasuryOracle:
    def __init__(
        self,
        *,
        client: httpx.AsyncClient | None = None,
        url: str = TREASURY_YIELD_URL,
        timeout_seconds: float = 3.0,
        cache_ttl_seconds: int = 60,
    ) -> None:
        self._client = client
        self._url = url
        self._timeout_seconds = timeout_seconds
        self._cache: TTLCache[Observation] = TTLCache(cache_ttl_seconds)
```

Replace the two `config.ORACLE_TIMEOUT_SECONDS` references in `get_observation` with `self._timeout_seconds`. `oracle/cache.py` already takes its TTL as a constructor argument and needs no change beyond dropping its `import config` if present.

In `gateway/server.py`, construct it with the configured values:

```python
oracle = TreasuryOracle(
    timeout_seconds=config.ORACLE_TIMEOUT_SECONDS,
    cache_ttl_seconds=config.ORACLE_CACHE_TTL_SECONDS,
)
```

Update `oracle/treasury.py`'s import of `models` to `from custos_protocol.models import Observation`.

- [ ] **Step 5: Write `gateway/keys.py`**

```python
# gateway/keys.py
"""Agent public-key resolution. Mutable process state, so it lives outside the protocol package."""

from __future__ import annotations

import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from custos_protocol.crypto import b64_to_public_key


class AgentKeyRegistry:
    def __init__(self) -> None:
        self._keys: dict[str, Ed25519PublicKey] = {}
        self._lock = threading.Lock()

    def register(self, agent_id: str, public_key_b64: str) -> None:
        key = b64_to_public_key(public_key_b64)
        with self._lock:
            self._keys[agent_id] = key

    def get(self, agent_id: str) -> Ed25519PublicKey | None:
        with self._lock:
            return self._keys.get(agent_id)

    def __len__(self) -> int:
        with self._lock:
            return len(self._keys)
```

- [ ] **Step 6: Rewrite `gateway/server.py`**

```python
# gateway/server.py
"""HTTP surface. Parse, resolve domain inputs, verify, sign, render."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ValidationError

from claims import ClaimRegistry
from custos_protocol.attestation import RecordSigner
from custos_protocol.crypto import load_private_key
from custos_protocol.envelope import envelope_hash
from custos_protocol.errors import CustosErrorCode, http_status_for
from custos_protocol.models import CustosEnvelope, VerificationTier
from custos_protocol.revocation import RevocationStore, SubjectType
from custos_protocol.verification import verify_intent
from gateway import config
from gateway.keys import AgentKeyRegistry
from gateway.proxy import forward
from oracle.treasury import TreasuryOracle, UnsupportedTenor

app = FastAPI(
    title="Custos Gateway",
    version="1.0.0",
    description="Pre-transaction asset-truth attestation for autonomous agents.",
)

registry = ClaimRegistry()
oracle = TreasuryOracle()
revocations = RevocationStore()
agent_keys = AgentKeyRegistry()
drift_config = config.load_drift_config()
signer = RecordSigner(
    load_private_key(Path(config.PRIVATE_KEY_PATH)) if config.PRIVATE_KEY_PATH else None,
    ttl_seconds=config.ATTESTATION_TTL_SECONDS,
)


def _render(model: Any, status_code: int = 200) -> JSONResponse:
    return JSONResponse(status_code=status_code, content=jsonable_encoder(model))


def _deny(envelope_hash_value: str, agent_id: str, asset_id: str | None,
          errors: list[CustosErrorCode], detail: str,
          scores=None, reference=None) -> JSONResponse:
    denial = signer.sign_denial(
        envelope_hash=envelope_hash_value, agent_id=agent_id, asset_id=asset_id,
        errors=errors, detail=detail, scores=scores, reference=reference,
    )
    return _render(denial, http_status_for(errors[0]))


@app.exception_handler(RequestValidationError)
async def _schema_error(_: Request, exc: RequestValidationError) -> JSONResponse:
    denial = signer.sign_denial(
        envelope_hash="", agent_id="", errors=[CustosErrorCode.SCHEMA_INVALID],
        detail="Envelope failed schema validation.",
    )
    return _render(denial, http_status_for(CustosErrorCode.SCHEMA_INVALID))


class AgentRegistration(BaseModel):
    agent_id: str
    public_key: str


@app.post("/v1/agents", status_code=201)
async def register_agent(registration: AgentRegistration) -> dict:
    agent_keys.register(registration.agent_id, registration.public_key)
    return {"registered": registration.agent_id}


async def _resolve(envelope: CustosEnvelope):
    """Returns (claim, observation, tenor_error)."""
    claim = registry.get_claim(envelope.intent.target)
    if claim is None:
        return None, None, None
    try:
        observation = await oracle.get_observation(claim.underlying_tenor)
    except UnsupportedTenor:
        return claim, None, CustosErrorCode.TENOR_UNSUPPORTED
    return claim, observation, None


@app.post("/v1/intent", response_model=None)
async def post_intent(envelope: CustosEnvelope, request: Request):
    digest = envelope_hash(envelope)

    public_key = agent_keys.get(envelope.agent.id)
    if public_key is None:
        return _deny(digest, envelope.agent.id, envelope.intent.target,
                     [CustosErrorCode.INVALID_SIGNATURE],
                     f"No registered key for agent {envelope.agent.id}; signature cannot be verified.")

    claim = observation = None
    if envelope.verification_tier is not VerificationTier.TIER_0:
        claim, observation, tenor_error = await _resolve(envelope)
        if tenor_error is not None:
            return _deny(digest, envelope.agent.id, envelope.intent.target,
                         [tenor_error],
                         f"Tenor {claim.underlying_tenor} has no yield-curve mapping.")

    result = verify_intent(
        envelope, public_key,
        claim=claim, observation=observation,
        revocation_store=revocations, drift_config=drift_config,
        request_geo=request.headers.get("X-Custos-Geo"),
        clock_skew_seconds=drift_config.clock_skew_seconds,
    )

    if not result.passed:
        return _deny(digest, envelope.agent.id, envelope.intent.target,
                     result.errors, result.detail, result.scores, result.reference)

    attestation = signer.sign_attestation(
        envelope_hash=digest, agent_id=envelope.agent.id,
        asset_id=envelope.intent.target, action=envelope.intent.action.value,
        amount=envelope.intent.parameters.get("amount"),
        tier_used=result.tier_used, scores=result.scores, reference=result.reference,
    )

    downstream_url = envelope.intent.parameters.get("downstream")
    if not downstream_url:
        return _render(attestation)

    try:
        downstream = await forward(str(downstream_url), envelope, attestation)
    except ConnectionError:
        return _render(
            {"attestation": jsonable_encoder(attestation),
             "downstream": {"errors": [CustosErrorCode.DOWNSTREAM_UNREACHABLE.value],
                            "detail": "The downstream service could not be reached."}},
            http_status_for(CustosErrorCode.DOWNSTREAM_UNREACHABLE),
        )
    return _render({"attestation": attestation, "downstream": downstream})


@app.get("/v1/assets")
async def list_assets():
    return _render({"assets": registry.list_claims()})


@app.get("/v1/assets/{asset_id}", response_model=None)
async def get_asset(asset_id: str):
    claim = registry.get_claim(asset_id)
    if claim is None:
        return _deny("", "diagnostic", asset_id, [CustosErrorCode.UNKNOWN_ASSET],
                     "The requested asset is not present in the claim registry.")
    try:
        observation = await oracle.get_observation(claim.underlying_tenor)
    except UnsupportedTenor:
        observation = None

    from custos_protocol.drift import check_asset_truth

    evaluation = check_asset_truth(claim, observation, drift_config)
    return _render({"claim": claim, "observation": observation, "evaluation": evaluation})


@app.get("/v1/pubkey")
async def get_public_key():
    return {
        "algorithm": "Ed25519",
        "public_key": signer.public_key_b64,
        "public_key_pem": signer.public_key_pem,
    }


@app.get("/v1/health", response_model=None)
async def health():
    try:
        observation = await oracle.get_observation("3M")
    except UnsupportedTenor:  # pragma: no cover - impossible unless the map changes
        observation = None
    ok = observation is not None
    return _render(
        {"status": "ok" if ok else "degraded",
         "oracle_reachable": ok,
         "observation": observation},
        200 if ok else 503,
    )


@app.get("/demo", include_in_schema=False)
async def live_demo_page():
    return FileResponse(Path(__file__).resolve().parents[1] / "demo" / "live.html")


# ---- demo-only routes, mounted only when CUSTOS_DEMO_MODE is set ----

demo_router = APIRouter()


@demo_router.post("/v1/demo/sync", response_model=None)
async def sync_live_demo_claims():
    """Align simulated demo claims to current observations. Never touches a real source of truth."""
    observations: dict[str, Any] = {}
    for tenor in {claim.underlying_tenor for claim in registry.list_claims()}:
        try:
            observation = await oracle.get_observation(tenor)
        except UnsupportedTenor:
            return _render({"errors": [CustosErrorCode.TENOR_UNSUPPORTED.value]}, 422)
        if observation is None:
            return _render({"errors": [CustosErrorCode.ORACLE_UNAVAILABLE.value]}, 503)
        observations[tenor] = observation

    updated = []
    for claim in registry.list_claims():
        observed = observations[claim.underlying_tenor].observed_yield_bps
        if claim.asset_id == "TKN-UST-3M-003":
            yield_bps = max(1, observed - max(40, round(observed * 0.04)))
        else:
            yield_bps = observed
        synced = registry.update_claim(claim.asset_id, claimed_yield_bps=yield_bps)
        if synced:
            updated.append({"asset_id": synced.asset_id, "claimed_yield_bps": synced.claimed_yield_bps})

    return _render({
        "mode": "live-market-demo",
        "notice": "Market observations are live; claim records remain simulated in memory.",
        "observations": observations,
        "updated_claims": updated,
    })


if config.DEMO_MODE:
    app.include_router(demo_router)
```

- [ ] **Step 7: Update `gateway/proxy.py`**

```python
# gateway/proxy.py
from __future__ import annotations

import base64
import json

import httpx

from custos_protocol.attestation import Attestation
from custos_protocol.models import CustosEnvelope
from gateway import config


async def forward(url: str, envelope: CustosEnvelope, attestation: Attestation) -> dict:
    """Forward an allowed intent with its signed proof in a header-safe encoding."""
    serialized = json.dumps(attestation.model_dump(mode="json"), separators=(",", ":"), ensure_ascii=True)
    headers = {"X-Custos-Attestation": base64.b64encode(serialized.encode("utf-8")).decode("ascii")}
    timeout = httpx.Timeout(config.DOWNSTREAM_TIMEOUT_SECONDS, connect=config.DOWNSTREAM_TIMEOUT_SECONDS)
    body = envelope.model_dump(mode="json", by_alias=True)
    try:
        # follow_redirects=False keeps a signed attestation from reaching an unvetted host.
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            response = await client.post(url, json=body, headers=headers)
        try:
            payload = response.json()
        except ValueError:
            payload = response.text
        return {"status_code": response.status_code, "body": payload}
    except httpx.HTTPError as exc:
        raise ConnectionError("downstream could not be reached") from exc
```

- [ ] **Step 8: Delete the superseded files**

```bash
git rm gateway/validation.py config.py
```

`gateway/validation.py` folds into `verification.py` steps 3 and 3b. `config.py` becomes `gateway/config.py`.

- [ ] **Step 9: Run tests to verify they pass**

Run: `pytest tests/test_gateway.py -v`
Expected: 16 passed

- [ ] **Step 10: Commit**

```bash
git add gateway/ claims/ tests/test_gateway.py
git commit -m "refactor: rebuild gateway as a thin surface over custos_protocol"
```

---

## Task 14: Rewrite the demos

**Files:**
- Rewrite: `demo/run_local_demo.py`, `demo/verify_attestation.py`, `demo/mock_lender.py`
- Modify: `demo/run_demo.py`, `demo/live.html`
- Test: covered by `tests/test_gateway.py::test_allow_is_independently_verifiable_against_the_published_key`

**Interfaces:**
- Consumes: the gateway HTTP surface, `custos_protocol.passport`, `custos_protocol.envelope`
- Produces: runnable demonstrations

- [ ] **Step 1: Rewrite `demo/verify_attestation.py`**

The standalone verifier must still import nothing from Custos — it is the second independent implementation of the canonical form, and the test suite checks the gateway against it.

```python
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
```

- [ ] **Step 2: Rewrite `demo/mock_lender.py`**

The reference consumer must implement the full contract, not a presence check. It is the only worked example anyone will copy.

```python
"""Reference downstream consumer. Implements all five checks a real one must do."""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone

from fastapi import FastAPI, Header, Request

from demo.verify_attestation import verify

app = FastAPI(title="Custos demo lender")

# Pinned out of band from GET /v1/pubkey. Without this, verification proves nothing.
CUSTOS_PUBLIC_KEY = os.getenv("CUSTOS_GATEWAY_PUBKEY", "")


@app.post("/loan")
async def loan(request: Request, x_custos_attestation: str | None = Header(default=None)):
    # 1. Present?
    if not x_custos_attestation:
        return {"accepted": False, "reason": "missing Custos attestation"}
    record = json.loads(base64.b64decode(x_custos_attestation))

    # 2. Signature valid against the PINNED key?
    if not CUSTOS_PUBLIC_KEY:
        return {"accepted": False, "reason": "no pinned Custos key configured"}
    try:
        verify(record, CUSTOS_PUBLIC_KEY)
    except Exception:
        return {"accepted": False, "reason": "attestation signature did not verify"}

    # 3. Still valid?
    if datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00")) < datetime.now(timezone.utc):
        return {"accepted": False, "reason": "attestation expired"}

    # 4. Verdict is ALLOW?
    if record.get("verdict") != "ALLOW":
        return {"accepted": False, "reason": "attestation is not an ALLOW"}

    # 5. Does it describe THIS request?
    envelope = await request.json()
    if record["asset_id"] != envelope["intent"]["target"]:
        return {"accepted": False, "reason": "attestation is for a different asset"}
    if record["amount"] != envelope["intent"]["parameters"].get("amount"):
        return {"accepted": False, "reason": "attestation is for a different amount"}

    return {"accepted": True, "message": "loan approved against a verified Custos attestation"}
```

- [ ] **Step 3: Rewrite `demo/run_local_demo.py`**

```python
"""Deterministic in-process demo. Substitutes only the observation.

Every route, model and signature in this run is the production one.
"""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx
from rich.console import Console
from rich.table import Table

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from custos_protocol.crypto import public_key_to_b64          # noqa: E402
from custos_protocol.envelope import create_envelope, sign_envelope  # noqa: E402
from custos_protocol.models import Action, Observation        # noqa: E402
from custos_protocol.passport import AgentPassport            # noqa: E402
from demo.verify_attestation import verify                    # noqa: E402
from gateway import server                                    # noqa: E402


class DemoOracle:
    """A known-good 4.00% observation, so every presentation has the intended outcomes."""

    async def get_observation(self, tenor: str) -> Observation:
        stamp = datetime.now(timezone.utc)
        return Observation(source="demo.fixed-observation", tenor=tenor,
                           observed_yield_bps=400, record_date=stamp.date(), fetched_at=stamp)


async def run() -> None:
    console = Console()
    original = server.oracle
    server.oracle = DemoOracle()

    passport = AgentPassport.create(
        domain="acme.com", agent_name="treasury-bot",
        allowed_actions=["borrow_against"], monetary_limit_per_txn=100000.0,
        asset_classes=["treasury"],
    )

    scenarios = [
        ("Stale claim", "TKN-UST-3M-002", "CUSTOS-E300"),
        ("Recent but drifted", "TKN-UST-3M-003", "CUSTOS-E301"),
        ("Under-backed", "TKN-UST-6M-004", "CUSTOS-E302"),
        ("Healthy claim", "TKN-UST-3M-001", "ALLOW"),
    ]

    table = Table(title="Custos Gateway — deterministic local demo")
    for column in ("Scenario", "Asset", "HTTP", "Result", "Expected"):
        table.add_column(column)

    try:
        transport = httpx.ASGITransport(app=server.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://custos.demo") as client:
            await client.post("/v1/agents", json={
                "agent_id": passport.agent.id,
                "public_key": public_key_to_b64(passport.public_key),
            })
            gateway_key = (await client.get("/v1/pubkey")).json()["public_key"]

            for name, asset_id, expected in scenarios:
                envelope = create_envelope(passport, Action.BORROW_AGAINST, asset_id,
                                           {"amount": 50000, "currency": "USD"})
                signed = sign_envelope(envelope, passport.private_key)
                response = await client.post("/v1/intent",
                                             json=signed.model_dump(mode="json", by_alias=True))
                body = response.json()
                result = body["errors"][0] if body.get("errors") else body.get("verdict", "UNKNOWN")
                style = "green" if result == expected else "red"
                table.add_row(name, asset_id, str(response.status_code),
                              f"[{style}]{result}[/{style}]", expected)

                if body.get("verdict") == "ALLOW":
                    output = Path(__file__).with_name("attestation.json")
                    output.write_text(json.dumps(body, indent=2), encoding="utf-8")
                    verify(body, gateway_key)
                    console.print(f"[green]Signature verified against the published key. Wrote {output}[/green]")
    finally:
        server.oracle = original

    console.print(table)
    console.print("[dim]Demo mode fixes the observation at 400 bps; the gateway remains live and fail-closed.[/dim]")


if __name__ == "__main__":
    asyncio.run(run())
```

- [ ] **Step 4: Update `demo/run_demo.py` and `demo/live.html`**

In `run_demo.py`, replace the hand-built `custos/1` dict with the passport + `create_envelope` + `sign_envelope` flow from Step 3, registering the agent against the running gateway first via `POST /v1/agents`.

In `live.html`, the browser cannot hold a private key safely, so the page keeps its four read-only scenario cards and the live-yield panel but **replaces the "Evaluate intent" button with a call to `GET /v1/assets/{id}`**, which returns the same claim, observation and evaluation without signing anything. Update the copy under the button to say so. The sync button stays and is a no-op unless the gateway runs with `CUSTOS_DEMO_MODE=1`.

- [ ] **Step 5: Run the demo end to end**

Run: `python demo/run_local_demo.py`
Expected: four rows, all green — `CUSTOS-E300`, `CUSTOS-E301`, `CUSTOS-E302`, `ALLOW` — plus the independent-verification line.

- [ ] **Step 6: Commit**

```bash
git add demo/
git commit -m "refactor: rewrite demos against the CustosEnvelope protocol"
```

---

## Task 15: Architecture tests and cleanup

Locks the dependency rules in and removes the superseded packages.

**Files:**
- Create: `tests/test_architecture.py`
- Delete: `models/`, `attest/`
- Modify: `README.md`, `AGENTS.md`
- Test: `tests/test_architecture.py`

**Interfaces:**
- Consumes: every module
- Produces: enforcement of the two structural invariants and the error-coverage invariant

- [ ] **Step 1: Write the failing test**

```python
# tests/test_architecture.py
"""The dependency rules are enforced by test, not by convention."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

from custos_protocol.errors import CustosErrorCode

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = PROJECT_ROOT / "custos_protocol"

# E203 (rolling per-day monetary limit) needs the Phase 2 ledger.
PHASE_2_CODES = {CustosErrorCode.MONETARY_LIMIT_PER_DAY}


def imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


@pytest.mark.parametrize("source", sorted(PROTOCOL.glob("*.py")), ids=lambda p: p.name)
def test_protocol_package_never_imports_application_layers(source):
    """custos_protocol must not depend on the gateway or on I/O services."""
    forbidden = {"gateway", "claims", "oracle"}
    for module in imported_modules(source):
        root = module.split(".")[0]
        assert root not in forbidden, f"{source.name} imports {module}"


@pytest.mark.parametrize("source", sorted(PROTOCOL.glob("*.py")), ids=lambda p: p.name)
def test_protocol_package_never_imports_aip(source):
    """The blueprint is documentation. There must be no linkage to the AIP SDK."""
    for module in imported_modules(source):
        assert not module.startswith("aip"), f"{source.name} imports {module}"


@pytest.mark.parametrize("source", sorted(PROTOCOL.glob("*.py")), ids=lambda p: p.name)
def test_protocol_package_performs_no_io(source):
    """Configuration arrives as value objects; the environment is read in gateway/config.py."""
    text = source.read_text(encoding="utf-8")
    assert "os.getenv" not in text, f"{source.name} reads the environment"
    assert "import httpx" not in text, f"{source.name} opens a socket"


@pytest.mark.parametrize(
    "source",
    sorted((PROJECT_ROOT / "oracle").glob("*.py")) + sorted((PROJECT_ROOT / "claims").glob("*.py")),
    ids=lambda p: f"{p.parent.name}/{p.name}",
)
def test_data_services_never_import_the_http_layer(source):
    """oracle/ and claims/ are injected into the gateway, never the reverse."""
    for module in imported_modules(source):
        assert module.split(".")[0] != "gateway", f"{source.name} imports {module}"


def test_superseded_packages_are_gone():
    assert not (PROJECT_ROOT / "models").exists()
    assert not (PROJECT_ROOT / "attest").exists()
    assert not (PROJECT_ROOT / "gateway" / "validation.py").exists()
    assert not (PROJECT_ROOT / "config.py").exists()


def test_every_error_code_is_exercised_by_the_suite():
    """The blueprint ships 4 of 23 codes dead. Custos ships none."""
    corpus = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (PROJECT_ROOT / "tests").glob("test_*.py")
    )
    missing = [
        code.name for code in CustosErrorCode
        if code not in PHASE_2_CODES
        and code.name not in corpus
        and code.value not in corpus
    ]
    assert missing == [], f"error codes with no test: {missing}"


def test_bare_pytest_collects_the_suite():
    """Regression guard: only `python -m pytest` worked before pyproject.toml existed."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=PROJECT_ROOT, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_architecture.py -v`
Expected: FAIL — `models/` and `attest/` still exist

- [ ] **Step 3: Delete the superseded packages**

```bash
git rm -r models attest
```

Everything in them now lives in `custos_protocol/`: `models/*` → `models.py`, `attest/errors.py` → `errors.py`, `attest/engine.py` → `drift.py`, `attest/signing.py` → `canonical.py` + `crypto.py` + `attestation.py`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_architecture.py -v`
Expected: all passed

- [ ] **Step 5: Update `README.md` and `AGENTS.md`**

In `README.md`: delete the stray `>>>>>>> 3da9d8f (Project Base)` merge marker on the last line, drop the duplicate `# APay-Gateway` heading, and replace the `custos/1` request example with a `CustosEnvelope` one. Document `POST /v1/agents` and note that `POST /v1/demo/sync` requires `CUSTOS_DEMO_MODE=1`.

In `AGENTS.md`: replace the module-dependency rule and the `evaluate()` contract with the new ones:

```markdown
# Custos implementation contract

Keep dependencies one-way. `custos_protocol` is the SDK and imports nothing from the
application: not `gateway`, not `claims`, not `oracle`. Within it, `errors`, `crypto` and
`canonical` are leaves; `models` depends only on leaves; feature modules depend on `models`;
`verification` is the only module that composes everything. There is no dependency on the
AIP SDK — `architecture1.md` is a blueprint, not a library.

`custos_protocol` performs no I/O. Configuration arrives as value objects (`DriftConfig`);
the environment is read only in `gateway/config.py`.

## Evaluation contract

`verify_intent(envelope, public_key, *, claim, observation, ...) -> VerificationResult`

Step order is API surface, not an implementation detail:
version, schema, expiry, clock skew, **signature**, nonce format, replay, boundaries,
revocation — then, at Tier 1+, asset truth and attestation. Signature precedes replay so an
unauthenticated caller cannot burn another agent's nonce. Never fail open.

Asset truth short-circuits in this order: E303 unknown asset, E500 no observation,
E501 observation too old, E305 future-dated claim, E300 stale claim, E501 negative yield,
E301 drift, E302 backing.
```

- [ ] **Step 6: Run the full suite and the demo**

Run: `pytest -q`
Expected: every test passes

Run: `python demo/run_local_demo.py`
Expected: four green rows

- [ ] **Step 7: Commit**

```bash
git add tests/test_architecture.py README.md AGENTS.md
git commit -m "test: enforce dependency rules and error-code coverage; drop superseded packages"
```

---

## Phase 1 exit criteria

- [ ] `pytest -q` green, run as bare `pytest`
- [ ] `POST /v1/intent` returns a signed `Attestation` on success and a signed `Denial` on failure
- [ ] Replay of a spent nonce is rejected with `CUSTOS-E102`
- [ ] A revoked agent is blocked at Tier 0
- [ ] A forged envelope does not consume the victim's nonce
- [ ] `python demo/run_local_demo.py` shows four deterministic outcomes and verifies the signature against the published key
- [ ] `tests/test_architecture.py` passes: no protocol→application imports, no AIP imports, no I/O in the protocol package
- [ ] Every error code except `CUSTOS-E203` is exercised by a test
- [ ] `models/`, `attest/`, `gateway/validation.py` and `config.py` are gone

## Deferred to Phase 2

`trust.py`, `delegation.py`, boundary predicate 4 (`CUSTOS-E203`), verification steps 10–11,
Tier 2 execution, and the `/v1/revocations` and `/v1/trust` routes.

## Not in scope

The live Treasury oracle is broken (`ARCHITECTURE.md` §18: wrong feed URL, 3 s timeout against
an 8–10 s feed). It is deliberately untouched here and `oracle/` keeps its interface, so the
fix can land independently at any time. Demos and tests substitute the oracle, as they do today.
