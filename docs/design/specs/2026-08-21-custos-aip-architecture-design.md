# Custos rebuilt in AIP's image — design

**Date:** 2026-08-21
**Status:** approved for planning
**Blueprint:** `architecture1.md` (AIP — Agent Intent Protocol, v0.4.0 documentation)

---

## 1. Goal

Restructure the Custos Gateway so its architecture mirrors the Agent Intent Protocol
described in `architecture1.md`: a flat-module protocol SDK with layered, independently
testable units, a canonical serialization core, a tier-gated verification pipeline, a
structured error taxonomy, and thin surfaces (gateway, CLI, decorators) built on top.

Custos keeps its reason for existing — **asset truth**: deciding whether a tokenized
Treasury claim is plausible against a live market observation before an agent transacts
against it. That check becomes a first-class layer of the pipeline rather than the whole
program.

## 2. Non-goals

- **No dependency on the AIP SDK.** `aip-protocol` exists in a sibling directory. Custos
  must not import it, vendor it, or link to it. AIP is a blueprint, not a library.
- **No interop with AIP-1.** Custos speaks its own protocol with its own `@context`. A
  future bridge is out of scope.
- **No oracle repair.** The live Treasury oracle is currently broken (documented in
  `ARCHITECTURE.md` §18: wrong feed URL, timeout too short). Fixing it is deliberately
  parked. `oracle/` keeps its current interface so the fix can land later without touching
  protocol code.
- **No new product surface.** Nothing here adds a hosted service, registry, or mesh.

## 3. Constraints

| Constraint | Source |
|---|---|
| Zero linkage to `../aip` | user directive |
| Architecture must mirror the blueprint's layering | user directive |
| Python 3.10+, Pydantic v2, FastAPI, `cryptography` | existing stack |
| Each phase ends with a working, green gateway | approach A |
| TDD — tests precede implementation | project workflow |

## 4. Architecture overview

### 4.1 Layer mapping

| # | AIP layer | Custos module | Purpose |
|---|---|---|---|
| 1 | Data Models | `custos_protocol/models.py` | Every wire message as a Pydantic v2 model |
| 2 | Cryptography | `custos_protocol/crypto.py` | Ed25519 + HMAC-SHA256, base64url, PEM I/O |
| 3 | Canonical Serialization | `custos_protocol/canonical.py` | Byte-stable signable payload |
| 4 | Agent Passport | `custos_protocol/passport.py` | DID identity + keypair + policy cage + persistence |
| 5 | Intent Envelope | `custos_protocol/envelope.py` | Construction, signing, hashing, tier selection |
| 6 | Verification Pipeline | `custos_protocol/verification.py` | Ordered, tier-gated `verify_intent()` |
| 7 | Boundary Enforcement | `custos_protocol/boundaries.py` | Action / monetary / time / geo / asset-class predicates |
| 8 | Intent Drift → **Asset Truth** | `custos_protocol/drift.py` | Staleness, yield drift, backing ratio |
| 9 | Attestation | `custos_protocol/attestation.py` | The signed ALLOW record |
| 10 | Delegation Chain | `custos_protocol/delegation.py` | Principal→agent continuity + monotonicity |
| 11 | Revocation Store | `custos_protocol/revocation.py` | Kill switch (agents, issuers) + nonce replay cache |
| 12 | Trust Score | `custos_protocol/trust.py` | Behavioural reputation for agents and issuers |
| 13 | Error Taxonomy | `custos_protocol/errors.py` | 30 `CUSTOS-Exxx` codes + descriptions + exception |
| 14 | Shield | `custos_protocol/shield.py` | Decorator that gates a callable on a Custos check |
| 15 | Observe | `custos_protocol/observe.py` | Log everything, block nothing |
| 16 | CLI | `custos_protocol/cli.py` | `custos` command |
| + | Conformance | `conformance/` | Frozen vectors + deterministic runner |
| + | Gateway | `gateway/` | FastAPI surface over the SDK |

### 4.2 Dependency direction

The blueprint's most valuable structural property is that the pipeline is the only module
that composes everything; everything else is a leaf or near-leaf. Custos adopts the same
rule, and it is testable by import graph:

```
errors.py  crypto.py  canonical.py            (leaves: no internal deps)
     ▲         ▲          ▲
     └─────────┴──────────┴──► models.py      (schema; depends only on the leaves)
                                   ▲
    ┌──────────┬───────────┬───────┴────┬──────────────┬─────────────┐
    │          │           │            │              │             │
passport.py envelope.py boundaries.py drift.py   revocation.py   trust.py
    │          │           │            │              │             │
    └──────────┴───────────┴────────────┴──────────────┴─────────────┘
                                   │
                          verification.py       ← the only composer
                                   ▲
                 ┌─────────────────┼─────────────────┐
             shield.py          cli.py           gateway/
                                                     │
             observe.py  (depends only on passport — structurally cannot block)

  claims/  oracle/   ← domain data services; imported by gateway, never by custos_protocol
```

Two rules to enforce with a test:

1. `custos_protocol/` must not import `gateway/`, `claims/`, or `oracle/`.
2. `observe.py` must not import `verification.py` — observability must be structurally
   incapable of blocking a call.

**Asset-truth data flows in, not out.** `drift.py` is a pure function of
`(envelope, claim, observation)`. The gateway resolves the claim from `claims/` and the
observation from `oracle/` and passes them in. The protocol package never performs I/O.

## 5. Data models

### 5.1 Enumerations

```python
class VerificationTier(str, Enum):
    TIER_0 = "tier_0"   # authorization only — NO market check
    TIER_1 = "tier_1"   # + asset truth + attestation
    TIER_2 = "tier_2"   # + delegation + trust

class Action(str, Enum):
    BORROW_AGAINST = "borrow_against"
    TRADE          = "trade"
    REDEEM         = "redeem"
    READ           = "read"          # non-value-moving; Tier 0 eligible

class AttestationMethod(str, Enum):
    SELF_REPORTED      = "self_reported"
    FRAMEWORK_REGISTRY = "framework_registry"
    THIRD_PARTY_AUDIT  = "third_party_audit"

class RevocationStatus(str, Enum):
    NOT_REVOKED = "not_revoked"
    REVOKED     = "revoked"
    SUSPENDED   = "suspended"
```

All inherit `str` for wire compatibility.

### 5.2 Sub-models

| Model | Fields |
|---|---|
| `MonetaryLimit` | `per_transaction ≥ 0`, `per_day ≥ 0`, `currency="USD"` — **both enforced** |
| `TimeWindow` | `start`, `end` |
| `Boundaries` | `allowed_actions[]`, `denied_actions[]`, `monetary_limit`, `asset_classes[]`, `geo_restriction`, `time_window` |
| `DelegationLink` | `from_id` (alias `from`), `to_id` (alias `to`), `scope`, `boundary_monotonicity=True`, `granted_at`, `expires_at` |
| `Principal` | `type="organization"`, `id`, `delegation_chain[]` |
| `AgentAttestation` | `method`, `framework_id`, `build_hash`, `system_prompt_hash`, `registry_signature` |
| `AgentIdentity` | `id`, `version`, `runtime="custos-sdk/1.0.0"`, `attestation` |
| `Intent` | `action: Action`, `target: str` (asset id), `parameters: dict` |
| `Proof` | `type="Ed25519Signature2020"`, `created`, `verification_method`, `proof_purpose`, `proof_value` |

`intent.parameters` carries `{"amount": <number>, "currency": "USD"}`. `amount` is the only
key the monetary boundary interprets, matching the blueprint.

### 5.3 `CustosEnvelope`

```python
class CustosEnvelope(BaseModel):
    context: str = Field(default="https://custos.protocol/v1", alias="@context")
    type: str    = Field(default="CustosEnvelope",             alias="@type")
    protocol_version: str = "1.0.0"

    agent: AgentIdentity
    principal: Principal
    intent: Intent
    boundaries: Boundaries

    verification_tier: VerificationTier = TIER_1
    entropy: str          # "nonce:" + 32 hex  → length 38
    ttl: int = 300        # 1 ≤ ttl ≤ 86400
    issued_at: datetime
    expires_at: datetime  # REQUIRED — see §11.1
    proof: Proof | None = None

    model_config = {"populate_by_name": True, "extra": "forbid"}
```

**Divergence from the blueprint:** `expires_at` is required and non-nullable. AIP permits
`None`, which produces an envelope that never expires; Custos rejects that at the schema
layer.

### 5.4 Domain models (unchanged in substance)

`Claim` and `Observation` move into `custos_protocol/models.py` with their current field sets.
`Observation` keeps `record_date` / `fetched_at` / `cache_hit` unchanged.

`Claim` gains **one** field: `asset_class: str` (e.g. `"treasury"`), which the
`asset_classes` boundary predicate in §11 reads. Seeded claims default it to `"treasury"`.
No other domain field changes.

### 5.5 `VerificationResult`

```python
class CheckOutcome(str, Enum):
    PASSED     = "passed"
    FAILED     = "failed"
    NOT_RUN    = "not_run"      # this tier does not perform this check

class VerificationResult(BaseModel):
    passed: bool                            # the single authority
    checks: dict[str, CheckOutcome]         # step name → outcome
    revocation: RevocationCheck
    trust_score: float = 0.0
    tier_used: VerificationTier
    scores: AssetScores | None = None       # staleness / drift / backing + thresholds
    reference: dict | None = None           # market evidence
    errors: list[CustosErrorCode] = []
    detail: str = ""
```

**Divergence:** the blueprint carries both `valid` and `passed`, with a documented trap where
Tier 0 force-sets `attestation_match=True` so that `passed` does not report `False` for a
legitimately accepted fast-path envelope. Custos removes the ambiguity entirely: there is no
`valid` field. `passed` is the single authority, and per-check state lives in `checks` as an
explicit three-valued outcome, so "this tier did not run that check" is representable without
lying about the result. A check that is `NOT_RUN` never contributes to `passed`.

`AssetScores` pairs every metric with the threshold applied to it — preserving the current
design's best property.

## 6. Canonical serialization

`custos_protocol/canonical.py`. The rules are normative and get their own conformance
category.

```
get_signable_payload(envelope):
    1. data = envelope.model_dump(mode="json", by_alias=True, exclude={"proof"})
    2. data = normalize_numbers(data)
    3. return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
```

| # | Rule | Prevents |
|---|---|---|
| 1 | Exclude `proof` | Signing your own signature |
| 2 | Whole floats → int (`500.0` → `500`) | Python/JavaScript byte divergence |
| 3 | Recursive lexicographic key sort | Dict-ordering differences |
| 4 | No whitespace | Pretty-printing differences |
| 5 | UTF-8 bytes | Encoding ambiguity |
| 6 | Datetimes ISO-8601 with `Z`, no fractional zeros | Cross-language formatting |
| 7 | Nulls emitted, never omitted | Presence ambiguity |
| 8 | Array order preserved (never sorted) | Semantic reordering |

**Divergence:** `normalize_numbers` **rejects non-finite floats** (`NaN`, `±inf`) at the
schema layer with `E103`, rather than crashing in the normalizer as the blueprint's
implementation does.

`Decimal` values are serialized as JSON strings by Pydantic before canonicalization,
preserving the exactness property the current gateway already has. This must be stated in
the conformance doc — it is the first thing a second implementation would get wrong.

## 7. Cryptography

`custos_protocol/crypto.py` — a thin wrapper over `cryptography`. No custom primitives.

| Function | Behaviour |
|---|---|
| `generate_keypair()` | Ed25519 private/public pair |
| `sign_data(priv, bytes) -> str` | 64-byte signature, **base64url** |
| `verify_signature(pub, bytes, sig) -> bool` | never raises; `False` on failure |
| `save_private_key` / `load_private_key` | PEM PKCS8, **optional passphrase** |
| `save_public_key` / `load_public_key` | PEM SubjectPublicKeyInfo |
| `public_key_to_b64` / `b64_to_public_key` | raw 32-byte, base64url |
| `generate_hmac_key()` / `hmac_sign` / `hmac_verify` | HMAC-SHA256, `compare_digest` |

Encoding is **base64url everywhere**, pinned by conformance vectors.

**Divergences:** private keys support encryption at rest (blueprint writes
`NoEncryption()`); `save_private_key` sets file mode `0600`; `verify_signature` catches
`InvalidSignature` specifically rather than bare `Exception`.

## 8. Passport

`custos_protocol/passport.py` — a plain class holding models plus live key objects.

`AgentPassport.create(domain, agent_name, allowed_actions=..., denied_actions=...,
monetary_limit_per_txn=..., monetary_limit_per_day=..., asset_classes=..., ...)`:

1. `agent_name` defaults to `agent-<8 hex>`.
2. DID synthesis: `did:web:{domain}:agents:{agent_name}`; principal `did:web:{domain}`.
3. Fresh Ed25519 keypair.
4. `AgentIdentity` with attestation method `FRAMEWORK_REGISTRY` iff `framework_id` given,
   else `SELF_REPORTED`.
5. `Principal` with one auto-generated delegation link `principal → agent`,
   `boundary_monotonicity=True`.
6. `Boundaries` from the flat kwargs.

Persistence writes `passport.json` + `private.pem` (mode `0600`) + `public.pem`. `load()`
resolves keys `private.pem` → `public.pem` → `passport.json["public_key"]`, yielding a
verify-only passport when the PEMs are absent.

## 9. Envelope construction and tier selection

`create_envelope(passport, action, target, parameters, tier=None, ttl=300)`.

**Tier auto-selection — divergence from the blueprint.** AIP uses a flat, currency-blind
`amount > 100`, which the blueprint itself documents as producing the opposite of the
intended risk ordering. Custos implements the risk-relative rule:

```
if action is not value-moving (READ):                        → TIER_0
if cross_org or first_contact:                               → TIER_2
if per_transaction > 0 and amount / per_transaction > 0.50:  → TIER_2
→ TIER_1
```

**Any value-moving action floors at Tier 1**, because asset truth runs at Tier 1+ and Custos
must never attest a transaction against an asset it did not check. Tier 0 is reachable only
by non-value-moving actions, so AIP's "small amount → Tier 0" branch has no Custos analogue
and is deliberately absent. The risk-relative rule therefore only decides Tier 1 vs Tier 2.

`sign_envelope(envelope, private_key, verification_method="")` returns a copy with `proof`
attached; the input is not mutated. `envelope_hash(env)` returns SHA-256 hex of the canonical
payload, usable as an idempotency key.

## 10. Verification pipeline

`custos_protocol/verification.py`:

```python
verify_intent(
    envelope, public_key, *,
    claim=None, observation=None,          # domain inputs, supplied by the caller
    revocation_store=None, trust_engine=None,
    min_trust_score=0.0, hmac_key=None,
    request_geo=None, registered_frameworks=None,
    known_build_hashes=None, known_prompt_hashes=None,
    max_revocation_staleness_ms=500,
    clock_skew_seconds=5,
) -> VerificationResult
```

**Divergence:** no module-level singletons. `revocation_store` and `trust_engine` default to
`None` and are constructed per-call if absent, or supplied explicitly. The blueprint's
process-global mutable defaults are a documented multi-tenancy hazard.

### 10.1 Steps

| # | Step | Tiers | Failure |
|---|---|---|---|
| 1 | `VERSION_CHECK` — `protocol_version ∈ {"1.0.0"}` | all | `E104` |
| 2 | `SCHEMA_CHECK` — non-empty action/agent id, finite numbers | all | `E103` |
| 3 | `EXPIRY_CHECK` — `expires_at`, with `clock_skew_seconds` grace | all | `E101` |
| 3b | `CLOCK_SKEW_CHECK` — `issued_at` not far future | all | `E106` |
| 4 | **`SIGNATURE_CHECK`** — HMAC iff Tier 0 and key supplied, else Ed25519 | all | `E100` |
| 5 | `NONCE_FORMAT` — `entropy` matches `^nonce:[0-9a-f]{32}$` | all | `E105` |
| 5b | `REPLAY_CHECK` — consumes the nonce | all | `E102` |
| 6 | `BOUNDARY_CHECK` — accumulates all violations | all | `E2xx` |
| 7 | `REVOCATION_CHECK` — agent + issuer, fails closed if stale | all | `E400`/`E401`/`E402`/`E405` |
| — | **Tier 0 exits** | | |
| 8 | **`ASSET_TRUTH_CHECK`** — staleness, yield drift, backing | T1, T2 | `E3xx` |
| 9 | `ATTESTATION_CHECK` — build/prompt hash, framework registry | T1, T2 | `E306` (opt-in) |
| — | **Tier 1 exits** | | |
| 10 | `DELEGATION_CHECK` — continuity, endpoints, expiry, monotonicity | T2 | `E403` |
| 11 | `TRUST_SCORE_CHECK` | T2 | `E404` |
| — | **Tier 2 exits** | | |

**Ordering divergences from the blueprint, both deliberate:**

- **Signature (4) precedes replay (5b).** AIP checks replay first, which lets an
  unauthenticated attacker burn a victim's nonce with a garbage envelope. Checking the
  signature first closes it.
- **Revocation is not staleness-gated into a pass.** See §14.

Failure is fail-fast except `BOUNDARY_CHECK`, which accumulates every violation so one
envelope can return `[ACTION_DENIED, MONETARY_LIMIT_PER_DAY, GEO_RESTRICTION]`.

## 11. Boundary enforcement

`custos_protocol/boundaries.py`. Predicates, in order:

```
1. action ∈ denied_actions                              → E201  (deny wins)
2. allowed_actions non-empty and action ∉ it            → E200
3. amount > per_transaction  (when per_transaction > 0) → E202
4. day_total + amount > per_day (when per_day > 0)      → E203   ← enforced
5. time_window and now ∉ [start, end]                   → E204
6. geo_restriction and request_geo ∉ allowed set        → E205
7. asset_classes non-empty and claim.asset_class ∉ it   → E206   ← enforced
```

**Divergences from the blueprint:**

- **`per_day` is enforced**, via a rolling-window ledger on the trust/accounting store keyed
  by `agent_id`. AIP signs the field and ignores it.
- **`asset_classes` is enforced** (AIP's analogous `data_access` is ignored).
- **Negative amounts are rejected** at the schema layer rather than silently passing every
  monetary comparison.
- `per_transaction == 0` continues to mean "no limit", matching the blueprint, but the
  passport constructor warns when a value-moving action list is combined with a zero limit.

Empty `allowed_actions` means "allow everything" — preserved from the blueprint, and
documented as a footgun rather than changed, because changing it would make every
minimally-configured passport fail closed in a way the blueprint's semantics do not.

On failure `trust.record_violation(agent_id)` fires before returning.

## 12. Asset truth (`drift.py`)

The layer that replaces AIP's intent-drift classifier and carries Custos's actual value.
Pure function, no I/O:

```python
def check_asset_truth(envelope, claim, observation, config) -> AssetScores | AssetTruthFailure
```

Ordered, short-circuiting — the returned code names the most fundamental problem:

| # | Guard | Code |
|---|---|---|
| 1 | `claim is None` | `E303` UNKNOWN_ASSET |
| 2 | `observation is None` | `E500` ORACLE_UNAVAILABLE (fail closed) |
| 3 | observation older than `MAX_OBSERVATION_AGE_DAYS` | `E501` |
| 4 | `last_attested_at` more than skew grace in the future | `E305` CLAIM_FUTURE_DATED |
| 5 | staleness > threshold | `E300` CLAIM_STALE |
| 6 | `observed_yield_bps < 0` | `E501` (invalid market data) |
| 7 | drift > threshold | `E301` YIELD_DRIFT_EXCEEDED |
| 8 | backing ratio < floor | `E302` BACKING_RATIO_BELOW_FLOOR |

**Divergences from the current implementation** (carried over from `ARCHITECTURE.md`
findings, since we are writing this file fresh):

- **Future-dated claims are rejected** (guard 4). The current `max(0.0, …)` clamp lets a
  claim dated in the future report zero staleness and pass.
- **A zero observed yield is legal.** The current code treats `observed_bps <= 0` as an
  oracle fault, which misreports a legitimate 0.00% bill print — Treasury bills printed
  0.00–0.02% through 2020–2021. Only a *negative* value is an error (guard 6).

  Because relative drift is undefined when `observed == 0`, the check falls back to an
  absolute comparison: `abs(claimed_bps - observed_bps) > ZERO_YIELD_ABS_TOLERANCE_BPS`
  → `E301`, where `ZERO_YIELD_ABS_TOLERANCE_BPS` defaults to **10 bps** and lives on
  `DriftConfig`. Rationale: at a 0.00% print, a claim asserting anything above ~0.10% is
  materially implausible, and no relative threshold can express that. `AssetScores` records
  `yield_drift_basis: "relative" | "absolute"` so the attestation states which rule applied.

Thresholds come from a `DriftConfig` value object passed in, not read from a module-level
`config` import — the layer must be testable without environment variables.

## 13. Attestation

`custos_protocol/attestation.py`. Two record types, both signed:

- `Attestation` — verdict `ALLOW`, plus `scores`, `reference`, `tier_used`, `issued_at`,
  `expires_at`, `proof`.
- `Denial` — verdict `BLOCK`, plus `errors[]`, `detail`, whatever `scores` were computed,
  `issued_at`, `proof`.

**Divergence:** denials are signed. The current gateway signs only ALLOW, which means a
relying party cannot prove it was denied — a gap for the compliance use case in
`utilisation.md` §7F. Signing costs ~33 µs (measured).

Both carry `signature_alg` and `canonicalization` inside the signed payload.

## 14. Revocation and replay

`custos_protocol/revocation.py` — thread-safe, holds the kill switch and the nonce cache.

`RevocationRecord(subject_id, subject_type, reason, revoked_at, revoked_by, scope,
suspended_until)` where `subject_type ∈ {agent, issuer}`. `suspended_until is None` means
permanent.

API: `revoke`, `suspend`, `is_revoked`, `is_suspended`, `reinstate`, `get_record`,
`rehydrate`, `touch_sync`, `last_sync_time`, `check_nonce`, `clear_nonces`.

**Divergences from the blueprint — the most important in this document:**

- **Stale revocation data fails closed.** AIP returns `NOT_REVOKED` with
  `confidence="weak"` when the store has not synced within 500 ms, which the blueprint's own
  audit identifies as its highest-severity finding — revoking an organisation stops working
  ~500 ms later. Custos emits **`E405 REVOCATION_STALE`** and rejects.
- **Issuer revocation is checked at every tier**, next to agent revocation, not only inside
  a staleness-gated deep path. It emits its own code `E402`.
- **Nonce cache is a `FIFO`/`OrderedDict` with time-based expiry** keyed by insertion time,
  evicting by age first and pressure second. AIP uses a `set` with arbitrary eviction, giving
  a probabilistic replay hole past the cap. Retention ≥ max envelope TTL.

## 15. Trust

`custos_protocol/trust.py`. Tracks `AgentHistory(total_intents, successful_intents,
boundary_violations, revocation_count, attestation_changes, delegation_depth, first_seen,
last_seen)` plus the per-day monetary ledger backing `E203`.

```
T(a) = 0.35·completion_rate
     + 0.25·(1 − violation_rate)
     + 0.15·max(0, 1 − 0.30·revocations)
     + 0.10·max(0, 1 − 0.15·attestation_changes)
     + 0.05·max(0, 1 − 0.20·(delegation_depth − 1))
     + 0.10·min(1, total_intents / 100)
```

Clamped `[0,1]`, 4 dp, `0.0` when `total_intents == 0`.

**Divergences:** `delegation_depth` is **actually derived** from the envelope's chain length
(the blueprint hardcodes 1, making the term permanently inert); the score is documented as a
*weighted behavioural score*, not "Bayesian"; the gate calls a single `meets_threshold()`
rather than re-implementing the comparison inline.

Issuer-level trust reuses the same engine keyed by `claim.issuer`, feeding a future
issuer-reputation signal. Recorded but not gated in phase 2.

## 16. Error taxonomy

`custos_protocol/errors.py` — 30 codes, five families, each with a name, description, and
HTTP status.

### 16.1 The codes

| Code | Name | HTTP | Emitted at |
|---|---|---|---|
| `CUSTOS-E100` | `INVALID_SIGNATURE` | 401 | step 4 |
| `CUSTOS-E101` | `EXPIRED_ENVELOPE` | 400 | step 3 |
| `CUSTOS-E102` | `REPLAY_DETECTED` | 409 | step 5b |
| `CUSTOS-E103` | `SCHEMA_INVALID` | 400 | step 2 / parse |
| `CUSTOS-E104` | `VERSION_UNSUPPORTED` | 400 | step 1 |
| `CUSTOS-E105` | `NONCE_INVALID` | 400 | step 5 |
| `CUSTOS-E106` | `CLOCK_SKEW` | 400 | step 3b |
| `CUSTOS-E200` | `ACTION_NOT_ALLOWED` | 403 | boundary |
| `CUSTOS-E201` | `ACTION_DENIED` | 403 | boundary |
| `CUSTOS-E202` | `MONETARY_LIMIT_PER_TXN` | 403 | boundary |
| `CUSTOS-E203` | `MONETARY_LIMIT_PER_DAY` | 403 | boundary |
| `CUSTOS-E204` | `TIME_WINDOW_VIOLATION` | 403 | boundary |
| `CUSTOS-E205` | `GEO_RESTRICTION` | 403 | boundary |
| `CUSTOS-E206` | `ASSET_CLASS_NOT_ALLOWED` | 403 | boundary |
| `CUSTOS-E300` | `CLAIM_STALE` | 403 | asset truth |
| `CUSTOS-E301` | `YIELD_DRIFT_EXCEEDED` | 403 | asset truth |
| `CUSTOS-E302` | `BACKING_RATIO_BELOW_FLOOR` | 403 | asset truth |
| `CUSTOS-E303` | `UNKNOWN_ASSET` | 404 | asset truth |
| `CUSTOS-E304` | `TENOR_UNSUPPORTED` | 422 | asset truth |
| `CUSTOS-E305` | `CLAIM_FUTURE_DATED` | 403 | asset truth |
| `CUSTOS-E306` | `ATTESTATION_MISMATCH` | 403 | attestation |
| `CUSTOS-E400` | `AGENT_REVOKED` | 403 | revocation |
| `CUSTOS-E401` | `AGENT_SUSPENDED` | 403 | revocation |
| `CUSTOS-E402` | `ISSUER_REVOKED` | 403 | revocation |
| `CUSTOS-E403` | `DELEGATION_INVALID` | 403 | delegation |
| `CUSTOS-E404` | `TRUST_SCORE_LOW` | 403 | trust |
| `CUSTOS-E405` | `REVOCATION_STALE` | 503 | revocation |
| `CUSTOS-E500` | `ORACLE_UNAVAILABLE` | 503 | asset truth |
| `CUSTOS-E501` | `ORACLE_DATA_STALE` | 503 | asset truth |
| `CUSTOS-E502` | `DOWNSTREAM_UNREACHABLE` | 502 | gateway proxy |

**Every code must be emitted by at least one test.** The blueprint ships 4 of 23 codes dead;
a conformance test asserts Custos has none.

### 16.2 Migration from today's codes

Breaking. Every code changes number; all eleven survive semantically.

| Old | New |
|---|---|
| `E100 MALFORMED_ENVELOPE` | `E103 SCHEMA_INVALID` |
| `E101 CLAIM_STALE` | `E300 CLAIM_STALE` |
| `E102 INTENT_EXPIRED` | `E101 EXPIRED_ENVELOPE` |
| `E103 CLOCK_SKEW` | `E106 CLOCK_SKEW` |
| `E200 UNKNOWN_ASSET` | `E303 UNKNOWN_ASSET` |
| `E201 YIELD_DRIFT_EXCEEDED` | `E301 YIELD_DRIFT_EXCEEDED` |
| `E202 BACKING_RATIO_BELOW_FLOOR` | `E302 BACKING_RATIO_BELOW_FLOOR` |
| `E203 TENOR_UNSUPPORTED` | `E304 TENOR_UNSUPPORTED` |
| `E300 ORACLE_UNAVAILABLE` | `E500 ORACLE_UNAVAILABLE` |
| `E301 ORACLE_DATA_STALE` | `E501 ORACLE_DATA_STALE` |
| `E400 DOWNSTREAM_UNREACHABLE` | `E502 DOWNSTREAM_UNREACHABLE` |

## 17. Gateway surface

`gateway/` becomes a thin adapter: parse → resolve domain inputs → `verify_intent` → render.

| Method | Path | Phase | Behaviour |
|---|---|---|---|
| `POST` | `/v1/intent` | 1 | Parse `CustosEnvelope`; resolve claim + observation; `verify_intent`; sign `Attestation` or `Denial`; optional downstream forward |
| `GET` | `/v1/assets` | 1 | Seeded claims |
| `GET` | `/v1/assets/{id}` | 1 | Claim + observation + asset-truth evaluation, executing nothing |
| `GET` | `/v1/pubkey` | 1 | Gateway Ed25519 key |
| `GET` | `/v1/health` | 1 | Oracle reachability |
| `GET` | `/demo` | 1 | Browser demo |
| `POST` | `/v1/revocations` | 2 | Revoke/suspend an agent or issuer |
| `DELETE` | `/v1/revocations/{id}` | 2 | Reinstate |
| `GET` | `/v1/trust/{agent_id}` | 2 | Current trust score and history |

**Divergence:** `POST /v1/demo/sync` moves behind a `CUSTOS_DEMO_MODE` env flag onto a
router mounted only in demo mode — it is currently an unauthenticated state-mutation
endpoint in the public schema.

The gateway keeps its signing key as a process singleton but constructs `RevocationStore`
and `TrustEngine` explicitly at startup and injects them, so tests and multi-tenant
deployments can substitute them.

## 18. Testing strategy

TDD throughout. Test suites per layer:

| Suite | Covers |
|---|---|
| `test_canonical.py` | All 8 rules, byte-exact fixtures, non-finite rejection |
| `test_crypto.py` | Sign/verify round trip, base64url pinning, tamper rejection, encrypted PEM, file mode |
| `test_models.py` | Schema constraints, aliases, `extra="forbid"`, required `expires_at` |
| `test_passport.py` | DID synthesis, save/load, verify-only passport, key precedence |
| `test_envelope.py` | Construction, signing immutability, `envelope_hash` determinism, tier selection table |
| `test_boundaries.py` | All 7 predicates, accumulation, per-day ledger, empty-allowlist semantics |
| `test_drift.py` | All 8 guards, ordering/short-circuit, boundary values, future-dated claim, zero yield |
| `test_verification.py` | Step order, tier gating, fail-fast, signature-before-replay |
| `test_revocation.py` | Kill switch both subject types, suspension expiry, **fail-closed staleness**, FIFO nonce eviction, time expiry |
| `test_trust.py` | Formula, worked example, delegation depth derivation, threshold gate |
| `test_delegation.py` | Continuity, endpoints, expiry, **monotonicity enforcement** |
| `test_gateway.py` | Every route, every error code → HTTP status, independent verification |
| `test_architecture.py` | Import-graph rules from §4.2 |
| `conformance/` | Frozen vectors incl. a published reference canonical payload |

Two suite-level invariants:
- **Every error code is emitted by a test.** Asserted programmatically over `CustosErrorCode`.
- **The import graph is enforced by test**, not convention.

Packaging gets a `pyproject.toml` so bare `pytest` works (currently only `python -m pytest`
does).

## 19. Phase plan

### Phase 1 — protocol core
`errors`, `crypto`, `canonical`, `models`, `passport`, `envelope`, `boundaries`, `drift`,
`attestation`, `revocation`, `verification` (steps 1–9, Tier 0/1), gateway rebuilt, tests and
demos rewritten, `pyproject.toml`.

`revocation.py` lands in phase 1 rather than phase 2 because **steps 5b (replay) and 7
(revocation) run at every tier**, including Tier 0 — a phase-1 gateway without them would
ship a pipeline with two permanent holes. Phase 1 therefore includes the kill switch, the
FIFO nonce cache, and fail-closed staleness. Only the *routes* that administer revocations
are deferred to phase 2.

Boundary predicate 4 (`E203 MONETARY_LIMIT_PER_DAY`) is **deferred to phase 2**, because it
requires the rolling-window ledger that lives on the trust store. Phase 1 ships predicates
1, 2, 3, 5, 6 and 7; `E203` exists in the taxonomy but is the one code without a test until
phase 2, and the "every code is emitted by a test" invariant is asserted with `E203`
explicitly exempted until then.

**Exit criteria:** full test suite green; `POST /v1/intent` serves signed ALLOW and signed
BLOCK against the new envelope; replay of a spent nonce is rejected; a revoked agent is
blocked at Tier 0; `demo/run_local_demo.py` shows four deterministic outcomes; import-graph
test passes.

### Phase 2 — trust layer
`trust` (score + per-day ledger), `delegation` (+ monotonicity enforcement), boundary
predicate 4, verification steps 10–11 and Tier 2, revocation/trust gateway routes.

**Exit criteria:** Tier 2 path green; revoking an issuer blocks immediately and stays
blocking past the staleness window; per-day limit enforced across requests; delegation
monotonicity rejects a widening chain; every code including `E203` covered by a test.

### Phase 3 — DX surfaces
`shield`, `observe`, `cli`, `conformance/` vectors + runner.

**Exit criteria:** conformance runner passes all vectors; `observe` proven structurally
incapable of blocking (import-graph test); `custos` CLI can create a passport, sign an
envelope, and verify one offline.

## 20. Risks

| Risk | Mitigation |
|---|---|
| Scope: ~10× current codebase | Three phases, each ending green and runnable |
| Breaking every existing test/demo/doc at once | Phase 1 rewrites them in the same pass; no half-migrated state |
| Divergences from the blueprint accumulate silently | §5–§15 each name their divergences explicitly; the spec is the record |
| The parked oracle bug makes phase-1 demos fail | Demos substitute the oracle, as they do today; the fix is independent and can land any time |
| Per-day ledger needs cross-request state | Lives in the injected trust store; documented as in-memory, non-persistent in phase 2 |
