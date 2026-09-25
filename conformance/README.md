# Custos conformance suite

This is what turns `custos_protocol` from "a Python library" into "a candidate
protocol": a fixed set of inputs and expected outputs that a second
implementation, in any language, can check itself against without ever
reading the Python source.

```
conformance/
├── vectors.json                 50 vectors + _meta (key material, exclusions, spec version)
├── generate_vectors.py          the reference generator (Python) — regenerating must be
│                                 byte-for-byte reproducible; see tests/test_conformance.py
├── run_conformance.py           the reference runner (Python)
├── CANONICAL_SERIALIZATION.md   the normative byte-level spec — read this first
└── README.md                    this file
```

## Quickstart

```bash
PYTHONPATH=. python conformance/run_conformance.py
```

```
Custos Conformance Suite
Spec: custos-conformance/1.0.0 | Vectors: 50 | Generated: 2026-09-25T12:00:00+00:00
  ALL 50 VECTORS PASSED
```

## What's fixed, so every implementation reproduces the same bytes

| Key | Seed (32 bytes, hex) | Role |
|---|---|---|
| `agent_1` | `aa` × 32 | primary signer; used for almost every vector |
| `agent_2` | `bb` × 32 | wrong-key tests (`B02`) |
| `hmac` | `cc` × 32 | Tier 0 HMAC (`B04`) |

Full public keys are in `vectors.json`'s `_meta.keys`. A fixed clock,
`T_NOW = 2026-09-25T12:00:00Z`, is used everywhere a vector needs "now" —
passed explicitly into `verify_intent(..., now=...)`, never read from the
system clock. Nonces are a monotonic counter formatted `nonce:{n:032x}`, so
they are always exactly 38 characters and strictly increasing across the
generation run.

**One exception, and it's a deliberate one:** vector `F06` (revocation
staleness) measures elapsed *real* time since a store's last sync — an
operational property, not an envelope timestamp, so it cannot be simulated
with an injected clock. `run_conformance.py` sleeps `requires_sleep_ms`
(pinned in the vector) before verifying, exactly as
`tests/test_verification.py::test_stale_revocation_data_fails_closed` already
does for the same check. Every other vector is pure data.

## Vector categories

| Cat | What it exercises | Codes |
|---|---|---|
| A | Envelope validity — version, expiry, clock skew, nonce format | `E101`, `E104`–`E106` |
| B | Signature — valid Ed25519, wrong key, tampered payload, valid HMAC (Tier 0) | `E100` |
| C | Replay — fresh nonce, duplicate nonce (`verify_twice: true`) | `E102` |
| D | Schema — the semantic minimums Pydantic doesn't already cover | `E103` |
| E | Boundary — action allow/deny, per-transaction and per-day limits, time window, geo, asset class | `E200`–`E206` |
| F | Revocation — clean, revoked (incl. at Tier 0), suspended, issuer revoked, stale-store fail-closed | `E400`–`E402`, `E405` |
| G | Asset truth — unknown asset, no/stale observation, future-dated claim, stale claim, negative yield, drift, backing ratio, the zero-yield absolute-tolerance edge case | `E300`–`E303`, `E305`, `E501` |
| H | Delegation — continuity, expiry, **real boundary monotonicity** (a hop cannot widen its authority) | `E403` |
| I | Trust — the score gate, inert at the default threshold | `E404` |
| J | Attestation — opt-in, unregistered framework, build-hash mismatch, prompt-hash mismatch | `E306` |
| K | Serialization — byte-exact canonical payloads; read `CANONICAL_SERIALIZATION.md` first | — |

**`E304 TENOR_UNSUPPORTED` and `E502 DOWNSTREAM_UNREACHABLE` are intentionally
absent.** Both are gateway/oracle integration concerns — `verify_intent`
itself never emits either one (grep the Python source; they only appear in
`gateway/server.py`). An SDK-level conformance suite has nothing to say about
them. `vectors.json`'s `_meta.excluded_codes` records this, and
`tests/test_conformance.py::test_every_sdk_reachable_error_code_has_a_vector`
enforces that every *other* code has at least one vector — the same
discipline `tests/test_architecture.py` already applies to the Python test
suite itself.

## Vector shape

Two shapes, by `category`:

**Pipeline vectors** (everything except `serialization`) carry a signed
envelope plus whatever auxiliary state the pipeline needs — `claim`/
`observation` (optional, for Tier 1+), `revocations` (a list of
revoke/suspend operations to apply before verifying), `now`, `hmac_key`
(optional), `verify_twice` (for replay), `day_total_seed` (pre-seeds the
per-day ledger, for `E203`), `min_trust_score`, `request_geo`,
`registered_frameworks`/`known_build_hashes`/`known_prompt_hashes` (for
`E306`). `expected` is `{passed, tier_used, errors}` — reconstruct every
input from JSON, run your implementation's equivalent of `verify_intent`, and
diff the result against `expected`.

**Serialization vectors** carry `payload_input` (a plain JSON object),
`exclude` (top-level keys to strip, rule 1), and `canonical_payload_hex` — the
expected output of your implementation's `canonical_bytes(payload_input,
exclude)`, as hex. Byte-diff on any mismatch; `run_conformance.py` reports the
first differing offset with 20 bytes of surrounding context on both sides.

## Porting to a new language

1. Read `CANONICAL_SERIALIZATION.md` in full before writing a verifier. Get
   the `serialization` vectors (`K01`–`K05`) passing byte-for-byte before
   touching signatures — nothing downstream can be correct if this isn't.
2. Implement Ed25519 sign/verify with base64url encoding (`-`/`_` alphabet,
   padding retained) — pin against `vectors.json`'s `_meta.keys` public keys
   and the `signature` category.
3. Implement the ordered `verify_intent` pipeline from
   `docs/superpowers/specs/2026-08-21-custos-aip-architecture-design.md` §10 —
   the step order is API surface, not an implementation detail. Signature
   precedes replay deliberately (an unauthenticated caller must not be able to
   burn a nonce); boundaries accumulate every violation rather than
   short-circuiting on the first one.
4. Work through the remaining categories in order — each one is
   self-contained and only depends on categories before it in this table.
5. Run every vector. A partial pass (e.g. "27/28 codes") means something is
   still wrong; there is no code in this suite that is "close enough."

## Regenerating vectors

Only do this after changing `custos_protocol` itself (a new error code, a
changed threshold). `PYTHONPATH=. python conformance/generate_vectors.py`
must produce a byte-identical `vectors.json` on a clean checkout — if it
doesn't, something reads the real wall clock or introduces nondeterminism,
and `tests/test_conformance.py::test_regenerating_the_vectors_is_byte_for_byte_reproducible`
will fail and say so.
