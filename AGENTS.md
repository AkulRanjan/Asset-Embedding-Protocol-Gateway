# Custos implementation contract

Keep dependencies one-way. `custos_protocol` is the SDK and imports nothing from the
application: not `gateway`, not `claims`, not `oracle`. Within it, `errors`, `crypto` and
`canonical` are leaves; `models` depends only on leaves; feature modules (`passport`,
`envelope`, `boundaries`, `drift`, `attestation`, `revocation`, `trust`, `delegation`) depend
on `models`; `verification` is the only module that composes everything. `shield` and `cli`
depend on `verification`; `observe` depends only on `passport` and must never import
`verification` — observability is structurally incapable of blocking a call, not just
incapable by convention. There is no dependency on the AIP blueprint that inspired this
architecture; it is external prior art, not a library in this repo.

`custos_protocol` performs no I/O beyond local file access (`passport.py` reads/writes PEMs;
`cli.py` reads/writes files): no environment reads, no network. Configuration arrives as value
objects (`DriftConfig`, `DelegationConfig`); the environment is read only in
`gateway/config.py`. Network calls against a live gateway live in a separate module,
`gateway/admin_cli.py`, never in `custos_protocol`.

These rules are enforced by `tests/test_architecture.py`, not by convention.

## Fixed data contracts

- `CustosEnvelope`: `@context="https://custos.protocol/v1"`, `@type="CustosEnvelope"`,
  `protocol_version="1.0.0"`, an `AgentIdentity`, a `Principal`, an `Intent`, the agent's
  `Boundaries`, a `nonce:<32 hex>` entropy value, aware-UTC `issued_at` and a **required**
  `expires_at`, and a detached Ed25519 `Proof`.
- `Claim`: asset identifier, issuer, Treasury tenor, asset class, claimed NAV/backing/tokens/yield,
  and last-attested timestamp.
- `Observation`: source, tenor, observed yield in integer bps, record date, fetch time, cache flag.
- Both verdicts are signed. ALLOW returns an `Attestation`, BLOCK returns a `Denial`; both carry
  a `proof` and both use the `CUSTOS-Exxx` taxonomy.

## Evaluation contract

`verify_intent(envelope, public_key, *, claim, observation, trust_engine, ...) -> VerificationResult`

Step order is API surface, not an implementation detail:
version, schema, expiry, clock skew, **signature**, nonce format, replay, boundaries,
revocation — then, at Tier 1+, asset truth and attestation — then, at Tier 2, delegation
(continuity, endpoints, expiry, depth, and real boundary monotonicity — a delegated hop may
never widen the authority it was granted) and the trust score gate. Signature precedes replay
so an unauthenticated caller cannot burn another agent's nonce. Trust bookkeeping only fires
after signature verification passes — a pre-auth failure can never pollute another agent's
trust history by spoofing its id. Never fail open.

The rolling per-day monetary ledger backing `E203` is reservation-based
(`TrustEngine.reserve_amount`/`release_amount`), not a separate read-then-write: two
concurrent requests for the same agent must never both pass a stale `day_total` and together
exceed the limit. `boundaries.py` stays a pure function — it receives `day_total` as a
parameter, never imports `trust.py` itself.

Asset truth short-circuits in this order: E303 unknown asset, E500 no observation,
E501 observation too old, E305 future-dated claim, E300 stale claim, E501 negative yield,
E301 drift, E302 backing.

`passed` is the single authority on the outcome — there is no `valid` field. `checks` is a
three-valued map (`passed` / `failed` / `not_run`) so a skipped check is representable
without lying about it.

## Error codes

Thirty codes in five families, defined in `custos_protocol/errors.py`:
`E1xx` envelope/protocol, `E2xx` boundary, `E3xx` asset truth, `E4xx` revocation/delegation/trust,
`E5xx` infrastructure. Do not invent new ones. All 30 are implemented; every one is exercised
by a test (`tests/test_architecture.py`'s `UNREACHABLE_IN_PHASE_1` exemption set is empty) and
by a conformance vector, except `E304` and `E502`, which are gateway/oracle integration
concerns `verify_intent` itself never emits — documented in
`conformance/vectors.json`'s `_meta.excluded_codes`.

## Signing contract

Canonicalize with `custos_protocol/canonical.py`: exclude `proof`, collapse whole floats to
ints, sort keys recursively, no whitespace, UTF-8 bytes, ISO-8601 `Z` datetimes, emit nulls,
preserve array order. Sign the resulting bytes with Ed25519; encode keys and signatures as
base64url. Verify against a **pinned** key fetched out of band from `GET /v1/pubkey` — the
`public_key` embedded in a record authenticates nothing. Keep `demo/verify_attestation.py`
independent of application modules; it is the second implementation that proves the canonical
form is portable. `conformance/` formalizes this further: every SDK-reachable error code and
every canonical-form rule has a byte-pinned vector, checked in `tests/test_conformance.py` and
runnable standalone via `conformance/run_conformance.py`. Read
`conformance/CANONICAL_SERIALIZATION.md` before changing anything in `canonical.py`.

## DX surfaces

`shield.py`'s `protect`/`shield`/`protect_agent` and `observe.py`'s `observe`/`observe_class`/
`observe_agent` are documented adaptations of a reference implementation's enforcement and
observability decorators — each divergence from that reference exists to close a bug that
reference has (see the module docstrings), except one kept deliberately: `@shield` on a class
leaves methods absent from its `actions` mapping completely unwrapped, not blocked. `cli.py`
is offline-only (no `httpx`, no `os.getenv` — same rule as the rest of `custos_protocol`);
`gateway/admin_cli.py` is the separate, networked CLI for the routes that need a live gateway
(`register-agent`, `revoke`, `reinstate`, `trust`, `register-framework`).
