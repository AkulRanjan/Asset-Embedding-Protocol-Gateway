# Custos implementation contract

Keep dependencies one-way. `custos_protocol` is the SDK and imports nothing from the
application: not `gateway`, not `claims`, not `oracle`. Within it, `errors`, `crypto` and
`canonical` are leaves; `models` depends only on leaves; feature modules depend on `models`;
`verification` is the only module that composes everything. There is no dependency on the
AIP SDK — `ARCHITECTURE1.md` is a blueprint, not a library.

`custos_protocol` performs no I/O. Configuration arrives as value objects (`DriftConfig`);
the environment is read only in `gateway/config.py`.

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

`verify_intent(envelope, public_key, *, claim, observation, ...) -> VerificationResult`

Step order is API surface, not an implementation detail:
version, schema, expiry, clock skew, **signature**, nonce format, replay, boundaries,
revocation — then, at Tier 1+, asset truth and attestation. Signature precedes replay so an
unauthenticated caller cannot burn another agent's nonce. Never fail open.

Asset truth short-circuits in this order: E303 unknown asset, E500 no observation,
E501 observation too old, E305 future-dated claim, E300 stale claim, E501 negative yield,
E301 drift, E302 backing.

`passed` is the single authority on the outcome — there is no `valid` field. `checks` is a
three-valued map (`passed` / `failed` / `not_run`) so a skipped check is representable
without lying about it.

## Error codes

Thirty codes in five families, defined in `custos_protocol/errors.py`:
`E1xx` envelope/protocol, `E2xx` boundary, `E3xx` asset truth, `E4xx` revocation/delegation/trust,
`E5xx` infrastructure. Do not invent new ones. Every implemented code is exercised by a test;
`E203`, `E306`, `E403` and `E404` are documented as unreachable until Phase 2.

## Signing contract

Canonicalize with `custos_protocol/canonical.py`: exclude `proof`, collapse whole floats to
ints, sort keys recursively, no whitespace, UTF-8 bytes, ISO-8601 `Z` datetimes, emit nulls,
preserve array order. Sign the resulting bytes with Ed25519; encode keys and signatures as
base64url. Verify against a **pinned** key fetched out of band from `GET /v1/pubkey` — the
`public_key` embedded in a record authenticates nothing. Keep `demo/verify_attestation.py`
independent of application modules; it is the second implementation that proves the canonical
form is portable.
