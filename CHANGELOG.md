# Changelog

All notable changes to this project are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-09-26

The first complete release: protocol core, trust layer, and DX surfaces, all
built and shipped in one continuous line of work. Full design history is in
`docs/design/specs/`.

### Added — protocol core

- `custos_protocol/`, a standalone SDK with zero dependency on `gateway/`,
  `claims/`, or `oracle/`: `errors` (30-code `CUSTOS-Exxx` taxonomy),
  `crypto` (Ed25519 + HMAC-SHA256, base64url), `canonical` (the byte-stable
  signable payload — the interop core), `models` (every wire and domain
  model, including the JSON-LD-flavored `CustosEnvelope`), `passport`
  (DID identity + keypair + boundary cage), `envelope` (construction,
  signing, risk-relative tier selection), `boundaries` (action/monetary/
  time/geo/asset-class predicates), `drift` (the asset-truth engine —
  staleness, yield drift, backing ratio), `attestation` (signed `Attestation`
  and `Denial` records — both verdicts signed, not just approvals),
  `revocation` (kill switch + FIFO nonce replay cache, fails closed on stale
  data), and `verification` (`verify_intent()`, the only module that
  composes everything).
- `gateway/`, a thin FastAPI adapter: `POST /v1/intent`, `POST /v1/agents`,
  `GET /v1/assets`, `GET /v1/assets/{id}`, `GET /v1/pubkey`,
  `GET /v1/health`, plus a demo-mode-only sync route.
- Deliberate divergences from the AIP blueprint this design is modeled on,
  each closing a documented defect in that reference: signature verification
  before replay checking (so a forged envelope can't burn a victim's nonce),
  revocation that fails closed on stale data instead of open, a
  `passed`-only verdict with a three-valued `checks` map instead of a
  `valid`/`passed` pair that can silently disagree, required `expires_at`,
  and risk-relative (not flat-threshold) tier auto-selection.
- `conformance`-grade admin authentication: state-changing control-plane
  routes require `X-Custos-Admin-Key`, fails closed if unconfigured.

### Added — trust layer

- `custos_protocol/trust.py`: the pinned behavioral trust score formula,
  and a reservation-based rolling per-day monetary ledger
  (`reserve_amount`/`release_amount`) that closes a TOCTOU race a simpler
  read-then-write ledger would have under concurrent requests.
- `custos_protocol/delegation.py`: full delegation-chain validation —
  continuity, endpoint binding, expiry, depth limits, and **real boundary
  monotonicity** (a delegated hop can never widen the authority it was
  granted — this is enforced, not just a decorative flag).
- Real attestation-hash checking (`CUSTOS-E306`) against admin-registered
  framework and build/prompt hashes.
- Tier 2 now actually executes delegation and trust checks, and reports
  `tier_used=TIER_2` only when it genuinely did.
- New admin routes: `POST /v1/frameworks`, `POST /v1/attestations/hashes`,
  `POST /v1/revocations`, `DELETE /v1/revocations/{subject_id}`, and the
  public `GET /v1/trust/{agent_id}`.
- All 30 error codes are now live; the Phase-1 exemption list is empty.

### Added — DX surfaces

- `custos_protocol/shield.py`: `protect`/`shield`/`protect_agent` (+
  aliases), a one-liner enforcement decorator with sync and async support,
  fixing six documented bugs in the reference implementation this is
  modeled on (shared global stores, hardcoded tiers, unsafe `dir()`
  enumeration, and more — see the module docstring) while deliberately
  keeping one behavior unchanged: a class-level `@shield` leaves methods
  absent from its configuration completely unwrapped.
- `custos_protocol/observe.py`: `observe`/`observe_class`/`observe_agent`,
  a one-liner observability decorator, structurally incapable of blocking a
  call (enforced by an import-graph test) and defaulting to *not* capturing
  call arguments (a safer default than the reference implementation).
- `custos_protocol/cli.py`: the offline `custos` CLI —
  `create-passport`, `sign-intent`, `verify` (exit 0/1, CI-friendly),
  `inspect`. No network access, no environment reads.
- `gateway/admin_cli.py`: the separate, networked `custos-admin` CLI for
  the routes that need a live gateway.
- `conformance/`: 50 vectors covering every one of the 28 error codes
  `verify_intent` can reach, a deterministic generator and reference runner,
  the normative `CANONICAL_SERIALIZATION.md`, and a porting guide.
  Regenerating the vectors is verified byte-for-byte reproducible.

### Fixed

- `claims/registry.py`'s `update_claim` bypassed Pydantic validation
  (`model_copy` skips validators); it now re-validates, so a negative yield
  or zero `tokens_outstanding` can never be installed.
- The gateway's schema-error handler discarded every per-field validation
  message; it now surfaces them, without ever echoing submitted input back.
- `CustosEnvelope` had no cap on `expires_at - issued_at` for a hand-built
  envelope that bypasses the `ttl` field; now bounded to the same 86400s
  ceiling `ttl` itself enforces.
- `TimeWindow` and `DelegationLink.granted_at`/`expires_at` didn't enforce
  timezone-aware datetimes, unlike every other timestamp in the protocol — a
  naive datetime would crash a comparison with a raw `TypeError` instead of
  a clean validation error.
- Structured logging added to `gateway/` and `oracle/`: Treasury fetch
  failures now distinguish transport error / HTTP status / empty feed /
  parse error, and every `/v1/intent` decision is logged with verdict,
  codes, agent, asset, and latency.

[1.0.0]: https://github.com/AkulRanjan/APay-Gateway/releases/tag/v1.0.0
