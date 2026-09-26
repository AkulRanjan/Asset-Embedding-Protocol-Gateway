# Custos architecture

This describes the system as it exists today. For the reasoning behind each
design decision — including every deliberate divergence from the AIP
blueprint this design was modeled on — see `docs/design/specs/`, which
records the actual decisions as they were made, in order.

## What Custos is

Custos is a pre-transaction asset-truth gateway for autonomous agents holding
tokenized U.S. Treasury claims. Before an agent borrows against, trades, or
redeems a position, it sends a signed intent envelope to Custos. Custos
cross-checks the asset's asserted **Claim** against a live **Observation** of
the Treasury par yield curve and returns either a cryptographically signed
`ALLOW` attestation or a signed `BLOCK` denial carrying a `CUSTOS-Exxx` code.

It is **not** an audit of a fund's private books — issuer NAV feeds are not
public. It checks whether a claimed yield is plausible against the live
market for its tenor.

## Repository layout

```
custos_protocol/   the protocol SDK — no dependency on gateway/, claims/, or oracle/
gateway/            thin FastAPI adapter over the SDK; the only place environment
                     variables are read and the only place besides admin_cli.py that
                     makes outbound HTTP calls
claims/              in-memory seeded claim registry (stands in for a real chain read)
oracle/              the live Treasury yield-curve client
conformance/         cross-language conformance vectors + generator + runner
demo/                runnable demonstrations; not production code
tests/               one test module per source module, plus architecture/conformance tests
docs/                this file, usage docs, and the dated design-decision record
```

## Module dependency graph

```
errors.py  crypto.py  canonical.py                    (leaves: no internal deps)
     ▲         ▲          ▲
     └─────────┴──────────┴──► models.py               (schema; depends only on leaves)
                                   ▲
   ┌──────────┬───────────┬───────┼────────┬───────────┬────────────┐
   │          │           │       │        │           │            │
passport   envelope   boundaries drift  revocation   trust      delegation
   │          │           │       │        │           │            │
   └──────────┴───────────┴───────┴────────┴───────────┴────────────┘
                                   │
                          verification.py                ← the only composer
                                   ▲
                 ┌─────────────────┼──────────────────┐
             shield.py          cli.py             gateway/
                                                        │
             observe.py  (depends only on passport — structurally
                           cannot import verification.py)
```

Two rules are enforced by `tests/test_architecture.py`, not by convention:

1. `custos_protocol/` never imports `gateway/`, `claims/`, or `oracle/`.
2. `observe.py` never imports `verification.py` — observability is
   structurally incapable of blocking a call.

`custos_protocol/` performs no I/O beyond local file access (`passport.py`
and `cli.py` read/write files). No module in it calls `os.getenv` or imports
`httpx`. Configuration arrives as explicit value objects — `DriftConfig`,
`DelegationConfig` — constructed by the caller. The environment is read only
in `gateway/config.py`; network calls against a *live* gateway happen only
in `gateway/admin_cli.py`, a separate module from the offline
`custos_protocol/cli.py`.

## The intent envelope

A `CustosEnvelope` is the atomic signed unit:

```
@context, @type, protocol_version
agent { id, version, runtime, attestation }
principal { id, delegation_chain[] }
intent { action, target, parameters }
boundaries { allowed_actions, denied_actions, monetary_limit, asset_classes,
             geo_restriction, time_window }
verification_tier, entropy (nonce), ttl, issued_at, expires_at
proof { type, created, verification_method, proof_value }
```

The boundary cage travels *inside* the signed envelope. A verifier does not
need a policy database to know what the agent was allowed to do — the
agent's own signature attests to its constraints, and tampering with the
cage invalidates the signature. `Action` is a closed, four-value enum
(`borrow_against`, `trade`, `redeem`, `read`) — Custos is a narrow-domain
protocol for a specific class of financial actions, not a generic
agent-action framework.

`expires_at` is required (the blueprint permits a never-expiring envelope);
its span from `issued_at` is capped at 86400 seconds even for a hand-built
envelope that bypasses the `ttl` field's own bound.

## The verification pipeline

`verify_intent(envelope, public_key, *, claim, observation, revocation_store,
trust_engine, ...) -> VerificationResult` is the only function that composes
every layer. Step order is API surface, not an implementation detail:

| # | Step | Runs at | Failure |
|---|---|---|---|
| 1 | Version | all | `E104` |
| 2 | Schema (semantic minimums beyond Pydantic) | all | `E103` |
| 3 | Expiry (with clock-skew grace) | all | `E101` |
| 3b | Clock skew on `issued_at` | all | `E106` |
| 4 | **Signature** | all | `E100` |
| 5 | Nonce format | all | `E105` |
| 5b | Replay (consumes the nonce) | all | `E102` |
| 6 | Boundaries (accumulates every violation) | all | `E2xx` |
| 7 | Revocation (fails closed on stale data) | all | `E400`–`E402`, `E405` |
| — | **Tier 0 exits here** | | |
| 8 | Asset truth | T1, T2 | `E3xx`, `E500`–`E501` |
| 9 | Attestation (opt-in) | T1, T2 | `E306` |
| — | **Tier 1 exits here** | | |
| 10 | Delegation | T2 | `E403` |
| 11 | Trust score gate | T2 | `E404` |
| — | **Tier 2 exits here** | | |

Signature is checked **before** replay — an unauthenticated caller must not
be able to burn a victim's nonce with a forged envelope carrying its nonce.
Trust bookkeeping (`record_intent`, `record_violation`, ...) only starts
*after* signature verification passes, for the same reason: an attacker
spoofing `agent.id` in an envelope that fails earlier can never pollute that
agent's real trust history.

Every step failure sets `passed=False` and a `checks` map recording
`passed`/`failed`/`not_run` per step — a skipped step is representable
without lying about it. There is no `valid` field; `passed` is the single
authority on the outcome.

### Asset truth (`drift.py`)

A pure function of `(claim, observation, config)`, short-circuiting in this
order: unknown asset (`E303`) → no observation (`E500`, fail closed) →
observation too old (`E501`) → future-dated claim (`E305`) → stale claim
(`E300`) → negative observed yield (`E501`) → yield drift beyond threshold
(`E301`) → backing ratio below floor (`E302`). A genuine 0.00% Treasury
print is legal data — only a *negative* yield is treated as an oracle fault
— so drift falls back to an absolute basis-point comparison exactly at that
boundary, since relative drift is undefined at zero.

### Delegation (`delegation.py`)

Validates chain continuity, endpoint binding, hop expiry, chain depth, and
**real boundary monotonicity**: each `DelegationLink` carries its own
`boundaries` (the authority actually granted at that hop), and every hop's
boundaries must be contained within the previous hop's — the envelope's own
operating boundaries must in turn be contained within the final hop's. `0`
and an empty list both mean "unrestricted" throughout, consistently on both
sides of a containment check.

### Trust (`trust.py`)

Tracks a per-agent `AgentHistory` and computes a weighted behavioral score,
clamped `[0,1]`, `0.0` for an agent with no history (not neutral trust). The
same object holds the rolling 24-hour per-day monetary ledger backing
`E203` — implemented as an atomic reserve-then-commit-or-release protocol
(`reserve_amount`/`release_amount`), not a separate read-then-write, so two
concurrent requests for the same agent can never both observe a stale total
and together exceed the limit.

## The error taxonomy

Thirty `CUSTOS-Exxx` codes across five families
(`custos_protocol/errors.py`): `E1xx` envelope/protocol, `E2xx` boundary,
`E3xx` asset truth, `E4xx` revocation/delegation/trust, `E5xx`
infrastructure. The taxonomy is fixed — new failure modes map to an existing
code rather than growing the list. Every code `verify_intent` can reach has
a unit test and a conformance vector; `E304` (tenor-to-observation mapping)
and `E502` (downstream-forwarding) are gateway/oracle integration concerns
`verify_intent` itself never emits, documented as such rather than silently
absent.

## The gateway (`gateway/`)

A thin FastAPI adapter. It resolves a `Claim` from `claims/` and an
`Observation` from `oracle/`, then calls `verify_intent`; it never contains
protocol logic itself.

| Route | Purpose |
|---|---|
| `POST /v1/intent` | Submit a signed envelope; returns a signed `Attestation` or `Denial` |
| `POST /v1/agents` | Bind an agent id to a public key (admin) |
| `POST /v1/frameworks` | Register a known framework id (admin) |
| `POST /v1/attestations/hashes` | Register a known build/prompt hash (admin) |
| `POST /v1/revocations` | Revoke or suspend an agent or issuer (admin) |
| `DELETE /v1/revocations/{subject_id}` | Reinstate (admin) |
| `GET /v1/trust/{agent_id}` | Look up a trust score (public read) |
| `GET /v1/assets`, `GET /v1/assets/{id}` | List / inspect seeded claims |
| `GET /v1/pubkey` | The gateway's signing key |
| `GET /v1/health` | Oracle reachability |

Admin routes require `X-Custos-Admin-Key`; the key has no default and every
admin route fails closed if it isn't configured.

## DX surfaces

Three adoption paths sit on top of the pipeline, all built by deliberately
diverging from documented bugs in the reference implementation they're
modeled on (see each module's docstring for the specific traps closed):

- **`shield.py`** — `protect`/`shield`/`protect_agent`, a decorator that
  signs and verifies a real envelope around a function call. This is local
  policy enforcement with a cryptographic audit trail, not remote
  attestation — the same passport signs and verifies, so there's no second
  party. A compromised process holding the key can bypass it entirely;
  that's a property of single-process enforcement, not a defect.
- **`observe.py`** — `observe`/`observe_class`/`observe_agent`, a
  decorator that logs every call to a ring-buffer store and never blocks or
  swallows an exception, enforced by an import-graph test. Defaults to not
  capturing call arguments.
- **`cli.py`** / **`gateway/admin_cli.py`** — two CLIs, deliberately
  separate. `custos` is offline-only (create a passport, sign an envelope,
  verify one — no network). `custos-admin` wraps the live gateway's admin
  routes over HTTP.

## Conformance (`conformance/`)

Fixed keys, fixed clock, monotonic nonces: 50 vectors covering every
SDK-reachable error code plus the canonical serialization rules, generated
by calling `custos_protocol`'s own functions so the vectors and this
repo's verifier cannot disagree by construction. `run_conformance.py` is a
standalone reference runner any second-language implementation can check
itself against without reading Python. Start with
`conformance/CANONICAL_SERIALIZATION.md` — it's the normative byte-level
spec and the first thing a new implementation gets wrong if skipped.
