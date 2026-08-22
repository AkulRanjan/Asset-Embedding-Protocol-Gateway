# Custos Gateway — Complete Technical Documentation

> A full read of the repository as it stands at commit `be4a191` (`main`, clean tree
> apart from this file), covering every module, every data contract, every scoring rule,
> the spec-vs-code divergences, the security model, measured performance, and the
> state of the live oracle path.
>
> Everything in this document was verified by reading the source and executing it —
> test runs, live network probes against Treasury, error-path sweeps and micro-benchmarks
> are reproduced inline. Where a claim in the existing docs does not survive execution,
> §19 and §22 say so explicitly.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Project Identity & Provenance](#2-project-identity--provenance)
3. [Repository Map](#3-repository-map)
4. [Architecture at a Glance](#4-architecture-at-a-glance)
5. [Layer 1 — Data Models (the wire format)](#5-layer-1--data-models-the-wire-format)
6. [Layer 2 — Configuration](#6-layer-2--configuration)
7. [Layer 3 — The Claim Registry](#7-layer-3--the-claim-registry)
8. [Layer 4 — The Treasury Oracle](#8-layer-4--the-treasury-oracle)
9. [Layer 5 — Canonical Serialization & Ed25519 Signing](#9-layer-5--canonical-serialization--ed25519-signing)
10. [Layer 6 — The Scoring Engine](#10-layer-6--the-scoring-engine)
11. [Layer 7 — Temporal Envelope Validation](#11-layer-7--temporal-envelope-validation)
12. [Layer 8 — Error Taxonomy](#12-layer-8--error-taxonomy)
13. [Layer 9 — The HTTP Gateway](#13-layer-9--the-http-gateway)
14. [Layer 10 — The Downstream Proxy](#14-layer-10--the-downstream-proxy)
15. [The Demo Surface](#15-the-demo-surface)
16. [The Test Suite](#16-the-test-suite)
17. [Measured Performance](#17-measured-performance)
18. [The Live Oracle Path Was Broken (fixed 2026-08-22)](#18-the-live-oracle-path-was-broken-fixed-2026-08-22)
19. [Spec ↔ Implementation Divergences](#19-spec--implementation-divergences)
20. [Security Model & Threat Analysis](#20-security-model--threat-analysis)
21. [Evolution (git history)](#21-evolution-git-history)
22. [Findings & Recommendations](#22-findings--recommendations)
23. [Glossary & Quick Reference](#23-glossary--quick-reference)

---

## 1. Executive Summary

**What this is.** Custos is a *pre-transaction asset-truth gateway* for autonomous agents
holding tokenized U.S. Treasury claims. Before an agent borrows against, trades, or redeems
a tokenized Treasury position, it sends a versioned **Intent** envelope to Custos. Custos
cross-checks the asset's asserted **Claim** against a live **Observation** of the U.S.
Treasury par yield curve, and returns either a **cryptographically signed ALLOW attestation**
or a **structured BLOCK** carrying a machine-readable `CUSTOS-Exxx` code.

**The core insight.** The agent-trust stack already answers "is this *agent* allowed to act?"
(passports, boundary cages, intent protocols) and "is this *counterparty* creditworthy?"
(underwriting). Nothing answers **"is the *asset* still telling the truth?"** A tokenized
Treasury fund that last published a NAV three days ago, or that claims a 4.00% yield while the
3-month bill prints 3.87%, is not a compromised agent and not a bad counterparty — it is a
stale or mispriced *thing*, and every downstream credit decision silently inherits that error.
Custos is a plausibility check on the claim, executed *before* the transaction fires.

**What it deliberately is not.** It is not an audit of a fund's private books. Issuer NAV feeds
are not publicly available. Custos checks whether a claimed yield is plausible **against the
live market for its tenor** — a materially weaker but honest and defensible claim, stated as
such in `Technical Document.md` §8.1 and in the README's opening paragraph. Preserving that
precision in every external description of the product is not modesty; it is the difference
between a claim you can defend and one you cannot.

**The four primitives.**

| Primitive | What it is | Where it lives |
|---|---|---|
| **Intent** | Versioned request envelope: `{who, what action, which asset, how much, valid when}` | `models/intent.py` |
| **Claim** | The asset state asserted by the issuer (NAV, backing, tokens, yield, last-attested) | `models/claim.py`, `claims/registry.py` |
| **Observation** | A live Treasury par-yield reading for the claim's tenor, in integer basis points | `models/observation.py`, `oracle/treasury.py` |
| **Attestation** | Ed25519-signed ALLOW record binding intent ↔ scores ↔ market reference | `models/attestation.py`, `attest/signing.py` |

**The three signals**, evaluated in a fixed short-circuit order so the returned code names the
most fundamental problem rather than an arbitrary one (`attest/engine.py:23`):

```
staleness_hours = (now − claim.last_attested_at) / 3600          > 24h  → CUSTOS-E101
yield_drift     = |observed_bps − claimed_bps| / observed_bps    > 2%   → CUSTOS-E201
backing_ratio   = claimed_backing_usd / (tokens × nav_per_token) < 1.0  → CUSTOS-E202
```

Signal 2 is the load-bearing one. Signal 1 alone would pass an asset that was updated an hour
ago carrying a wrong number — the *recent but wrong* case, which is precisely the dangerous one.
Seed asset `TKN-UST-3M-003` exists to make that argument concrete on stage.

**State of the code (verified by execution).**

```
python -m pytest -q   → 12 tests: 12 passed in 0.31s
error-path sweep      → all 11 CUSTOS-Exxx codes reachable, each mapped to the documented HTTP status
POST /v1/intent       → 0.68 ms median end-to-end (ASGI, warm oracle), 500 iterations
```

**The one thing that did not work — fixed 2026-08-22.** The live Treasury oracle **never
returned an observation**, for two independent, separately verified reasons (§18). Both are now
fixed; the gateway reaches the live curve and issues a signed ALLOW in default configuration.
The diagnosis is kept below because it is the reason the fix looks the way it does:

1. `TREASURY_YIELD_URL` (`oracle/treasury.py:16`) points at `.../interest-rates/yield.xml`,
   which serves a legacy `QR_BC_CM` document containing **no `<entry>` elements**.
   `parse_yield_curve` scans for `entry` nodes, finds none, and returns `None`. The parser is
   *correct* — it was written for Treasury's OData/Atom feed, and against that feed it returns
   `(2026-08-20, 3.87)` on the first attempt. Only the URL constant is wrong.
2. Both feeds respond in **~8–10 s** from this host against a **3 s** timeout with one retry,
   so the client abandons the fetch after ~7 s of wall time regardless of which URL it uses.

The consequence was that in its default configuration Custos failed closed on *every* request.
The fail-closed behaviour was exactly right; the availability was zero. This was the
highest-priority finding in the repository.

**Both causes are fixed** (§18). `oracle/treasury.py` now builds the OData URL for the current
year, falls back to the previous year when that feed is still empty, and defaults to a 15 s
timeout — matched by `gateway.config.ORACLE_TIMEOUT_SECONDS`, which is the value the server
actually runs with. Measured after the fix: `1M 380 · 3M 388 · 6M 395 · 1Y 403 · 2Y 424` bps,
`record_date 2026-08-21`, and a `POST /v1/intent` ALLOW whose signature verifies against the
published key. `demo/run_local_demo.py` still substitutes the oracle, but now by choice — so a
presentation is deterministic — rather than by necessity.

**Maturity assessment.** The scoring engine, canonical serialization, Ed25519 signing chain, error
taxonomy and fail-closed discipline are real, tested, and honest about their limits. The module
boundaries declared in `AGENTS.md` hold exactly, verified by import graph (§4.1). The *perimeter*
— live data acquisition, key persistence, authentication, replay defence, amount authorization —
ranges from broken to absent. §19 and §22 enumerate which is which, because the README and
`Technical Document.md` currently describe several of them without qualification.

---

## 2. Project Identity & Provenance

| Fact | Value | Source |
|---|---|---|
| Product name | Custos Gateway | `README.md`, `gateway/server.py:23` |
| Repository name | `AIP-Gateway` (working dir), `APay-Gateway` (README H1) | filesystem, `README.md:2` |
| FastAPI app version | `0.1.0` | `gateway/server.py:23` |
| Envelope version | `custos/1` (regex-pinned, `^custos/1$`) | `models/intent.py:20` |
| Error namespace | `CUSTOS-Exxx` — 11 codes | `attest/errors.py` |
| Python requirement | 3.10+ (PEP 604 `X \| None`, `from __future__ import annotations`) | source-wide |
| Packaging | **none** — no `pyproject.toml`, `setup.py`, or `setup.cfg` | verified by `ls` |
| Signature suite | Ed25519 over `JCS/RFC8785-lite` canonical JSON | `models/attestation.py:31-32` |
| Git branch | `main`, clean apart from this file | `git status` |
| Commits | 6 | `git log --oneline` |
| Author | Akul Ranjan | `git config` |
| Verified against | Python 3.10.11, Windows 11 | `python --version` |

**Naming layers to keep straight.** *Custos* is the product and the error namespace. The
repository directory is `AIP-Gateway` and the README's first heading is `APay-Gateway`; neither
name appears anywhere in the code. The `AIP` refers to the sibling *Agent Intent Protocol*
project — `Technical Document.md` §7 states outright that the error taxonomy "mirrors the
`AIP-Exxx` convention so Custos reads as a peer component in the agent-trust stack." That
positioning is deliberate and worth keeping. The three competing repository names are not.

**Runtime dependencies** (`requirements.txt`, deliberately small):

```
fastapi           >=0.110,<1.0   # HTTP surface + OpenAPI + request validation
uvicorn[standard] >=0.27,<1.0    # ASGI server
pydantic          >=2.0,<3.0     # every data contract in the system
httpx             >=0.27,<1.0    # Treasury oracle client + downstream proxy
cryptography      >=42.0,<47.0   # Ed25519
rich              >=13.0,<15.0   # demo console rendering only
pytest            >=8.0,<10.0    # test runner
```

`rich` and `pytest` are runtime-listed but used only by `demo/` and `tests/`. There is no
dev/prod split because there is no packaging manifest to hold one.

**Network posture.** Exactly two outbound call sites exist: `oracle/treasury.py` (the Treasury
feed) and `gateway/proxy.py` (the downstream forward). Nothing in `attest/`, `claims/`, or
`models/` opens a socket — the scoring engine is a pure function of its three arguments, which is
why §16's tests need no mocking framework and §17's benchmarks are meaningful.

---

## 3. Repository Map

```
AIP-Gateway/
├── models/                        ← the wire format (Pydantic v2, leaf package)
│   ├── __init__.py          6 L   re-exports
│   ├── intent.py           29 L   Intent + Action enum — the request envelope
│   ├── claim.py            23 L   Claim — asserted asset state
│   ├── observation.py      15 L   Observation — a market reading
│   └── attestation.py      44 L   Scores, Attestation (ALLOW), BlockResponse (BLOCK)
│
├── attest/                        ← the decision core (no I/O, no network)
│   ├── __init__.py          4 L   re-exports evaluate, AttestationSigner, canonicalize
│   ├── errors.py           25 L   11 CUSTOS-Exxx codes → name + HTTP status
│   ├── engine.py           72 L   evaluate() — the entire scoring contract
│   └── signing.py          51 L   canonicalize() + Ed25519 AttestationSigner
│
├── oracle/                        ← market data acquisition
│   ├── __init__.py          3 L   re-exports TreasuryOracle
│   ├── tenors.py           12 L   8 tenors → Treasury XML field names
│   ├── cache.py            30 L   generic monotonic-clock TTLCache
│   └── treasury.py        104 L   XML parse + fetch + retry + cache  ← §18 lives here
│
├── claims/                        ← asserted asset state (simulated chain)
│   ├── __init__.py          3 L   re-exports ClaimRegistry
│   ├── registry.py         37 L   in-memory registry, relative-offset seeding
│   └── seed.json           50 L   4 assets, one per demo outcome
│
├── gateway/                       ← the HTTP boundary (the only composer)
│   ├── __init__.py          1 L   docstring
│   ├── validation.py       28 L   temporal envelope checks (E100/E102/E103)
│   ├── proxy.py            27 L   downstream forward + X-Custos-Attestation header
│   └── server.py          175 L   FastAPI app: 7 routes + orchestration
│
├── demo/
│   ├── run_local_demo.py   97 L   deterministic in-process demo (fixed 400 bps oracle)
│   ├── run_demo.py         37 L   HTTP client against a running gateway
│   ├── verify_attestation.py 29 L standalone verifier — imports zero Custos modules
│   ├── mock_lender.py      10 L   downstream that checks for the attestation header
│   ├── live.html           59 L   single-file browser demo served at GET /demo
│   ├── start_live_demo.ps1  9 L   uvicorn launcher
│   └── README.md                  demo runbook
│
├── tests/                         ← 12 tests, no conftest.py, no __init__.py
│   ├── test_engine.py      77 L   7 tests: scoring paths + crypto + canonical form
│   ├── test_gateway.py     57 L   4 tests: HTTP surface, signing, demo sync
│   └── test_oracle.py      10 L   1 test: XML parse picks the latest record
│
├── config.py               19 L   8 env-overridable knobs (one of them dead)
├── requirements.txt         7 L
├── README.md               39 L   ← carries an unresolved merge marker on line 39
├── AGENTS.md               24 L   the implementation contract (holds — verified §4.1)
├── Technical Document.md  689 L   the pre-build specification
├── TECHNICAL_DIAGRAM.md    19 L   diagram index + endpoint-to-module map
├── utilisation.md         180 L   operator guide + six use-case narratives
├── diagrams/                      ← referenced by TECHNICAL_DIAGRAM.md
│   ├── custos-architecture.svg
│   └── custos-request-flow.svg
├── custos-architecture.svg        ← orphaned: referenced by nothing
└── custos-sequence.svg            ← orphaned: referenced by nothing
```

**1,025 lines of Python total**, of which 175 are the FastAPI server and 72 are the engine that
makes every decision. The four SVGs are two distinct pairs, not copies (differing MD5s):
`diagrams/*` is referenced by `TECHNICAL_DIAGRAM.md`; the root pair is dead weight.

---

## 4. Architecture at a Glance

### 4.1 Module dependency graph

`AGENTS.md` opens with a hard rule: *"Keep dependencies one-way: `gateway` may use `attest`,
`claims`, and `oracle`; `attest` may use models/config only; `claims` and `oracle` do not import
gateway."* Extracting every import statement in the tree confirms the rule holds with **zero
violations**:

```
                    config.py                models/         (leaves: no internal deps)
                        ▲                       ▲
        ┌───────────────┼───────────────┬───────┴────────┬──────────────┐
        │               │               │                │              │
   attest/errors.py     │        claims/registry.py   oracle/cache   oracle/tenors
        ▲               │               ▲                ▲              ▲
        │               │               │                └──────┬───────┘
   attest/engine.py ────┤               │                       │
   attest/signing.py    │               │              oracle/treasury.py
        ▲               │               │                       ▲
        └───────────────┴───────────────┴───────────────────────┘
                                │
                    gateway/validation.py
                    gateway/proxy.py
                                ▲
                                │
                        gateway/server.py     ← the only module that composes everything
                                ▲
                                │
                    demo/  ·  tests/          (both may import server; nothing imports them)
```

Three things worth noticing:

1. **`attest/engine.py` performs no I/O whatsoever.** `evaluate(intent, claim, obs)` is a pure
   function of three already-materialised objects. It cannot fetch, cannot block on a socket, and
   cannot fail non-deterministically. Every failure mode it can express is a value it returns.
   This is why it benchmarks at 6.4 µs and why its tests need no mocks.
2. **`oracle/` does not import `attest/` and vice versa.** The oracle's entire contract with the
   rest of the system is `Observation | None`. Replacing the Treasury XML client with a Fiscal
   Data JSON client — which is what §19 item 1 says should happen — touches one file.
3. **`gateway/server.py` is the sole choke point.** It owns the three module-level singletons
   (`registry`, `oracle`, `signer`), the ordering of validation vs scoring, and every HTTP status
   mapping. It is therefore also the only place where per-request or per-tenant state could be
   isolated, and today none is (§20.3).

### 4.2 The request dataflow

```
  ┌──────────────────────────── AGENT ────────────────────────────────────┐
  │  did:web:acme.com:agents:treasury-bot                                 │
  │  wants to borrow $50,000 against TKN-UST-3M-001                       │
  └───────────────────────────────────────────────────────────────────────┘
                                   │  POST /v1/intent
                                   ▼
  ┌────────────────────────── INTENT ENVELOPE ────────────────────────────┐
  │  envelope_version : "custos/1"        ← regex-pinned, extra="forbid"  │
  │  agent_id         : non-empty string                                  │
  │  action           : borrow_against | trade | redeem                   │
  │  asset_id         : registry key                                      │
  │  amount           : Decimal > 0       currency: "USD" only            │
  │  issued_at        : aware UTC         expires_at: aware UTC           │
  │  downstream       : optional AnyHttpUrl                               │
  └───────────────────────────────────────────────────────────────────────┘
                                   │
   ① Pydantic schema ─────────────►│  fail → CUSTOS-E100  (400)
   ② validate_temporal_envelope ──►│  fail → E100 / E102 / E103  (400)
                                   ▼
  ┌──────────────────────── assess(intent) ───────────────────────────────┐
  │  registry.get_claim(asset_id)   ──── miss ────► CUSTOS-E200  (404)    │
  │  oracle.get_observation(tenor)  ── unmapped ──► CUSTOS-E203  (422)    │
  │                                 ── None ──────► CUSTOS-E300  (503)    │
  └───────────────────────────────────────────────────────────────────────┘
                                   │  Intent + Claim + Observation
                                   ▼
  ┌───────────────────── evaluate() — the scoring engine ─────────────────┐
  │  claim is None ?                              → E200                  │
  │  obs is None ?                                → E300  (fail closed)   │
  │  obs age_days > 4 ?                           → E301                  │
  │  staleness_hours > 24 ?                       → E101                  │
  │  observed_bps <= 0 ?                          → E300                  │
  │  |obs − claimed| / obs > 0.02 ?               → E201                  │
  │  backing / (tokens × nav) < 1.0 ?             → E202                  │
  │  otherwise                                    → Scores                │
  └───────────────────────────────────────────────────────────────────────┘
                     │                                    │
            Scores   │                                    │  BlockResponse
                     ▼                                    ▼
  ┌──────────── ATTESTATION (ALLOW) ─────────┐   ┌──── BLOCK ─────────────┐
  │ attestation_id, verdict:"ALLOW"          │   │ verdict:"BLOCK"        │
  │ asset_id, agent_id, action, amount       │   │ error: CUSTOS-Exxx     │
  │ scores{staleness, drift, backing + each  │   │ error_name             │
  │        threshold that was applied}       │   │ detail (human prose)   │
  │ reference{source, tenor, claimed_bps,    │   │ asset_id, scores,      │
  │           observed_bps, record_date}     │   │ reference, issued_at   │
  │ issued_at, expires_at (+300 s)           │   └────────────────────────┘
  │ signature (Ed25519), public_key          │            │
  │ signature_alg, canonicalization          │            ▼
  └──────────────────────────────────────────┘   HTTP 400/403/404/422/502/503
                     │
        downstream set?  ── no ──► 200 { attestation }
                     │
                    yes
                     ▼
        POST downstream + X-Custos-Attestation: base64(compact JSON)
                     │
          reachable? ── no ──► CUSTOS-E400 (502), attestation discarded
                     │
                    yes ──────► 200 { attestation, downstream{status_code, body} }
```

**The load-bearing design decision:** the attestation carries its own *evidence*, not just a
verdict. `scores` reports each computed value **beside the threshold that was applied**, and
`reference` names the source, the tenor, the record date, and both yield figures. A relying party
can re-derive the decision without calling Custos back, and an auditor reading a six-month-old
attestation can see the market conditions it was issued under. Everything in both objects is
inside the signature.

**The trade-off, stated plainly:** Custos attests that a *claim* was plausible at a moment in
time. It does not authorize the *transaction*. `amount` and `action` are signed but never
evaluated — §10.5 demonstrates a $1,000,000,000,000 borrow against a $100 fund returning ALLOW.
A consumer who reads the attestation as an authorization is reading something that is not there.

---
## 5. Layer 1 — Data Models (the wire format)

Every message in the system is a Pydantic v2 model. `models/` is a leaf package: it imports
nothing from Custos. These five classes *are* the protocol.

### 5.1 `Intent` — the request envelope

`models/intent.py`. `model_config = ConfigDict(extra="forbid")` — an unknown field is a
rejection, not a silent drop.

| Field | Type | Constraint | Why it is shaped this way |
|---|---|---|---|
| `envelope_version` | `str` | `pattern=r"^custos/1$"` | Version is pinned by regex, not compared in code. A `custos/2` envelope is rejected at the schema layer with `E100` before any handler runs |
| `agent_id` | `str` | `min_length=1` | Identity is recorded and signed, never authenticated (§20.1) |
| `action` | `Action` | `borrow_against \| trade \| redeem` | A closed enum; anything else is `E100` |
| `asset_id` | `str` | `min_length=1` | Registry key |
| `amount` | `Decimal` | `gt=0` | `Decimal`, not `float` — money never touches binary floating point on the wire, and the exact submitted text survives into the signature (§9.3) |
| `currency` | `str` | `pattern=r"^USD$"` | Single-currency by construction |
| `issued_at` | `datetime` | — | Aware-UTC is enforced downstream in `gateway/validation.py`, not here |
| `expires_at` | `datetime` | — | Same |
| `downstream` | `AnyHttpUrl \| None` | optional | Presence switches the gateway from attest-only to attest-and-forward (§14) |

Two deliberate choices worth calling out. **`Decimal` for `amount`** means `"50000.00"` round-trips
as `"50000.00"`, not `50000.0` — verified in §9.3 across four representations including `1E+3` and
an 18-significant-digit value. **Timezone-awareness is not a schema constraint**, because Pydantic
would reject a naive datetime with a generic validation error; deferring it to `validation.py`
produces the specific message `issued_at and expires_at must include a UTC offset.`

### 5.2 `Claim` — asserted asset state

`models/claim.py`, also `extra="forbid"`. This is what the issuer says is true.

| Field | Type | Constraint |
|---|---|---|
| `asset_id`, `issuer`, `underlying_tenor`, `chain`, `contract_address` | `str` | — |
| `claimed_nav_per_token` | `Decimal` | `gt=0` |
| `claimed_backing_usd` | `Decimal` | `ge=0` — zero backing is representable, and blocks at `E202` |
| `tokens_outstanding` | `Decimal` | `gt=0` — guarantees the §10.4 division cannot divide by zero |
| `claimed_yield_bps` | `int` | `ge=0` — integer basis points, no float yields anywhere |
| `last_attested_at` | `datetime` | — naive values are coerced to UTC in the engine (§10.2) |

`tokens_outstanding: gt=0` is doing real work: it is the schema-level guarantee that
`implied_liability` in the backing-ratio calculation is non-zero.

### 5.3 `Observation` — a market reading

`models/observation.py`. The only model without `extra="forbid"`, and the only one carrying a
default that describes provenance:

```python
source: str                                    # "home.treasury.gov"
dataset: str = "daily_treasury_yield_curve"
tenor: str
observed_yield_bps: int                        # integer bps — 3.87% → 387
record_date: date                              # the curve's own date, not the fetch date
fetched_at: datetime
cache_hit: bool = False
```

The split between `record_date` and `fetched_at` is the point: `record_date` drives the `E301`
staleness check on the *data*, `fetched_at` records when Custos saw it, and `cache_hit` tells an
operator whether this request paid for a network round trip. All three end up in the audit trail.

### 5.4 `Scores` — the evidence object

`models/attestation.py`. Every field is `float | None`, and every metric is paired with the
threshold that was applied to it:

```python
staleness_hours / staleness_threshold_hours
yield_drift     / yield_drift_threshold
backing_ratio   / backing_ratio_floor
```

Pairing value with threshold is what makes an attestation self-describing. A consumer reading
`{"yield_drift": 0.0336, "yield_drift_threshold": 0.02}` needs no access to the gateway's config
to understand the decision, and an attestation issued under a since-changed threshold still
explains itself. The engine builds `Scores` incrementally with `model_copy(update=...)`, so a
BLOCK carries **exactly the metrics that were computed before the failure** and `None` for the
ones never reached — the object's shape is itself a record of how far evaluation got.

### 5.5 `Attestation` and `BlockResponse` — the two verdicts

```python
class Attestation(BaseModel):
    attestation_id: str                  # "att_" + uuid4().hex
    verdict: Literal["ALLOW"] = "ALLOW"  # Literal, not str — an Attestation cannot say BLOCK
    asset_id / agent_id / action / amount
    scores: Scores
    reference: dict[str, Any]            # source, tenor, both yields, record_date
    issued_at / expires_at               # expires_at = issued_at + ATTESTATION_TTL_SECONDS
    signature: str | None = None         # base64 Ed25519, filled after construction
    public_key: str | None = None        # base64 raw 32-byte key
    signature_alg: str = "Ed25519"
    canonicalization: str = "JCS/RFC8785-lite"

class BlockResponse(BaseModel):
    verdict: Literal["BLOCK"] = "BLOCK"
    error: str                           # "CUSTOS-E201"
    error_name: str                      # "YIELD_DRIFT_EXCEEDED"
    detail: str                          # human prose with the actual numbers substituted
    asset_id: str | None
    scores: Scores | None
    reference: dict | None
    issued_at: datetime
```

Using `Literal` for `verdict` makes the two response types statically non-interchangeable — an
`Attestation` is incapable of expressing a denial. `signature_alg` and `canonicalization` are
carried *inside the signed payload*, so an attestation names its own verification procedure and a
future algorithm change cannot be applied retroactively to old records without invalidating them.

**BLOCK responses are not signed.** Only ALLOW carries a signature. A denial can therefore be
forged or suppressed by anything on the path; a permit cannot. For a fail-closed system that is
the defensible asymmetry — but consumers who want to *prove* they were denied (a compliance
posture named in `utilisation.md` §7F) do not get that from the current design (§22, P1-9).

---

## 6. Layer 2 — Configuration

`config.py` — 19 lines, eight knobs, read from the environment at import time.

| Constant | Env var | Default | Read by | Effect |
|---|---|---|---|---|
| `STALENESS_THRESHOLD_HOURS` | `CUSTOS_STALENESS_HOURS` | `24.0` | engine ×3 | `E101` boundary |
| `DRIFT_THRESHOLD` | `CUSTOS_DRIFT_THRESHOLD` | `0.02` | engine ×3 | `E201` boundary |
| `BACKING_FLOOR` | `CUSTOS_BACKING_FLOOR` | `1.0` | engine ×3 | `E202` boundary |
| `MAX_OBSERVATION_AGE_DAYS` | `CUSTOS_MAX_OBS_AGE_DAYS` | `4` | engine ×2 | `E301` boundary |
| `ORACLE_TIMEOUT_SECONDS` | `CUSTOS_ORACLE_TIMEOUT` | `3.0` | oracle **and proxy** | connect+read timeout |
| `ORACLE_CACHE_TTL_SECONDS` | `CUSTOS_CACHE_TTL` | `60` | oracle | observation cache lifetime |
| `ATTESTATION_TTL_SECONDS` | `CUSTOS_ATTESTATION_TTL` | `300` | server | attestation `expires_at` |
| `FAIL_MODE` | `CUSTOS_FAIL_MODE` | `"closed"` | **nothing** | none — dead config |

Two problems, both verified by grepping every `config.X` reference in the tree:

**`FAIL_MODE` is never read.** `Technical Document.md` §13 documents it as `closed | open` and adds
"its presence as a config key is itself a talking point: the choice is deliberate and documented."
The choice *is* deliberate — it is hard-coded. Setting `CUSTOS_FAIL_MODE=open` changes nothing.
Failing safe when a knob is ignored is the right direction to be wrong in, but a documented knob
that silently does nothing is worse than no knob: it invites an operator to believe they have
changed the system's behaviour.

**`ORACLE_TIMEOUT_SECONDS` controls two unrelated things.** `gateway/proxy.py:19` uses it as the
downstream lender timeout. Tightening the oracle budget silently tightens the downstream budget;
there is no `CUSTOS_DOWNSTREAM_TIMEOUT`. Worse, the same constant is also the *retry* budget: the
oracle attempts the fetch twice (§8.3), so the effective worst-case oracle latency is **2 ×
`ORACLE_TIMEOUT_SECONDS`**, measured at ~7 s wall time in §18. Nothing in the request path enforces
an overall deadline, so a client's first sight of `E300` is roughly seven seconds after it asked.

Every value is read **once, at import**. There is no reload path; changing a threshold means
restarting the process. For a gateway whose thresholds are explicitly described as "hand-set, not
calibrated" (`Technical Document.md` §18.6), a runtime reload endpoint would be a small addition
with real operational value.

---

## 7. Layer 3 — The Claim Registry

`claims/registry.py` — 37 lines, in-memory, seeded from `claims/seed.json` at construction.

### 7.1 Relative-offset seeding

The one non-obvious idea in this file, and it is a good one:

```python
offset = raw.pop("last_attested_offset_hours")
raw["last_attested_at"] = now + timedelta(hours=float(offset))
```

The seed file stores **offsets**, not timestamps. `TKN-UST-3M-001` is seeded at `-2` hours, so it
is two hours old whenever the process starts, not two hours old on the day the JSON was written.
`Technical Document.md` §11 names the failure this avoids: *"A hardcoded timestamp silently becomes
'stale' as the day progresses and will break the healthy-asset demo path at the worst possible
moment."* Note the offsets are computed at **registry construction**, not per request, so a process
left running for two days will see its "healthy" asset cross the 24-hour staleness threshold. For a
demo gateway that is correct; for a long-running service the registry is the wrong home for it.

### 7.2 The four seeded assets

Each exercises exactly one path. Every one names issuer *Meridian Short Duration Treasury Fund* and
a placeholder Ethereum address.

| Asset | Tenor | `claimed_yield_bps` | Attested | Backing | Designed outcome |
|---|---|---|---|---|---|
| `TKN-UST-3M-001` | 3M | 400 | −2 h | 1.00× | **ALLOW** |
| `TKN-UST-3M-002` | 3M | 400 | −72 h | 1.00× | `E101` claim stale |
| `TKN-UST-3M-003` | 3M | 360 | −1 h | 1.00× | `E201` recent but drifted |
| `TKN-UST-6M-004` | 6M | 400 | −1 h | 0.94× | `E202` under-backed |

`TKN-UST-3M-003` is the argument for the product: attested one hour ago, so any staleness-only
check passes it, and wrong by 40 bps. `TKN-UST-3M-002`'s contract address is
`0x0000000000000000000000000000000000002` — **39 hex digits, not 40**, so it is not a valid
Ethereum address. Nothing validates it, but it will not survive contact with a real RPC client.

### 7.3 The `claimed_yield_bps` calibration trap — quantified

The seeds hard-code 400 bps (4.00%). The live 3M par yield on 2026-08-20 is **387 bps**. Running
every seeded claim through `evaluate()` against the live curve — fetched via the OData feed the
parser actually understands (§18) — gives:

| Asset | claimed | observed | drift | verdict against the live curve |
|---|---|---|---|---|
| `TKN-UST-3M-001` | 400 | 387 | **3.36%** | **`CUSTOS-E201`** ← the "healthy" asset blocks |
| `TKN-UST-3M-002` | 400 | 387 | 3.36% | `CUSTOS-E101` (staleness fires first) |
| `TKN-UST-3M-003` | 360 | 387 | 6.98% | `CUSTOS-E201` ✓ as designed |
| `TKN-UST-6M-004` | 400 | 394 | 1.52% | `CUSTOS-E202` ✓ as designed |

**With a working oracle and today's curve, the demo has no ALLOW path.** The README knows this and
says so: *"Before a live demo, set the healthy seed's `claimed_yield_bps` to the current 3M
observation."* `POST /v1/demo/sync` (§13.5) exists to automate exactly that. This is the correct
mitigation for a demo, and it is also the clearest illustration of why the seeded registry is
simulation rather than chain state: the claims must be tuned to the market, because nothing writes
them from it.

### 7.4 `update_claim` — mutation, and who may call it

```python
def update_claim(self, asset_id: str, **updates: object) -> Claim | None:
```

Docstring: *"Replace a simulated claim in memory; used only by the interactive demo sync."* The
restriction is real in the code — the only caller is `POST /v1/demo/sync`. But `**updates: object`
is unvalidated pass-through to `model_copy(update=...)`, which **bypasses Pydantic validation**:
`model_copy` does not re-run validators, so a caller can install a negative `claimed_yield_bps` or
a `tokens_outstanding` of zero and reintroduce the division the schema was protecting against. The
current single caller passes an `int`, so nothing is wrong today. The next caller is the risk.

---

## 8. Layer 4 — The Treasury Oracle

`oracle/treasury.py` (104 L) + `oracle/cache.py` (30 L) + `oracle/tenors.py` (12 L). This layer is
where the product's honesty claim lives — and where it is currently broken (§18).

### 8.1 The tenor map

```python
TENOR_FIELDS = {"1M": "BC_1MONTH", "1.5M": "BC_1_5MONTH", "2M": "BC_2MONTH", "3M": "BC_3MONTH",
                "4M": "BC_4MONTH", "6M": "BC_6MONTH", "1Y": "BC_1YEAR",   "2Y": "BC_2YEAR"}
```

Eight short-duration tenors, matching the specification's table exactly. A claim whose
`underlying_tenor` is absent raises `UnsupportedTenor`, which `gateway/server.py:76` converts to
`CUSTOS-E203` (422). **In practice E203 is unreachable**: the registry seeds only `3M` and `6M`,
so the code path exists for a future in which claims come from chain state and can name `10Y`.
Verified reachable only by forcing the oracle to raise.

The map stops at 2Y deliberately — the product is about short-duration Treasury funds. Extending it
is a one-line change per tenor, since Treasury publishes `BC_3YEAR` through `BC_30YEAR` in the same
document.

### 8.2 `parse_yield_curve` — namespace-agnostic by design

```python
def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]
```

Every tag comparison strips the XML namespace, so the parser survives Treasury changing its
namespace URI — a real hazard with government feeds. The algorithm:

1. Walk every node; keep those whose local name is `entry`.
2. Flatten each entry's descendants into `{local_name: text}`.
3. Take the date from `NEW_DATE`, else `QUOTE_DATE`, else `record_date`; take the yield from the
   requested field.
4. Skip entries with a missing value or the literal `N/A` / `NA`.
5. Coerce; a non-numeric yield becomes `-1` and is dropped by the `>= 0` filter.
6. Return `max(candidates, key=date)` — **the latest record wins**, not document order.

Step 6 is the one the test suite guards (`test_parse_yield_curve_selects_latest_record`), and it is
the right invariant: Treasury's feed is not guaranteed to be date-ordered.

`_parse_date` accepts full ISO-8601 (normalizing a trailing `Z` to `+00:00`) and falls back to the
first ten characters as a bare date. It does **not** accept `MM-DD-YYYY` or `DD-MON-YY`, both of
which appear in Treasury's legacy document — see §18.

### 8.3 `get_observation` — the fetch path

```python
async def get_observation(self, tenor: str) -> Observation | None
```

| Step | Behaviour | Consequence |
|---|---|---|
| Tenor lookup | `TENOR_FIELDS.get(tenor)`; `None` → `raise UnsupportedTenor` | `E203`, the only exception that escapes this layer |
| Cache read | hit → `model_copy(update={"cache_hit": True})` | The cached object is never mutated; the caller sees a flagged copy |
| Fetch | 2 attempts, `httpx.TransportError` only | HTTP error statuses do **not** retry — correct: a 404 will not fix itself |
| Error status | `response.is_error` → `None` | fail closed |
| Parse failure | `None` | fail closed |
| Success | `int(round(percent * 100))` → bps | 3.87% → 387 |
| Exceptions | `httpx.HTTPError`, `ElementTree.ParseError` → `None` | fail closed |
| Cleanup | `finally: await client.aclose()` if the oracle owns the client | injected clients are left open for the caller |

**Every failure mode collapses to `None`, and `None` becomes `CUSTOS-E300`.** That single-valued
error channel is what makes the fail-closed guarantee easy to audit — but it also means the gateway
cannot distinguish "Treasury returned 503" from "the XML shape changed" from "DNS failed." All
three produce the same opaque `E300`, and nothing is logged. Diagnosing §18 required probing the
feed by hand, because the running system had no way to say what was wrong.

The optional `client` injection parameter is the seam that makes the oracle testable without a
network. Notably, **no test uses it** — `tests/` substitutes whole fake oracle objects instead
(§16.3).

### 8.4 `TTLCache`

30 lines, generic over `T`, keyed by tenor.

- **`time.monotonic()`**, not `time.time()` — immune to wall-clock adjustment and NTP steps. The
  correct choice, and easy to get wrong.
- Lazy expiry: entries are evicted on read, never by a sweeper. With eight possible keys, unbounded
  growth is not a concern.
- **No size cap and no locking.** Under CPython's GIL, dict get/set are atomic enough that the
  worst concurrent outcome is a duplicate fetch, not corruption. Two simultaneous cold requests for
  the same tenor will both hit the network — a thundering-herd window of one request per tenor per
  TTL, which at 60 s and eight tenors is negligible.
- 60 s TTL against a feed that updates **once per business day** is 5,760× more often than the data
  changes. That is a deliberate demo trade-off (see fresh data during a presentation) with a real
  cost: it multiplies exposure to the §18 latency problem by a factor of 5,760.

---

## 9. Layer 5 — Canonical Serialization & Ed25519 Signing

`attest/signing.py` — 51 lines, and the most security-critical file in the repository.

### 9.1 The canonical form

```python
def canonicalize(payload: dict[str, Any]) -> bytes:
    unsigned = {k: v for k, v in payload.items() if k not in {"signature", "public_key"}}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
```

Four rules, each load-bearing:

| Rule | Purpose |
|---|---|
| Exclude `signature`, `public_key` | The signature cannot cover itself; the key is transport metadata, not attested content |
| `sort_keys=True` | Byte-stability across dict insertion orders, Python versions, and languages |
| `separators=(",", ":")` | No incidental whitespace — the most common cross-language divergence |
| `ensure_ascii=True` | Non-ASCII escapes to `\uXXXX`, so the bytes do not depend on the reader's encoding |

The name `JCS/RFC8785-lite` is carried in the attestation itself and is accurate about being a
subset. It matches RFC 8785 on key sorting and whitespace; it does **not** implement RFC 8785's
number canonicalization, because Pydantic has already converted every `Decimal` to a JSON *string*
and every float to whatever `json.dumps` emits. That is fine while every numeric field either
arrives as a Decimal-backed string or a `round()`-ed float — which is true today — and it is the
first thing that would break a second implementation in another language. §22 P2-19 recommends
saying so in the spec.

The exclusion is expressed as a **set of field names, applied to a flat dict**. Nested objects are
not scanned, so a nested `signature` key inside `scores` or `reference` would be signed rather than
stripped. No such key exists today; the constraint is undocumented.

### 9.2 `AttestationSigner`

```python
key_path = private_key_path or os.getenv("CUSTOS_PRIVATE_KEY")
if key_path:  load PEM, assert isinstance(loaded, Ed25519PrivateKey)
else:         Ed25519PrivateKey.generate()
```

- The `isinstance` check produces a clear `TypeError` on an RSA or P-256 PEM instead of a confusing
  failure at signing time. Good.
- The PEM is loaded with `password=None` — **an encrypted key file is not supported**.
- The default is an **ephemeral key generated at startup**. Restart the gateway and every previously
  issued attestation becomes unverifiable against `GET /v1/pubkey`. `Technical Document.md` §9.2
  and §18.4 both name this and call it "correct for a demo," which it is. It also means the
  signature's value today is integrity-within-a-session, not provenance (§20.2).
- Public key is exposed in two encodings: raw base64 (32 bytes, what goes in the attestation) and
  SubjectPublicKeyInfo PEM (what OpenSSL and most tooling expect). Offering both is thoughtful.

### 9.3 Verified round-trip properties

Executed against the running gateway:

```
amount '0.005'                → served '0.005'                signature verifies
amount '1E+3'                 → served '1E+3'                 signature verifies
amount '123456789.123456789'  → served '123456789.123456789'  signature verifies
amount '1'                    → served '1'                    signature verifies

tamper amount   "50000.00" → "1.00"        → InvalidSignature   (rejected)
tamper scores   backing_ratio 1.0 → 2.0    → InvalidSignature   (rejected)
canonical form  {"b":2,"a":1,"signature":…} == {"a":1,"b":2,"public_key":…} == b'{"a":1,"b":2}'
```

The `Decimal` exactness claim holds end to end: an 18-significant-digit amount survives model
validation, `model_dump(mode="json")`, the canonical form, the signature, FastAPI's
`jsonable_encoder`, and the independent verifier without a single digit lost. That is the property
that makes `Decimal` worth the ergonomic cost over `float`.

### 9.4 `demo/verify_attestation.py` — and the substitution gap

The standalone verifier duplicates `canonicalize` verbatim and imports nothing from Custos. That
independence is the point: it is a second implementation of the canonical form, and it is what
turns "cryptographically signed" from a marketing phrase into a demonstrated property.
`tests/test_gateway.py` imports this demo script rather than the application signer, so the two
implementations are checked against each other on every test run. That is a genuinely good
structural decision.

**But `verify()` trusts the key embedded in the payload.** Verified by execution:

```
forged = dict(real_attestation)
forged["amount"] = "999999.00"
forged["public_key"] = attacker.public_key_base64
forged["signature"]  = attacker.sign(forged)
verify(forged)  →  ACCEPTS
```

This is not a bug in the script — a self-contained demo verifier has no trust anchor to pin
against. It *is* a trap for anyone who copies the 29 lines into a relying party. A real consumer
must compare `public_key` against a key obtained out-of-band from `GET /v1/pubkey`, and that
comparison is meaningless while the key is ephemeral (§9.2). §20.2 and §22 P0-3 carry the fix.

---

## 10. Layer 6 — The Scoring Engine

`attest/engine.py` — 72 lines. Every decision Custos makes happens here.

```python
def evaluate(intent: Intent, claim: Claim | None, obs: Observation | None) -> Scores | BlockResponse
```

The return type is the design: `Scores` means allow, `BlockResponse` means deny, and there is no
third possibility. `AGENTS.md` freezes this signature as the contract between modules, and the
docstring states the ordering is "the public error-precedence contract" — the order is API surface,
not an implementation detail.

### 10.1 The order, exactly as implemented

| # | Guard | Code | Rationale for its position |
|---|---|---|---|
| 1 | `claim is None` | `E200` | You cannot evaluate an asset you do not know. Also saves a network call — verified by `test_unknown_asset_precedes_oracle_fetch` |
| 2 | `obs is None` | `E300` | **The fail-closed guarantee.** No market data ⇒ no attestation, ever |
| 3 | `age_days > 4` | `E301` | The data itself is too old to be evidence |
| 4 | `staleness > 24 h` | `E101` | The most fundamental claim defect: nobody is maintaining it |
| 5 | `observed_bps <= 0` | `E300` | Divide-by-zero guard for step 6, expressed as an oracle fault |
| 6 | `drift > 2%` | `E201` | The signal that catches *recent but wrong* |
| 7 | `ratio < 1.0` | `E202` | Internal consistency; needs no oracle, so it is cheapest and runs last |
| — | otherwise | `Scores` | ALLOW |

Ordering matters and is tested. `test_stale_claim_short_circuits_first` constructs a claim that is
*both* 25 hours old *and* off by 399 bps, and asserts `E101` — the error names the deeper problem.
An operator seeing `E101` knows to fix the publishing pipeline; an operator seeing `E201` from the
same asset would go looking for a pricing error that is really a staleness symptom.

The `reference` dict is assembled **once, before any check that could fail**, so every block from
step 3 onward carries the same market evidence an ALLOW would have. A `E201` response tells you
exactly which observation it disagreed with.

### 10.2 Staleness

```python
if last_attested.tzinfo is None:
    last_attested = last_attested.replace(tzinfo=timezone.utc)
staleness = max(0.0, (utc_now() - last_attested).total_seconds() / 3600)
```

Naive timestamps are assumed UTC rather than rejected — pragmatic for a seeded registry, and
verified to produce the same result as an aware value.

**The `max(0.0, …)` clamp is a real gap.** A claim dated in the *future* reports zero staleness and
sails through. Verified:

```
claim.last_attested_at = now + 1825 days  →  Scores(staleness_hours=0.0)  →  ALLOW
```

An issuer whose clock is wrong — or who wants to defeat the check — gets a permanently fresh claim.
The intent envelope is protected against exactly this by `E103` (`issued_at` more than five minutes
ahead is rejected); the claim is not. The asymmetry looks unintentional. §22 P1-6.

### 10.3 Yield drift

```python
drift = abs(obs.observed_yield_bps - claim.claimed_yield_bps) / obs.observed_yield_bps
```

Relative, not absolute, and the specification's justification is sound: 10 bps is noise at a 4.3%
yield and material at 0.5%. Verified boundary behaviour at `observed = 400`:

| claimed | drift | verdict |
|---|---|---|
| 392 | 0.0200 | ALLOW — the comparison is `>`, so exactly 2.00% passes |
| 391 | 0.0225 | `E201` |
| 408 | 0.0200 | ALLOW |
| 409 | 0.0225 | `E201` |

At a 4.00% observation the tolerance is ±8 bps; at today's 3.87% it is ±7.7 bps.

**The denominator is `observed`, which makes the check asymmetric.** Verified:

```
claimed 200 vs observed 400  →  drift 0.50
claimed 400 vs observed 200  →  drift 1.00
```

The same 200 bps gap scores differently depending on direction. Since `observed` is the trusted
quantity, normalizing by it is the defensible choice — but the asymmetry is worth documenting,
because an issuer overstating yield is penalised more heavily than one understating it by the same
absolute amount, and that is a policy decision nobody has written down.

**The `observed_bps <= 0` guard is over-broad.** Treasury bills genuinely printed 0.00–0.02% in
2020–2021. A legitimate 0.00% quote parses to `0` bps and produces `E300 — "Treasury oracle
returned an invalid zero yield"`, blaming the oracle for accurate data. A negative observation
produces the same message, which is doubly wrong. Verified: `observed_yield_bps = -5` → `E300` with
the word "zero" in the detail string. §22 P1-7.

### 10.4 Backing ratio

```python
implied_liability = claim.tokens_outstanding * claim.claimed_nav_per_token   # Decimal × Decimal
ratio = float(claim.claimed_backing_usd / implied_liability)                 # → float
```

The division is exact `Decimal` arithmetic; the `float()` cast happens only for the `Scores` field,
which is typed `float | None`, and only after the value is computed. Money never rounds — the cast
affects the reported number, not the comparison. `tokens_outstanding: gt=0` guarantees the
denominator is non-zero.

The check is a **floor, not a band**. A claim asserting 10× backing passes cleanly (verified:
`backing_ratio = 10.0` → ALLOW). Implausible over-collateralization is as strong a signal of a
broken data feed as under-collateralization, and nothing flags it. §22 P2-13.

### 10.5 What the engine never looks at

`evaluate()` reads `intent.asset_id` and nothing else from the intent. It never reads `amount`,
`action`, or `agent_id`. Verified:

```
Intent(action="borrow_against", amount=Decimal("1000000000000"))  against  claimed_backing_usd=$100
→ Scores(...)  →  signed ALLOW
```

A $1 trillion borrow against a $100 fund is attested. This is *consistent* with the stated
scope — Custos attests asset truthfulness, not transaction authorization — but the attestation
prominently carries `action` and `amount` inside its signature, which invites exactly the wrong
reading. Either the engine should gain a proportionality check (amount vs `claimed_backing_usd`),
or the attestation should state in a field that the amount is recorded and not authorized. §22 P1-8.

---

## 11. Layer 7 — Temporal Envelope Validation

`gateway/validation.py` — 28 lines, and it runs *before* the engine. `evaluate()`'s docstring says
so explicitly: *"Envelope checks are intentionally performed by `gateway.validation` first."*

| # | Check | Code | HTTP | Detail |
|---|---|---|---|---|
| 1 | `issued_at.tzinfo is None or expires_at.tzinfo is None` | `E100` | 400 | `issued_at and expires_at must include a UTC offset.` |
| 2 | `expires_at <= now` | `E102` | 400 | `expires_at must be in the future.` |
| 3 | `issued_at > now + 5 min` | `E103` | 400 | `issued_at is more than five minutes in the future.` |

Three observations:

**Naive-datetime rejection is a distinct message, not a schema error.** Pydantic would happily
accept a naive datetime and the comparison would then raise `TypeError` deep in the handler.
Catching it here converts a 500 into a 400 with an actionable sentence. This is the reason the
awareness constraint is not in `models/intent.py`.

**The five-minute clock-skew window is one-directional.** A far-future `issued_at` is rejected; a
far-*past* `issued_at` is not. An envelope claiming to have been issued in 2019 but expiring in ten
minutes passes. Since `expires_at` bounds the useful window, this is defensible — but combined with
the absence of any nonce or replay cache (§20.4), it means a captured envelope stays valid for its
entire TTL and there is no `issued_at`-based way to narrow that.

**No maximum TTL.** `expires_at` may be years away; only "in the future" is enforced. A client can
mint a decade-long intent. Nothing in the design suggests that was intended.

---

## 12. Layer 8 — Error Taxonomy

`attest/errors.py` — a frozen dataclass and a dict. 25 lines that give the whole system a stable
public contract.

```python
@dataclass(frozen=True)
class CustosError:
    code: str
    name: str
    status_code: int
```

Every code carries its own HTTP status, so the mapping lives in one place and `gateway/server.py`
never writes a status literal — it writes `ERRORS[response.error].status_code`.

### 12.1 The full taxonomy — every row verified by execution

| Code | Name | HTTP | Layer | Verified trigger |
|---|---|---|---|---|
| `CUSTOS-E100` | `MALFORMED_ENVELOPE` | 400 | schema / validation | `{}`, `custos/2`, extra field, negative amount, `EUR`, `action:"steal"`, naive datetimes |
| `CUSTOS-E101` | `CLAIM_STALE` | 403 | engine | `TKN-UST-3M-002` → *"last attested 72.00 hours ago; threshold is 24.0 hours."* |
| `CUSTOS-E102` | `INTENT_EXPIRED` | 400 | validation | `expires_at` one minute in the past |
| `CUSTOS-E103` | `CLOCK_SKEW` | 400 | validation | `issued_at` ten minutes ahead |
| `CUSTOS-E200` | `UNKNOWN_ASSET` | 404 | registry | unknown `asset_id` — precedes any oracle call |
| `CUSTOS-E201` | `YIELD_DRIFT_EXCEEDED` | 403 | engine | `TKN-UST-3M-003` → *"Claimed yield 360 bps diverges 10.00% from observed 3M yield of 400 bps; threshold is 2.0%."* |
| `CUSTOS-E202` | `BACKING_RATIO_BELOW_FLOOR` | 403 | engine | `TKN-UST-6M-004` → *"Backing ratio is 0.9400; floor is 1.0000."* |
| `CUSTOS-E203` | `TENOR_UNSUPPORTED` | 422 | oracle | requires `UnsupportedTenor`; unreachable with the current seed |
| `CUSTOS-E300` | `ORACLE_UNAVAILABLE` | 503 | oracle / engine | oracle returns `None`; **also** `observed_bps <= 0` |
| `CUSTOS-E301` | `ORACLE_DATA_STALE` | 503 | engine | 9-day-old observation → *"is 9 days old; maximum is 4."* |
| `CUSTOS-E400` | `DOWNSTREAM_UNREACHABLE` | 502 | proxy | `downstream` pointing at a closed port |

All 11 codes are reachable and every status matches `Technical Document.md` §7 exactly. That table
is one of the few places where spec and code agree without qualification.

### 12.2 Status-code choices worth defending

- **`E101`/`E201`/`E202` are 403, not 422.** The request was well-formed; the *asset* failed policy.
  403 Forbidden is the right shape — an agent that retries verbatim will get the same answer, and
  the fix is on the issuer's side.
- **`E300`/`E301` are 503**, which is retryable and correctly signals "not your fault."
- **`E203` is 422** — the claim references a tenor Custos cannot price. Neither client nor market
  is at fault; the registry is.
- **`E400` is 502**, standard gateway semantics.

### 12.3 The `E300` overload

`E300` means two unrelated things: *the oracle could not be reached* and *the oracle returned a
non-positive yield*. The `detail` strings differ, but the code does not, so a client cannot
distinguish "retry in a minute" from "the feed is publishing something we refuse to price." Given
that §18 makes `E300` the *only* response the default configuration ever produces, splitting it —
or at minimum logging the distinction server-side — is worth more than its size suggests.

### 12.4 Error prose

Every `detail` substitutes the actual numbers *and* the threshold that was applied. Compare:

```
"Claimed yield 360 bps diverges 10.00% from observed 3M yield of 400 bps; threshold is 2.0%."
```

against the more common `"yield drift exceeded"`. The first tells an operator what to change; the
second sends them to the source. This is a consistent strength across the codebase.

---
## 13. Layer 9 — The HTTP Gateway

`gateway/server.py` — 175 lines, seven routes, three module-level singletons.

```python
app      = FastAPI(title="Custos Gateway", version="0.1.0", …)
registry = ClaimRegistry()      # loaded once, at import
oracle   = TreasuryOracle()     # one shared cache
signer   = AttestationSigner()  # one key for the process lifetime
```

Import-time construction is why `monkeypatch.setattr(server, "oracle", FakeOracle())` works in the
tests and in `run_local_demo.py` — the seam is intentional and used. It is also why there is no
per-tenant isolation and no way to run two configurations in one process (§20.3).

### 13.1 The route table

| Method | Path | Calls | Returns |
|---|---|---|---|
| `POST` | `/v1/intent` | validation → registry → oracle → engine → signer → optional proxy | Signed ALLOW or structured BLOCK |
| `GET` | `/v1/assets` | registry | All seeded claims |
| `GET` | `/v1/assets/{asset_id}` | registry → oracle → engine | Claim + observation + evaluation, executing nothing |
| `GET` | `/v1/pubkey` | signer | Ed25519 key, base64 and PEM |
| `GET` | `/v1/health` | oracle (`3M`) | `ok` (200) or `degraded` (503) |
| `POST` | `/v1/demo/sync` | oracle → registry mutation | Re-aligns simulated claims to the live curve |
| `GET` | `/demo` | filesystem | `demo/live.html`, hidden from OpenAPI |

### 13.2 `POST /v1/intent` — the orchestration

```
validate_temporal_envelope(intent)     → BLOCK?  return with ERRORS[code].status_code
assess(intent)                         → (result, claim, observation)
isinstance(result, BlockResponse)      → return with ERRORS[code].status_code
make_attestation(intent, result, claim, observation)
intent.downstream is None              → 200 {attestation}
forward(intent, attestation)           → 200 {attestation, downstream}
ConnectionError                        → 502 CUSTOS-E400
```

Fourteen lines of handler, because every decision is delegated. The one piece of logic it owns is
the ALLOW/forward branch, and that is the piece worth scrutinising (§14.2).

`assess()` is the composition seam: it resolves the claim, catches `UnsupportedTenor` from the
oracle and converts it to `E203`, and passes the triple to `evaluate()`. Note it calls
`evaluate(intent, None, None)` on a registry miss rather than constructing the `E200` block inline —
so the *engine* remains the single source of the error-precedence contract even for a condition the
gateway has already detected.

### 13.3 `make_attestation` — sign-after-construct

```python
attestation = Attestation(..., public_key=signer.public_key_base64)   # signature is None
payload = attestation.model_dump(mode="json")
attestation.signature = signer.sign(payload)
```

The two-phase construction is required by the canonical form: the payload must exist in its final
JSON shape *before* it can be signed, and `signature` must be absent (or `None`) at that moment.
`canonicalize` strips both `signature` and `public_key`, so the `None` placeholder is harmless.

`mode="json"` is doing critical work: it converts `Decimal` → string and `datetime` → ISO-8601
*before* canonicalization, so the signed bytes contain only JSON primitives. FastAPI's
`jsonable_encoder` then re-derives the same representation for the response, which is why the
independent verifier can reproduce the bytes exactly. Verified across four amount formats in §9.3.

`attestation_id` is `att_` + `uuid4().hex` — 122 bits of randomness, never stored, never checked. It
is a correlation handle for logs, not a replay defence (§20.4).

### 13.4 The other read routes

**`GET /v1/assets/{asset_id}`** builds a *synthetic* intent to reuse the scoring path:

```python
diagnostic_intent = Intent(envelope_version="custos/1", agent_id="diagnostic", action="trade",
                           asset_id=asset_id, amount="0.01", currency="USD", ...)
```

The dummy `agent_id="diagnostic"` and `amount="0.01"` are inert precisely because the engine ignores
both (§10.5) — a small dependency on a property nobody has written down. The endpoint returns the
claim, the observation, and the full evaluation without executing or signing anything, which makes
it the right tool for showing *why* an asset is about to be blocked. `Technical Document.md` §10
recommends building it early for exactly that reason.

**`GET /v1/health`** probes the `3M` tenor and returns 200/`ok` or 503/`degraded`. Verified in both
states. Because it goes through the same cache, a healthy response can be up to 60 s stale — fine
for a liveness check, misleading as a data-freshness signal. It is also the only endpoint that will
answer truthfully about §18 without reading logs.

**`GET /v1/pubkey`** returns the raw base64 key and the SPKI PEM. It is the trust anchor a relying
party must pin — and today it changes on every restart (§9.2).

### 13.5 `POST /v1/demo/sync` — honest, and in the wrong place

The handler's docstring is careful and correct: *"It never changes a chain claim or production
source of truth; the seeded registry is an explicitly in-memory v1 simulation."* What it does:

1. Fetch a live observation for every distinct tenor in the registry (`3M`, `6M`).
2. Set every claim's `claimed_yield_bps` to the observed value…
3. …except `TKN-UST-3M-003`, which is pushed **4% or 40 bps below** observed, whichever is larger,
   so the drift demo still fires.
4. Return `{"mode": "live-market-demo", "notice": "…claim records remain simulated in memory.", …}`.

This is the correct mitigation for the calibration trap quantified in §7.3, and the `notice` field
in every response is the right instinct — the API itself tells you the claims are simulated.

The problem is placement. It is an **unauthenticated POST that mutates shared server state**,
registered on the same app as `/v1/intent`, and it appears in the public OpenAPI schema (unlike
`/demo`, which is hidden with `include_in_schema=False`). Deployed as-is, anyone who can reach the
gateway can rewrite every claim it evaluates. Mounting it on a separate router that is only included
when an explicit `CUSTOS_DEMO_MODE` flag is set would cost about five lines. §22 P0-2.

### 13.6 The validation-error handler

```python
@app.exception_handler(RequestValidationError)
```

FastAPI's default 422 body is replaced with a `BlockResponse` carrying `CUSTOS-E100` at HTTP 400.
Every rejection the client can see — schema, temporal, scoring, proxy — therefore has the same
shape: `{verdict, error, error_name, detail, …}`. A client needs exactly one error parser. That
consistency is worth more than adherence to FastAPI's 422 default, and the choice matches the
specification's table.

The trade-off is that all seven distinct schema failures collapse into one `detail` string,
`"Envelope schema validation failed."` — the `exc` argument is bound and never used. Pydantic's
per-field errors are discarded. Including `exc.errors()` (field paths and reasons, without echoing
submitted values) would make client debugging dramatically easier at no security cost. §22 P2-14.

---

## 14. Layer 10 — The Downstream Proxy

`gateway/proxy.py` — 27 lines, reached only after an ALLOW when `intent.downstream` is set.

### 14.1 What it does

```python
serialized = json.dumps(attestation.model_dump(mode="json"), separators=(",", ":"), ensure_ascii=True)
headers = {"X-Custos-Attestation": base64.b64encode(serialized.encode("utf-8")).decode("ascii")}
...
await client.post(str(intent.downstream), json=intent.model_dump(mode="json", exclude={"downstream"}), headers=headers)
```

| Decision | Why |
|---|---|
| base64 in a header | Raw JSON in an HTTP header is illegal (control characters, non-ASCII). base64 is header-safe and universally decodable |
| `exclude={"downstream"}` | The lender receives the intent without the routing field it does not need |
| `follow_redirects=False` | **A security control.** A redirect would carry the signed attestation to an unvetted host; refusing to follow keeps the credential where it was addressed. The oracle client, by contrast, sets `follow_redirects=True`, which is right for a public data feed |
| `httpx.HTTPError` → `ConnectionError` | Translates a transport exception into a domain one, so `server.py` never imports httpx |

Measured header size for a real attestation: **1,024 bytes** of base64. Comfortably inside the 8 KB
default header budget of nginx and most gateways, but large enough that a proxy configured with
tight limits would truncate it. Worth stating in the integration guide.

The `assert intent.downstream is not None` on the first line is a `-O`-strippable guard on an
invariant the caller already enforces. Harmless, but it is the only assert in the codebase.

### 14.2 The E400 hole

Verified end-to-end against a live mock lender on port 9000 (success) and a closed port (failure):

```
downstream reachable    → 200 {"attestation": {...}, "downstream": {"status_code": 200, "body": {...}}}
downstream unreachable  → 502 {"verdict": "BLOCK", "error": "CUSTOS-E400", ...}
```

The 502 body **does not contain the attestation**. The gateway evaluated the asset, decided ALLOW,
minted and signed a record — and then discarded it because a third party was down. Three
consequences:

1. **The agent gets nothing for the work.** It cannot retry against the lender itself, cannot show
   an auditor that Custos approved, and cannot cache the verdict for the attestation's 300-second
   TTL. It must re-run the whole evaluation.
2. **`verdict: "BLOCK"` is a false statement.** The asset passed. The response says the opposite,
   and a client that keys on `verdict` will record a denial that did not happen.
3. **There is no idempotency.** `httpx` may have delivered the POST before failing on the response.
   The agent cannot distinguish "never arrived" from "arrived and the reply was lost," and a retry
   may double-submit a loan request.

Returning `502 {"attestation": {...}, "downstream": {"error": "CUSTOS-E400"}}` would fix (1) and (2)
in a few lines. (3) needs an idempotency key echoed to the downstream — `attestation_id` is already
a unique value and is already in the header. §22 P1-10.

### 14.3 What the downstream is expected to do

`demo/mock_lender.py` is the reference consumer, in full:

```python
@app.post("/loan")
async def loan(x_custos_attestation: str | None = Header(default=None)):
    if not x_custos_attestation:
        return {"accepted": False, "reason": "missing Custos attestation"}
    return {"accepted": True, "message": "loan request reached the lender with a Custos attestation"}
```

It checks **presence, not validity**. It does not base64-decode, does not verify the signature, does
not check `expires_at`, and does not compare `asset_id` against the loan it is being asked to make.
As a ten-line demo prop that is fine. As the only worked example of a consumer, it teaches the wrong
integration — and `utilisation.md` §5 shows the same presence-only pattern. The complete consumer
contract is: decode → verify signature against a **pinned** key from `/v1/pubkey` → check
`expires_at` → check `asset_id`, `action`, and `amount` match the request being served → then act.
That is five checks, of which the reference implements zero. §22 P1-11.

---

## 15. The Demo Surface

Four entry points, three fidelity levels. The layering is deliberate and better thought through
than most demo code.

### 15.1 `demo/run_local_demo.py` — deterministic, in-process

Runs the **real FastAPI app** through `httpx.ASGITransport`, substituting only the oracle:

```python
class DemoOracle:
    """A known-good 4.00% Treasury observation for deterministic demo outcomes."""
```

It swaps `server.oracle`, runs four scenarios, and restores the original in a `finally` block. The
docstring is explicit about the boundary: *"Only the Treasury observation is fixed so every
presentation has the intended outcomes. Production continues to use `oracle.treasury.TreasuryOracle`
and its live feed."* Every route, model, and signature in the run is the production one.

Four scenarios, rendered as a `rich` table with expected-vs-actual columns:

| Scenario | Asset | Expected |
|---|---|---|
| Stale claim | `TKN-UST-3M-002` | `CUSTOS-E101` |
| Recent but drifted | `TKN-UST-3M-003` | `CUSTOS-E201` |
| Under-backed | `TKN-UST-6M-004` | `CUSTOS-E202` |
| Healthy | `TKN-UST-3M-001` | signed `ALLOW` |

On ALLOW it writes `demo/attestation.json` and **immediately calls the independent verifier**, so
the cryptographic claim is demonstrated inside the same run rather than asserted. It also inserts
the project root into `sys.path` explicitly, so `python demo/run_local_demo.py` works from the
repository root — the invocation the README documents.

### 15.2 `demo/run_demo.py` — over real HTTP

The same three intents against a running gateway via `httpx.Client`, printing each response in a
`rich` panel and writing `attestation.json` on the first ALLOW. This is the version that exercises
uvicorn, real sockets, and the live oracle — and therefore the version that surfaces §18. It has no
`--asset` flag and no exit code, so it cannot be used as a smoke test in CI.

### 15.3 `demo/live.html` — the browser demo

A single self-contained 59-line page served at `GET /demo`, with no build step and no external
assets. On load it calls `/v1/demo/sync`, renders the live 3M yield as a headline metric with its
record date and cache status, offers a dropdown of the four scenarios, and polls `/v1/health` every
60 seconds to keep a status dot honest.

Its failure copy is the detail worth noticing: when sync fails it says *"Live market unavailable —
Custos will fail closed"*, which is accurate rather than reassuring. A demo page that tells the
truth about degradation is doing the product's job. Given §18, this is the message it will show by
default today.

### 15.4 `demo/verify_attestation.py` — the closer

29 lines, imports nothing from Custos, prints:

```
VALID: Ed25519 signature matches the canonical attestation payload.
```

`Technical Document.md` §9.4 calls it "the strongest 15 seconds of the demo," and structurally it
earns that: it is a second independent implementation of the canonical form, and the test suite
checks the gateway against *it* rather than against itself. Its trust-anchor limitation is §9.4.

### 15.5 Fidelity ladder

| Runner | App | Oracle | Network | Deterministic |
|---|---|---|---|---|
| `run_local_demo.py` | real | **fixed 400 bps** | none (ASGI) | yes |
| `run_demo.py` | real | live | real HTTP | no |
| `live.html` | real | live + sync | browser | no |
| `pytest` | real | fixed | none | yes |

The invariant across all four: **only the oracle is ever substituted.** No demo mocks the engine,
the signer, or the routes. That discipline is what lets the deterministic runs stand as evidence
about the real system — and it is also precisely why every demo passes while the live path (§18)
does not.

---

## 16. The Test Suite

12 tests, three files, 144 lines, no `conftest.py`, no fixtures, no mocking library.

```
python -m pytest -q  →  12 passed in 0.31s
```

### 16.1 Coverage map

| File | Tests | What they pin |
|---|---|---|
| `test_engine.py` | 7 | ALLOW path; `E101` short-circuit precedence; `E201`; `E300` fail-closed; `E202`; Ed25519 round-trip; canonical-form stability |
| `test_gateway.py` | 4 | `E100` structured 400; ALLOW signed **and independently verified**; `E200` precedes the oracle fetch; demo-sync behaviour |
| `test_oracle.py` | 1 | `parse_yield_curve` selects the latest record, not document order |

### 16.2 The three that carry the most weight

**`test_stale_claim_short_circuits_first`** builds a claim that is both 25 hours old and off by 399
bps, and asserts `E101`. It pins the *ordering contract*, not a single check — the one property most
likely to be broken by a well-meaning refactor.

**`test_allow_is_signed_and_independently_verifiable`** posts a real intent through `TestClient` and
runs `demo.verify_attestation.verify` on the response body. It is a cross-implementation test:
gateway serialization (via `jsonable_encoder`) against a verifier that shares no code with it. If
FastAPI ever changed how it renders a `Decimal` or a `datetime`, this test fails immediately.

**`test_canonical_form_is_stable`** asserts the exact bytes:

```python
assert first == second == b'{"a":1,"b":2}'
```

Byte-level, not structural. That is the correct strength for a signing primitive — anything weaker
would let a whitespace or ordering change through.

### 16.3 What is not covered

| Gap | Risk |
|---|---|
| **`TreasuryOracle.get_observation` — the network path** | **Critical.** `parse_yield_curve` is tested against a hand-written Atom fixture that matches the parser's assumptions. Nothing tests the fetch, the retry, the cache, or the parser against the *actual* configured URL. This is the exact gap that hides §18 |
| **A live-feed shape test** | `Technical Document.md` §14 explicitly lists *"Live oracle fetch returns a plausible bps value (300–600) — catches API shape changes"* as a planned test. **It was never written.** It is the one test that would have caught §18 on the day it appeared |
| `TTLCache` | TTL expiry, `cache_hit` flagging, monotonic behaviour — untested |
| `gateway/proxy.py` | Not imported by any test. Header encoding, `exclude`, redirect refusal, `E400` — all unverified by CI |
| `gateway/validation.py` | `E102`/`E103` have no unit test; only reachable through the API |
| `E301`, `E203`, `E400` | Three of eleven codes are never exercised by a test |
| Concurrency | No test of simultaneous requests against the shared cache/registry |
| Boundary conditions | The exact-2.00%-drift and exact-1.0-ratio edges are undefended by tests (both verified by hand in §10) |

### 16.4 The invocation trap

```
python -m pytest -q   →  12 passed
pytest -q             →  3 collection errors: ModuleNotFoundError: No module named 'oracle'
```

Verified. There is no `pyproject.toml`, no `conftest.py`, and no `tests/__init__.py`, so the package
root reaches `sys.path` **only** via `python -m`'s implicit insertion of the working directory. The
README documents the working form, so a reader following it is fine — but a CI job, an IDE test
runner, or a contributor typing the habitual `pytest` gets three import errors that look like a
broken checkout. A four-line `pyproject.toml` with `[tool.pytest.ini_options] pythonpath = ["."]`
fixes it permanently. §22 P3-21.

---

## 17. Measured Performance

Benchmarked on this machine (Windows 11, CPython 3.10.11). Engine and crypto: 2,000 iterations
each. HTTP paths: 500 iterations through `httpx.ASGITransport` against the real app with a
substituted oracle.

| Operation | Median | Min | p95 | Max |
|---|---|---|---|---|
| `validate_temporal_envelope()` | **0.0010 ms** | 0.0009 | 0.0011 | 0.0198 |
| `Intent` model validation (Pydantic) | **0.0031 ms** | 0.0028 | 0.0033 | 0.0585 |
| `canonicalize()` | **0.0047 ms** | 0.0042 | 0.0051 | 0.2257 |
| `evaluate()` — full ALLOW path | **0.0064 ms** | 0.0059 | 0.0071 | 0.1844 |
| `evaluate()` — `E101` short-circuit | **0.0095 ms** | 0.0086 | 0.0117 | 0.0859 |
| `AttestationSigner.sign()` (canonicalize + Ed25519) | **0.0333 ms** | 0.0302 | 0.0363 | 0.2228 |
| `POST /v1/intent` — BLOCK `E200`, no oracle call | **0.4928 ms** | 0.4393 | 0.6112 | 0.9727 |
| `POST /v1/intent` — full ALLOW, warm cache | **0.6828 ms** | 0.6068 | 0.8330 | 1.2109 |

Network, measured separately against the live feed (§18):

| Operation | Observed |
|---|---|
| Treasury feed fetch (either URL, 7 samples) | **8,000–10,400 ms** |
| `TreasuryOracle.get_observation` cold, 3 s timeout × 2 attempts | **~7,000 ms → `None`** |
| `TreasuryOracle.get_observation` cache hit | sub-millisecond |

**Reading these numbers.**

- **The decision itself is free.** `evaluate()` at 6.4 µs is 0.9% of the 683 µs end-to-end request.
  Adding checks to the engine — a proportionality test, an over-backing ceiling, a future-date guard
  — costs nothing measurable. There is no performance argument against fixing §10's gaps.
- **Signing is 33 µs, 4.9% of the request.** Ed25519 was the right primitive; this is not a place to
  optimise.
- **The BLOCK path is 28% cheaper than ALLOW** (493 µs vs 683 µs), and the difference is almost
  entirely signing plus the larger response body. Denials are cheaper than approvals, which is the
  correct shape for a system under adversarial load.
- **~1,460 requests/second/core** on the warm path, single-process. Uvicorn workers scale that
  linearly since the only shared state is a read-mostly cache.
- **The entire in-process cost is noise next to the oracle.** A cold fetch is **10,000×** the cost
  of the local evaluation. The 60-second cache is therefore not an optimisation — it is the only
  thing standing between the gateway and an 8-second p100 on every request. Which makes the
  cache-miss path, and §18's failure of it, the whole performance story.

---
## 18. The Live Oracle Path Was Broken (fixed 2026-08-22)

> **RESOLVED 2026-08-22.** Both causes below are fixed, in `oracle/treasury.py` and
> `gateway/config.py`. In default configuration the gateway now reaches the live par yield
> curve and issues a signed ALLOW. Verified by execution on 2026-08-22:
>
> ```
> TreasuryOracle() with production defaults, no substitution:
>     1M 380 · 3M 388 · 6M 395 · 1Y 403 · 2Y 424 bps
>     record_date 2026-08-21 (latest business day), cache_hit False
>     cold-fetch latency across 10 calls: 8.2 / 8.6 / 9.1 / 9.1 / 9.5 / 10.1 / 10.1 / 11.6 s
>     -- the 15 s default leaves ~3.4 s over the worst observed. Tune with
>     CUSTOS_ORACLE_TIMEOUT if a deployment sees slower responses.
>
> GET  /v1/health  → 200  oracle_reachable: true, observed_yield_bps: 388,
>                         record_date 2026-08-21, source home.treasury.gov
> POST /v1/intent  → 200  ALLOW — signature verifies against the published gateway key
>                  → 403  CUSTOS-E300 / E301 / E302 for the stale, drifted and
>                         under-backed claims, against the real curve
> ```
>
> What changed, and nothing else:
>
> | Change | Where |
> |---|---|
> | `TREASURY_YIELD_URL` (legacy `QR_BC_CM`) replaced by `TREASURY_XML_BASE` + `yield_curve_url(year)` on the OData endpoint | `oracle/treasury.py` |
> | Year computed per request, with a previous-year fallback for the 1 January gap | `oracle/treasury.py:_candidate_urls` |
> | Default timeout 3.0 s → 15.0 s, in the class and in the config the server actually uses | `oracle/treasury.py`, `gateway/config.py` |
> | Seven tests, all hermetic (`httpx.MockTransport`, no network in CI) | `tests/test_oracle.py`, `tests/test_gateway.py` |
>
> **`parse_yield_curve` was not touched.** §18.2 below suggested the date parser needed
> repair too; that turned out to be a property of the legacy document only. Pointed at the
> OData feed the existing parser returns correct values for every mapped tenor on the first
> attempt, so fixing `_parse_date` would have been treating a symptom of the wrong URL.
>
> One cause was found that §18 did not predict: Treasury's year feed answers **HTTP 200 with
> zero entries** until the year's first business day closes — measured against
> `field_tdr_date_value=2027` on 2026-08-22, which returned 673 bytes and no `<entry>`. A
> bare current-year URL would therefore have failed closed every 1 January. Hence the
> previous-year fallback, which costs a second request only when the first yields nothing.
>
> The diagnosis is kept below as the record of what was wrong and how it was proven.
> §18.5 marks which remedies landed and which remain open.

This section is separated from §22 because it was not one finding among many. In its default
configuration, **Custos could not produce an ALLOW.** Every request failed closed with
`CUSTOS-E300` (`CUSTOS-E500` in the Phase 1 taxonomy). Two independent causes, each
individually sufficient, each verified by execution.

### 18.1 Symptom

```
>>> await TreasuryOracle().get_observation("3M")
cold fetch:  7017 ms  →  None
1M → None   3M → None   6M → None   1Y → None   2Y → None
```

Seven seconds, then `None`, for every tenor. `None` becomes `E300` at `attest/engine.py:31`.

### 18.2 Cause 1 — the URL serves a document the parser cannot read

```python
# oracle/treasury.py:16
TREASURY_YIELD_URL = "https://home.treasury.gov/sites/default/files/interest-rates/yield.xml"
```

That URL is reachable and healthy — `HTTP 200`, 19,041 bytes — but it serves Treasury's **legacy
`QR_BC_CM` report**, not the Atom/OData feed:

```xml
<QR_BC_CM><LIST_G_WEEK_OF_MONTH><G_WEEK_OF_MONTH><WEEK_OF_MONTH>2632</WEEK_OF_MONTH>
  <LIST_G_NEW_DATE><G_NEW_DATE>
    <BID_CURVE_DATE>03-AUG-26</BID_CURVE_DATE><DAY_OF_WEEK>MONDAY   </DAY_OF_WEEK>
    <LIST_G_BC_CAT><G_BC_CAT>
      <BC_1MONTH>3.79</BC_1MONTH><BC_3MONTH>3.91</BC_3MONTH><BC_6MONTH>4.02</BC_6MONTH>…
```

`parse_yield_curve` filters on `_local_name(entry.tag) != "entry"` (`oracle/treasury.py:43`). Tag
census of the live document:

```
distinct tags: G_NEW_DATE, BID_CURVE_DATE, DAY_OF_WEEK, LIST_G_BC_CAT, G_BC_CAT,
               BC_1MONTH … BC_30YEARDISPLAY      (14 occurrences each)
has <entry>:  False
parse_yield_curve(xml, "BC_3MONTH")  →  None
```

**No `entry` elements exist**, so the candidate list is empty and `max(..., default=None)` returns
`None`. The date field is `BID_CURVE_DATE` in `DD-MON-YY` form (`03-AUG-26`); the document's one
`NEW_DATE` element carries `08-03-2026`, `MM-DD-YYYY`. `_parse_date` accepts neither. Even a parser
patched to find the right nodes would fail on the dates.

**The parser is not the problem.** Pointed at Treasury's OData/Atom feed — the one it was clearly
written against, with `<entry>` elements and ISO `NEW_DATE` values — it works on the first attempt:

```
https://home.treasury.gov/resource-center/data-chart-center/interest-rates/pages/xml
    ?data=daily_treasury_yield_curve&field_tdr_date_value=2026
→ HTTP 200, 247,873 bytes, has <entry>: True
→ parse_yield_curve(xml, "BC_3MONTH")  →  (datetime.date(2026, 8, 20), 3.87)
```

The full curve parses cleanly for every mapped tenor:

```
1M 380 bps   1.5M 377 bps   2M 379 bps   3M 387 bps
4M 388 bps   6M 394 bps     1Y 399 bps   2Y 419 bps      (all record 2026-08-20)
```

**Cause 1 is a one-line fix**: change the constant. `TreasuryOracle.__init__` already accepts a
`url` override, so the fix is testable without touching the class.

### 18.3 Cause 2 — the timeout cannot be met

Independently of the URL, both feeds are slow from this host. Seven samples, two connection
strategies:

| Sample | Feed | Latency |
|---|---|---|
| Keep-alive ×4 | `yield.xml` | 10,295 / 8,062 / 8,055 / 9,055 ms — median **8,559 ms** |
| Fresh client ×3 | `yield.xml` | 10,440 / 9,050 / 9,044 ms |
| Fresh client | OData feed | 8,369 ms |

Against `ORACLE_TIMEOUT_SECONDS = 3.0`. The client makes two attempts (`for attempt in range(2)`),
so a cold miss burns ~7 seconds of wall time and returns `None`. Correcting the URL alone would not
restore service.

Three things follow:

- **The retry doubles the worst case.** The effective oracle budget is `2 × ORACLE_TIMEOUT_SECONDS`,
  which no configuration key names and no document states.
- **Nothing bounds the request.** `POST /v1/intent` has no overall deadline, so a client's first
  sight of `E300` arrives ~7 s after it asked. At the 60-second cache TTL, one in every ~8 requests
  in a steady stream pays that cost.
- **A 3 s budget for a government bulk-XML endpoint was optimistic.** `Technical Document.md` §8.2
  specifies "3s connect, 3s read" without a measurement behind it. 15 s with a single retry, or a
  10-second connect and a 20-second read, is realistic for a 248 KB document from this host.

### 18.4 Why no test caught it

`tests/test_oracle.py` tests `parse_yield_curve` against a **hand-written Atom fixture** that
matches the parser's assumptions perfectly. It is a correct test of a correct function. Nothing
tests the function against the bytes the configured URL actually returns, and nothing tests the
fetch at all.

`Technical Document.md` §14 planned exactly this test:

> *"Live oracle fetch returns a plausible bps value (300–600) — **catches API shape changes**"*

It was specified, its purpose was correctly predicted, and it was never written. That single row of
the testing table is the difference between a working product and a permanently-failing one.

### 18.5 Recommended fix, in order — status 2026-08-22

1. **DONE — Repoint `TREASURY_YIELD_URL`** at the OData feed. Landed as `TREASURY_XML_BASE`
   plus `yield_curve_url(year)`, because the endpoint needs a year parameter and that year
   has to be computed rather than frozen into a constant.
2. **DONE — Raise the timeout** to 15 s, in `TreasuryOracle` *and* in
   `gateway.config.ORACLE_TIMEOUT_SECONDS`. The second one is the one the server actually
   runs with; fixing only the class default would have left the bug in place. Both are now
   covered by a test that fails below 12 s.
3. **DONE, differently — Add the specified live test.** A network test in the suite would be
   flaky and slow (8-10 s per call), so the seven new tests are hermetic: they pin the URL
   shape, the current-year-then-previous-year order, the fallback behaviour on an empty feed,
   the single-request happy path, and both timeout defaults. The live-shape check was instead
   run by hand and its output recorded in the resolution box above. What would have caught
   the original bug is the URL-shape assertion, which is now permanent:
   `assert "sites/default/files" not in url`.
4. **Log the reason for every `None`** in the oracle — HTTP status, timeout, or parse failure.
   Today all three are silent and indistinguishable, which is why diagnosing this required probing
   the feed by hand.
5. **Add a fallback source.** `Technical Document.md` §8.1 designates the Fiscal Data JSON API as
   the primary and this XML feed as the fallback; the code implements only the fallback. Wiring the
   JSON client behind the same `Observation | None` interface — which the module boundary already
   supports — gives two independent paths to the same number.

---

## 19. Spec ↔ Implementation Divergences

The repository carries four documents that describe the system: `Technical Document.md` (the
pre-build specification), `AGENTS.md` (the implementation contract), `README.md`, and
`utilisation.md`. They do not all agree with the code.

| # | Topic | Docs say | Code does | Impact |
|---|---|---|---|---|
| 1 | **Oracle source** | Fiscal Data JSON API is primary; `home.treasury.gov` XML is the "fallback source" (§8.1) | Only the XML source, now pointed at the OData endpoint the parser was written for | ~~Fatal~~ **Resolved 2026-08-22** for correctness (§18). Still a single point of failure: the documented primary JSON source is not wired, so there is one path to the number, not two |
| 2 | **Live-feed test** | §14 lists "live oracle fetch returns a plausible bps value (300–600)" as a required test | Not written | The gap that hid #1 |
| 3 | `FAIL_MODE` | §13: `closed \| open`, "deliberate and documented" | Declared in `config.py:19`, **read by nothing** | A knob that silently does nothing |
| 4 | Tenor mapping | §8.3 maps to CMT series names (`1 Mo`, `3 Mo`) | Maps to XML field names (`BC_1MONTH`) | Consistent with the fallback source; the spec table describes the API that was not built |
| 5 | `E101` category | §7 classifies it under "Envelope" | Emitted by the engine as a claim check | Taxonomy mislabel; behaviour correct |
| 6 | Retry budget | §8.2: "Timeout 3s connect, 3s read" | Two attempts ⇒ ~7 s effective | Understates worst-case latency by 2× |
| 7 | Seed count | §11 specifies 3 assets + 1 optional | 4 assets seeded | Doc lag, harmless |
| 8 | Seed yields | §11: healthy = "live ± 2 bps" | Hard-coded 400 bps | All four assets block against today's curve (§7.3) |
| 9 | Repo name | README H1: `APay-Gateway`, then `Custos Gateway` | Directory is `AIP-Gateway`; code says Custos | Three names for one product |
| 10 | README integrity | — | **Unresolved merge marker `>>>>>>> 3da9d8f (Project Base)` on line 39** | The first file a reader opens ends in a conflict artifact |
| 11 | Test-suite claim | README: "covers all scoring paths, fail-closed behavior, canonical serialization, Ed25519 verification, and Treasury XML normalization" | Accurate for those five; silent on the untested fetch, proxy, cache, and 3 of 11 error codes | True but incomplete in the place that mattered |
| 12 | `pytest` invocation | README: `python -m pytest -q` | Bare `pytest` fails with 3 collection errors | Documented form works; the habitual one does not |
| 13 | Diagram assets | `TECHNICAL_DIAGRAM.md` references `diagrams/*.svg` | Root `custos-architecture.svg` and `custos-sequence.svg` are referenced by nothing and differ in content | Two orphaned assets |
| 14 | Contract address | Seed `TKN-UST-3M-002` | `0x…002` — 39 hex digits, not 40 | Invalid Ethereum address, unvalidated |
| 15 | Attestation TTL | `ATTESTATION_TTL_SECONDS = 300` sets `expires_at` | **Nothing reads it back** — not the proxy, not the mock lender, not the verifier | An expiry field no code enforces |
| 16 | Signing spec | §9.3 gives the canonical algorithm | Matches exactly | ✔ no divergence — the most security-critical spec is the most accurate |
| 17 | Module boundaries | `AGENTS.md` dependency rule | Import graph verified clean | ✔ no divergence |
| 18 | Error taxonomy | §7 table: 11 codes, names, HTTP statuses | All 11 verified reachable with matching statuses | ✔ no divergence |
| 19 | Evaluation order | `AGENTS.md`: E200 → E300 → E301 → E101 → E201 → E202 | Exactly that order | ✔ no divergence |

Items 1, 2, 3, 8 and 10 change behaviour or block a reader. Items 16–19 are worth noting for the
opposite reason: the specification's *core* contracts — signing, module boundaries, error taxonomy,
evaluation order — were implemented precisely as written. The divergences are concentrated at the
edges of the system, which is the normal and expected failure pattern for a build under time
pressure, and exactly why the perimeter deserves the next work.

---

## 20. Security Model & Threat Analysis

### 20.1 What Custos genuinely provides

| Property | Strength | Basis |
|---|---|---|
| **Fail-closed availability semantics** | Strong | Verified: every oracle failure mode collapses to `None` → `E300`. There is no code path that allows a transaction without a fresh observation |
| **Tamper-evident verdicts** | Strong | Ed25519 over a byte-stable canonical form. Verified: mutating `amount` or any `scores` field invalidates the signature |
| **Self-describing evidence** | Strong | `scores` carries each metric beside its threshold; `reference` names source, tenor, record date and both yields. All inside the signature |
| **Deterministic, ordered denials** | Strong | The precedence contract is tested; `detail` strings carry actual values |
| **Input hardening** | Good | `extra="forbid"`, regex-pinned version, closed action enum, `Decimal` money, explicit UTC enforcement |
| **Redirect containment on forward** | Good | `follow_redirects=False` keeps a signed attestation from being carried to an unvetted host |

### 20.2 The trust boundary question

**Custos is a trusted third party, and today it is a single one.** The attestation says "this
gateway, holding this key, believed this claim was plausible at this time." That is worth something
only if a relying party can (a) identify the key and (b) trust the operator. Right now:

- **The key is ephemeral by default** (§9.2). It changes on every restart, so `/v1/pubkey` is not a
  stable anchor and pinning is impossible without setting `CUSTOS_PRIVATE_KEY`.
- **The reference verifier trusts the embedded key** (§9.4, verified: a forged attestation signed by
  an attacker key is accepted). Any consumer who copies those 29 lines gets no authentication at all.
- **There is one attestor.** `Technical Document.md` §18.3 names this: *"a single attestor is itself
  a trust assumption."* Correct, and the roadmap's threshold-signature item is the right answer.

The chain is only as strong as its weakest link, and today the weakest link is that a relying party
has no reliable way to know whose signature it is looking at.

### 20.3 Multi-tenancy and shared state

`registry`, `oracle`, and `signer` are module-level singletons created at import (§13). Consequences:

- One key for all callers — no per-tenant signing identity.
- One shared observation cache — no per-caller freshness guarantee.
- One mutable registry — and `POST /v1/demo/sync` can rewrite it (§13.5).
- No way to run two configurations in one process.

For a demo gateway this is right-sized. As a hosted service it means every tenant shares a blast
radius, and the demo-sync endpoint is a state-mutation primitive available to anyone who can reach
the port.

### 20.4 Threat table

| Threat | Status | Detail |
|---|---|---|
| **Tampered attestation** | **Mitigated** | Ed25519 over canonical bytes; verified rejection of `amount` and `scores` mutation |
| **Forged attestation with attacker key** | **Not mitigated** | Verified accepted by the reference verifier. Requires key pinning + a persistent key |
| **Replayed attestation** | **Not mitigated** | `attestation_id` is never stored or checked; `expires_at` is never enforced by any consumer. An ALLOW is reusable for its 300 s window, and indefinitely if the consumer ignores expiry |
| **Replayed intent** | **Not mitigated** | No nonce, no `jti`, no seen-cache. A captured envelope is valid for its whole TTL, and TTL is unbounded (§11) |
| **Unauthenticated caller** | **Not mitigated** | No auth on any route. `agent_id` is a self-asserted string, signed but never verified |
| **Unauthenticated state mutation** | **Not mitigated** | `POST /v1/demo/sync` rewrites every claim; no flag, no auth, in the public OpenAPI schema |
| **Future-dated claim defeats staleness** | **Not mitigated** | Verified: `last_attested_at = now + 5 years` → `staleness_hours = 0.0` → ALLOW |
| **Oracle compromise / feed poisoning** | **Not mitigated** | Single source, no cross-check, no signature on the feed. A wrong `observed_yield_bps` moves the drift check directly |
| **Oracle outage** | **Mitigated (by failing)** | `E300`. Availability is the cost, and §18 shows the cost is currently 100% |
| **Stale market data** | **Mitigated** | `E301` at >4 days, plus the 60 s cache TTL |
| **Downstream credential leak via redirect** | **Mitigated** | `follow_redirects=False` on the proxy |
| **Attestation lost on downstream failure** | **Not mitigated** | `E400` discards a valid attestation and reports `verdict: BLOCK` (§14.2) |
| **Amount/action not authorized** | **By design, but mis-signalled** | Verified: $1T against a $100 fund → ALLOW. Both fields are signed, inviting the wrong reading |
| **Unencrypted key at rest** | **Not mitigated** | `load_pem_private_key(pem, password=None)`; no passphrase support, no file-mode check |
| **DoS via cold-cache stampede** | **Partially mitigated** | 60 s TTL bounds it to one fetch per tenor per minute; no lock, so simultaneous misses duplicate the fetch |
| **Information leak in errors** | **Mitigated** | `detail` strings carry thresholds and market figures — all public data. No stack traces, no internal paths |

### 20.5 Deployment hardening checklist

Before this is exposed to anything real:

1. **Set `CUSTOS_PRIVATE_KEY`** to a persistent Ed25519 PEM, `chmod 0600`, and publish the public
   key somewhere a relying party can pin it out-of-band.
2. **Gate `POST /v1/demo/sync`** behind an explicit demo flag, or move it to a router that is only
   mounted in demo mode.
3. **Authenticate callers** — at minimum an API key per `agent_id`, so the signed identity means
   something.
4. **Add replay defence** — a nonce on the intent and a seen-cache keyed by `attestation_id`,
   bounded by the attestation TTL.
5. **Enforce a maximum intent TTL** (minutes, not years) and reject implausibly old `issued_at`.
6. **Reject future-dated `last_attested_at`** with the same five-minute grace the envelope gets.
7. **Publish the consumer contract** (§14.3) and fix `demo/mock_lender.py` to implement all five
   checks, since it is the only worked example anyone will copy.
8. **Fix §18 first.** A gateway that returns `E300` to every request is not secure; it is offline.

---

## 21. Evolution (git history)

Six commits, reading bottom-up as a coherent two-day build:

| Commit | Date | Milestone |
|---|---|---|
| `3a359d6` | 2026-08-15 | Initial commit — README only, 1 line |
| `6acb1b9` | 2026-08-15 | **The entire system in one commit** — 37 files, 1,973 insertions: models, engine, signing, oracle, registry, gateway, proxy, 3 test files, both diagram sets, `AGENTS.md`, and the 689-line `Technical Document.md` |
| `24cce0c` | 2026-08-15 | README wording |
| `ebfa0c8` | 2026-08-15 | **`demo/run_local_demo.py`** — the deterministic in-process runner (97 L) + demo README |
| `3e46c22` | 2026-08-15 | **Live browser demo** — `live.html`, `/demo` and `/v1/demo/sync` routes, `registry.update_claim`, launcher script, +1 test |
| `be4a191` | 2026-08-16 | `utilisation.md` — operator guide and six use-case narratives (180 L) |

The arc is legible: *specify → build the whole thing at once → make the demo deterministic → make
the demo live → explain how to use it.*

Two observations that matter more than the count:

**The spec preceded the code and the code followed it closely.** `Technical Document.md` landed in
the same commit as the implementation, and §19 shows the core contracts — signing, module
boundaries, error taxonomy, evaluation order — were implemented exactly as written. That is
unusual and it shows in the coherence of the result.

**Every commit after the build adds demo surface; none adds test surface** (beyond the single
demo-sync test in `3e46c22`). The three commits following the implementation are `run_local_demo.py`,
`live.html`, and `utilisation.md` — all of them ways to *show* the system working, none of them a
check that it does. `Technical Document.md` §14's live-oracle test was specified before any of them
and written after none of them. §18 is the direct consequence: the demos were made progressively
more convincing while the one path they all substitute quietly stopped working.

---
## 22. Findings & Recommendations

Ordered by severity. Every item was verified against the running code; the evidence column names
the check that produced it.

### P0 — the product does not work / security

| # | Finding | Evidence | Fix |
|---|---|---|---|
| 1 | ~~**The live oracle never returns an observation.**~~ **FIXED 2026-08-22.** `TREASURY_YIELD_URL` served a legacy `QR_BC_CM` document with no `<entry>` elements, which `parse_yield_curve` could not read; independently, the feed takes 8–10 s against a 3 s timeout with one retry. Default configuration returned an oracle-unavailable code to **every** request | §18: `get_observation("3M")` → `None` after 7,017 ms; `has <entry>: False`. **After the fix:** all five tenors return live values dated 2026-08-21; `/v1/health` reports `oracle_reachable: true`; `POST /v1/intent` returns a signed ALLOW that verifies | Done: OData URL with a computed year and previous-year fallback; timeout raised to 15 s in `TreasuryOracle` *and* `gateway/config.py`; seven hermetic tests in `tests/test_oracle.py` + one in `tests/test_gateway.py`. Still open: structured logging for the reason behind every `None` (§18.5 item 4) and a second independent source (item 5) |
| 2 | **`POST /v1/demo/sync` is an unauthenticated state-mutation endpoint** on the production app, listed in the public OpenAPI schema. Anyone who can reach the port can rewrite every claim the gateway evaluates | `gateway/server.py:134`; no auth on any route; only `/demo` uses `include_in_schema=False` | Mount it on a router included only when an explicit `CUSTOS_DEMO_MODE` env flag is set |
| 3 | **The reference verifier accepts forged attestations.** `verify()` trusts the `public_key` embedded in the payload, so an attacker can re-sign arbitrary content with their own key | Verified: forged `amount="999999.00"` + attacker key + attacker signature → `verify()` accepts | Take a pinned key parameter; document that consumers must fetch the key from `/v1/pubkey` out-of-band and compare it. Requires #4 to be meaningful |
| 4 | **Keys are ephemeral by default**, so every attestation becomes unverifiable after a restart and no relying party can pin a stable identity | `attest/signing.py:26` — `Ed25519PrivateKey.generate()` when `CUSTOS_PRIVATE_KEY` is unset | Persist a key for any non-demo deployment; support an encrypted PEM (`password=` is hard-coded `None`) and check file mode on load |
| 5 | **No authentication anywhere.** `agent_id` is a self-asserted string that is signed but never verified, so the attestation's subject is whatever the caller typed | All 7 routes; no dependency, header check, or middleware | An API key per `agent_id` at minimum, before the signed identity means anything |

### P1 — correctness / semantics

| # | Finding | Evidence | Fix |
|---|---|---|---|
| 6 | **A future-dated claim defeats the staleness check.** `max(0.0, …)` clamps negative age to zero | Verified: `last_attested_at = now + 1825 days` → `staleness_hours = 0.0` → ALLOW | Reject `last_attested_at > now + 5 min` with the same grace `E103` gives the envelope |
| 7 | **A legitimate 0.00% yield is reported as an oracle fault.** `observed_bps <= 0` → `E300 "returned an invalid zero yield"`, which also fires for negative values | Verified: `observed_yield_bps = -5` → `E300` with "zero" in the detail | Guard only the division (`== 0`), treat a negative observation as a distinct data error, and correct the message |
| 8 | **`intent.amount` and `intent.action` are signed but never evaluated** | Verified: `amount = 1_000_000_000_000` against `claimed_backing_usd = 100` → signed ALLOW | Either add a proportionality check against `claimed_backing_usd`, or state in the attestation that amount is *recorded, not authorized* |
| 9 | **BLOCK responses are unsigned**, so a denial cannot be proved or distinguished from a forgery — while `utilisation.md` §7F offers Custos as compliance evidence | `models/attestation.py:36` — no signature fields on `BlockResponse` | Sign BLOCK with the same canonical form; it costs 33 µs (§17) |
| 10 | **`E400` discards a valid attestation and reports `verdict: "BLOCK"`** for an asset that passed, with no idempotency for a possibly-delivered POST | Verified: closed downstream port → `502 {"verdict":"BLOCK","error":"CUSTOS-E400"}`, attestation absent | Return the attestation alongside the downstream error; echo `attestation_id` as an idempotency key |
| 11 | **The reference consumer checks presence, not validity.** `mock_lender.py` never decodes, verifies, checks expiry, or matches `asset_id`/`amount` — and it is the only worked example | `demo/mock_lender.py`; same pattern in `utilisation.md` §5 | Implement all five consumer checks (§14.3) in the mock lender and publish the contract |
| 12 | **`registry.update_claim(**updates)` bypasses validation.** `model_copy(update=…)` does not re-run validators, so a caller can install a negative yield or zero `tokens_outstanding` | `claims/registry.py:31`; `tokens_outstanding: gt=0` is the guard the engine relies on | Re-validate with `Claim.model_validate(updated.model_dump())`, or type the accepted keys |
| 13 | **The backing check is a floor with no ceiling.** A 10× backing ratio is as strong a signal of a broken feed as 0.94× | Verified: `claimed_backing_usd = 1000` on a 100-unit liability → `backing_ratio = 10.0` → ALLOW | Add an upper bound (e.g. 1.5×) as a distinct code, or document the omission |
| 14 | **All schema failures collapse to one `detail` string.** The bound `exc` is never used, discarding Pydantic's per-field errors | `gateway/server.py:43` — `exc` unused | Include `exc.errors()` field paths and reasons without echoing submitted values |
| 15 | **`FAIL_MODE` is dead config** documented as a live knob | `grep config.FAIL_MODE` → 0 hits | Implement it, or delete it from `config.py` and `Technical Document.md` §13 |
| 16 | **`ORACLE_TIMEOUT_SECONDS` also governs the downstream proxy**, and the retry silently doubles it | `gateway/proxy.py:19`; `for attempt in range(2)` | Add `CUSTOS_DOWNSTREAM_TIMEOUT`; document the effective oracle budget as 2× |
| 17 | **No maximum intent TTL, and no lower bound on `issued_at`.** A decade-long envelope is accepted | `gateway/validation.py` checks only `expires_at > now` and `issued_at < now + 5 min` | Cap `expires_at - issued_at` at minutes; reject implausibly old `issued_at` |
| 18 | **`ATTESTATION_TTL_SECONDS` sets an `expires_at` nothing reads back** | `grep` — one write site, zero read sites | Enforce it in the mock lender and the documented consumer contract |

### P2 — documentation (high reader impact, low effort)

| # | Finding | Fix |
|---|---|---|
| 19 | **README line 39 carries an unresolved merge marker** `>>>>>>> 3da9d8f (Project Base)` — in the first file anyone opens | Delete the line |
| 20 | **README has two H1s: `APay-Gateway` and `Custos Gateway`**, and the directory is `AIP-Gateway` | Pick one name; keep the AIP-peer positioning in prose where it is an asset |
| 21 | **`Technical Document.md` §8.1 names Fiscal Data as the oracle source; the code uses the fallback** | Update the spec to describe what was built, and keep the JSON client as the roadmap item it now clearly is |
| 22 | **The canonical-form spec does not state its RFC 8785 subset.** Number canonicalization is not implemented and works only because Pydantic pre-converts every `Decimal` to a string | Document the invariant explicitly — it is the first thing a second-language implementation will break |
| 23 | **`canonicalize` strips `signature`/`public_key` only at the top level**; a nested key of either name would be signed | One sentence in §9.3 of the spec |
| 24 | **`README.md` claims full scoring-path test coverage** without noting that the fetch, cache, proxy, and 3 of 11 error codes are untested | Qualify the sentence; §16.3 has the list |
| 25 | **Seed `TKN-UST-3M-002` has a 39-digit contract address** | Add the missing digit |
| 26 | **Two orphaned SVGs** at the repo root, distinct in content from `diagrams/` | Delete, or reference them |
| 27 | **The demo calibration trap is described but not quantified** | Link the README caveat to `/v1/demo/sync` and state plainly that all four seeds block against an un-synced live curve (§7.3) |

### P3 — engineering hygiene

| # | Finding | Fix |
|---|---|---|
| 28 | **Bare `pytest` fails with 3 collection errors**; only `python -m pytest` works | Add a 4-line `pyproject.toml` with `[tool.pytest.ini_options] pythonpath = ["."]` |
| 29 | **No packaging manifest at all** — no `pyproject.toml`, `setup.py`, or `setup.cfg` | The same file fixes #28, separates dev deps, and pins the Python floor |
| 30 | **`pytest` and `rich` are runtime dependencies** but used only by `tests/` and `demo/` | Move to a dev/demo extra once #29 lands |
| 31 | **The oracle logs nothing.** Timeout, HTTP error, and parse failure are indistinguishable from the outside | Log the cause of every `None`; this is what made §18 invisible |
| 32 | **`TreasuryOracle`'s `client` injection seam exists but is unused by tests** | Use it to test the fetch/retry/cache paths without a network |
| 33 | **`TTLCache` has no test** — TTL expiry, `cache_hit` flagging, monotonic behaviour all unverified | Three short tests |
| 34 | **`gateway/proxy.py` is imported by no test** | Cover header encoding, `exclude={"downstream"}`, redirect refusal, and the `E400` path |
| 35 | **No CI configuration** | A workflow running `python -m pytest` on 3.10–3.12, plus a nightly job for the live-feed shape test |
| 36 | **No structured request logging** anywhere — no verdict, code, latency, or asset per request | A single log line per decision; the gateway currently cannot report its own `E300` rate |
| 37 | **Registry offsets are computed at construction**, so a long-running process drifts its "healthy" claim into staleness after 24 h | Compute per read, or reload the registry on a timer |
| 38 | **No concurrency test** against the shared cache and mutable registry | One test issuing simultaneous cold-cache requests |

---

## 23. Glossary & Quick Reference

### 23.1 Glossary

| Term | Meaning |
|---|---|
| **Intent** | The versioned request envelope an agent sends: who, what action, which asset, how much, valid when |
| **Claim** | What the issuer asserts about a tokenized asset — NAV per token, dollar backing, tokens outstanding, yield, last-attested time |
| **Observation** | A Treasury par-yield reading for one tenor, in integer basis points, with its own record date |
| **Attestation** | The signed ALLOW record: verdict + scores + market reference + expiry, sealed with Ed25519 |
| **Block response** | The structured denial: `CUSTOS-Exxx` code, name, human detail, and whatever scores were computed before the failure |
| **Staleness** | Hours since the claim was last attested. `> 24 h` → `E101` |
| **Yield drift** | `\|observed − claimed\| / observed`, relative to the trusted quantity. `> 2%` → `E201` |
| **Backing ratio** | `claimed_backing_usd / (tokens_outstanding × claimed_nav_per_token)`. `< 1.0` → `E202` |
| **Tenor** | The maturity bucket of the underlying Treasury instrument (`3M`, `6M`, …), mapped to a field in Treasury's XML |
| **Fail closed** | No observation ⇒ no attestation. Every oracle failure mode returns `None`, which becomes `E300` |
| **Canonical form** | `JCS/RFC8785-lite`: sorted keys, compact separators, ASCII-escaped, `signature`/`public_key` excluded |
| **Basis point (bps)** | 1/100th of a percent. 3.87% = 387 bps. All yields are integer bps end-to-end |

### 23.2 Minimum working example

```powershell
python -m pip install -r requirements.txt
python -m uvicorn gateway.server:app --reload
```

```powershell
# a healthy intent
$body = @{
  envelope_version = "custos/1"
  agent_id   = "did:web:acme.com:agents:treasury-bot"
  action     = "borrow_against"
  asset_id   = "TKN-UST-3M-001"
  amount     = "50000.00"
  currency   = "USD"
  issued_at  = (Get-Date).ToUniversalTime().ToString("o")
  expires_at = (Get-Date).AddMinutes(5).ToUniversalTime().ToString("o")
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/v1/intent `
                  -ContentType application/json -Body $body
```

> **Expect `CUSTOS-E300` today.** The live oracle path is broken (§18). For a working run use the
> deterministic in-process demo, which substitutes only the observation:
> `python demo/run_local_demo.py`

### 23.3 Command reference

| Command | Purpose |
|---|---|
| `python -m uvicorn gateway.server:app --reload` | Start the gateway (`/docs` for OpenAPI, `/demo` for the browser demo) |
| `python -m pytest -q` | Run the 12 tests — **`python -m` is required** (§16.4) |
| `python demo/run_local_demo.py` | Deterministic four-scenario demo, in-process, fixed 400 bps observation |
| `python demo/run_demo.py` | Same scenarios over real HTTP against a running gateway |
| `python demo/verify_attestation.py demo/attestation.json` | Verify an ALLOW independently of every Custos module |
| `python -m uvicorn demo.mock_lender:app --port 9000` | Start the downstream lender for the forwarding demo |
| `.\demo\start_live_demo.ps1` | Launch the gateway for the browser demo |

### 23.4 One-page cheat sheet

```
ENDPOINTS
  POST /v1/intent            → signed ALLOW | structured BLOCK
  GET  /v1/assets            → all seeded claims
  GET  /v1/assets/{id}       → claim + observation + evaluation (executes nothing)
  GET  /v1/pubkey            → Ed25519 key, base64 + PEM
  GET  /v1/health            → 200 ok | 503 degraded
  POST /v1/demo/sync         → re-align simulated claims to the live curve  [demo only — P0-2]
  GET  /demo                 → browser demo page

ERROR CODES                                              HTTP   LAYER
  CUSTOS-E100  MALFORMED_ENVELOPE                         400   schema / validation
  CUSTOS-E101  CLAIM_STALE                                403   engine
  CUSTOS-E102  INTENT_EXPIRED                             400   validation
  CUSTOS-E103  CLOCK_SKEW                                 400   validation
  CUSTOS-E200  UNKNOWN_ASSET                              404   registry
  CUSTOS-E201  YIELD_DRIFT_EXCEEDED                       403   engine
  CUSTOS-E202  BACKING_RATIO_BELOW_FLOOR                  403   engine
  CUSTOS-E203  TENOR_UNSUPPORTED                          422   oracle
  CUSTOS-E300  ORACLE_UNAVAILABLE                         503   oracle / engine
  CUSTOS-E301  ORACLE_DATA_STALE                          503   engine
  CUSTOS-E400  DOWNSTREAM_UNREACHABLE                     502   proxy

EVALUATION ORDER (the public precedence contract)
  E200 unknown asset → E300 no observation → E301 observation too old
  → E101 claim stale → E300 non-positive yield → E201 drift → E202 backing → ALLOW

THRESHOLDS (env-overridable, read once at import)
  CUSTOS_STALENESS_HOURS    24.0    CUSTOS_ORACLE_TIMEOUT     3.0
  CUSTOS_DRIFT_THRESHOLD    0.02    CUSTOS_CACHE_TTL          60
  CUSTOS_BACKING_FLOOR      1.0     CUSTOS_ATTESTATION_TTL    300
  CUSTOS_MAX_OBS_AGE_DAYS   4       CUSTOS_PRIVATE_KEY        (path to Ed25519 PEM)
  CUSTOS_FAIL_MODE          "closed"  ← declared, never read

MEASURED (Windows 11, CPython 3.10.11)
  evaluate()                0.0064 ms      POST /v1/intent ALLOW   0.68 ms
  sign()                    0.0333 ms      POST /v1/intent BLOCK   0.49 ms
  Treasury fetch            8,000–10,400 ms  ← vs a 3,000 ms timeout (§18)

SEEDED ASSETS
  TKN-UST-3M-001   3M   400 bps   −2 h    1.00×   → ALLOW (after /v1/demo/sync)
  TKN-UST-3M-002   3M   400 bps   −72 h   1.00×   → E101
  TKN-UST-3M-003   3M   360 bps   −1 h    1.00×   → E201
  TKN-UST-6M-004   6M   400 bps   −1 h    0.94×   → E202

THE ONE-LINE SUMMARY
  The decision core is sound, tested, fast, and honest about its scope.
  The data path that feeds it does not currently work (§18), and the
  perimeter around it — identity, replay, authorization — is not yet built.
```
