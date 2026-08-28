# Continue here — Custos Gateway session handoff

**Written:** 2026-08-27 (supersedes the 2026-08-22 handoff — Phase 1 + oracle fix are now committed)
**Repo:** `C:\Users\asus\AIP-Gateway` · branch **`main`, the only branch** · **Phase 1 + the oracle fix are committed and green at `8f92327`**
**Read this first, then `docs/superpowers/plans/2026-08-21-custos-aip-phase-1.md` §"Deferred to Phase 2".**


### Git state — read before running any git command

**The user drives git themselves. Do not commit or push; do not delete refs.**

`main` @ `8f92327` is the only branch — 16 commits carrying all of Phase 1 and the oracle fix.
`phase-1-protocol-core` was deleted on 2026-08-22 as the user asked. The only uncommitted
change is this file, rewritten 2026-08-27 with the backlog in section 6.

Two safety refs survive from that consolidation and are now **verified redundant** — checked
2026-08-27, both by content, not by assumption:

| Ref | Status | How that was checked |
|---|---|---|
| tag `phase-1-backup` @ `3cecd94` | Safe to delete | `git diff phase-1-backup HEAD` shows only the oracle fix + doc updates, i.e. `main` is strictly ahead |
| `stash@{0}` | Safe to drop | `git apply --check --reverse` of the stash patch succeeds, i.e. its content is already in `main` |

Cleanup, whenever the user wants it: `git tag -d phase-1-backup && git stash drop`. Nothing
depends on either ref. They are not an ancestor of `main` — the work was recommitted as fresh
commits rather than merged — so `git branch --contains` will not show them; the content checks
above are the ones that matter.

---

## 1. What this project is

Custos is a **pre-transaction asset-truth gateway** for autonomous agents holding tokenized
U.S. Treasury claims. Before an agent borrows against, trades, or redeems a position, it sends
a signed intent envelope to Custos. Custos cross-checks the asset's asserted **Claim** against a
live **Observation** of the Treasury par yield curve and returns either a cryptographically
signed ALLOW attestation or a signed BLOCK denial carrying a `CUSTOS-Exxx` code.

It is **not** an audit of a fund's private books — issuer NAV feeds are not public. It checks
whether a claimed yield is plausible **against the live market for its tenor**. Keep that
precision in any external description.

---

## 2. State right now

**Phase 1 is fully implemented and the live oracle works.** All 15 plan tasks executed, all
exit criteria verified by execution, all of it committed.

```bash
cd C:/Users/asus/AIP-Gateway
pytest -q                      # 223 passed, 1 skipped (the skip is POSIX file modes on Windows)
python demo/run_local_demo.py  # four deterministic rows, all green
```

Exit criteria, each checked by running it:

| Criterion | Status |
|---|---|
| bare `pytest` green | 223 passed, 1 skipped |
| `POST /v1/intent` returns a signed `Attestation` on success | HTTP 200, signature verifies |
| ...and a signed `Denial` on failure | HTTP 403, signature verifies |
| replay of a spent nonce → `CUSTOS-E102` | HTTP 409 |
| a forged envelope does not burn the victim's nonce | forged 401 → genuine 200 |
| a revoked agent is blocked at Tier 0 | HTTP 403 `CUSTOS-E400` |
| demo shows four outcomes + independent signature check | E300 / E301 / E302 / ALLOW |
| `tests/test_architecture.py` passes | 46 tests |
| `models/`, `attest/`, `gateway/validation.py`, `config.py` gone | confirmed absent |
| no `aip_protocol` import anywhere | grep clean |

Beyond the Phase 1 criteria, the live path was verified on 2026-08-22 with production
defaults and no oracle substitution:

| Check | Result |
|---|---|
| `TreasuryOracle()` live, all tenors | `1M 380 · 3M 388 · 6M 395 · 1Y 403 · 2Y 424` bps, `record_date 2026-08-21` |
| `GET /v1/health` | `200`, `oracle_reachable: true` |
| `POST /v1/intent` against the real curve | `200 ALLOW`, signature verifies against the published key |
| the three block paths, real curve | `403` — `E300` stale, `E301` drifted, `E302` under-backed |

**Everything is committed** (16 commits, tree clean). See the git block above before running
any git command.

---

## 3. What was built

`custos_protocol/` — a standalone SDK, no dependency on `gateway/`, none on the AIP SDK:

| Module | Contents |
|---|---|
| `errors.py` | 30-code taxonomy in five families + HTTP mapping + `CustosError` |
| `crypto.py` | Ed25519, HMAC-SHA256, base64url, PEM I/O with optional passphrase |
| `canonical.py` | The 8-rule byte-stable signable payload — the interop core |
| `models.py` | Every wire + domain model; JSON-LD `CustosEnvelope` |
| `passport.py` | `AgentPassport` — DID identity, keys, policy cage, persistence |
| `envelope.py` | Construction, signing, hashing, risk-relative tier selection |
| `boundaries.py` | Predicates 1,2,3,5,6,7 — violations accumulate |
| `drift.py` | Asset-truth engine: staleness, yield drift, backing ratio |
| `attestation.py` | Signed `Attestation` **and** `Denial`, `verify_record` |
| `revocation.py` | Kill switch + FIFO nonce cache, fails closed on stale data |
| `verification.py` | `verify_intent()` — the only composer |

`gateway/` is now a thin adapter (`config.py`, `keys.py`, `server.py`, `proxy.py`).
`claims/` and `oracle/` kept their interfaces; `oracle/` was decoupled from the old global
`config` module and now takes `timeout_seconds` / `cache_ttl_seconds` as constructor args.

---

## 4. Three deliberate deviations from the plan

Each was a defect in the plan, verified by execution, not a shortcut:

1. **`tomllib` → `tomli` fallback** (`tests/test_packaging.py`). `tomllib` is stdlib only on
   3.11+; the declared floor and the actual interpreter are 3.10.11. Imports `tomllib` with a
   `tomli` fallback; `tomli` is declared in the `dev` extra.
2. **`test_expiry_allows_a_small_clock_skew_grace`** built the envelope near-expired and signed
   it *after*, instead of mutating `expires_at` on an already-signed envelope. The plan's
   version invalidated its own signature, so it failed at step 4 and never reached the step 3
   grace window it meant to test.
3. **Four error codes are exempt from the coverage invariant, not one.** The plan exempted only
   `E203`. `E306` (attestation step is a stub), `E403` (delegation) and `E404` (trust) are
   equally unreachable in Phase 1. `UNREACHABLE_IN_PHASE_1` documents each, and a new test —
   `test_the_deferred_code_list_does_not_hide_a_live_code` — asserts no exempted code is
   actually emitted by protocol source, so the list cannot be used to excuse a live code.

---

## 5. Standing decisions the user has made

These persist across sessions. Do not relitigate them.

- **Git is the user's job.** They run `git status`, `git add`, and the commits themselves.
  Do not commit, push, or delete refs unless explicitly asked. (2026-08-22: they also asked that
  everything live on `main` — no feature branches — and `phase-1-protocol-core` was deleted
  accordingly.)
- **`demo/live.html`:** accepted the downgrade. The "Evaluate intent" button is now
  "Inspect asset" calling `GET /v1/assets/{id}`. A browser cannot hold a signing key safely and
  every envelope must be signed. The signed flow lives in `demo/run_local_demo.py` and
  `demo/run_demo.py`.

---

## 6. What is next

Everything below was **re-verified against the committed code on 2026-08-27**, not copied from
`ARCHITECTURE.md` §22. That matters: §22 was written against the *pre-Phase-1* codebase and
roughly half of it is now fixed. Items confirmed still-open carry the grep or run that proved it.
Do not work from §22 directly without re-checking — use this list.

### 6.0 Recommendation, if you want one

**Do 6.1 (auth) before 6.2 (Phase 2).** Phase 2 is the declared next phase and it is the more
interesting work, but it builds a *trust score keyed on `agent_id`* on top of a gateway where
`agent_id` is unauthenticated. Trust scoring an identity anyone can assert produces a number that
means nothing. Auth is the smaller job and it is a prerequisite for Phase 2 being worth anything.

If Phase 2 must start first, that is a legitimate call — but write down that the trust score is
provisional until auth lands, so nobody ships it as a real signal.

---

### 6.1 Security — the gate on everything else

| # | Gap | Verified how | Notes |
|---|---|---|---|
| S1 | **No authentication on any route.** `agent_id` is self-asserted: signed, but the *binding* between key and identity is whatever the caller registered | `grep -n "Depends\|api_key\|Authorization\|middleware" gateway/server.py` → no hits | The signature proves *someone holding that key* sent it; nothing proves that key belongs to that agent |
| S2 | **`POST /v1/agents` is an open registration endpoint** | same file, no auth | Follows directly from S1. First-registration-wins, or an admin token, or both |
| S3 | **Gateway signing key is ephemeral unless `CUSTOS_PRIVATE_KEY` is set** | `gateway/server.py:42` — `load_private_key(...) if config.PRIVATE_KEY_PATH else None` | Every attestation becomes unverifiable after a restart. `custos_protocol/crypto.py` already supports encrypted PEM and `0600` checks, so this is deployment docs plus a startup warning, not new crypto |

S1 is the honest headline: **Custos currently authenticates envelopes, not agents.**

---

### 6.2 Phase 2 — the trust layer (the declared next phase)

The to-do list is machine-readable: `UNREACHABLE_IN_PHASE_1` in `tests/test_architecture.py`.
Remove each code as its feature lands. A guard test
(`test_the_deferred_code_list_does_not_hide_a_live_code`) already fails if a code is exempted
while the protocol emits it, so the list cannot rot silently.

| Code | Blocks on | Module |
|---|---|---|
| `E203 MONETARY_LIMIT_PER_DAY` | boundary predicate 4 — needs the rolling per-day ledger | `boundaries.py` + `trust.py` |
| `E403 DELEGATION_INVALID` | verification step 10 | `delegation.py` (new) |
| `E404 TRUST_SCORE_LOW` | verification step 11 | `trust.py` (new) |
| `E306 ATTESTATION_MISMATCH` | verification step 9 is a stub until hashes are plumbed | `verification.py` |

Also in Phase 2: **Tier 2 execution** and the `/v1/revocations` + `/v1/trust` routes.

The trust formula is already specified — spec §15,
`docs/superpowers/specs/2026-08-21-custos-aip-architecture-design.md`, section 15 “Trust”:

```
T(a) = 0.35*completion_rate + 0.25*(1 - violation_rate)
     + 0.15*max(0, 1 - 0.30*revocations) + 0.10*max(0, 1 - 0.15*attestation_changes)
     + 0.05*max(0, 1 - 0.20*(delegation_depth - 1)) + 0.10*min(1, total_intents/100)
```

Clamped `[0,1]`, 4 dp, `0.0` when `total_intents == 0`. `delegation_depth` is **derived from the
envelope's chain length**, not passed in — a deliberate divergence from the AIP blueprint that
must stay.

**Carry the Phase 1 honesty rule forward:** a Tier 2 envelope currently reports
`tier_used = TIER_1`, because claiming TIER_2 while running Tier 1 checks is a lie a relying
party cannot detect. When Tier 2 actually executes, that mapping changes — and not before.

---

### 6.3 Correctness gaps still open

Each re-verified 2026-08-27 against committed code.

| # | Gap | Verified how |
|---|---|---|
| C1 | **`registry.update_claim()` bypasses validation.** `model_copy(update=...)` does not re-run validators, so a caller can install a negative yield or zero `tokens_outstanding` — the `gt=0` guard the drift engine relies on | `claims/registry.py:35`. Fix: `Claim.model_validate(updated.model_dump())` |
| C2 | **Schema errors collapse to one string.** The handler binds `exc` and never reads it, discarding every per-field Pydantic error | `gateway/server.py:62` — `exc` unused in the body. Include `exc.errors()` paths and reasons **without** echoing submitted values |
| C3 | **Backing ratio is a floor with no ceiling.** A 10x ratio signals a broken feed exactly as loudly as 0.94x, and passes | `custos_protocol/drift.py:155` — only `ratio < config.backing_floor`. Needs a distinct code, or a documented decision to allow it |
| C4 | **No maximum envelope TTL.** Verification rejects a past `expires_at` and an `issued_at` more than 5 min in the future, but never bounds `expires_at - issued_at`. A decade-long envelope is accepted | `custos_protocol/verification.py:96,102` — no span check. `envelope.py:68` defaults `ttl=300`, but that is a *default*, not a cap |

Fixed by Phase 1, do **not** re-fix (verified): future-dated claims (`drift.py:82`), zero and
negative yield handling (`zero_yield_abs_tolerance_bps`), unsigned denials, `demo/sync` exposure,
`FAIL_MODE` dead config, the downstream-vs-oracle timeout split, and packaging.

---

### 6.4 Observability — the reason the oracle P0 stayed invisible

| # | Gap | Verified how |
|---|---|---|
| O1 | **Nothing logs anywhere.** No `import logging`, no logger, in `gateway/`, `oracle/`, `custos_protocol/`, or `claims/` | `grep -rln "import logging\|logger" --include=*.py` across all four → zero files |
| O2 | **The oracle returns a bare `None`** for HTTP error, timeout, and parse failure alike — indistinguishable from outside | `oracle/treasury.py:_fetch` returns `None` on every path. **This is what hid §18 for the whole life of the repo** |
| O3 | **No per-decision request log** — no verdict, code, latency, or asset id. The gateway cannot report its own block rate | follows from O1 |

O2 is the highest-value item here: it is the specific blindness that let a 100%-failure bug sit
undetected behind correct fail-closed behaviour.

---

### 6.5 Test coverage gaps

| # | Gap | Verified how |
|---|---|---|
| T1 | **`TTLCache` has no test.** TTL expiry, `cache_hit` flagging, monotonic behaviour all unverified | no `tests/test_cache.py`; `grep -rl TTLCache tests/` → nothing |
| T2 | **`gateway/proxy.py` is imported by no test.** Header encoding, `exclude={"downstream"}`, redirect refusal, and the `E400` path are all uncovered | `grep -rl proxy tests/` → nothing |
| T3 | **No CI.** Nothing runs the suite on push | `.github/workflows` does not exist |
| T4 | **No concurrency test** against the shared cache and mutable registry | no test issues simultaneous cold-cache requests |

For T3: the suite is fully hermetic — the oracle tests use `httpx.MockTransport` — so CI needs no
network. A *separate* nightly job should do the live-feed shape check, since that is the thing
that would catch a Treasury API change.

---

### 6.6 Oracle follow-ups (the P0 is fixed; these are the leftovers)

| # | Item | Why it is not done |
|---|---|---|
| R1 | **Fiscal Data JSON API is still not wired.** The spec (§8.1) designates it *primary* and the XML feed *fallback*; only the XML path exists | One path to the number, not two. `oracle/` keeps its `Observation \| None` interface, so this can land independently |
| R2 | **The 8–12 s fetch sits in the request path.** The 60 s cache means one caller per tenor per minute pays it, but that caller waits ~9 s | A background refresh fixes it. Deliberately not done: design change, not a bug fix |
| R3 | **Timeout margin is thinner than first documented.** Measured cold: 8.2 / 8.6 / 9.1 / 9.1 / 9.5 / 10.1 / 10.1 / **11.6** s. The 15 s default leaves ~3.4 s over the worst observed | Tunable via `CUSTOS_ORACLE_TIMEOUT` with no code change |

**Do not "fix" `parse_yield_curve` or `_parse_date`.** §18 originally blamed the date parser too;
that was a property of the legacy `QR_BC_CM` document only. Against the OData feed the untouched
parser is correct for every mapped tenor on the first attempt. Changing it would be treating a
symptom of a URL that is no longer wrong.

**The 1 January trap, in case it looks like dead code:** Treasury's year feed answers `HTTP 200`
with **zero entries** until the year's first business day closes — measured against
`field_tdr_date_value=2027` on 2026-08-22: 673 bytes, no `<entry>`. That is why
`_candidate_urls()` falls back to the previous year. It costs a second request only when the
first returns nothing.

---

### 6.7 Documentation

| # | Item | Status |
|---|---|---|
| D1 | Two orphaned SVGs at the repo root (`custos-architecture.svg`, `custos-sequence.svg`), distinct in content from `diagrams/` | still there — delete or reference them |
| D2 | `Technical Document.md` §8.1 still names Fiscal Data as the oracle source | update it to describe what was built; keep the JSON client as roadmap item R1 |
| D3 | The canonical-form spec does not state its RFC 8785 subset | number canonicalization is not implemented and works only because Pydantic pre-converts every `Decimal` to a string. **First thing a second-language implementation will break** |
| D4 | `canonicalize` strips `signature`/`public_key` at the top level only | a nested key of either name would be signed. One sentence in spec §9.3 |

Already fixed, do not re-do (checked 2026-08-27): the README merge marker is gone, there is one
H1, and all four seed contract addresses are a correct 40 hex digits.

---

### 6.8 Phase 3 — DX surfaces

`shield`, `observe`, `cli`, and `conformance/` vectors + runner. Unchanged from the original plan.
The conformance vectors matter more than they look: they are what make the canonical form (D3)
testable by a second implementation.

---

## 7. Do NOT re-derive these

### Environment (measured)

```
Python 3.10.11 · Windows 11
pydantic 2.12.5 · fastapi 0.128.0 · cryptography 46.0.4 · httpx 0.28.1 · tomli 2.4.0
```

### Pydantic 2.12 serialization shapes (pinned by the byte-exact test in `tests/test_canonical.py`)

- Aware-UTC datetime → `"2026-08-21T12:00:00Z"` (no fractional part when `microsecond == 0`)
- `Decimal("50000.00")` → the **string** `"50000.00"` — exactness survives the signature
- `float 500.0` → stays `500.0` through `json.dumps` — this is why the whole-float→int rule exists
- `None` → `null`, emitted not omitted
- `@context` sorts before all letters (`@` is `U+0040`)

### Divergences from the AIP blueprint that are intentional

The blueprint documents defects in its own implementation. **Do not "fix" these back toward it.**
Signature before replay · revocation fails closed on stale data · `local_only` store never stale ·
FIFO nonce eviction · risk-relative tier selection · `per_day` and `asset_classes` enforced ·
no `valid` field, `passed` is the single authority with a three-valued `checks` map ·
`expires_at` required · denials signed too · non-finite floats rejected at the schema layer ·
encrypted private keys supported with mode `0600`.

Two honesty rules that show up in the code and should stay:
- **An unregistered agent yields `CUSTOS-E100`**, detail `"No registered key for agent <id>;
  signature cannot be verified."` The taxonomy has no `UNKNOWN_AGENT`; a signature that cannot be
  validated is an invalid signature, and it fails closed.
- **A Tier 2 envelope reports `tier_used = TIER_1`** in Phase 1. Claiming `TIER_2` while running
  Tier 1 checks would be a lie a relying party cannot detect.

---

## 8. Working agreements

- Tell the user what changed and why, concisely, with the reasoning visible.
- Do not commit or push unless explicitly asked.
- Do not spawn subagents unless asked.
- Report findings plainly with evidence. Several claims in the repo's own docs did not survive
  execution; those are catalogued in `ARCHITECTURE.md` §19 and §22 rather than smoothed over.
