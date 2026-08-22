# Continue here — Custos Gateway session handoff

**Written:** 2026-08-22 (updated later the same day — oracle P0 fixed)
**Repo:** `C:\Users\asus\AIP-Gateway` · branch **`main`, the only branch** · **Phase 1 + the oracle fix are built and green, and uncommitted**
**Read this first, then `docs/superpowers/plans/2026-08-21-custos-aip-phase-1.md` §"Deferred to Phase 2".**


### Git state — read before running any git command

The user drives git themselves; do not commit or push.

| Ref | Holds |
|---|---|
| `main` @ `f56f285` | HEAD. The working tree carries Phase 1 **and** the oracle fix, all uncommitted |
| tag `phase-1-backup` @ `3cecd94` | Phase 1 as a commit. It was committed on `phase-1-protocol-core`, which the user asked to delete; the tag is what keeps that commit reachable. **Delete the tag only after Phase 1 is committed on `main`** |
| `stash@{0}` | The oracle fix. Redundant with the working tree, kept as a second copy until `main` has a commit |

Once `main` carries a commit with this work: `git tag -d phase-1-backup` and `git stash drop`.

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

**Phase 1 is fully implemented.** All 15 plan tasks executed, all exit criteria verified by
execution.

```bash
cd C:\Users\asus\AIP-Gateway
git checkout phase-1-protocol-core
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

**Nothing is committed.** The user chose "branch, no commits" — deletions are staged via
`git rm`, new files are untracked. Review with `git status` / `git diff`, then commit however
you like. Do not commit without being asked.

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

## 5. Decisions the user made this session

- **Git:** branch, no commits.
- **`demo/live.html`:** accepted the downgrade. The "Evaluate intent" button is now
  "Inspect asset" calling `GET /v1/assets/{id}`. A browser cannot hold a signing key safely and
  every envelope must be signed. The signed flow lives in `demo/run_local_demo.py` and
  `demo/run_demo.py`.

---

## 6. What is next

**Phase 2 — trust layer.** `trust.py`, `delegation.py`, boundary predicate 4 (`E203` rolling
per-day limit), verification steps 10–11, Tier 2 execution, and the `/v1/revocations` and
`/v1/trust` routes. When each lands, remove its code from `UNREACHABLE_IN_PHASE_1` in
`tests/test_architecture.py` — that list is the Phase 2 to-do list.

**Phase 3 — DX surfaces.** `shield`, `observe`, `cli`, `conformance/` vectors + runner.

**The oracle P0 is DONE** (2026-08-22, `ARCHITECTURE.md` §18 rewritten to match).
`oracle/treasury.py` now builds `yield_curve_url(year)` against Treasury's OData endpoint for the
current year, falls back to the previous year when that feed is still empty, and defaults to a
15 s timeout — matched by `gateway.config.ORACLE_TIMEOUT_SECONDS`, which is the value the server
actually runs with. Verified live: `1M 380 · 3M 388 · 6M 395 · 1Y 403 · 2Y 424` bps,
`record_date 2026-08-21`; `/v1/health` → `oracle_reachable: true`; `POST /v1/intent` → signed
ALLOW that verifies against the published key. Eight new tests, all hermetic.

Two things worth carrying forward:

- **`parse_yield_curve` was never broken.** §18 also blamed `_parse_date`; that was a property of
  the legacy document only. Against the OData feed the untouched parser is correct for every
  mapped tenor. Do not "fix" it.
- **The 8–10 s fetch sits in the request path.** The 60 s cache means one request per tenor per
  minute pays it, but the first caller after a cache miss waits ~9 s. A background refresh would
  remove that; it was deliberately not done, being a design change rather than a bug fix.

Still open from §18.5, both pre-existing: the oracle returns a bare `None` for HTTP errors,
timeouts and parse failures alike, so failures are indistinguishable in logs (item 4); and the
Fiscal Data JSON API that the spec designates as the *primary* source is still not wired, so
there is one path to the number rather than two (item 5).

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
