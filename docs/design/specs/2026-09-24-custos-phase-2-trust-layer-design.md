# Custos Phase 2 — trust layer design

**Status:** approved in chat 2026-09-24; implemented same session. **2026-09-25 addendum:**
the per-day ledger's `day_total()`-then-`record_amount()` pattern had a TOCTOU race under
concurrent requests for the same agent (documented, not fixed, in the first pass). Closed by
replacing it with `TrustEngine.reserve_amount()`/`release_amount()` — an atomic check-and-reserve
under one lock acquisition, released by `verification.py`'s `fail_authenticated` on any failure
after the reservation, so budget is never lost on success or permanently consumed by a request
that never executes. See §5 and §7, updated below.
**Builds on:** `docs/superpowers/specs/2026-08-21-custos-aip-architecture-design.md` §10, §11,
§13, §15, and `docs/superpowers/plans/2026-08-21-custos-aip-phase-1.md` (Phase 1, committed).

## 1. Goal

Land the four Phase 2 error codes (`E203`, `E306`, `E403`, `E404`) for real: the per-day
monetary ledger, real attestation-hash checking, delegation validation with enforced boundary
monotonicity, and the trust score gate — then let Tier 2 envelopes actually execute Tier 2
instead of being served at Tier 1.

## 2. Two decisions locked in before design (both made by the user, 2026-09-24)

1. **Delegation boundary monotonicity gets real enforcement.** `DelegationLink` gains a
   required `boundaries: Boundaries` field — the authority actually granted at that hop — and
   the verifier checks each hop is no looser than the one before it. This is a genuine schema
   change, not a decorative flag (which is what both the AIP blueprint and Custos Phase 1 have
   today).
2. **Attestation hashes are admin-registered**, not env-config. New admin-gated gateway routes
   let an operator register known frameworks and known build/prompt hashes at runtime, the
   same trust posture as `POST /v1/agents`.

## 3. Data model changes (`custos_protocol/models.py`)

- `DelegationLink.boundaries: Boundaries` — required, no default. A link with no boundaries
  is meaningless once monotonicity is enforced; forcing it prevents an accidentally-unbounded
  grant.
- `AgentHistory`: `agent_id`, `total_intents`, `successful_intents`, `boundary_violations`,
  `revocation_count`, `attestation_changes`, `delegation_depth`, `first_seen`, `last_seen`.
- `TrustScore`: `agent_id`, `score`, `history: AgentHistory`.

`AgentPassport.create`'s auto-generated single-hop link sets `boundaries=boundaries` (the
agent's own cage) — existing single-hop passports satisfy containment trivially, so this is not
a behavior change for anyone not building multi-hop chains today.

## 4. `custos_protocol/delegation.py` (new; depends only on `models`)

```python
@dataclass(frozen=True)
class DelegationConfig:
    clock_skew_seconds: int = 5
    max_delegation_depth: int = 8

def check_delegation(envelope, *, config=None, now=None) -> CustosErrorCode | None
```

Single fail-fast code (`DELEGATION_INVALID`), matching the spec's step-10 behavior — not an
accumulator like `boundaries.py`. Ordered checks:

1. Empty chain valid only if `principal.id == agent.id` (self-sovereign agent).
2. `chain[0].from_id == principal.id`; `chain[-1].to_id == agent.id`.
3. Continuity: `chain[i].to_id == chain[i+1].from_id`.
4. Depth: `len(chain) <= config.max_delegation_depth` — bounds a user-controlled array before
   anything below walks it (a signed envelope can still declare an arbitrarily long array; this
   caps the verifier's own work, independent of the envelope's own schema limits).
5. Expiry: no link's `expires_at` before `now`.
6. `granted_at` not later than `now + clock_skew_seconds` — closes a gap the AIP blueprint
   leaves open (a link "granted" in the future passes there).
7. **Monotonicity.** `_contained(child: Boundaries, parent: Boundaries) -> bool`:
   - `allowed_actions`/`asset_classes`: child ⊆ parent, *unless parent's is empty* (empty means
     unrestricted — nothing to narrow against, so any child list is contained).
   - `denied_actions`: parent ⊆ child (child may deny more, never less).
   - `monetary_limit.per_transaction` / `per_day`: child ≤ parent, *unless parent's is `0`*
     (`0` means "no limit", matching existing semantics elsewhere in the codebase).
   - `geo_restriction`: child's comma-separated set ⊆ parent's, *unless parent has none*. A
     child with **no** restriction while the parent has one is a violation (child would be
     broader).
   - `time_window`: child's `[start, end]` nests inside parent's, *unless parent has none*.

   Checked for every adjacent pair in the chain, and finally between `envelope.boundaries` and
   `chain[-1].boundaries` (the agent's actual operating cage must not exceed what its last
   delegation hop granted). An empty chain (self-sovereign case) skips this — there is nothing
   above the agent's own boundaries to compare against, matching current no-delegation
   semantics.

Each failure's detail names which specific check and which hop index failed, so a denial is
debuggable without re-deriving the chain by hand.

## 5. `custos_protocol/trust.py` (new; depends only on `models`)

`TrustEngine`, thread-safe, in-memory, modeled on `RevocationStore`'s locking style:

- `record_intent(agent_id, *, success)` — `total_intents` / `successful_intents`.
- `record_violation(agent_id)` — boundary failures only, per spec §11.
- `record_revocation(agent_id)` — called by the gateway route alongside
  `revocations.revoke(...)`, not from inside `revocation.py`, keeping the two feature modules
  decoupled (neither imports the other).
- `record_attestation(agent_id, build_hash, system_prompt_hash)` — increments
  `attestation_changes` when a hash differs from the last one seen for that agent (both
  non-`None`; a first sighting or a `None` doesn't count as a change).
- `record_delegation_depth(agent_id, depth)` — latest-observed chain length (the "derived, not
  hardcoded" divergence from the AIP blueprint).
- `score(agent_id) -> float` — the pinned formula:

  ```
  T(a) = 0.35*completion_rate + 0.25*(1 - violation_rate)
       + 0.15*max(0, 1 - 0.30*revocations) + 0.10*max(0, 1 - 0.15*attestation_changes)
       + 0.05*max(0, 1 - 0.20*(delegation_depth - 1)) + 0.10*min(1, total_intents/100)
  ```

  Clamped `[0,1]`, rounded 4dp, `0.0` when `total_intents == 0` (an unknown agent has no
  trust, not neutral trust). `completion_rate = successful_intents/total_intents`,
  `violation_rate = boundary_violations/total_intents`; both only ever evaluated when
  `total_intents > 0`.
- `meets_threshold(agent_id, min_score) -> bool`.
- `get_history(agent_id) -> AgentHistory | None`.
- Per-day ledger, same object: `day_total(agent_id, *, now) -> float` — **trailing 24h rolling
  window**, not calendar-day (a calendar-day reset is a known gaming vector: spend the limit at
  23:59, spend it again at 00:01). `record_amount(agent_id, amount, *, now)` appends an entry;
  entries older than 24h are evicted lazily on the next read or write for that agent, bounding
  memory the same way the nonce cache bounds itself.

## 6. `custos_protocol/boundaries.py`

`check_boundaries` gains `day_total: float = 0.0` (amount already spent in the trailing 24h,
computed by the caller). **Stays pure** — no import of `trust.py`. Predicate 4:
`day_total + amount > per_day` (when `per_day > 0`) → `CUSTOS-E203`.

## 7. `custos_protocol/verification.py`

- `_MAX_IMPLEMENTED_TIER` → `TIER_2`. A Tier-2 envelope now runs Tier 2 and reports
  `tier_used=TIER_2` honestly.
- New kwargs: `trust_engine`, `min_trust_score=0.0`, `registered_frameworks`,
  `known_build_hashes`, `known_prompt_hashes`, `delegation_config`.
- Step 6 (boundaries): query `trust_engine.day_total(...)` first, pass it in; on failure, call
  `trust_engine.record_violation(agent_id)` — the only failure path that does.
- Step 9 (attestation), now real: framework-registry / build-hash / prompt-hash checks against
  the supplied maps → `E306` on mismatch. Still fully opt-in — no maps supplied means the step
  trivially passes, so existing callers are unaffected.
- Step 10: `check_delegation(...)` → `E403`.
- Step 11 (Tier 2 only): `trust_engine.meets_threshold(agent_id, min_trust_score)` → `E404`.
  Inert while `min_trust_score=0.0` (the default).
- **Trust bookkeeping fires exactly once per call, only after signature verification passes** —
  an attacker can't spoof `agent_id` in a pre-auth failure to pollute someone else's score.
  A successful result additionally calls `record_amount(...)`.

## 8. Error taxonomy

Remove `MONETARY_LIMIT_PER_DAY`, `ATTESTATION_MISMATCH`, `DELEGATION_INVALID`,
`TRUST_SCORE_LOW` from `UNREACHABLE_IN_PHASE_1` in `tests/test_architecture.py`. The existing
guard tests force this correctly: `test_the_deferred_code_list_does_not_hide_a_live_code` fails
the moment a "deferred" code appears in protocol source, and
`test_every_error_code_is_exercised_by_the_suite` fails unless each has a real test.

## 9. Gateway surface

All new routes admin-gated via `require_admin`, matching `/v1/agents`:

- `POST /v1/frameworks` — register a known `framework_id`.
- `POST /v1/attestations/hashes` — register a known `build_hash` (keyed by `framework_id`) or
  `system_prompt_hash` (keyed by `agent_id`).
- `POST /v1/revocations` / `DELETE /v1/revocations/{subject_id}` — wraps
  `revocations.revoke`/`suspend`/`reinstate` **and** `trust.record_revocation` together.
- `GET /v1/trust/{agent_id}` — returns `TrustScore`. Not admin-gated: a read of a public
  reputation number, same posture as `GET /v1/assets`.

New env var: `CUSTOS_MIN_TRUST_SCORE` (default `0.0`).

## 10. Testing strategy

New `tests/test_delegation.py`, `tests/test_trust.py`. Extended: `tests/test_verification.py`
and `tests/test_gateway.py` for Tier 2 paths and the four newly-live codes;
`tests/test_boundaries.py` for `day_total`; `tests/test_architecture.py` for the shrunk
exemption list. Particular attention to monotonicity edge cases: empty vs. non-empty
`allowed_actions`/`asset_classes`, zero vs. non-zero monetary limits, geo and time-window
nesting, and the "child has no restriction, parent does" broadening case.
