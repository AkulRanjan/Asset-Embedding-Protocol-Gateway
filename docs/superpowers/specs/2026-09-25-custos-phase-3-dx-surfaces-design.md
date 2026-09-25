# Custos Phase 3 — DX surfaces design

**Status:** approved in chat 2026-09-25; implemented same session.
**Builds on:** `docs/superpowers/specs/2026-08-21-custos-aip-architecture-design.md` §4.1, §19
(Phase 3), and `ARCHITECTURE1.md` §18–21 (the AIP blueprint's actual Shield/Observe/CLI/
Conformance implementations, read in full to catalogue their documented bugs before designing
around them).

## 1. Goal

Ship the three one-liner adoption surfaces (`shield`, `observe`, `cli`) plus the conformance
suite that makes the canonical form testable by a second implementation — the last item on the
original three-phase plan.

## 2. Two decisions locked in before design (both made by the user, 2026-09-25)

1. **The offline `custos` CLI has no `revoke` command.** `custos_protocol/` cannot import
   `httpx` (enforced by `test_protocol_package_performs_no_io`), and a fake in-memory-only
   revoke would repeat AIP's own documented mistake (§20.3: not signposted as non-persistent).
   Revocation already has a real, persistent, admin-gated route (`POST /v1/revocations`,
   Phase 2). A **separate** networked CLI, `gateway/admin_cli.py`, wraps it instead.
2. **`@shield` on a class leaves methods absent from its `actions`/`denied` configuration
   completely unwrapped**, matching AIP's actual (buggy, fail-open-by-omission) behavior
   rather than a safer deny-by-default. Documented prominently in the docstring and this spec
   so it is a known trade-off, not a silent gap.

## 3. `custos_protocol/shield.py`

```python
def protect(func, *, action=None, actions=None, denied=None, limit=0.0, daily_limit=0.0,
            currency="USD", domain="localhost", agent_name=None, geo=None, tier=None,
            on_violation="raise", passport=None, revocation_store=None,
            trust_engine=None) -> ProtectedCallable

def shield(*, actions=None, denied=None, ...) -> class decorator          (alias: shield_class)
def protect_agent(agent_instance, passport, *, actions=None, ...) -> same instance
                                                                            (alias: shield_object)
```

`ProtectedCallable.__call__` (sync or async, detected via `inspect.iscoroutinefunction`):

1. Build `parameters` from bound arguments (`inspect.signature`, skip `self`).
2. `create_envelope(passport, action=self._action, target="self", parameters=params, tier=tier)`
   — `tier=None` uses `envelope.py`'s real risk-based `select_tier()`, not a hardcoded value.
3. `sign_envelope(envelope, passport.private_key)`.
4. `verify_intent(signed, passport.public_key, revocation_store=..., trust_engine=...)`. No
   claim/observation is available in-process, so Tier 1+ asset-truth naturally reports
   `ORACLE_UNAVAILABLE` unless a caller wires a resolver — undocumented magic avoided by simply
   not pretending Shield can check market data it has no way to fetch. `on_violation="raise"`
   is the honest default for anyone hitting this by surprise.
5. On failure: `on_violation="raise"` raises `CustosViolation` (carries the full
   `VerificationResult`), `"log"` logs and returns `None`, `"silent"` returns `None`.
6. Otherwise call the wrapped function (`await` if async) and return its result.

**Deliberate divergences from AIP, each closing a documented blueprint bug (§18.3):**

| AIP trap | Custos fix |
|---|---|
| Trap 1: `actions` allowlist never matches `func.__name__` | `action=` is explicit and defaults to `func.__name__`; `actions=[...]` names that same string |
| Trap 3: `limit=0` = unlimited | Kept — matches the existing `boundaries.py` footgun, not a new one |
| Trap 4: `dir(obj)`/`getattr` evaluates every property (side effects) | `protect_agent`/`shield_object` only `getattr` the specific names in `actions ∪ denied` |
| Trap 7: fresh passport minted per decorated instance | `passport` is a required argument, never auto-minted, so identity is stable and revocable |
| Trap 8: module-level default store shared process-wide | `revocation_store`/`trust_engine` default per-call, matching `verify_intent`'s own idiom |
| Trap 9: tier hardcoded to `TIER_1` | `tier=None` uses real risk-based auto-selection |
| (async) not supported | Both sync and async callables work |

**Trap 2 is kept, by the user's explicit choice**: a method not named in `actions`/`denied`
on a `@shield`-decorated class is left completely unwrapped.

## 4. `custos_protocol/observe.py`

Same shape as AIP's: `ObservationEvent` (dataclass), `ObservationStore` (thread-safe ring
buffer via `collections.deque(maxlen=10_000)`, per-agent `{total, success, errors}` counters,
callbacks fired **outside** the lock with exceptions caught and logged), `passport(name,
domain="localhost", **kwargs)` shorthand returning a real `AgentPassport` — the same identity
object `shield` consumes, which is what makes the observe→protect upgrade a one-line diff.
Three decorator forms: `@observe`, `@observe()`, `@observe(passport)`; `observe_agent(instance,
...)` for a live object.

**Enforced by test: `observe.py` must not import `verification.py`.** Structurally incapable
of blocking, regardless of what future maintenance does to the rest of the module.

**Divergence:** `log_params=False` by default (AIP defaults to `True`, capturing raw call
arguments — including any secrets or PII a caller passes — into an in-memory store with no
redaction). Matches the "never echo submitted values" precedent set in the earlier bug-fix
pass on the gateway's schema-error handler.

## 5. `custos_protocol/cli.py` — offline only

No `httpx` import, no `os.getenv` — `test_protocol_package_performs_no_io` covers this file
too. Commands (`click`):

- `custos create-passport -d DOMAIN -n NAME -a ACTION... --deny ACTION... -m LIMIT
  --daily-limit LIMIT -o DIR` — mints identity + keys, writes `passport.json` + both PEMs.
- `custos sign-intent -p DIR -a ACTION [-t TARGET] [--amount N] [--ttl S] [-o FILE]` — build +
  sign an envelope, print JSON or write a file.
- `custos verify -e ENVELOPE.json -k PUBLIC.pem [--claim FILE] [--observation FILE]` — runs
  `verify_intent` offline; renders a table; **exits 0/1 on `result.passed`** for CI use. Claim/
  observation are optional JSON files — Tier 0 needs neither, Tier 1+ without them reports
  `ORACLE_UNAVAILABLE` rather than crashing.
- `custos inspect PATH` — pretty-prints a passport directory or an envelope file.

## 6. `gateway/admin_cli.py` — networked, separate entry point

Thin `httpx` wrappers over the Phase 2 admin routes. `--gateway-url` defaults from
`CUSTOS_GATEWAY_URL` (new env var, default `http://127.0.0.1:8000`), `--admin-key` defaults
from the existing `CUSTOS_ADMIN_API_KEY`.

- `custos-admin register-agent --agent-id ID --public-key B64`
- `custos-admin revoke SUBJECT_ID --subject-type agent|issuer [--suspend --duration N]`
- `custos-admin reinstate SUBJECT_ID`
- `custos-admin trust AGENT_ID` — no admin key needed, matches the route's own posture
- `custos-admin register-framework FRAMEWORK_ID`

## 7. `conformance/`

- `vectors.json` — fixed seeds/clock (`T_NOW`, `agent_1`/`agent_2`/`hmac` keys), generated *by
  calling `custos_protocol`'s own `canonical.py`/`crypto.py`*, so vectors and verifier cannot
  disagree about canonicalization by construction.
- `generate_vectors.py` — deterministic generator.
- `run_conformance.py` — reference runner; byte-diffs serialization vectors on first
  differing offset.
- `CANONICAL_SERIALIZATION.md` — the normative byte-level spec, closing the documented gap
  that Custos's canonical form never stated its RFC 8785 subset.
- `README.md` — porting guide for a second-language implementation.

Categories A–K, covering **every one of the 30 implemented error codes** (the same discipline
`test_architecture.py` already applies to the test suite) plus pure-serialization cases.
Several categories have no AIP equivalent at all, because Custos actually implements what AIP
only stubs: `E203` per-day limit, `E402` issuer revocation, real Tier 2 delegation +
monotonicity + trust gating, the entire asset-truth family (`E300`–`E305`, `E500`–`E501`), and
real attestation-hash comparison (`E306`).

## 8. Testing

`tests/test_shield.py`, `tests/test_observe.py`, `tests/test_cli.py` (Click's `CliRunner`),
`tests/test_admin_cli.py` (`httpx.MockTransport`, same pattern as `test_oracle.py`),
`tests/test_conformance.py`. `tests/test_architecture.py` gains the observe/verification
import-graph rule.

## 9. Dependencies

`click` and `rich` move from demo-only to core dependencies in `pyproject.toml`, with two new
console-script entry points: `custos = custos_protocol.cli:cli`,
`custos-admin = gateway.admin_cli:cli`.
