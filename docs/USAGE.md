# Using Custos

Custos is most useful as a mandatory policy checkpoint before an agent
borrows against, trades, or redeems a tokenized asset. It verifies market
plausibility and claim freshness before a downstream protocol ever sees the
request.

> Custos checks a claimed yield against a live Treasury market reference. It
> does not audit an issuer's private NAV, holdings, or legal redemption
> rights.

There are three ways to use it, depending on how much of the protocol you
want to own yourself.

## 1. As a gateway (HTTP)

Run the FastAPI server and send signed envelopes to it:

```bash
python -m pip install -r requirements.txt
export CUSTOS_ADMIN_API_KEY="replace-with-a-long-random-secret"
export CUSTOS_PRIVATE_KEY="/path/to/custos-gateway-ed25519.pem"   # optional; ephemeral if unset
python -m uvicorn gateway.server:app --reload
```

Open `http://127.0.0.1:8000/docs` for the interactive API, or
`http://127.0.0.1:8000/demo` for a read-only browser view (it does **not**
submit intents — a browser can't hold a signing key safely).

### Recommended flow

1. The agent creates an intent envelope with a short expiry (five minutes or
   less is typical).
2. It signs the envelope with its own Ed25519 private key.
3. It sends it to `POST /v1/intent` before contacting a lender, DEX, or
   execution service.
4. Custos validates the envelope, resolves the claim, fetches the market
   observation, and evaluates staleness, drift, and backing.
5. On `ALLOW`, take the returned signed `Attestation` to the downstream
   system, or let Custos proxy it (see below).
6. On `BLOCK`, stop. Branch on the `CUSTOS-Exxx` code in the signed
   `Denial` — never treat a block as a soft warning.
7. Store every signed record with the transaction; verify it independently
   later if you need to (see "Independent verification" below).

### Registering an agent and sending an intent

An envelope from an unregistered key returns `CUSTOS-E100` — a signature
that can't be checked against anything is treated as an invalid signature,
and Custos fails closed rather than trusting an unverified claim of
identity.

```bash
# Register the agent's public key (admin-gated)
curl -X POST http://127.0.0.1:8000/v1/agents \
  -H "X-Custos-Admin-Key: $CUSTOS_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "did:web:acme.com:agents:treasury-bot", "public_key": "<base64url Ed25519 public key>"}'
```

The envelope itself is JSON-LD-flavored and nested — it is **not** a flat
set of fields. Build and sign one with the SDK rather than hand-writing the
JSON:

```python
from custos_protocol.passport import AgentPassport
from custos_protocol.envelope import create_envelope, sign_envelope
from custos_protocol.models import Action

passport = AgentPassport.create(
    domain="acme.com", agent_name="treasury-bot",
    allowed_actions=["borrow_against"], monetary_limit_per_txn=100_000.0,
    asset_classes=["treasury"],
)
# passport.save("./my-agent") to persist it; register passport.public_key with the gateway

envelope = create_envelope(
    passport, Action.BORROW_AGAINST, "TKN-UST-3M-001",
    {"amount": 50_000.00, "currency": "USD"},
)
signed = sign_envelope(envelope, passport.private_key)
body = signed.model_dump(mode="json", by_alias=True)  # POST this to /v1/intent
```

An `ALLOW` response carries the asset, agent, action, computed scores, the
live-market reference used, an expiry, and a detached Ed25519 signature. The
attestation is time-limited — don't reuse it past its own `expires_at`.

For a scripted example end to end, see `demo/run_local_demo.py` (in-process,
deterministic, no server needed) or `demo/run_demo.py` (against a running
gateway). `run_local_demo.py` prints four outcomes — `CUSTOS-E300` stale,
`CUSTOS-E301` drifted, `CUSTOS-E302` under-backed, `ALLOW` healthy.

### Independent verification

```bash
python demo/verify_attestation.py attestation.json --public-key <key from GET /v1/pubkey>
```

The key is passed **out of band, on purpose**. The `public_key` field
embedded inside a record authenticates nothing — an attacker could re-sign
arbitrary content with their own key and update that field to match.
`demo/verify_attestation.py` imports nothing from `custos_protocol`; it's
the second implementation that proves the canonical form is portable, the
same role `conformance/run_conformance.py` plays at larger scale.

### Forwarding to a downstream service

Add `"downstream": "http://127.0.0.1:9000/loan"` to an intent's parameters.
Custos forwards only on `ALLOW`, and places a base64-encoded signed
attestation in the `X-Custos-Attestation` header of the forwarded request.
`demo/mock_lender.py` is a minimal receiver to try this against.

## 2. As an embedded library (`shield` / `observe`)

If you don't want to run a separate gateway process, `custos_protocol`
works as a decorator library. **This is local policy enforcement with a
cryptographic audit trail, not remote attestation** — the same passport
signs the envelope and verifies it in the same process, so there's no
second party checking the caller's honesty. What you get: every call
produces a signed, canonically-serialized, nonce-bearing record of what was
attempted and whether it was allowed, and the boundary/revocation/trust
engines are the real gate.

```python
from custos_protocol.passport import AgentPassport
from custos_protocol.shield import protect, CustosViolation
from custos_protocol.models import Action

passport = AgentPassport.create(
    domain="acme.com", agent_name="treasury-bot",
    allowed_actions=["borrow_against"], monetary_limit_per_txn=100_000.0,
)

def borrow_against(target: str, amount: float) -> str:
    return f"borrowed {amount} against {target}"

protected = protect(borrow_against, action=Action.BORROW_AGAINST, passport=passport)

try:
    protected(target="TKN-UST-3M-001", amount=50_000.0)
except CustosViolation as violation:
    print(violation.result.errors, violation.result.detail)
```

`protect`/`shield`/`protect_agent` never have access to a claims registry or
an oracle (`custos_protocol` performs no I/O), so a value-moving action
(which auto-selects Tier 1+) fails closed with `UNKNOWN_ASSET` unless you
supply `claim_resolver`/`observation_resolver` callables — plain functions
you write, which may do I/O on your side:

```python
protected = protect(
    borrow_against, action=Action.BORROW_AGAINST, passport=passport,
    claim_resolver=lambda target: my_claims_source.get(target),
    observation_resolver=lambda claim: my_oracle.get(claim.underlying_tenor),
)
```

For visibility without enforcement, `observe` never blocks and never
swallows an exception:

```python
from custos_protocol.observe import observe, passport as observe_passport

p = observe_passport("treasury-bot", allowed_actions=["borrow_against"])

@observe(p, log_params=True)
def borrow_against(target: str, amount: float) -> str:
    return f"borrowed {amount} against {target}"
```

`observe`'s passport is the same object `shield.protect()` consumes — moving
from visibility to enforcement is a one-line diff, not a rewrite.

## 3. From the command line (`custos`)

```bash
custos create-passport -d acme.com -n treasury-bot -a trade -a read \
  -m 100000 --daily-limit 250000 -o ./my-agent

custos sign-intent -p ./my-agent -a trade -t TKN-UST-3M-001 --amount 50000 -o envelope.json

custos verify -e envelope.json -k ./my-agent/public.pem   # exits 0/1 — CI-friendly

custos inspect ./my-agent
```

Entirely offline — no network access, no environment reads. For operations
against a *live* gateway (registering agents, revoking, checking trust
scores), use the separate `custos-admin` CLI:

```bash
export CUSTOS_GATEWAY_URL=http://127.0.0.1:8000
export CUSTOS_ADMIN_API_KEY="replace-with-a-long-random-secret"

custos-admin register-agent --agent-id did:web:acme.com:agents:treasury-bot --public-key <b64>
custos-admin revoke did:web:acme.com:agents:treasury-bot --reason "compromised"
custos-admin trust did:web:acme.com:agents:treasury-bot   # no admin key needed
```

## Configuration reference

| Variable | Purpose | Default |
|---|---|---|
| `CUSTOS_ADMIN_API_KEY` | Required for state-changing control-plane routes | none — fails closed |
| `CUSTOS_PRIVATE_KEY` | Path to the gateway's Ed25519 signing key PEM | ephemeral demo key |
| `CUSTOS_MIN_TRUST_SCORE` | Tier 2 trust gate threshold | `0.0` (inert) |
| `CUSTOS_STALENESS_HOURS` | Claim staleness threshold | `24.0` |
| `CUSTOS_DRIFT_THRESHOLD` | Relative yield-drift threshold | `0.02` |
| `CUSTOS_BACKING_FLOOR` | Minimum backing ratio | `1.0` |
| `CUSTOS_MAX_OBS_AGE_DAYS` | Maximum market observation age | `4` |
| `CUSTOS_ZERO_YIELD_TOLERANCE_BPS` | Absolute tolerance at a 0.00% print | `10` |
| `CUSTOS_CLOCK_SKEW_SECONDS` | Envelope expiry grace window | `5` |
| `CUSTOS_ORACLE_TIMEOUT` | Treasury feed fetch timeout | `15.0`s |
| `CUSTOS_DOWNSTREAM_TIMEOUT` | Proxy forwarding timeout | `3.0`s |
| `CUSTOS_CACHE_TTL` | Oracle observation cache TTL | `60`s |
| `CUSTOS_ATTESTATION_TTL` | Signed record validity window | `300`s |
| `CUSTOS_DEMO_MODE` | Mounts `POST /v1/demo/sync` | unset (route absent) |
| `CUSTOS_GATEWAY_URL` | `custos-admin`'s target gateway | `http://127.0.0.1:8000` |

`POST /v1/demo/sync` is unauthenticated state mutation. It's absent from
the app and from the OpenAPI schema unless `CUSTOS_DEMO_MODE=1` — don't
enable it against a gateway holding anything you care about.
