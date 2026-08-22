# Custos Gateway

Custos prevents an autonomous agent from transacting against a tokenized Treasury claim until the claim is cross-checked against a current U.S. Treasury yield curve observation. It is a plausibility check against market rates, not an audit of a fund's private NAV or holdings.

The protocol lives in `custos_protocol/` — a standalone SDK with no dependency on the gateway, and none on the AIP SDK that inspired its architecture. `gateway/` is a thin HTTP adapter over it.

## Run

```powershell
python -m pip install -r requirements.txt
python -m uvicorn gateway.server:app --reload
```

Open `http://127.0.0.1:8000/docs` for the API. The oracle reads Treasury's official daily par yield curve from the OData/Atom endpoint, requesting the current calendar year and falling back to the previous one on the first business days of January, when the new year's feed is still empty. It keeps a 60-second in-process cache and allows 15 seconds per fetch — the feed answers in 8–10 seconds cold, so a shorter budget never completes. When the source cannot be reached it returns `CUSTOS-E500` rather than allowing an unverifiable transaction.

For the interactive browser demo, open `http://127.0.0.1:8000/demo`. It shows the live Treasury observation and lets you inspect any seeded asset read-only via `GET /v1/assets/{id}`. It does **not** submit intents: every envelope must now carry an Ed25519 signature, and a web page cannot hold a signing key safely. The signed flow lives in the scripts below.

## Submit an intent

Every envelope is signed, so an agent registers its public key once, then signs each envelope:

```powershell
python demo/run_local_demo.py    # in-process, deterministic, no server needed
python demo/run_demo.py          # against a running gateway on :8000
```

`run_local_demo.py` prints four outcomes — `CUSTOS-E300` stale, `CUSTOS-E301` drifted, `CUSTOS-E302` under-backed, `ALLOW` healthy — and verifies the returned attestation with a verifier that imports nothing from Custos.

```powershell
python demo/verify_attestation.py attestation.json --public-key <key from GET /v1/pubkey>
```

The key is passed **out of band on purpose**. Trusting the `public_key` field inside a record authenticates nothing.

To demonstrate forwarding, start `python -m uvicorn demo.mock_lender:app --port 9000` and add `"downstream": "http://127.0.0.1:9000/loan"` to an intent's parameters. Custos forwards only an ALLOW and places a base64-encoded signed attestation in `X-Custos-Attestation`.

## API

| Route | Purpose |
|---|---|
| `POST /v1/agents` | Register an agent's Ed25519 public key so its envelopes can be verified |
| `POST /v1/intent` | Submit a signed `CustosEnvelope`; returns a signed `Attestation` or `Denial` |
| `GET /v1/assets` | List the seeded claims |
| `GET /v1/assets/{id}` | Claim, live observation, and asset-truth evaluation — read-only |
| `GET /v1/pubkey` | The gateway's signing key, base64url and PEM |
| `GET /v1/health` | Oracle reachability; `503` when degraded |
| `POST /v1/demo/sync` | Realigns simulated claims to the live curve — **only when `CUSTOS_DEMO_MODE=1`** |

An envelope from an agent with no registered key returns `CUSTOS-E100`: a signature that cannot be validated is an invalid signature, and it fails closed.

## Configuration

`CUSTOS_STALENESS_HOURS`, `CUSTOS_DRIFT_THRESHOLD`, `CUSTOS_BACKING_FLOOR`, `CUSTOS_MAX_OBS_AGE_DAYS`, `CUSTOS_ZERO_YIELD_TOLERANCE_BPS`, `CUSTOS_CLOCK_SKEW_SECONDS`, `CUSTOS_ORACLE_TIMEOUT`, `CUSTOS_DOWNSTREAM_TIMEOUT`, `CUSTOS_CACHE_TTL`, `CUSTOS_ATTESTATION_TTL`, `CUSTOS_PRIVATE_KEY` and `CUSTOS_DEMO_MODE` are supported. The private-key value is a path to an Ed25519 PEM; without it Custos generates an ephemeral demo key at startup.

`POST /v1/demo/sync` is unauthenticated state mutation, so it is absent from the app and from the OpenAPI schema unless `CUSTOS_DEMO_MODE=1`.

The seeds use relative attestation ages, so a healthy claim does not become stale merely because the process has been running. Claims are intentionally simulated rather than written by the oracle; before a live demo, set the healthy seed's `claimed_yield_bps` to the current 3M observation (and the drifted seed at least 2% away), or run the gateway in demo mode and call `/v1/demo/sync`.

## Verify

```powershell
pytest -q
```

The suite covers the canonical form byte-for-byte, Ed25519 and HMAC primitives, every scoring path, boundary enforcement, replay and revocation, the full verification pipeline, the HTTP surface, and the architectural dependency rules themselves.
