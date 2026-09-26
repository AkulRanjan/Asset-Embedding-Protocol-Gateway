# Custos

[![tests](https://github.com/AkulRanjan/APay-Gateway/actions/workflows/tests.yml/badge.svg)](https://github.com/AkulRanjan/APay-Gateway/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

**Custos is a pre-transaction asset-truth gateway for autonomous agents
holding tokenized U.S. Treasury claims.** Before an agent borrows against,
trades, or redeems a position, it sends a signed intent envelope to Custos.
Custos cross-checks the asset's asserted claim against a live observation of
the Treasury par yield curve and returns either a cryptographically signed
`ALLOW` attestation or a signed `BLOCK` denial carrying a machine-readable
`CUSTOS-Exxx` code.

It is **not** an audit of a fund's private books — issuer NAV feeds aren't
public. It checks whether a claimed yield is plausible against the live
market for its tenor, right before money moves.

```
Agent → signs an intent envelope → Custos verifies it →
  ALLOW (signed attestation)  or  BLOCK (signed denial + CUSTOS-Exxx)
```

## Why

API keys and OAuth authenticate the *caller*. None of them answer "is this
specific action, with these specific parameters, plausible against the
current market" — and none of them can do it *before* the action fires.
Custos's boundary cage travels inside the signed envelope itself, so
verification is a local, deterministic check: no policy database lookup, no
trusting the caller's word for what it's allowed to do.

## What's in the box

- **A 30-code error taxonomy** — every rejection is a machine-readable
  `CUSTOS-Exxx`, not a string to `grep` for.
- **A verification pipeline** — signature, replay, boundaries (action /
  monetary / per-day / time / geo / asset-class), revocation, asset truth
  (staleness / drift / backing ratio), delegation (with real boundary
  monotonicity — a delegated hop can never widen its own authority), and a
  behavioral trust score gate. Ordered, tier-gated, and every step is
  covered by both a unit test and a conformance vector.
- **A behavioral trust layer** — a pinned scoring formula and a rolling
  per-day monetary ledger, implemented as an atomic reservation so
  concurrent requests can't race past a limit.
- **Three ways to use it**: a FastAPI gateway over HTTP, an embedded
  `shield`/`observe` decorator library for single-process enforcement or
  observability, or an offline CLI (`custos`) for scripting and CI.
- **A conformance suite** — 50 vectors, fixed keys and clock, covering
  every reachable error code and the canonical serialization form byte for
  byte, so a second-language implementation can check itself without
  reading a line of this repo's Python.

Full details: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Quickstart

```bash
python -m pip install -e .
```

### Run the gateway

```bash
export CUSTOS_ADMIN_API_KEY="replace-with-a-long-random-secret"
python -m uvicorn gateway.server:app --reload
```

Open `http://127.0.0.1:8000/docs` for the interactive API, then:

```bash
python demo/run_local_demo.py    # in-process, deterministic, no server needed
```

### Or embed it directly

```python
from custos_protocol.passport import AgentPassport
from custos_protocol.shield import protect
from custos_protocol.models import Action

passport = AgentPassport.create(
    domain="acme.com", agent_name="treasury-bot",
    allowed_actions=["borrow_against"], monetary_limit_per_txn=100_000.0,
)

@protect(action=Action.BORROW_AGAINST, passport=passport)
def borrow_against(target: str, amount: float) -> str:
    return f"borrowed {amount} against {target}"
```

### Or use the CLI

```bash
custos create-passport -d acme.com -n treasury-bot -a trade -o ./my-agent
custos sign-intent -p ./my-agent -a trade -t TKN-UST-3M-001 --amount 50000 -o envelope.json
custos verify -e envelope.json -k ./my-agent/public.pem   # exits 0/1 — CI-friendly
```

**Full usage guide, every configuration variable, and the admin CLI:
[`docs/USAGE.md`](docs/USAGE.md).**

## Development

```bash
git clone https://github.com/AkulRanjan/APay-Gateway.git
cd APay-Gateway
python -m pip install -e ".[dev]"
pytest -q                                  # 428+ tests, fully hermetic
python conformance/run_conformance.py      # protocol-level conformance
```

The suite covers the canonical form byte-for-byte, Ed25519 and HMAC
primitives, every scoring and delegation path, boundary enforcement, replay
and revocation, the full verification pipeline at every tier, the HTTP
surface, both CLIs, and the architectural dependency rules themselves — see
[`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a PR, and
[`AGENTS.md`](AGENTS.md) for the implementation contract the codebase
enforces by test, not by convention.

## Documentation

| Doc | Covers |
|---|---|
| [`docs/USAGE.md`](docs/USAGE.md) | Every way to use Custos, with working examples for each |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | The system as it exists today: modules, pipeline, error taxonomy, gateway routes |
| [`conformance/README.md`](conformance/README.md) | Porting Custos's verification pipeline to another language |
| [`docs/design/`](docs/design/) | The dated design-decision record — why things work the way they do |
| [`AGENTS.md`](AGENTS.md) | The implementation contract, enforced by test |
| [`CHANGELOG.md`](CHANGELOG.md) | What shipped and when |

## Contributing

Contributions are welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md) for the
rules this codebase enforces by test (dependency direction, the fixed error
taxonomy, canonical-form stability) and the workflow that keeps a PR review
short. This project follows the
[Contributor Covenant](CODE_OF_CONDUCT.md).

## Security

Found a vulnerability? Please don't open a public issue — see
[`SECURITY.md`](SECURITY.md) for how to report it privately.

## License

[MIT](LICENSE) — © 2026 Akul Ranjan.
