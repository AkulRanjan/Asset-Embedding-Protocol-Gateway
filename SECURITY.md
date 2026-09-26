# Security policy

Custos is a pre-transaction verification protocol; a bug in it can mean a
transaction that should have been blocked is allowed, or an agent's signing
key or a gateway's admin key is exposed. Please report security issues
privately.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Instead, use GitHub's private vulnerability reporting: open the
[Security tab](https://github.com/AkulRanjan/APay-Gateway/security) on this
repository and select "Report a vulnerability." If that isn't available,
email the maintainer directly (see the `authors` field in `pyproject.toml`)
with `[SECURITY]` in the subject line.

Please include:

- What you found and where (file/line, or the HTTP route, or the CLI
  command).
- A minimal reproduction — a failing test is ideal, since this repo is
  entirely test-driven, but a clear step-by-step works too.
- What you'd expect Custos to do instead, and why the current behavior is a
  security issue rather than a correctness bug (both are welcome as reports,
  but they get triaged differently).

You should hear back within a few days. This is a small project maintained
by one person, not a company with an SLA — please be patient, and thank you
for reporting responsibly instead of disclosing publicly first.

## Scope

In scope:

- `custos_protocol/` — the verification pipeline, canonical serialization,
  cryptographic primitives, boundary/delegation/trust enforcement.
- `gateway/` — the HTTP surface, including authentication on admin routes.
- `conformance/` — a vector that claims to pass but shouldn't (or vice
  versa) is a real finding, since the suite exists specifically to make
  correctness checkable by someone who isn't reading the Python source.

Out of scope:

- `demo/` — explicitly for local demonstration, not production use; treat
  anything there as insecure by design.
- Findings that require an attacker who already holds an agent's private
  key. Custos's threat model (see `AGENTS.md` and the design docs in
  `docs/design/`) is explicit that a compromised signing key is a different
  problem than a protocol defect — Shield in particular is documented as
  local policy enforcement with an audit trail, not remote attestation.
- The Treasury data source itself (`oracle/treasury.py` fetches from
  `home.treasury.gov`) — issues with that upstream feed aren't a Custos
  vulnerability, though a case where Custos *mishandles* a malformed or
  adversarial response from it (rather than failing closed) is in scope.

## Known, deliberate trade-offs — not vulnerabilities

A few things that look like bugs on first read are documented, intentional
design decisions. Check `AGENTS.md` and the module docstrings in
`custos_protocol/shield.py` and `custos_protocol/trust.py` before reporting:

- `@shield` on a class leaves methods absent from its `actions` mapping
  completely unwrapped (not blocked) — a deliberate choice, not an oversight.
- The per-day monetary ledger's reservation is released if a later
  verification step fails, by design — see `TrustEngine.reserve_amount`'s
  docstring for the reasoning.
- A revoked agent is blocked at every tier, including Tier 0 — this is
  intentional (the kill switch is not tier-gated); the reverse would be the
  bug.
