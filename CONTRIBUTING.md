# Contributing to Custos

Thanks for considering a contribution. Custos is a small, opinionated protocol
implementation, and it stays trustworthy by staying strict about a few rules.
Read this before opening a PR — it'll save you a review round-trip.

## Set up

```bash
git clone https://github.com/AkulRanjan/APay-Gateway.git
cd APay-Gateway
python -m pip install -e ".[dev]"
pytest -q
```

Bare `pytest` works (no `python -m` needed) — `pyproject.toml`'s
`[tool.pytest.ini_options]` sets `pythonpath = ["."]` for exactly this reason.
The suite is fully hermetic: the oracle tests use `httpx.MockTransport`, so no
network access is required to run it.

## The rules that are enforced by test, not by convention

These live in `AGENTS.md` in full; the short version:

- **`custos_protocol/` imports nothing from `gateway/`, `claims/`, or
  `oracle/`.** It's the SDK; the application layers depend on it, never the
  reverse. Checked by `tests/test_architecture.py`.
- **`custos_protocol/` performs no I/O beyond local files** — no
  `os.getenv`, no `import httpx`, anywhere in that package.
  `gateway/admin_cli.py` is where network calls against a live gateway live.
- **`observe.py` never imports `verification.py`.** Observability must be
  structurally incapable of blocking a call.
- **The error taxonomy is fixed at 30 `CUSTOS-Exxx` codes.** Don't add a
  31st for a new failure mode — find the closest existing code and use it,
  or open an issue to discuss extending the taxonomy first. Every code that
  `verify_intent` can emit needs both a unit test and a conformance vector
  (`tests/test_architecture.py::test_every_error_code_is_exercised_by_the_suite`
  and `tests/test_conformance.py::test_every_sdk_reachable_error_code_has_a_vector`
  both enforce this).
- **The canonical serialization form (`custos_protocol/canonical.py`) is the
  single most sensitive file in the repo.** A one-byte change breaks every
  existing signature and every conformance vector. Read
  `conformance/CANONICAL_SERIALIZATION.md` before touching it, and regenerate
  vectors (`python conformance/generate_vectors.py`) if you do.
- **Never fail open.** If you're unsure whether a new check should default
  to permissive or restrictive when its inputs are missing or ambiguous,
  default to restrictive and say so in the PR description.

## Workflow

1. **Write the failing test first.** Every module in this repo was built
   test-first; PRs that add behavior without a test that would fail on `main`
   without the change will be asked to add one.
2. **Keep the diff scoped.** A bug fix doesn't need a refactor riding along
   with it. If you spot an unrelated problem while you're in a file, open a
   separate issue or PR for it.
3. **Run the full suite before pushing**, not just the file you touched —
   `custos_protocol/` modules are more interconnected than their file
   boundaries suggest, and a change to `boundaries.py` or `models.py` can
   break tests three files away.
4. **Match the existing comment style.** Comments explain *why*, not *what*
   — a hidden constraint, a divergence from the reference implementation
   this project is modeled on, a subtle invariant. If removing a comment
   wouldn't confuse a future reader, it shouldn't be there.
5. **Conventional commits** (`feat:`, `fix:`, `test:`, `docs:`, `refactor:`,
   `chore:`) — check `git log` for the existing style.

## What a good PR description includes

- What changed and why — the *why* matters more than the *what* here, since
  the diff already shows the what.
- Which tests cover it, and confirmation the full suite passes.
- If it touches `canonical.py`, `verification.py`, or anything in the error
  taxonomy: explicit confirmation the conformance suite still passes
  (`python conformance/run_conformance.py`).
- Any deliberate divergence from what a reader might expect, with the
  reasoning — this repo has a strong track record of documenting *why*
  something works differently than the obvious approach would; keep that up.

## Reporting a security issue

Don't open a public issue for a vulnerability — see `SECURITY.md`.

## Questions

Open an issue. If it's a design question rather than a bug, say so in the
title — those get triaged differently.
