"""Deterministic conformance vector generator.

Every vector is built from real `custos_protocol` objects and signed with
`custos_protocol`'s own canonical/crypto functions, so the vectors and this
repo's own verifier cannot disagree about canonicalization by construction. A
second-language implementation is conformant when it reproduces the same
canonical bytes and the same `verify_intent` verdict for every vector here.

Fixed seeds and a fixed clock make every byte of `vectors.json` reproducible:
regenerating must produce a byte-identical file (checked by
`tests/test_conformance.py`).

Scope: every `CUSTOS-Exxx` code reachable from `custos_protocol.verify_intent`
is covered. `E304 TENOR_UNSUPPORTED` and `E502 DOWNSTREAM_UNREACHABLE` are
gateway/oracle integration concerns — verify_intent never emits either one
(grep confirms both are raised only in gateway/server.py) — so they are
correctly out of scope for an SDK-level conformance suite and are not vectors
here; they're covered by tests/test_gateway.py instead.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from custos_protocol.canonical import canonical_bytes
from custos_protocol.crypto import hmac_sign, public_key_to_b64
from custos_protocol.envelope import sign_envelope
from custos_protocol.models import (
    Action,
    AgentAttestation,
    AgentIdentity,
    AttestationMethod,
    Boundaries,
    Claim,
    CustosEnvelope,
    DelegationLink,
    Intent,
    MonetaryLimit,
    Observation,
    Principal,
    TimeWindow,
    VerificationTier,
)
from custos_protocol.passport import AgentPassport

SPEC_VERSION = "custos-conformance/1.0.0"
T_NOW = datetime(2026, 9, 25, 12, 0, 0, tzinfo=timezone.utc)
T_EXPIRED = datetime(2020, 1, 1, tzinfo=timezone.utc)

_SEED_AGENT_1 = bytes.fromhex("aa" * 32)
_SEED_AGENT_2 = bytes.fromhex("bb" * 32)
_HMAC_KEY = bytes.fromhex("cc" * 32)

_KEY_AGENT_1 = Ed25519PrivateKey.from_private_bytes(_SEED_AGENT_1)
_KEY_AGENT_2 = Ed25519PrivateKey.from_private_bytes(_SEED_AGENT_2)

_nonce_counter = [0]


def _nonce() -> str:
    _nonce_counter[0] += 1
    return f"nonce:{_nonce_counter[0]:032x}"


def _boundaries(**overrides) -> Boundaries:
    base: dict = {
        "allowed_actions": [], "denied_actions": [],
        "monetary_limit": MonetaryLimit(), "asset_classes": [],
        "geo_restriction": None, "time_window": None,
    }
    base.update(overrides)
    return Boundaries(**base)


def _passport(
    agent_id: str, principal_id: str, private_key: Ed25519PrivateKey, boundaries: Boundaries,
    *, framework_id: str | None = None, build_hash: str | None = None,
    system_prompt_hash: str | None = None,
) -> AgentPassport:
    public_key = private_key.public_key()
    attestation = AgentAttestation(
        method=AttestationMethod.FRAMEWORK_REGISTRY if framework_id else AttestationMethod.SELF_REPORTED,
        framework_id=framework_id, build_hash=build_hash, system_prompt_hash=system_prompt_hash,
    )
    agent = AgentIdentity(id=agent_id, attestation=attestation)
    principal = Principal(id=principal_id, delegation_chain=[
        DelegationLink(from_id=principal_id, to_id=agent_id, boundaries=boundaries, granted_at=T_NOW - timedelta(days=1)),
    ] if principal_id != agent_id else [])
    return AgentPassport(agent, principal, boundaries, public_key, private_key)


def _envelope(
    holder: AgentPassport, action: Action, target: str, parameters: dict,
    *, tier: VerificationTier = VerificationTier.TIER_1, issued_at: datetime = T_NOW,
    expires_at: datetime | None = None, entropy: str | None = None,
) -> CustosEnvelope:
    expires_at = expires_at or issued_at + timedelta(minutes=5)
    return CustosEnvelope(
        agent=holder.agent, principal=holder.principal, boundaries=holder.boundaries,
        intent=Intent(action=action, target=target, parameters=parameters),
        verification_tier=tier, entropy=entropy or _nonce(),
        issued_at=issued_at, expires_at=expires_at,
    )


def _sign(envelope: CustosEnvelope, private_key: Ed25519PrivateKey) -> CustosEnvelope:
    return sign_envelope(envelope, private_key, now=T_NOW)


def _hmac_sign(envelope: CustosEnvelope) -> CustosEnvelope:
    from custos_protocol.canonical import get_signable_payload
    from custos_protocol.models import Proof

    payload = get_signable_payload(envelope, exclude={"proof"})
    proof = Proof(created=T_NOW, verification_method="hmac", proof_value=hmac_sign(_HMAC_KEY, payload))
    return envelope.model_copy(update={"proof": proof})


def _claim(**overrides) -> Claim:
    base: dict = {
        "asset_id": "TKN-UST-3M-001", "issuer": "Meridian", "underlying_tenor": "3M",
        "asset_class": "treasury", "claimed_nav_per_token": Decimal("1"),
        "claimed_backing_usd": Decimal("100"), "tokens_outstanding": Decimal("100"),
        "claimed_yield_bps": 400, "last_attested_at": T_NOW - timedelta(hours=1),
        "chain": "ethereum", "contract_address": "0x1",
    }
    base.update(overrides)
    return Claim(**base)


def _observation(**overrides) -> Observation:
    base: dict = {
        "source": "conformance", "tenor": "3M", "observed_yield_bps": 400,
        "record_date": T_NOW.date(), "fetched_at": T_NOW,
    }
    base.update(overrides)
    return Observation(**base)


def _dump(model) -> dict:
    return model.model_dump(mode="json", by_alias=True) if model is not None else None


VECTORS: list[dict] = []


def _add(
    id_: str, category: str, description: str, *,
    envelope: CustosEnvelope, verify_key: Ed25519PrivateKey = _KEY_AGENT_1,
    claim: Claim | None = None, observation: Observation | None = None,
    now: datetime = T_NOW, revocations: list[dict] | None = None,
    hmac: bool = False, verify_twice: bool = False,
    day_total_seed: float | None = None, min_trust_score: float = 0.0,
    expected_passed: bool, expected_tier: str, expected_errors: list[str],
) -> None:
    VECTORS.append({
        "id": id_, "category": category, "description": description,
        "envelope": _dump(envelope),
        "verify_public_key": public_key_to_b64(verify_key.public_key()),
        "claim": _dump(claim), "observation": _dump(observation),
        "now": now.isoformat(),
        "revocations": revocations or [],
        "hmac_key": _HMAC_KEY.hex() if hmac else None,
        "verify_twice": verify_twice,
        "day_total_seed": day_total_seed,
        "min_trust_score": min_trust_score,
        "expected": {
            "passed": expected_passed, "tier_used": expected_tier, "errors": expected_errors,
        },
    })


def build_vectors() -> None:
    # ---- A: envelope / protocol -------------------------------------------
    holder = _passport("did:web:acme.com:agents:bot", "did:web:acme.com", _KEY_AGENT_1,
                       _boundaries(allowed_actions=["read"]))

    a01 = _sign(_envelope(holder, Action.READ, "TKN-UST-3M-001", {}, tier=VerificationTier.TIER_0), _KEY_AGENT_1)
    _add("A01", "envelope validity", "A healthy Tier 0 envelope passes.",
         envelope=a01, expected_passed=True, expected_tier="tier_0", expected_errors=[])

    a02 = _sign(_envelope(holder, Action.READ, "x", {}, tier=VerificationTier.TIER_0,
                          issued_at=T_EXPIRED, expires_at=T_EXPIRED + timedelta(minutes=5)), _KEY_AGENT_1)
    _add("A02", "envelope validity", "An expired envelope is rejected.",
         envelope=a02, expected_passed=False, expected_tier="tier_0", expected_errors=["CUSTOS-E101"])

    a03 = _sign(_envelope(holder, Action.READ, "x", {}, tier=VerificationTier.TIER_0), _KEY_AGENT_1)
    a03 = a03.model_copy(update={"protocol_version": "9.9.9"})
    a03 = _sign(a03, _KEY_AGENT_1)
    _add("A03", "envelope validity", "An unsupported protocol version is rejected before anything else.",
         envelope=a03, expected_passed=False, expected_tier="tier_0", expected_errors=["CUSTOS-E104"])

    a04 = _envelope(holder, Action.READ, "x", {}, tier=VerificationTier.TIER_0, entropy="not-a-nonce")
    a04 = _sign(a04, _KEY_AGENT_1)
    _add("A04", "envelope validity", "A malformed nonce (not matching nonce:<32 hex>) is rejected.",
         envelope=a04, expected_passed=False, expected_tier="tier_0", expected_errors=["CUSTOS-E105"])

    a05 = _envelope(holder, Action.READ, "x", {}, tier=VerificationTier.TIER_0,
                    issued_at=T_NOW + timedelta(minutes=10), expires_at=T_NOW + timedelta(minutes=20))
    a05 = _sign(a05, _KEY_AGENT_1)
    _add("A05", "envelope validity", "issued_at more than 5 minutes in the future is a clock-skew rejection.",
         envelope=a05, expected_passed=False, expected_tier="tier_0", expected_errors=["CUSTOS-E106"])

    d01 = _envelope(holder, Action.READ, "x", {}, tier=VerificationTier.TIER_0)
    d01 = d01.model_copy(update={"agent": holder.agent.model_copy(update={"id": ""})})
    d01 = _sign(d01, _KEY_AGENT_1)
    _add("D01", "schema", "An empty agent id fails the semantic schema check.",
         envelope=d01, expected_passed=False, expected_tier="tier_0", expected_errors=["CUSTOS-E103"])

    # ---- B: signature -------------------------------------------------------
    b01 = _sign(_envelope(holder, Action.READ, "x", {}, tier=VerificationTier.TIER_0), _KEY_AGENT_1)
    _add("B01", "signature", "A valid Ed25519 signature verifies.",
         envelope=b01, expected_passed=True, expected_tier="tier_0", expected_errors=[])

    b02 = _sign(_envelope(holder, Action.READ, "x", {}, tier=VerificationTier.TIER_0), _KEY_AGENT_1)
    _add("B02", "signature", "Verifying against the wrong public key fails.",
         envelope=b02, verify_key=_KEY_AGENT_2,
         expected_passed=False, expected_tier="tier_0", expected_errors=["CUSTOS-E100"])

    b03 = _sign(_envelope(holder, Action.READ, "x", {}, tier=VerificationTier.TIER_0), _KEY_AGENT_1)
    b03 = b03.model_copy(update={"intent": b03.intent.model_copy(update={"target": "tampered"})})
    _add("B03", "signature", "A tampered payload (post-signing) fails signature verification.",
         envelope=b03, expected_passed=False, expected_tier="tier_0", expected_errors=["CUSTOS-E100"])

    b04 = _hmac_sign(_envelope(holder, Action.READ, "x", {}, tier=VerificationTier.TIER_0))
    _add("B04", "signature", "A valid HMAC signature verifies at Tier 0.",
         envelope=b04, hmac=True, expected_passed=True, expected_tier="tier_0", expected_errors=[])

    # ---- C: replay ------------------------------------------------------------
    c01 = _sign(_envelope(holder, Action.READ, "x", {}, tier=VerificationTier.TIER_0), _KEY_AGENT_1)
    _add("C01", "replay", "A fresh nonce is accepted.",
         envelope=c01, expected_passed=True, expected_tier="tier_0", expected_errors=[])

    c02 = _sign(_envelope(holder, Action.READ, "x", {}, tier=VerificationTier.TIER_0), _KEY_AGENT_1)
    _add("C02", "replay", "The same nonce used twice is rejected the second time.",
         envelope=c02, verify_twice=True,
         expected_passed=False, expected_tier="tier_0", expected_errors=["CUSTOS-E102"])

    # ---- E: boundary ------------------------------------------------------
    trader = _passport("did:web:acme.com:agents:trader", "did:web:acme.com", _KEY_AGENT_1,
                       _boundaries(allowed_actions=["trade"], denied_actions=["redeem"],
                                  monetary_limit=MonetaryLimit(per_transaction=1000, per_day=2000),
                                  asset_classes=["treasury"], geo_restriction="US,CA",
                                  time_window=TimeWindow(start=T_NOW - timedelta(hours=1), end=T_NOW + timedelta(hours=1))))

    e01 = _sign(_envelope(trader, Action.TRADE, "TKN-UST-3M-001", {"amount": 100}), _KEY_AGENT_1)
    _add("E01", "boundary", "A permitted trade within every limit passes (through Tier 1 asset truth).",
         envelope=e01, claim=_claim(), observation=_observation(),
         expected_passed=True, expected_tier="tier_1", expected_errors=[])

    e02 = _sign(_envelope(trader, Action.BORROW_AGAINST, "TKN-UST-3M-001", {"amount": 100}), _KEY_AGENT_1)
    _add("E02", "boundary", "An action absent from a non-empty allowlist is rejected.",
         envelope=e02, expected_passed=False, expected_tier="tier_1", expected_errors=["CUSTOS-E200"])

    e03 = _sign(_envelope(trader, Action.REDEEM, "TKN-UST-3M-001", {"amount": 100}), _KEY_AGENT_1)
    _add("E03", "boundary", "A denied action is rejected even if also allowed elsewhere.",
         envelope=e03, expected_passed=False, expected_tier="tier_1", expected_errors=["CUSTOS-E201"])

    e04 = _sign(_envelope(trader, Action.TRADE, "TKN-UST-3M-001", {"amount": 1500}), _KEY_AGENT_1)
    _add("E04", "boundary", "An amount over the per-transaction limit is rejected "
                            "(1500 > 1000, but still under the 2000 per-day limit, isolating this to E202).",
         envelope=e04, expected_passed=False, expected_tier="tier_1", expected_errors=["CUSTOS-E202"])

    e05 = _sign(_envelope(trader, Action.TRADE, "TKN-UST-3M-001", {"amount": 600}), _KEY_AGENT_1)
    _add("E05", "boundary", "An amount that would exceed the rolling per-day limit is rejected.",
         envelope=e05, claim=_claim(), observation=_observation(), day_total_seed=1500,
         expected_passed=False, expected_tier="tier_1", expected_errors=["CUSTOS-E203"])

    outside_window = _passport("did:web:acme.com:agents:trader2", "did:web:acme.com", _KEY_AGENT_1,
                               _boundaries(allowed_actions=["trade"],
                                          time_window=TimeWindow(start=T_NOW - timedelta(hours=3), end=T_NOW - timedelta(hours=2))))
    e06 = _sign(_envelope(outside_window, Action.TRADE, "TKN-UST-3M-001", {"amount": 100}), _KEY_AGENT_1)
    _add("E06", "boundary", "A request outside the agent's time window is rejected.",
         envelope=e06, expected_passed=False, expected_tier="tier_1", expected_errors=["CUSTOS-E204"])

    e07 = _sign(_envelope(trader, Action.TRADE, "TKN-UST-3M-001", {"amount": 100}), _KEY_AGENT_1)
    VECTORS.append({
        **{
            "id": "E07", "category": "boundary",
            "description": "A request from outside the agent's permitted geography is rejected.",
            "envelope": _dump(e07), "verify_public_key": public_key_to_b64(_KEY_AGENT_1.public_key()),
            "claim": None, "observation": None, "now": T_NOW.isoformat(), "revocations": [],
            "hmac_key": None, "verify_twice": False, "day_total_seed": None, "min_trust_score": 0.0,
            "request_geo": "RU",
            "expected": {"passed": False, "tier_used": "tier_1", "errors": ["CUSTOS-E205"]},
        },
    })

    e08 = _sign(_envelope(trader, Action.TRADE, "TKN-UST-3M-001", {"amount": 100}), _KEY_AGENT_1)
    _add("E08", "boundary", "An asset class outside the permitted set is rejected.",
         envelope=e08, claim=_claim(asset_class="corporate_credit"),
         expected_passed=False, expected_tier="tier_1", expected_errors=["CUSTOS-E206"])

    # ---- F: revocation --------------------------------------------------------
    f01 = _sign(_envelope(holder, Action.READ, "x", {}, tier=VerificationTier.TIER_0), _KEY_AGENT_1)
    _add("F01", "revocation", "A clean, unrevoked agent passes.",
         envelope=f01, expected_passed=True, expected_tier="tier_0", expected_errors=[])

    f02 = _sign(_envelope(trader, Action.TRADE, "TKN-UST-3M-001", {"amount": 100}), _KEY_AGENT_1)
    _add("F02", "revocation", "A revoked agent is blocked.",
         envelope=f02, revocations=[{"subject_id": trader.agent.id, "subject_type": "agent", "action": "revoke"}],
         expected_passed=False, expected_tier="tier_1", expected_errors=["CUSTOS-E400"])

    f03 = _sign(_envelope(holder, Action.READ, "x", {}, tier=VerificationTier.TIER_0), _KEY_AGENT_1)
    _add("F03", "revocation", "A revoked agent is blocked even at Tier 0 — the kill switch is not tier-gated.",
         envelope=f03, revocations=[{"subject_id": holder.agent.id, "subject_type": "agent", "action": "revoke"}],
         expected_passed=False, expected_tier="tier_0", expected_errors=["CUSTOS-E400"])

    f04 = _sign(_envelope(holder, Action.READ, "x", {}, tier=VerificationTier.TIER_0), _KEY_AGENT_1)
    _add("F04", "revocation", "A suspended agent reports its own code.",
         envelope=f04, revocations=[{"subject_id": holder.agent.id, "subject_type": "agent", "action": "suspend", "duration_seconds": 1800}],
         expected_passed=False, expected_tier="tier_0", expected_errors=["CUSTOS-E401"])

    f05 = _sign(_envelope(trader, Action.TRADE, "TKN-UST-3M-001", {"amount": 100}), _KEY_AGENT_1)
    _add("F05", "revocation", "A revoked issuer blocks the transaction.",
         envelope=f05, claim=_claim(issuer="Meridian"),
         revocations=[{"subject_id": "Meridian", "subject_type": "issuer", "action": "revoke"}],
         expected_passed=False, expected_tier="tier_1", expected_errors=["CUSTOS-E402"])

    f06 = _sign(_envelope(holder, Action.READ, "x", {}, tier=VerificationTier.TIER_0), _KEY_AGENT_1)
    VECTORS.append({
        "id": "F06", "category": "revocation",
        "description": "A non-local revocation store that hasn't synced within the staleness "
                       "budget fails closed rather than reporting not-revoked. Custos's highest-"
                       "severity divergence from the reference implementation, which fails open "
                       "here. The one vector in this suite that is not purely data-driven: "
                       "staleness is measured against the real wall clock (an operational "
                       "concern, unlike envelope timestamps), so the runner must sleep past "
                       "requires_sleep_ms before verifying, exactly as tests/test_verification.py "
                       "does for the same check.",
        "envelope": _dump(f06), "verify_public_key": public_key_to_b64(_KEY_AGENT_1.public_key()),
        "claim": None, "observation": None, "now": T_NOW.isoformat(), "revocations": [],
        "hmac_key": None, "verify_twice": False, "day_total_seed": None, "min_trust_score": 0.0,
        "revocation_local_only": False, "max_revocation_staleness_ms": 1, "requires_sleep_ms": 20,
        "expected": {"passed": False, "tier_used": "tier_0", "errors": ["CUSTOS-E405"]},
    })

    # ---- G: asset truth -----------------------------------------------------
    g01 = _sign(_envelope(trader, Action.TRADE, "NOPE", {"amount": 100}), _KEY_AGENT_1)
    _add("G01", "asset truth", "An unknown asset (no claim) is rejected.",
         envelope=g01, claim=None, expected_passed=False, expected_tier="tier_1", expected_errors=["CUSTOS-E303"])

    g02 = _sign(_envelope(trader, Action.TRADE, "TKN-UST-3M-001", {"amount": 100}), _KEY_AGENT_1)
    _add("G02", "asset truth", "A known asset with no market observation fails closed.",
         envelope=g02, claim=_claim(), observation=None,
         expected_passed=False, expected_tier="tier_1", expected_errors=["CUSTOS-E500"])

    g03 = _sign(_envelope(trader, Action.TRADE, "TKN-UST-3M-001", {"amount": 100}), _KEY_AGENT_1)
    _add("G03", "asset truth", "An observation older than the maximum age is rejected.",
         envelope=g03, claim=_claim(), observation=_observation(record_date=(T_NOW - timedelta(days=10)).date()),
         expected_passed=False, expected_tier="tier_1", expected_errors=["CUSTOS-E501"])

    g04 = _sign(_envelope(trader, Action.TRADE, "TKN-UST-3M-001", {"amount": 100}), _KEY_AGENT_1)
    _add("G04", "asset truth", "A claim attested in the future is rejected.",
         envelope=g04, claim=_claim(last_attested_at=T_NOW + timedelta(hours=1)), observation=_observation(),
         expected_passed=False, expected_tier="tier_1", expected_errors=["CUSTOS-E305"])

    g05 = _sign(_envelope(trader, Action.TRADE, "TKN-UST-3M-001", {"amount": 100}), _KEY_AGENT_1)
    _add("G05", "asset truth", "A stale claim (older than the staleness threshold) is rejected.",
         envelope=g05, claim=_claim(last_attested_at=T_NOW - timedelta(hours=48)), observation=_observation(),
         expected_passed=False, expected_tier="tier_1", expected_errors=["CUSTOS-E300"])

    g06 = _sign(_envelope(trader, Action.TRADE, "TKN-UST-3M-001", {"amount": 100}), _KEY_AGENT_1)
    _add("G06", "asset truth", "A negative observed yield is impossible market data.",
         envelope=g06, claim=_claim(), observation=_observation(observed_yield_bps=-5),
         expected_passed=False, expected_tier="tier_1", expected_errors=["CUSTOS-E501"])

    g07 = _sign(_envelope(trader, Action.TRADE, "TKN-UST-3M-001", {"amount": 100}), _KEY_AGENT_1)
    _add("G07", "asset truth", "A claimed yield diverging beyond the relative threshold is rejected.",
         envelope=g07, claim=_claim(claimed_yield_bps=360), observation=_observation(observed_yield_bps=400),
         expected_passed=False, expected_tier="tier_1", expected_errors=["CUSTOS-E301"])

    g08 = _sign(_envelope(trader, Action.TRADE, "TKN-UST-3M-001", {"amount": 100}), _KEY_AGENT_1)
    _add("G08", "asset truth", "A backing ratio below the floor is rejected.",
         envelope=g08, claim=_claim(claimed_backing_usd=Decimal("50")), observation=_observation(),
         expected_passed=False, expected_tier="tier_1", expected_errors=["CUSTOS-E302"])

    g09 = _sign(_envelope(trader, Action.TRADE, "TKN-UST-3M-001", {"amount": 100}), _KEY_AGENT_1)
    _add("G09", "asset truth", "At a genuine 0.00% print, a small claimed yield within absolute tolerance passes.",
         envelope=g09, claim=_claim(claimed_yield_bps=5), observation=_observation(observed_yield_bps=0),
         expected_passed=True, expected_tier="tier_1", expected_errors=[])

    # ---- H: delegation --------------------------------------------------------
    outer_boundaries = _boundaries(allowed_actions=["trade"], monetary_limit=MonetaryLimit(per_transaction=1000))
    mid_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("dd" * 32))
    inner_boundaries = _boundaries(allowed_actions=["trade"], monetary_limit=MonetaryLimit(per_transaction=500))

    def _chain_envelope(inner_link_boundaries: Boundaries, *, envelope_boundaries: Boundaries | None = None,
                        link_expires: datetime | None = None, granted_at: datetime = T_NOW - timedelta(days=1)) -> CustosEnvelope:
        principal_id = "did:web:acme.com"
        mid_id = "did:web:acme.com:agents:mid"
        leaf_id = "did:web:acme.com:agents:leaf"
        chain = [
            DelegationLink(from_id=principal_id, to_id=mid_id, boundaries=outer_boundaries, granted_at=T_NOW - timedelta(days=2)),
            DelegationLink(from_id=mid_id, to_id=leaf_id, boundaries=inner_link_boundaries,
                          granted_at=granted_at, expires_at=link_expires),
        ]
        agent = AgentIdentity(id=leaf_id)
        principal = Principal(id=principal_id, delegation_chain=chain)
        env_boundaries = envelope_boundaries or inner_link_boundaries
        return CustosEnvelope(
            agent=agent, principal=principal, boundaries=env_boundaries,
            intent=Intent(action=Action.TRADE, target="TKN-UST-3M-001", parameters={"amount": 100}),
            verification_tier=VerificationTier.TIER_2, entropy=_nonce(),
            issued_at=T_NOW, expires_at=T_NOW + timedelta(minutes=5),
        )

    h01 = _sign(_chain_envelope(inner_boundaries), _KEY_AGENT_1)
    _add("H01", "delegation", "A valid two-hop delegation chain with correct monotonicity passes.",
         envelope=h01, claim=_claim(), observation=_observation(),
         expected_passed=True, expected_tier="tier_2", expected_errors=[])

    h02_env = _chain_envelope(inner_boundaries)
    h02_env = h02_env.model_copy(update={"principal": h02_env.principal.model_copy(update={
        "delegation_chain": [
            h02_env.principal.delegation_chain[0],
            h02_env.principal.delegation_chain[1].model_copy(update={"from_id": "did:web:acme.com:agents:someone-else"}),
        ],
    })})
    h02 = _sign(h02_env, _KEY_AGENT_1)
    _add("H02", "delegation", "A discontinuous chain is rejected.",
         envelope=h02, claim=_claim(), observation=_observation(),
         expected_passed=False, expected_tier="tier_2", expected_errors=["CUSTOS-E403"])

    h03 = _sign(_chain_envelope(inner_boundaries, link_expires=T_NOW - timedelta(hours=1)), _KEY_AGENT_1)
    _add("H03", "delegation", "An expired delegation hop is rejected.",
         envelope=h03, claim=_claim(), observation=_observation(),
         expected_passed=False, expected_tier="tier_2", expected_errors=["CUSTOS-E403"])

    wider_inner = _boundaries(allowed_actions=["trade", "redeem"], monetary_limit=MonetaryLimit(per_transaction=1000))
    h04 = _sign(_chain_envelope(wider_inner, envelope_boundaries=wider_inner), _KEY_AGENT_1)
    _add("H04", "delegation", "A hop widening its authority beyond its delegator is rejected (real boundary monotonicity).",
         envelope=h04, claim=_claim(), observation=_observation(),
         expected_passed=False, expected_tier="tier_2", expected_errors=["CUSTOS-E403"])

    # ---- I: trust ---------------------------------------------------------
    i01 = _sign(_chain_envelope(inner_boundaries), _KEY_AGENT_1)
    _add("I01", "trust", "min_trust_score at the default of 0.0 never gates.",
         envelope=i01, claim=_claim(), observation=_observation(),
         expected_passed=True, expected_tier="tier_2", expected_errors=[])

    i02 = _sign(_chain_envelope(inner_boundaries), _KEY_AGENT_1)
    _add("I02", "trust", "A fresh agent (trust score 0.0) fails a configured minimum threshold.",
         envelope=i02, claim=_claim(), observation=_observation(), min_trust_score=0.5,
         expected_passed=False, expected_tier="tier_2", expected_errors=["CUSTOS-E404"])

    # ---- J: attestation -----------------------------------------------------
    framework_holder = _passport("did:web:acme.com:agents:framework-bot", "did:web:acme.com", _KEY_AGENT_1,
                                 _boundaries(allowed_actions=["read"]), framework_id="langchain")
    j01 = _sign(_envelope(framework_holder, Action.READ, "x", {}, tier=VerificationTier.TIER_1), _KEY_AGENT_1)
    _add("J01", "attestation", "With no known-hash maps supplied, attestation is opt-in and trivially passes.",
         envelope=j01, claim=_claim(asset_class="treasury"), observation=_observation(),
         expected_passed=True, expected_tier="tier_1", expected_errors=[])

    VECTORS.append({
        "id": "J02", "category": "attestation",
        "description": "An unregistered framework is rejected.",
        "envelope": _dump(j01), "verify_public_key": public_key_to_b64(_KEY_AGENT_1.public_key()),
        "claim": _dump(_claim()), "observation": _dump(_observation()), "now": T_NOW.isoformat(),
        "revocations": [], "hmac_key": None, "verify_twice": False,
        "day_total_seed": None, "min_trust_score": 0.0,
        "registered_frameworks": ["crewai"],
        "expected": {"passed": False, "tier_used": "tier_1", "errors": ["CUSTOS-E306"]},
    })

    build_hash_holder = _passport("did:web:acme.com:agents:framework-bot2", "did:web:acme.com", _KEY_AGENT_1,
                                  _boundaries(allowed_actions=["read"]), framework_id="langchain", build_hash="actual-hash")
    j03_env = _sign(_envelope(build_hash_holder, Action.READ, "x", {}, tier=VerificationTier.TIER_1), _KEY_AGENT_1)
    VECTORS.append({
        "id": "J03", "category": "attestation",
        "description": "A build_hash mismatch against the registered framework hash is rejected.",
        "envelope": _dump(j03_env), "verify_public_key": public_key_to_b64(_KEY_AGENT_1.public_key()),
        "claim": _dump(_claim()), "observation": _dump(_observation()), "now": T_NOW.isoformat(),
        "revocations": [], "hmac_key": None, "verify_twice": False,
        "day_total_seed": None, "min_trust_score": 0.0,
        "known_build_hashes": {"langchain": "expected-hash"},
        "expected": {"passed": False, "tier_used": "tier_1", "errors": ["CUSTOS-E306"]},
    })

    prompt_holder = _passport("did:web:acme.com:agents:prompt-bot", "did:web:acme.com", _KEY_AGENT_1,
                              _boundaries(allowed_actions=["read"]), system_prompt_hash="actual-prompt")
    j04_env = _sign(_envelope(prompt_holder, Action.READ, "x", {}, tier=VerificationTier.TIER_1), _KEY_AGENT_1)
    VECTORS.append({
        "id": "J04", "category": "attestation",
        "description": "A system_prompt_hash mismatch against the registered hash is rejected.",
        "envelope": _dump(j04_env), "verify_public_key": public_key_to_b64(_KEY_AGENT_1.public_key()),
        "claim": _dump(_claim()), "observation": _dump(_observation()), "now": T_NOW.isoformat(),
        "revocations": [], "hmac_key": None, "verify_twice": False,
        "day_total_seed": None, "min_trust_score": 0.0,
        "known_prompt_hashes": {prompt_holder.agent.id: "expected-prompt"},
        "expected": {"passed": False, "tier_used": "tier_1", "errors": ["CUSTOS-E306"]},
    })

    # ---- K: canonical serialization -----------------------------------------
    k_full = _sign(_envelope(holder, Action.READ, "x", {"amount": 500.0}, tier=VerificationTier.TIER_0,
                             issued_at=T_NOW, entropy="nonce:" + "0" * 32), _KEY_AGENT_1)
    payload = canonical_bytes(_dump(k_full), exclude={"proof"})
    VECTORS.append({
        "id": "K01", "category": "serialization",
        "description": "Byte-exact canonical payload of a full envelope: whole floats become ints, "
                       "keys sorted recursively (@ sorts first), no whitespace, Z-suffixed datetime, "
                       "nulls present, proof excluded.",
        "payload_input": _dump(k_full), "exclude": ["proof"],
        "canonical_payload_hex": payload.hex(),
    })

    VECTORS.append({
        "id": "K02", "category": "serialization",
        "description": "A whole float (500.0) normalizes to the JSON integer 500; a fractional float "
                       "(45.5) is untouched.",
        "payload_input": {"whole": 500.0, "fractional": 45.5}, "exclude": [],
        "canonical_payload_hex": canonical_bytes({"whole": 500.0, "fractional": 45.5}, exclude=set()).hex(),
    })

    VECTORS.append({
        "id": "K03", "category": "serialization",
        "description": "A Decimal is carried through Pydantic as a JSON string, preserving exactness.",
        "payload_input": {"amount": "50000.00"}, "exclude": [],
        "canonical_payload_hex": canonical_bytes({"amount": "50000.00"}, exclude=set()).hex(),
    })

    VECTORS.append({
        "id": "K04", "category": "serialization",
        "description": "Keys sort recursively and lexicographically; '@' (U+0040) sorts before all letters.",
        "payload_input": {"zebra": 1, "@context": "x", "alpha": {"z": 1, "a": 2}}, "exclude": [],
        "canonical_payload_hex": canonical_bytes(
            {"zebra": 1, "@context": "x", "alpha": {"z": 1, "a": 2}}, exclude=set(),
        ).hex(),
    })

    VECTORS.append({
        "id": "K05", "category": "serialization",
        "description": "null is emitted for a None field, never omitted.",
        "payload_input": {"optional": None, "present": 1}, "exclude": [],
        "canonical_payload_hex": canonical_bytes({"optional": None, "present": 1}, exclude=set()).hex(),
    })


def main() -> None:
    build_vectors()
    output = {
        "_meta": {
            "spec_version": SPEC_VERSION,
            "generated_at": T_NOW.isoformat(),
            "t_now": T_NOW.isoformat(),
            "t_expired": T_EXPIRED.isoformat(),
            "vector_count": len(VECTORS),
            "keys": {
                "agent_1": {"seed_hex": _SEED_AGENT_1.hex(), "public_key_b64": public_key_to_b64(_KEY_AGENT_1.public_key())},
                "agent_2": {"seed_hex": _SEED_AGENT_2.hex(), "public_key_b64": public_key_to_b64(_KEY_AGENT_2.public_key())},
                "hmac": {"key_hex": _HMAC_KEY.hex()},
            },
            "excluded_codes": {
                "CUSTOS-E304": "gateway/oracle integration concern (tenor-to-observation mapping); "
                               "never emitted by custos_protocol.verify_intent",
                "CUSTOS-E502": "gateway downstream-forwarding concern; never emitted by verify_intent",
            },
        },
        "vectors": VECTORS,
    }
    out_path = Path(__file__).with_name("vectors.json")
    out_path.write_text(json.dumps(output, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"Wrote {len(VECTORS)} vectors to {out_path}")


if __name__ == "__main__":
    main()
