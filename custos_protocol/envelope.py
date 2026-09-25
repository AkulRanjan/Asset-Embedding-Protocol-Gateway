"""Envelope construction, signing, hashing, and risk-relative tier selection."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from custos_protocol.canonical import get_signable_payload, payload_hash
from custos_protocol.crypto import sign_data
from custos_protocol.models import (
    Action,
    Boundaries,
    CustosEnvelope,
    Intent,
    Proof,
    VerificationTier,
)
from custos_protocol.passport import AgentPassport

VALUE_MOVING_ACTIONS = frozenset({Action.BORROW_AGAINST, Action.TRADE, Action.REDEEM})

_ESCALATION_RATIO = 0.50


def _numeric(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def select_tier(
    action: Action,
    parameters: dict[str, Any],
    boundaries: Boundaries,
    *,
    cross_org: bool = False,
    first_contact: bool = False,
) -> VerificationTier:
    """Risk-relative escalation.

    The blueprint uses a flat, currency-blind ``amount > 100``, which gives an agent
    with a $1,000,000 limit moving $101 full Tier 2 treatment while an agent with a
    $50 limit moving $99 gets the fast path — the opposite of the intended ordering.
    Custos escalates on the amount as a fraction of the agent's own limit.
    """
    if action not in VALUE_MOVING_ACTIONS:
        return VerificationTier.TIER_0
    if cross_org or first_contact:
        return VerificationTier.TIER_2

    per_transaction = boundaries.monetary_limit.per_transaction
    amount = _numeric(parameters.get("amount"))
    if per_transaction > 0 and amount is not None and amount / per_transaction > _ESCALATION_RATIO:
        return VerificationTier.TIER_2
    return VerificationTier.TIER_1


def create_envelope(
    passport: AgentPassport,
    action: Action,
    target: str,
    parameters: dict[str, Any] | None = None,
    *,
    tier: VerificationTier | None = None,
    ttl: int = 300,
    now: datetime | None = None,
) -> CustosEnvelope:
    parameters = dict(parameters or {})
    # Whole seconds keep the canonical payload free of fractional-second divergence.
    issued_at = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    selected = tier or select_tier(action, parameters, passport.boundaries)

    return CustosEnvelope(
        agent=passport.agent,
        principal=passport.principal,
        intent=Intent(action=action, target=target, parameters=parameters),
        boundaries=passport.boundaries,
        verification_tier=selected,
        entropy=f"nonce:{secrets.token_hex(16)}",
        ttl=ttl,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=ttl),
    )


def sign_envelope(
    envelope: CustosEnvelope,
    private_key: Ed25519PrivateKey,
    verification_method: str = "",
    *,
    now: datetime | None = None,
) -> CustosEnvelope:
    """Returns a signed copy. The input envelope is never mutated.

    `proof.created` is excluded from the signed payload (you cannot sign your
    own signature), so `now=` has no effect on the signature itself — it exists
    so a caller building deterministic fixtures (tests, conformance vectors)
    doesn't have the real wall clock leak into an otherwise-reproducible
    envelope dump, matching `create_envelope`'s own `now=` parameter.
    """
    payload = get_signable_payload(envelope, exclude={"proof"})
    proof = Proof(
        created=(now or datetime.now(timezone.utc)).replace(microsecond=0),
        verification_method=verification_method or f"{envelope.principal.id}#keys-1",
        proof_value=sign_data(private_key, payload),
    )
    return envelope.model_copy(update={"proof": proof})


def envelope_hash(envelope: CustosEnvelope) -> str:
    """SHA-256 of the canonical payload. Stable before and after signing."""
    return payload_hash(get_signable_payload(envelope, exclude={"proof"}))
