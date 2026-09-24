from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from pydantic import ValidationError

from custos_protocol.models import (
    Action,
    AgentIdentity,
    Boundaries,
    CheckOutcome,
    Claim,
    CustosEnvelope,
    DelegationLink,
    Intent,
    MonetaryLimit,
    Principal,
    VerificationResult,
    VerificationTier,
)


def now() -> datetime:
    return datetime.now(timezone.utc)


def envelope_kwargs(**overrides) -> dict:
    issued = now()
    base = {
        "agent": AgentIdentity(id="did:web:acme.com:agents:bot"),
        "principal": Principal(id="did:web:acme.com"),
        "intent": Intent(action=Action.TRADE, target="TKN-UST-3M-001",
                         parameters={"amount": 50000, "currency": "USD"}),
        "boundaries": Boundaries(),
        "entropy": "nonce:" + "a" * 32,
        "issued_at": issued,
        "expires_at": issued + timedelta(minutes=5),
    }
    base.update(overrides)
    return base


def test_envelope_defaults_match_the_protocol():
    envelope = CustosEnvelope(**envelope_kwargs())
    assert envelope.context == "https://custos.protocol/v1"
    assert envelope.type == "CustosEnvelope"
    assert envelope.protocol_version == "1.0.0"
    assert envelope.verification_tier is VerificationTier.TIER_1
    assert envelope.ttl == 300
    assert envelope.proof is None


def test_envelope_serializes_jsonld_aliases():
    dumped = CustosEnvelope(**envelope_kwargs()).model_dump(mode="json", by_alias=True)
    assert dumped["@context"] == "https://custos.protocol/v1"
    assert dumped["@type"] == "CustosEnvelope"


def test_envelope_accepts_alias_or_field_name_on_input():
    """populate_by_name lets callers use either form."""
    assert CustosEnvelope(**envelope_kwargs(), **{}).context == "https://custos.protocol/v1"
    payload = CustosEnvelope(**envelope_kwargs()).model_dump(mode="json", by_alias=True)
    assert CustosEnvelope.model_validate(payload).type == "CustosEnvelope"


def test_expires_at_is_required():
    """Divergence from the blueprint, which permits a never-expiring envelope."""
    kwargs = envelope_kwargs()
    del kwargs["expires_at"]
    with pytest.raises(ValidationError):
        CustosEnvelope(**kwargs)


def test_envelope_rejects_a_span_longer_than_the_ttl_ceiling():
    """`ttl` is bounded 1..86400s, but a hand-built envelope sets `expires_at`
    directly and bypasses that field entirely — the span itself must still be capped."""
    issued = now()
    kwargs = envelope_kwargs(issued_at=issued, expires_at=issued + timedelta(days=3650))
    with pytest.raises(ValidationError):
        CustosEnvelope(**kwargs)


def test_envelope_rejects_expires_at_before_issued_at():
    issued = now()
    kwargs = envelope_kwargs(issued_at=issued, expires_at=issued - timedelta(seconds=1))
    with pytest.raises(ValidationError):
        CustosEnvelope(**kwargs)


def test_envelope_accepts_a_span_at_exactly_the_ttl_ceiling():
    issued = now()
    kwargs = envelope_kwargs(issued_at=issued, expires_at=issued + timedelta(seconds=86400))
    assert CustosEnvelope(**kwargs).expires_at == issued + timedelta(seconds=86400)


def test_envelope_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        CustosEnvelope(**envelope_kwargs(), surprise="x")


def test_envelope_rejects_naive_datetimes():
    with pytest.raises(ValidationError):
        CustosEnvelope(**envelope_kwargs(issued_at=datetime.now()))


def test_ttl_is_bounded():
    with pytest.raises(ValidationError):
        CustosEnvelope(**envelope_kwargs(ttl=0))
    with pytest.raises(ValidationError):
        CustosEnvelope(**envelope_kwargs(ttl=86401))


def test_delegation_link_accepts_from_and_to_aliases():
    """`from` is a Python keyword, so the field is from_id with an alias."""
    link = DelegationLink.model_validate(
        {"from": "did:web:acme.com", "to": "did:web:acme.com:agents:bot",
         "scope": "default", "granted_at": now().isoformat()}
    )
    assert link.from_id == "did:web:acme.com"
    assert link.to_id == "did:web:acme.com:agents:bot"
    assert link.boundary_monotonicity is True
    assert link.model_dump(by_alias=True)["from"] == "did:web:acme.com"


def test_monetary_limit_rejects_negatives():
    with pytest.raises(ValidationError):
        MonetaryLimit(per_transaction=-1)


def test_claim_requires_positive_tokens_outstanding():
    """Schema-level guarantee that the backing-ratio denominator is never zero."""
    with pytest.raises(ValidationError):
        Claim(asset_id="a", issuer="i", underlying_tenor="3M", asset_class="treasury",
              claimed_nav_per_token=Decimal("1"), claimed_backing_usd=Decimal("100"),
              tokens_outstanding=Decimal("0"), claimed_yield_bps=400,
              last_attested_at=now(), chain="ethereum", contract_address="0x1")


def test_claim_coerces_naive_last_attested_at_to_utc():
    claim = Claim(asset_id="a", issuer="i", underlying_tenor="3M", asset_class="treasury",
                  claimed_nav_per_token=Decimal("1"), claimed_backing_usd=Decimal("100"),
                  tokens_outstanding=Decimal("100"), claimed_yield_bps=400,
                  last_attested_at=datetime(2026, 8, 21, 12, 0, 0),
                  chain="ethereum", contract_address="0x1")
    assert claim.last_attested_at.tzinfo is timezone.utc


def test_verification_result_passed_is_the_single_authority():
    """There is no `valid` field; NOT_RUN checks never contribute to `passed`."""
    assert not hasattr(VerificationResult, "valid")
    result = VerificationResult(
        passed=True,
        checks={"signature": CheckOutcome.PASSED, "asset_truth": CheckOutcome.NOT_RUN},
        tier_used=VerificationTier.TIER_0,
    )
    assert result.passed is True
    assert result.checks["asset_truth"] is CheckOutcome.NOT_RUN


def test_intent_rejects_negative_and_non_numeric_amounts():
    """A negative amount would silently pass every monetary boundary comparison."""
    for bad in (-1, -0.01, "500", True, None if False else object()):
        with pytest.raises(ValidationError):
            Intent(action=Action.TRADE, target="a", parameters={"amount": bad})
    assert Intent(action=Action.TRADE, target="a", parameters={"amount": 0}).parameters["amount"] == 0
