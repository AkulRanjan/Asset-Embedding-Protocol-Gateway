from __future__ import annotations

import re
from datetime import datetime, timezone

import pytest

from custos_protocol.crypto import verify_signature
from custos_protocol.envelope import (
    create_envelope,
    envelope_hash,
    select_tier,
    sign_envelope,
)
from custos_protocol.canonical import get_signable_payload
from custos_protocol.models import Action, Boundaries, MonetaryLimit, VerificationTier
from custos_protocol.passport import AgentPassport


def passport(**kw) -> AgentPassport:
    return AgentPassport.create(domain="acme.com", agent_name="bot", **kw)


def limits(per_txn: float) -> Boundaries:
    return Boundaries(monetary_limit=MonetaryLimit(per_transaction=per_txn))


def test_read_action_selects_tier_0():
    assert select_tier(Action.READ, {}, limits(0)) is VerificationTier.TIER_0


@pytest.mark.parametrize("action", [Action.BORROW_AGAINST, Action.TRADE, Action.REDEEM])
def test_value_moving_actions_never_select_tier_0(action):
    """Asset truth runs at Tier 1+, so a value-moving action must never skip it."""
    assert select_tier(action, {"amount": 1}, limits(1_000_000)) is VerificationTier.TIER_1


def test_amount_over_half_the_limit_escalates_to_tier_2():
    assert select_tier(Action.TRADE, {"amount": 501}, limits(1000)) is VerificationTier.TIER_2
    assert select_tier(Action.TRADE, {"amount": 500}, limits(1000)) is VerificationTier.TIER_1


def test_tier_selection_is_relative_not_absolute():
    """The blueprint's flat `amount > 100` inverts risk ordering; this rule does not."""
    rich = select_tier(Action.TRADE, {"amount": 101}, limits(1_000_000))
    poor = select_tier(Action.TRADE, {"amount": 99}, limits(50))
    assert rich is VerificationTier.TIER_1
    assert poor is VerificationTier.TIER_2


def test_cross_org_and_first_contact_force_tier_2():
    assert select_tier(Action.TRADE, {"amount": 1}, limits(10**9), cross_org=True) is VerificationTier.TIER_2
    assert select_tier(Action.TRADE, {"amount": 1}, limits(10**9), first_contact=True) is VerificationTier.TIER_2


def test_create_envelope_populates_identity_and_cage_from_the_passport():
    holder = passport(allowed_actions=["trade"], monetary_limit_per_txn=1000.0)
    envelope = create_envelope(holder, Action.TRADE, "TKN-UST-3M-001", {"amount": 100})
    assert envelope.agent.id == holder.agent.id
    assert envelope.principal.id == holder.principal.id
    assert envelope.boundaries.allowed_actions == ["trade"]
    assert envelope.intent.target == "TKN-UST-3M-001"
    assert envelope.intent.parameters == {"amount": 100}


def test_create_envelope_generates_a_well_formed_nonce():
    envelope = create_envelope(passport(), Action.TRADE, "asset", {"amount": 1})
    assert re.fullmatch(r"nonce:[0-9a-f]{32}", envelope.entropy)


def test_nonces_are_unique_per_envelope():
    holder = passport()
    first = create_envelope(holder, Action.TRADE, "asset", {"amount": 1})
    second = create_envelope(holder, Action.TRADE, "asset", {"amount": 1})
    assert first.entropy != second.entropy


def test_expires_at_is_issued_at_plus_ttl_truncated_to_whole_seconds():
    envelope = create_envelope(passport(), Action.TRADE, "asset", {"amount": 1}, ttl=120)
    assert (envelope.expires_at - envelope.issued_at).total_seconds() == 120
    assert envelope.issued_at.microsecond == 0


def test_sign_envelope_does_not_mutate_its_input():
    holder = passport()
    envelope = create_envelope(holder, Action.TRADE, "asset", {"amount": 1})
    signed = sign_envelope(envelope, holder.private_key)
    assert envelope.proof is None
    assert signed.proof is not None


def test_signature_verifies_against_the_canonical_payload():
    holder = passport()
    signed = sign_envelope(create_envelope(holder, Action.TRADE, "asset", {"amount": 1}),
                           holder.private_key)
    payload = get_signable_payload(signed, exclude={"proof"})
    assert verify_signature(holder.public_key, payload, signed.proof.proof_value) is True


def test_tampering_after_signing_breaks_verification():
    holder = passport()
    signed = sign_envelope(create_envelope(holder, Action.TRADE, "asset", {"amount": 1}),
                           holder.private_key)
    tampered = signed.model_copy(update={"intent": signed.intent.model_copy(
        update={"parameters": {"amount": 999999}})})
    payload = get_signable_payload(tampered, exclude={"proof"})
    assert verify_signature(holder.public_key, payload, signed.proof.proof_value) is False


def test_sign_envelope_accepts_a_deterministic_now():
    """proof.created is excluded from the signed payload, so this can't affect
    signature validity — it exists so deterministic fixtures (tests,
    conformance vectors) don't pick up the real wall clock."""
    holder = passport()
    fixed = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    signed = sign_envelope(create_envelope(holder, Action.TRADE, "asset", {"amount": 1}),
                           holder.private_key, now=fixed)
    assert signed.proof.created == fixed


def test_verification_method_defaults_to_principal_keys_1():
    holder = passport()
    signed = sign_envelope(create_envelope(holder, Action.TRADE, "asset", {"amount": 1}),
                           holder.private_key)
    assert signed.proof.verification_method == f"{holder.principal.id}#keys-1"


def test_envelope_hash_is_deterministic_and_ignores_the_proof():
    holder = passport()
    envelope = create_envelope(holder, Action.TRADE, "asset", {"amount": 1})
    signed = sign_envelope(envelope, holder.private_key)
    assert envelope_hash(envelope) == envelope_hash(signed)
    assert len(envelope_hash(envelope)) == 64
