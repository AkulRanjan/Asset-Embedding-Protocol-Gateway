from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from custos_protocol.drift import DriftConfig
from custos_protocol.envelope import create_envelope, sign_envelope
from custos_protocol.errors import CustosErrorCode
from custos_protocol.models import (
    Action,
    CheckOutcome,
    Claim,
    Observation,
    VerificationTier,
)
from custos_protocol.passport import AgentPassport
from custos_protocol.revocation import RevocationStore, SubjectType
from custos_protocol.verification import verify_intent


def now() -> datetime:
    return datetime.now(timezone.utc)


def holder(**kw) -> AgentPassport:
    kw.setdefault("allowed_actions", ["trade", "borrow_against", "read"])
    return AgentPassport.create(domain="acme.com", agent_name="bot", **kw)


def claim(**overrides) -> Claim:
    values = {
        "asset_id": "TKN-UST-3M-001", "issuer": "Meridian", "underlying_tenor": "3M",
        "asset_class": "treasury", "claimed_nav_per_token": Decimal("1"),
        "claimed_backing_usd": Decimal("100"), "tokens_outstanding": Decimal("100"),
        "claimed_yield_bps": 400, "last_attested_at": now() - timedelta(hours=1),
        "chain": "ethereum", "contract_address": "0x1",
    }
    values.update(overrides)
    return Claim(**values)


def observation(**overrides) -> Observation:
    values = {"source": "test", "tenor": "3M", "observed_yield_bps": 400,
              "record_date": now().date(), "fetched_at": now()}
    values.update(overrides)
    return Observation(**values)


def signed(passport=None, action=Action.TRADE, amount=100, **envelope_kw):
    passport = passport or holder()
    envelope = create_envelope(passport, action, "TKN-UST-3M-001", {"amount": amount}, **envelope_kw)
    return sign_envelope(envelope, passport.private_key), passport


def verify(envelope, passport, **kw):
    kw.setdefault("claim", claim())
    kw.setdefault("observation", observation())
    kw.setdefault("drift_config", DriftConfig())
    kw.setdefault("revocation_store", RevocationStore())
    return verify_intent(envelope, passport.public_key, **kw)


def test_healthy_envelope_passes_tier_1():
    envelope, passport = signed()
    result = verify(envelope, passport)
    assert result.passed is True
    assert result.errors == []
    assert result.tier_used is VerificationTier.TIER_1
    assert result.scores is not None


def test_unsupported_version_is_rejected_first():
    envelope, passport = signed()
    result = verify(envelope.model_copy(update={"protocol_version": "9.9.9"}), passport)
    assert result.errors == [CustosErrorCode.VERSION_UNSUPPORTED]


def test_expired_envelope_is_rejected():
    envelope, passport = signed()
    stale = envelope.model_copy(update={"expires_at": now() - timedelta(minutes=1)})
    result = verify(stale, passport)
    assert CustosErrorCode.EXPIRED_ENVELOPE in result.errors


def test_expiry_allows_a_small_clock_skew_grace():
    """Built near-expired and signed after, because mutating a signed envelope
    would break its signature and fail at step 4 instead of reaching step 3."""
    passport = holder()
    envelope = create_envelope(
        passport, Action.TRADE, "TKN-UST-3M-001", {"amount": 100},
        ttl=300, now=now() - timedelta(seconds=302),
    )
    just_expired = sign_envelope(envelope, passport.private_key)
    assert just_expired.expires_at < now()
    assert verify(just_expired, passport, clock_skew_seconds=5).passed is True


def test_future_issued_at_is_clock_skew():
    envelope, passport = signed()
    future = envelope.model_copy(update={
        "issued_at": now() + timedelta(minutes=10),
        "expires_at": now() + timedelta(minutes=20),
    })
    assert CustosErrorCode.CLOCK_SKEW in verify(future, passport).errors


def test_bad_signature_is_rejected():
    envelope, passport = signed()
    tampered = envelope.model_copy(update={
        "intent": envelope.intent.model_copy(update={"parameters": {"amount": 999999}})
    })
    assert verify(tampered, passport).errors == [CustosErrorCode.INVALID_SIGNATURE]


def test_unsigned_envelope_is_rejected():
    envelope, passport = signed()
    assert CustosErrorCode.INVALID_SIGNATURE in verify(
        envelope.model_copy(update={"proof": None}), passport
    ).errors


def test_signature_is_checked_before_replay():
    """A forged envelope carrying a victim nonce must not burn it."""
    envelope, passport = signed()
    store = RevocationStore()
    forged = envelope.model_copy(update={
        "intent": envelope.intent.model_copy(update={"parameters": {"amount": 1}})
    })

    forged_result = verify(forged, passport, revocation_store=store)
    assert forged_result.errors == [CustosErrorCode.INVALID_SIGNATURE]
    assert forged_result.checks["replay"] is CheckOutcome.NOT_RUN

    # The genuine envelope still works — its nonce was never consumed.
    assert verify(envelope, passport, revocation_store=store).passed is True


def test_malformed_nonce_is_rejected():
    envelope, passport = signed()
    bad = envelope.model_copy(update={"entropy": "not-a-nonce"})
    signed_bad = sign_envelope(bad, passport.private_key)
    assert CustosErrorCode.NONCE_INVALID in verify(signed_bad, passport).errors


def test_replayed_envelope_is_rejected():
    envelope, passport = signed()
    store = RevocationStore()
    assert verify(envelope, passport, revocation_store=store).passed is True
    assert verify(envelope, passport, revocation_store=store).errors == [
        CustosErrorCode.REPLAY_DETECTED
    ]


def test_boundary_violations_are_reported_together():
    passport = holder(allowed_actions=["read"], monetary_limit_per_txn=10.0)
    envelope, _ = signed(passport, action=Action.TRADE, amount=5000)
    result = verify(envelope, passport)
    assert CustosErrorCode.ACTION_NOT_ALLOWED in result.errors
    assert CustosErrorCode.MONETARY_LIMIT_PER_TXN in result.errors


def test_revoked_agent_is_blocked_at_every_tier():
    envelope, passport = signed(action=Action.READ)       # Tier 0
    store = RevocationStore()
    store.revoke(passport.agent.id, SubjectType.AGENT, reason="compromised")
    result = verify(envelope, passport, revocation_store=store)
    assert result.tier_used is VerificationTier.TIER_0
    assert CustosErrorCode.AGENT_REVOKED in result.errors


def test_suspended_agent_reports_its_own_code():
    envelope, passport = signed()
    store = RevocationStore()
    store.suspend(passport.agent.id, SubjectType.AGENT, duration_seconds=1800)
    assert CustosErrorCode.AGENT_SUSPENDED in verify(envelope, passport, revocation_store=store).errors


def test_revoked_issuer_blocks_the_transaction():
    envelope, passport = signed()
    store = RevocationStore()
    store.revoke("Meridian", SubjectType.ISSUER, reason="fraud")
    assert CustosErrorCode.ISSUER_REVOKED in verify(envelope, passport, revocation_store=store).errors


def test_stale_revocation_data_fails_closed():
    """The blueprint fails open here; that is its highest-severity finding."""
    import time

    envelope, passport = signed()
    store = RevocationStore(local_only=False)
    store.touch_sync()
    time.sleep(0.02)
    result = verify(envelope, passport, revocation_store=store, max_revocation_staleness_ms=1)
    assert CustosErrorCode.REVOCATION_STALE in result.errors
    assert result.passed is False


def test_tier_0_skips_the_market_check_entirely():
    envelope, passport = signed(action=Action.READ)
    result = verify(envelope, passport, claim=None, observation=None)
    assert result.passed is True
    assert result.tier_used is VerificationTier.TIER_0
    assert result.checks["asset_truth"] is CheckOutcome.NOT_RUN


def test_tier_1_runs_the_market_check_and_can_fail_it():
    envelope, passport = signed()
    result = verify(envelope, passport, claim=claim(claimed_yield_bps=360))
    assert result.passed is False
    assert CustosErrorCode.YIELD_DRIFT_EXCEEDED in result.errors
    assert result.checks["asset_truth"] is CheckOutcome.FAILED


def test_tier_1_fails_closed_without_an_observation():
    envelope, passport = signed()
    result = verify(envelope, passport, observation=None)
    assert CustosErrorCode.ORACLE_UNAVAILABLE in result.errors


def test_tier_2_is_downgraded_honestly_in_phase_1():
    """Reporting TIER_2 while running Tier 1 checks would be a lie."""
    passport = holder(monetary_limit_per_txn=100.0)
    envelope, _ = signed(passport, amount=100, tier=VerificationTier.TIER_2)
    result = verify(envelope, passport)
    assert result.tier_used is VerificationTier.TIER_1
    assert result.checks["delegation"] is CheckOutcome.NOT_RUN
    assert result.checks["trust"] is CheckOutcome.NOT_RUN


def test_failure_is_fail_fast_and_later_checks_do_not_run():
    envelope, passport = signed()
    result = verify(envelope.model_copy(update={"protocol_version": "9.9.9"}), passport)
    assert result.checks["signature"] is CheckOutcome.NOT_RUN
    assert result.checks["boundaries"] is CheckOutcome.NOT_RUN
