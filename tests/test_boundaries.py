from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal

from custos_protocol.boundaries import check_boundaries
from custos_protocol.envelope import create_envelope
from custos_protocol.errors import CustosErrorCode
from custos_protocol.models import Action, Claim, TimeWindow
from custos_protocol.passport import AgentPassport


def now() -> datetime:
    return datetime.now(timezone.utc)


def claim(asset_class: str = "treasury") -> Claim:
    return Claim(
        asset_id="TKN-UST-3M-001", issuer="Meridian", underlying_tenor="3M",
        asset_class=asset_class, claimed_nav_per_token=Decimal("1"),
        claimed_backing_usd=Decimal("100"), tokens_outstanding=Decimal("100"),
        claimed_yield_bps=400, last_attested_at=now(), chain="ethereum",
        contract_address="0x1",
    )


def envelope(action=Action.TRADE, amount=100, **passport_kw):
    holder = AgentPassport.create(domain="acme.com", agent_name="bot", **passport_kw)
    return create_envelope(holder, action, "TKN-UST-3M-001", {"amount": amount})


def test_clean_envelope_has_no_violations():
    assert check_boundaries(envelope(allowed_actions=["trade"]), claim()) == []


def test_denied_action_is_rejected():
    result = check_boundaries(envelope(denied_actions=["trade"]), claim())
    assert CustosErrorCode.ACTION_DENIED in result


def test_deny_wins_over_allow():
    """Both lists contain the action; deny must take precedence."""
    result = check_boundaries(
        envelope(allowed_actions=["trade"], denied_actions=["trade"]), claim()
    )
    assert CustosErrorCode.ACTION_DENIED in result
    assert CustosErrorCode.ACTION_NOT_ALLOWED not in result


def test_action_outside_a_non_empty_allowlist_is_rejected():
    result = check_boundaries(envelope(allowed_actions=["redeem"]), claim())
    assert CustosErrorCode.ACTION_NOT_ALLOWED in result


def test_empty_allowlist_permits_everything():
    """Preserved from the blueprint and documented as a footgun, not changed."""
    assert check_boundaries(envelope(), claim()) == []


def test_amount_over_per_transaction_limit_is_rejected():
    result = check_boundaries(envelope(amount=1001, monetary_limit_per_txn=1000.0), claim())
    assert CustosErrorCode.MONETARY_LIMIT_PER_TXN in result


def test_amount_exactly_at_the_limit_passes():
    assert check_boundaries(envelope(amount=1000, monetary_limit_per_txn=1000.0), claim()) == []


def test_zero_per_transaction_limit_means_no_limit():
    """Matches the blueprint's semantics; the passport constructor warns about it."""
    assert check_boundaries(envelope(amount=10**9, monetary_limit_per_txn=0.0), claim()) == []


def test_time_window_violation():
    holder = AgentPassport.create(domain="acme.com", agent_name="bot")
    holder.boundaries.time_window = TimeWindow(
        start=now() - timedelta(hours=2), end=now() - timedelta(hours=1)
    )
    result = check_boundaries(create_envelope(holder, Action.TRADE, "a", {"amount": 1}), claim())
    assert CustosErrorCode.TIME_WINDOW_VIOLATION in result


def test_geo_restriction_is_inert_without_a_request_geo():
    """Custos cannot determine geography; the caller supplies it or the boundary sleeps."""
    env = envelope(geo_restriction="US,CA")
    assert check_boundaries(env, claim()) == []
    assert check_boundaries(env, claim(), request_geo="US") == []
    assert CustosErrorCode.GEO_RESTRICTION in check_boundaries(env, claim(), request_geo="RU")


def test_geo_restriction_accepts_a_comma_separated_list_case_insensitively():
    env = envelope(geo_restriction="us, ca , gb")
    assert check_boundaries(env, claim(), request_geo="GB") == []


def test_asset_class_outside_the_permitted_set_is_rejected():
    env = envelope(asset_classes=["treasury"])
    assert check_boundaries(env, claim(asset_class="corporate_credit")) != []
    assert CustosErrorCode.ASSET_CLASS_NOT_ALLOWED in check_boundaries(
        env, claim(asset_class="corporate_credit")
    )


def test_asset_class_check_is_skipped_without_a_claim():
    assert check_boundaries(envelope(asset_classes=["treasury"]), None) == []


def test_violations_accumulate_rather_than_short_circuit():
    """One envelope can legitimately fail several boundaries at once."""
    env = envelope(amount=5000, denied_actions=["trade"],
                   monetary_limit_per_txn=1000.0, geo_restriction="US")
    result = check_boundaries(env, claim(asset_class="corporate_credit"), request_geo="RU")
    assert CustosErrorCode.ACTION_DENIED in result
    assert CustosErrorCode.MONETARY_LIMIT_PER_TXN in result
    assert CustosErrorCode.GEO_RESTRICTION in result
    assert len(result) >= 3
