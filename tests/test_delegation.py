from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from custos_protocol.delegation import DelegationConfig, check_delegation
from custos_protocol.errors import CustosErrorCode
from custos_protocol.models import (
    Action,
    AgentIdentity,
    Boundaries,
    CustosEnvelope,
    DelegationLink,
    Intent,
    MonetaryLimit,
    Principal,
    TimeWindow,
)


def now() -> datetime:
    return datetime.now(timezone.utc)


def cage(**overrides) -> Boundaries:
    base = {
        "allowed_actions": [],
        "denied_actions": [],
        "monetary_limit": MonetaryLimit(),
        "asset_classes": [],
        "geo_restriction": None,
        "time_window": None,
    }
    base.update(overrides)
    return Boundaries(**base)


def link(from_id: str, to_id: str, boundaries: Boundaries, **overrides) -> DelegationLink:
    base = {"from_id": from_id, "to_id": to_id, "boundaries": boundaries, "granted_at": now()}
    base.update(overrides)
    return DelegationLink(**base)


def envelope(*, principal_id: str, agent_id: str, chain: list[DelegationLink],
             boundaries: Boundaries) -> CustosEnvelope:
    issued = now()
    return CustosEnvelope(
        agent=AgentIdentity(id=agent_id),
        principal=Principal(id=principal_id, delegation_chain=chain),
        intent=Intent(action=Action.TRADE, target="TKN-UST-3M-001", parameters={"amount": 100}),
        boundaries=boundaries,
        entropy="nonce:" + "a" * 32,
        issued_at=issued,
        expires_at=issued + timedelta(minutes=5),
    )


# ---- continuity, endpoints, expiry, depth --------------------------------


def test_self_sovereign_agent_with_empty_chain_passes():
    env = envelope(principal_id="did:web:acme.com", agent_id="did:web:acme.com",
                    chain=[], boundaries=cage())
    assert check_delegation(env) is None


def test_empty_chain_with_distinct_principal_and_agent_fails():
    env = envelope(principal_id="did:web:acme.com", agent_id="did:web:acme.com:agents:bot",
                    chain=[], boundaries=cage())
    failure = check_delegation(env)
    assert failure is not None
    assert failure.code is CustosErrorCode.DELEGATION_INVALID


def test_a_well_formed_single_hop_chain_passes():
    grant = cage(allowed_actions=["trade"])
    chain = [link("did:web:acme.com", "did:web:acme.com:agents:bot", grant)]
    env = envelope(principal_id="did:web:acme.com", agent_id="did:web:acme.com:agents:bot",
                    chain=chain, boundaries=grant)
    assert check_delegation(env) is None


def test_a_well_formed_two_hop_chain_passes():
    outer = cage(allowed_actions=["trade", "redeem"], monetary_limit=MonetaryLimit(per_transaction=100000))
    inner = cage(allowed_actions=["trade"], monetary_limit=MonetaryLimit(per_transaction=50000))
    chain = [
        link("did:web:acme.com", "did:web:acme.com:agents:mid", outer),
        link("did:web:acme.com:agents:mid", "did:web:acme.com:agents:leaf", inner),
    ]
    env = envelope(principal_id="did:web:acme.com", agent_id="did:web:acme.com:agents:leaf",
                    chain=chain, boundaries=inner)
    assert check_delegation(env) is None


def test_chain_not_starting_at_the_principal_fails():
    grant = cage()
    chain = [link("did:web:someone-else.com", "did:web:acme.com:agents:bot", grant)]
    env = envelope(principal_id="did:web:acme.com", agent_id="did:web:acme.com:agents:bot",
                    chain=chain, boundaries=grant)
    assert check_delegation(env).code is CustosErrorCode.DELEGATION_INVALID


def test_chain_not_ending_at_the_agent_fails():
    grant = cage()
    chain = [link("did:web:acme.com", "did:web:acme.com:agents:someone-else", grant)]
    env = envelope(principal_id="did:web:acme.com", agent_id="did:web:acme.com:agents:bot",
                    chain=chain, boundaries=grant)
    assert check_delegation(env).code is CustosErrorCode.DELEGATION_INVALID


def test_discontinuous_chain_fails():
    grant = cage()
    chain = [
        link("did:web:acme.com", "did:web:acme.com:agents:mid", grant),
        link("did:web:acme.com:agents:someone-else", "did:web:acme.com:agents:leaf", grant),
    ]
    env = envelope(principal_id="did:web:acme.com", agent_id="did:web:acme.com:agents:leaf",
                    chain=chain, boundaries=grant)
    failure = check_delegation(env)
    assert failure.code is CustosErrorCode.DELEGATION_INVALID
    assert "discontinuous" in failure.detail


def test_an_expired_hop_fails():
    grant = cage()
    chain = [link("did:web:acme.com", "did:web:acme.com:agents:bot", grant,
                  expires_at=now() - timedelta(seconds=1))]
    env = envelope(principal_id="did:web:acme.com", agent_id="did:web:acme.com:agents:bot",
                    chain=chain, boundaries=grant)
    assert check_delegation(env).code is CustosErrorCode.DELEGATION_INVALID


def test_a_hop_granted_in_the_future_fails():
    """The AIP blueprint never validates granted_at; Custos closes that gap."""
    grant = cage()
    chain = [link("did:web:acme.com", "did:web:acme.com:agents:bot", grant,
                  granted_at=now() + timedelta(hours=1))]
    env = envelope(principal_id="did:web:acme.com", agent_id="did:web:acme.com:agents:bot",
                    chain=chain, boundaries=grant)
    assert check_delegation(env).code is CustosErrorCode.DELEGATION_INVALID


def test_a_hop_granted_within_clock_skew_grace_passes():
    grant = cage()
    chain = [link("did:web:acme.com", "did:web:acme.com:agents:bot", grant,
                  granted_at=now() + timedelta(seconds=2))]
    env = envelope(principal_id="did:web:acme.com", agent_id="did:web:acme.com:agents:bot",
                    chain=chain, boundaries=grant)
    assert check_delegation(env, config=DelegationConfig(clock_skew_seconds=5)) is None


def test_a_chain_longer_than_the_configured_max_depth_fails():
    grant = cage()
    ids = ["did:web:acme.com"] + [f"did:web:acme.com:agents:hop{i}" for i in range(4)]
    chain = [link(ids[i], ids[i + 1], grant) for i in range(len(ids) - 1)]
    env = envelope(principal_id=ids[0], agent_id=ids[-1], chain=chain, boundaries=grant)
    failure = check_delegation(env, config=DelegationConfig(max_delegation_depth=2))
    assert failure.code is CustosErrorCode.DELEGATION_INVALID
    assert "exceeds the maximum" in failure.detail


# ---- boundary monotonicity ------------------------------------------------


def test_a_hop_widening_allowed_actions_fails():
    outer = cage(allowed_actions=["trade"])
    inner = cage(allowed_actions=["trade", "redeem"])  # wider than outer
    chain = [link("did:web:acme.com", "did:web:acme.com:agents:bot", outer)]
    env = envelope(principal_id="did:web:acme.com", agent_id="did:web:acme.com:agents:bot",
                    chain=chain, boundaries=inner)
    failure = check_delegation(env)
    assert failure.code is CustosErrorCode.DELEGATION_INVALID
    assert "allowed_actions" in failure.detail


def test_an_unrestricted_parent_allowed_actions_permits_any_child():
    outer = cage(allowed_actions=[])  # unrestricted
    inner = cage(allowed_actions=["trade"])
    chain = [link("did:web:acme.com", "did:web:acme.com:agents:bot", outer)]
    env = envelope(principal_id="did:web:acme.com", agent_id="did:web:acme.com:agents:bot",
                    chain=chain, boundaries=inner)
    assert check_delegation(env) is None


def test_a_hop_dropping_an_inherited_deny_fails():
    outer = cage(denied_actions=["redeem"])
    inner = cage(denied_actions=[])  # narrower deny list than outer — a widening of authority
    chain = [link("did:web:acme.com", "did:web:acme.com:agents:bot", outer)]
    env = envelope(principal_id="did:web:acme.com", agent_id="did:web:acme.com:agents:bot",
                    chain=chain, boundaries=inner)
    failure = check_delegation(env)
    assert failure.code is CustosErrorCode.DELEGATION_INVALID
    assert "denied_actions" in failure.detail


def test_a_hop_raising_the_per_transaction_limit_fails():
    outer = cage(monetary_limit=MonetaryLimit(per_transaction=1000))
    inner = cage(monetary_limit=MonetaryLimit(per_transaction=5000))
    chain = [link("did:web:acme.com", "did:web:acme.com:agents:bot", outer)]
    env = envelope(principal_id="did:web:acme.com", agent_id="did:web:acme.com:agents:bot",
                    chain=chain, boundaries=inner)
    failure = check_delegation(env)
    assert failure.code is CustosErrorCode.DELEGATION_INVALID
    assert "per_transaction" in failure.detail


def test_a_hop_lowering_to_no_limit_when_the_parent_capped_fails():
    """0 means "no limit" — a child dropping to 0 under a capped parent is a widening."""
    outer = cage(monetary_limit=MonetaryLimit(per_transaction=1000))
    inner = cage(monetary_limit=MonetaryLimit(per_transaction=0))
    chain = [link("did:web:acme.com", "did:web:acme.com:agents:bot", outer)]
    env = envelope(principal_id="did:web:acme.com", agent_id="did:web:acme.com:agents:bot",
                    chain=chain, boundaries=inner)
    assert check_delegation(env).code is CustosErrorCode.DELEGATION_INVALID


def test_an_unlimited_parent_permits_any_child_limit():
    outer = cage(monetary_limit=MonetaryLimit(per_transaction=0))
    inner = cage(monetary_limit=MonetaryLimit(per_transaction=999999))
    chain = [link("did:web:acme.com", "did:web:acme.com:agents:bot", outer)]
    env = envelope(principal_id="did:web:acme.com", agent_id="did:web:acme.com:agents:bot",
                    chain=chain, boundaries=inner)
    assert check_delegation(env) is None


def test_a_hop_widening_geo_restriction_fails():
    outer = cage(geo_restriction="US")
    inner = cage(geo_restriction="US,CA")
    chain = [link("did:web:acme.com", "did:web:acme.com:agents:bot", outer)]
    env = envelope(principal_id="did:web:acme.com", agent_id="did:web:acme.com:agents:bot",
                    chain=chain, boundaries=inner)
    failure = check_delegation(env)
    assert failure.code is CustosErrorCode.DELEGATION_INVALID
    assert "geo_restriction" in failure.detail


def test_a_hop_dropping_geo_restriction_entirely_fails():
    """No restriction is broader than any restriction, even a generous one."""
    outer = cage(geo_restriction="US,CA,GB")
    inner = cage(geo_restriction=None)
    chain = [link("did:web:acme.com", "did:web:acme.com:agents:bot", outer)]
    env = envelope(principal_id="did:web:acme.com", agent_id="did:web:acme.com:agents:bot",
                    chain=chain, boundaries=inner)
    assert check_delegation(env).code is CustosErrorCode.DELEGATION_INVALID


def test_an_empty_string_geo_restriction_is_treated_as_unrestricted():
    """Matches boundaries.py's truthiness check: "" and None both mean unrestricted."""
    outer = cage(geo_restriction="")
    inner = cage(geo_restriction="US")
    chain = [link("did:web:acme.com", "did:web:acme.com:agents:bot", outer)]
    env = envelope(principal_id="did:web:acme.com", agent_id="did:web:acme.com:agents:bot",
                    chain=chain, boundaries=inner)
    assert check_delegation(env) is None


def test_an_unrestricted_parent_geo_permits_any_child_geo():
    outer = cage(geo_restriction=None)
    inner = cage(geo_restriction="US")
    chain = [link("did:web:acme.com", "did:web:acme.com:agents:bot", outer)]
    env = envelope(principal_id="did:web:acme.com", agent_id="did:web:acme.com:agents:bot",
                    chain=chain, boundaries=inner)
    assert check_delegation(env) is None


def test_a_hop_widening_asset_classes_fails():
    outer = cage(asset_classes=["treasury"])
    inner = cage(asset_classes=["treasury", "corporate"])
    chain = [link("did:web:acme.com", "did:web:acme.com:agents:bot", outer)]
    env = envelope(principal_id="did:web:acme.com", agent_id="did:web:acme.com:agents:bot",
                    chain=chain, boundaries=inner)
    assert check_delegation(env).code is CustosErrorCode.DELEGATION_INVALID


def test_a_hop_widening_the_time_window_fails():
    start, end = now(), now() + timedelta(hours=1)
    outer = cage(time_window=TimeWindow(start=start, end=end))
    inner = cage(time_window=TimeWindow(start=start - timedelta(minutes=1), end=end))
    chain = [link("did:web:acme.com", "did:web:acme.com:agents:bot", outer)]
    env = envelope(principal_id="did:web:acme.com", agent_id="did:web:acme.com:agents:bot",
                    chain=chain, boundaries=inner)
    assert check_delegation(env).code is CustosErrorCode.DELEGATION_INVALID


def test_a_nested_time_window_passes():
    start, end = now(), now() + timedelta(hours=1)
    outer = cage(time_window=TimeWindow(start=start, end=end))
    inner = cage(time_window=TimeWindow(start=start + timedelta(minutes=5), end=end - timedelta(minutes=5)))
    chain = [link("did:web:acme.com", "did:web:acme.com:agents:bot", outer)]
    env = envelope(principal_id="did:web:acme.com", agent_id="did:web:acme.com:agents:bot",
                    chain=chain, boundaries=inner)
    assert check_delegation(env) is None


def test_an_unrestricted_parent_time_window_permits_any_child_window():
    outer = cage(time_window=None)
    inner = cage(time_window=TimeWindow(start=now(), end=now() + timedelta(hours=1)))
    chain = [link("did:web:acme.com", "did:web:acme.com:agents:bot", outer)]
    env = envelope(principal_id="did:web:acme.com", agent_id="did:web:acme.com:agents:bot",
                    chain=chain, boundaries=inner)
    assert check_delegation(env) is None


def test_the_envelopes_own_boundaries_exceeding_the_final_hop_fails():
    """The agent's actual operating cage, not just the chain, must stay contained."""
    grant = cage(allowed_actions=["trade"])
    wider_operating_cage = cage(allowed_actions=["trade", "redeem"])
    chain = [link("did:web:acme.com", "did:web:acme.com:agents:bot", grant)]
    env = envelope(principal_id="did:web:acme.com", agent_id="did:web:acme.com:agents:bot",
                    chain=chain, boundaries=wider_operating_cage)
    failure = check_delegation(env)
    assert failure.code is CustosErrorCode.DELEGATION_INVALID
    assert "final delegation hop" in failure.detail
