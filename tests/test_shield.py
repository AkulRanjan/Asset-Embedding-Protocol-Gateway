from __future__ import annotations

import asyncio

import pytest

from custos_protocol.errors import CustosErrorCode
from custos_protocol.models import Action
from custos_protocol.passport import AgentPassport
from custos_protocol.revocation import RevocationStore, SubjectType
from custos_protocol.shield import (
    CustosViolation,
    protect,
    protect_agent,
    shield,
    shield_class,
    shield_object,
)
from custos_protocol.trust import TrustEngine


def passport(**kw) -> AgentPassport:
    kw.setdefault("allowed_actions", ["trade", "read"])
    return AgentPassport.create(domain="acme.com", agent_name="bot", **kw)


def test_protect_requires_an_action():
    with pytest.raises(TypeError, match="action"):
        protect(lambda: None, passport=passport())


def test_protect_requires_a_passport():
    with pytest.raises(TypeError, match="passport"):
        protect(lambda: None, action=Action.READ)


def test_a_permitted_call_passes_through_and_returns_the_result():
    holder = passport()

    def read_position(target: str) -> str:
        return f"read {target}"

    protected = protect(read_position, action=Action.READ, passport=holder)
    assert protected(target="TKN-UST-3M-001") == "read TKN-UST-3M-001"


def test_a_denied_action_raises_custos_violation_by_default():
    holder = passport(allowed_actions=["read"])  # trade not allowed

    def trade(**kw) -> str:
        return "traded"

    protected = protect(trade, action=Action.TRADE, passport=holder)
    with pytest.raises(CustosViolation) as caught:
        protected(amount=100)
    assert CustosErrorCode.ACTION_NOT_ALLOWED in caught.value.result.errors


def test_on_violation_log_returns_none_instead_of_raising(caplog):
    holder = passport(allowed_actions=["read"])

    def trade(**kw) -> str:
        return "traded"

    protected = protect(trade, action=Action.TRADE, passport=holder, on_violation="log")
    with caplog.at_level("WARNING"):
        assert protected(amount=100) is None
    assert "Custos blocked" in caplog.text


def test_on_violation_silent_returns_none_with_no_log(caplog):
    holder = passport(allowed_actions=["read"])

    def trade(**kw) -> str:
        return "traded"

    protected = protect(trade, action=Action.TRADE, passport=holder, on_violation="silent")
    with caplog.at_level("WARNING"):
        assert protected(amount=100) is None
    assert "Custos blocked" not in caplog.text


def test_an_invalid_on_violation_value_raises():
    holder = passport()

    def read_position(**kw) -> str:
        return "ok"

    protected = protect(read_position, action=Action.READ, passport=holder, on_violation="explode")
    with pytest.raises(ValueError, match="on_violation"):
        protected()


def test_protect_works_as_a_decorator_factory():
    holder = passport()

    @protect(action=Action.READ, passport=holder)
    def read_position(**kw) -> str:
        return "ok"

    assert read_position() == "ok"
    assert read_position.__name__ == "read_position"


def test_async_functions_are_supported():
    holder = passport()

    @protect(action=Action.READ, passport=holder)
    async def read_position(**kw) -> str:
        return "async-ok"

    assert asyncio.run(read_position()) == "async-ok"


def test_a_blocked_async_call_still_raises():
    holder = passport(allowed_actions=["read"])

    @protect(action=Action.TRADE, passport=holder)
    async def trade(**kw) -> str:
        return "traded"

    with pytest.raises(CustosViolation):
        asyncio.run(trade(amount=100))


def test_a_shared_revocation_store_blocks_a_revoked_agent():
    holder = passport()
    store = RevocationStore()

    def read_position(**kw) -> str:
        return "ok"

    protected = protect(read_position, action=Action.READ, passport=holder, revocation_store=store)
    assert protected() == "ok"

    store.revoke(holder.agent.id, SubjectType.AGENT, reason="compromised")
    with pytest.raises(CustosViolation) as caught:
        protected()
    assert CustosErrorCode.AGENT_REVOKED in caught.value.result.errors


def test_a_target_kwarg_overrides_the_decorator_default():
    holder = passport()
    captured: dict = {}

    def read_position(target: str) -> str:
        captured["target"] = target
        return "ok"

    protected = protect(read_position, action=Action.READ, target="default-asset", passport=holder)
    protected(target="TKN-UST-3M-001")
    assert captured["target"] == "TKN-UST-3M-001"


def test_a_value_moving_action_without_a_claim_resolver_fails_closed():
    """Any TRADE/BORROW_AGAINST/REDEEM auto-selects at least Tier 1 (envelope.py's
    own risk-based selection). Shield has no built-in way to fetch claim data, so
    without a resolver it fails closed with UNKNOWN_ASSET rather than silently
    skipping the asset-truth check."""
    holder = passport()

    def trade(**kw) -> str:
        return "traded"

    protected = protect(trade, action=Action.TRADE, passport=holder)
    with pytest.raises(CustosViolation) as caught:
        protected(amount=10)
    assert CustosErrorCode.UNKNOWN_ASSET in caught.value.result.errors


def test_a_claim_resolver_enables_a_real_asset_truth_check():
    from datetime import datetime, timezone
    from decimal import Decimal

    from custos_protocol.models import Claim, Observation

    holder = passport()

    def make_claim(target: str) -> Claim | None:
        return Claim(
            asset_id=target, issuer="Meridian", underlying_tenor="3M", asset_class="treasury",
            claimed_nav_per_token=Decimal("1"), claimed_backing_usd=Decimal("100"),
            tokens_outstanding=Decimal("100"), claimed_yield_bps=400,
            last_attested_at=datetime.now(timezone.utc), chain="ethereum", contract_address="0x1",
        )

    def make_observation(claim: Claim) -> Observation:
        stamp = datetime.now(timezone.utc)
        return Observation(source="test", tenor=claim.underlying_tenor, observed_yield_bps=400,
                           record_date=stamp.date(), fetched_at=stamp)

    def trade(**kw) -> str:
        return "traded"

    protected = protect(trade, action=Action.TRADE, target="TKN-UST-3M-001", passport=holder,
                        claim_resolver=make_claim, observation_resolver=make_observation)
    assert protected(amount=10) == "traded"


def test_a_claim_resolver_returning_none_still_fails_closed_on_unknown_asset():
    holder = passport()

    protected = protect(lambda **kw: "traded", action=Action.TRADE, passport=holder,
                        claim_resolver=lambda target: None)
    with pytest.raises(CustosViolation) as caught:
        protected(amount=10)
    assert CustosErrorCode.UNKNOWN_ASSET in caught.value.result.errors


def test_trust_history_accumulates_across_protected_calls():
    holder = passport()
    engine = TrustEngine()

    def read_position(**kw) -> str:
        return "ok"

    protected = protect(read_position, action=Action.READ, passport=holder, trust_engine=engine)
    protected()
    protected()
    assert engine.get_history(holder.agent.id).total_intents == 2


# ---- shield() class decorator and protect_agent() --------------------------


def test_shield_class_decorator_wraps_only_named_methods():
    from custos_protocol.models import VerificationTier

    holder = passport(allowed_actions=["trade", "read"])

    # tier=TIER_0 isolates this test to the wrapping mechanism itself; TRADE
    # otherwise auto-selects Tier 1+ asset truth, exercised separately above.
    @shield_class(actions={"trade": Action.TRADE}, passport=holder, tier=VerificationTier.TIER_0)
    class Bot:
        def trade(self, **kw):
            return "traded"

        def unlisted(self):
            return "unprotected"

    bot = Bot()
    assert bot.trade(amount=100) == "traded"
    # Documented trade-off: unlisted methods are left completely unwrapped.
    assert bot.unlisted() == "unprotected"


def test_shield_class_decorator_still_blocks_a_denied_action():
    holder = passport(allowed_actions=["read"])  # trade absent -> not allowed

    @shield_class(actions={"trade": Action.TRADE}, passport=holder)
    class Bot:
        def trade(self, **kw):
            return "traded"

    with pytest.raises(CustosViolation):
        Bot().trade(amount=100)


def test_shield_raises_if_the_named_method_does_not_exist():
    holder = passport()
    with pytest.raises(AttributeError):
        shield_class(actions={"nope": Action.TRADE}, passport=holder)(type("Bot", (), {}))


def test_protect_agent_wraps_a_live_instance_in_place():
    from custos_protocol.models import VerificationTier

    holder = passport(allowed_actions=["trade"])

    class Bot:
        def trade(self, **kw):
            return "traded"

        def unlisted(self):
            return "unprotected"

    bot = Bot()
    returned = protect_agent(bot, actions={"trade": Action.TRADE}, passport=holder,
                             tier=VerificationTier.TIER_0)
    assert returned is bot
    assert bot.trade(amount=100) == "traded"
    assert bot.unlisted() == "unprotected"


def test_protect_agent_only_getattrs_the_named_methods():
    """Must never blindly enumerate dir(instance) and evaluate every property."""
    holder = passport(allowed_actions=["read"])
    evaluated = []

    class Bot:
        def read(self, **kw):
            return "ok"

        @property
        def dangerous(self):
            evaluated.append("dangerous")
            return "side-effect"

    bot = Bot()
    protect_agent(bot, actions={"read": Action.READ}, passport=holder)
    bot.read()
    assert evaluated == []


def test_shield_object_and_shield_class_are_aliases():
    assert shield_object is protect_agent
    assert shield is shield_class
