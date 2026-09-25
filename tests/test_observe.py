from __future__ import annotations

import asyncio
import json

import pytest

from custos_protocol.observe import (
    ObservationEvent,
    ObservationStore,
    get_observation_store,
    observe,
    observe_agent,
    observe_class,
    passport,
    set_observation_store,
)
from custos_protocol.models import Action
from custos_protocol.passport import AgentPassport


# ---- ObservationEvent -------------------------------------------------------


def test_to_dict_is_json_serializable():
    event = ObservationEvent(agent_id="did:web:a.com:agents:bot", agent_name="bot", action="read")
    json.dumps(event.to_dict())  # must not raise


def test_to_dict_falls_back_to_repr_for_unserializable_values():
    class Unserializable:
        def __repr__(self):
            return "<Unserializable>"

    event = ObservationEvent(agent_id="a", agent_name="a", action="x", result=Unserializable())
    assert event.to_dict()["result"] == "<Unserializable>"


def test_event_id_and_timestamp_are_auto_generated():
    event = ObservationEvent(agent_id="a", agent_name="a", action="x")
    assert len(event.event_id) == 16
    assert "T" in event.timestamp


# ---- ObservationStore --------------------------------------------------------


def test_record_and_read_back_events():
    store = ObservationStore()
    event = ObservationEvent(agent_id="a", agent_name="a", action="read")
    store.record(event)
    assert store.events == [event]


def test_events_for_agent_filters_correctly():
    store = ObservationStore()
    store.record(ObservationEvent(agent_id="a", agent_name="a", action="x"))
    store.record(ObservationEvent(agent_id="b", agent_name="b", action="x"))
    assert [e.agent_id for e in store.events_for_agent("a")] == ["a"]


def test_stats_tracks_totals_success_and_errors():
    store = ObservationStore()
    store.record(ObservationEvent(agent_id="a", agent_name="a", action="x", success=True))
    store.record(ObservationEvent(agent_id="a", agent_name="a", action="x", success=False))
    assert store.stats("a") == {"total": 2, "success": 1, "errors": 1}


def test_stats_for_an_unknown_agent_is_zeroed_not_missing():
    store = ObservationStore()
    assert store.stats("nobody") == {"total": 0, "success": 0, "errors": 0}


def test_clear_empties_events_and_stats():
    store = ObservationStore()
    store.record(ObservationEvent(agent_id="a", agent_name="a", action="x"))
    store.clear()
    assert store.events == []
    assert store.stats("a") == {"total": 0, "success": 0, "errors": 0}


def test_export_json_round_trips():
    store = ObservationStore()
    store.record(ObservationEvent(agent_id="a", agent_name="a", action="x"))
    exported = json.loads(store.export_json())
    assert len(exported) == 1
    assert exported[0]["agent_id"] == "a"


def test_ring_buffer_evicts_the_oldest_event_past_maxlen():
    store = ObservationStore(maxlen=3)
    for i in range(5):
        store.record(ObservationEvent(agent_id="a", agent_name="a", action=str(i)))
    assert [e.action for e in store.events] == ["2", "3", "4"]


def test_on_event_callback_fires_for_every_record():
    store = ObservationStore()
    seen = []
    store.on_event(seen.append)
    store.record(ObservationEvent(agent_id="a", agent_name="a", action="x"))
    assert len(seen) == 1


def test_a_callback_exception_is_caught_and_does_not_break_recording():
    store = ObservationStore()

    def bad_callback(event):
        raise RuntimeError("dashboard is down")

    store.on_event(bad_callback)
    store.record(ObservationEvent(agent_id="a", agent_name="a", action="x"))  # must not raise
    assert len(store.events) == 1


# ---- default store -----------------------------------------------------------


def test_set_and_get_observation_store_round_trips():
    custom = ObservationStore()
    original = get_observation_store()
    try:
        set_observation_store(custom)
        assert get_observation_store() is custom
    finally:
        set_observation_store(original)


# ---- passport shorthand -------------------------------------------------------


def test_passport_shorthand_returns_a_real_passport_usable_by_shield():
    holder = passport("treasury-bot", allowed_actions=["trade"])
    assert isinstance(holder, AgentPassport)
    assert holder.agent.id.endswith(":agents:treasury-bot")
    assert holder.boundaries.allowed_actions == ["trade"]


# ---- @observe decorator forms -------------------------------------------------


def test_bare_observe_executes_the_function_and_records_an_event():
    store = ObservationStore()

    @observe
    def add(a, b):
        return a + b

    assert add(2, 3) == 5


def test_observe_with_parens_auto_creates_a_passport_and_records():
    store = ObservationStore()

    @observe(store=store)
    def add(a, b):
        return a + b

    assert add(2, 3) == 5
    assert len(store.events) == 1
    assert store.events[0].action == "add"
    assert store.events[0].success is True


def test_observe_with_an_explicit_passport():
    store = ObservationStore()
    holder = passport("named-bot")

    @observe(holder, store=store)
    def add(a, b):
        return a + b

    add(2, 3)
    assert store.events[0].agent_id == holder.agent.id


def test_observe_never_blocks_execution_regardless_of_boundaries():
    """The whole point of @observe: it has no verification pipeline to consult
    at all, so there is nothing that could block a call."""
    store = ObservationStore()

    @observe(store=store)
    def anything(**kw):
        return "always runs"

    assert anything(amount=10**9, action="anything-goes") == "always runs"


def test_observe_never_swallows_an_exception():
    store = ObservationStore()

    @observe(store=store)
    def boom():
        raise ValueError("kaboom")

    with pytest.raises(ValueError, match="kaboom"):
        boom()
    assert store.events[0].success is False
    assert "kaboom" in store.events[0].error


def test_log_params_defaults_to_false():
    """Divergence from the reference implementation: arguments are not captured
    unless explicitly opted in, so secrets/PII don't land in memory by default."""
    store = ObservationStore()

    @observe(store=store)
    def login(username, password):
        return "ok"

    login("alice", "s3cr3t")
    assert store.events[0].parameters == {}


def test_log_params_true_captures_bound_arguments():
    store = ObservationStore()

    @observe(store=store, log_params=True)
    def login(username, password):
        return "ok"

    login("alice", "s3cr3t")
    assert store.events[0].parameters == {"username": "alice", "password": "s3cr3t"}


def test_log_result_defaults_to_false():
    store = ObservationStore()

    @observe(store=store)
    def compute():
        return 42

    compute()
    assert store.events[0].result is None


def test_log_result_true_captures_the_return_value():
    store = ObservationStore()

    @observe(store=store, log_result=True)
    def compute():
        return 42

    compute()
    assert store.events[0].result == 42


def test_latency_is_recorded_as_a_non_negative_float():
    store = ObservationStore()

    @observe(store=store)
    def fast():
        return None

    fast()
    assert store.events[0].latency_ms >= 0.0


def test_caller_location_is_captured():
    store = ObservationStore()

    @observe(store=store)
    def fn():
        return None

    fn()
    assert store.events[0].caller is not None
    assert __file__.split("\\")[-1].split("/")[-1] in store.events[0].caller or ":" in store.events[0].caller


def test_async_functions_are_observed_without_blocking():
    store = ObservationStore()

    @observe(store=store)
    async def async_add(a, b):
        return a + b

    assert asyncio.run(async_add(2, 3)) == 5
    assert store.events[0].success is True


def test_async_exceptions_still_propagate_and_are_recorded():
    store = ObservationStore()

    @observe(store=store)
    async def boom():
        raise ValueError("async-kaboom")

    with pytest.raises(ValueError):
        asyncio.run(boom())
    assert store.events[0].success is False


# ---- observe_class / observe_agent -------------------------------------------


def test_observe_class_wraps_public_methods_and_skips_private_and_properties():
    store = ObservationStore()
    evaluated = []

    @observe_class(store=store)
    class Bot:
        def read(self):
            return "ok"

        def _internal(self):
            return "hidden"

        @property
        def dangerous(self):
            evaluated.append("touched")
            return "side-effect"

    bot = Bot()
    bot.read()
    assert len(store.events) == 1
    assert store.events[0].action == "read"
    assert evaluated == []  # the property was never evaluated by decoration


def test_observe_agent_wraps_a_live_instance_and_skips_properties():
    store = ObservationStore()
    evaluated = []

    class Bot:
        def read(self):
            return "ok"

        @property
        def dangerous(self):
            evaluated.append("touched")
            return "side-effect"

    bot = Bot()
    returned = observe_agent(bot, store=store)
    assert returned is bot
    bot.read()
    assert len(store.events) == 1
    assert evaluated == []


def test_the_observe_to_protect_upgrade_path_shares_the_same_passport():
    """The commercially load-bearing invariant from the reference implementation:
    a passport minted for @observe works unchanged with shield.protect(), same DID."""
    from custos_protocol.shield import protect

    holder = passport("upgrade-bot", allowed_actions=["read"])
    store = ObservationStore()

    @observe(holder, store=store)
    def observed_only():
        return "observed"

    protected = protect(lambda **kw: "protected", action=Action.READ, passport=holder)

    assert observed_only() == "observed"
    assert protected() == "protected"
    assert store.events[0].agent_id == holder.agent.id
