from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

from custos_protocol.trust import TrustEngine


def now() -> datetime:
    return datetime.now(timezone.utc)


def test_an_unknown_agent_has_zero_trust_not_neutral_trust():
    engine = TrustEngine()
    assert engine.score("did:web:acme.com:agents:new") == 0.0
    assert engine.get_history("did:web:acme.com:agents:new") is None


def test_the_pinned_formula_computes_correctly():
    """Hand-computed: 8/10 successful, 1 violation, 0 revocations, 0 attestation
    changes, delegation_depth=1, total_intents=10.

    0.35*0.8 + 0.25*0.9 + 0.15*1 + 0.10*1 + 0.05*1 + 0.10*0.1
      = 0.28 + 0.225 + 0.15 + 0.10 + 0.05 + 0.01 = 0.815
    """
    engine = TrustEngine()
    agent = "did:web:acme.com:agents:bot"
    for _ in range(8):
        engine.record_intent(agent, success=True)
    for _ in range(2):
        engine.record_intent(agent, success=False)
    engine.record_violation(agent)
    engine.record_delegation_depth(agent, 1)

    assert engine.score(agent) == 0.815
    history = engine.get_history(agent)
    assert history.total_intents == 10
    assert history.successful_intents == 8
    assert history.boundary_violations == 1
    assert history.delegation_depth == 1


def test_score_is_clamped_to_zero_one_and_rounded_to_four_places():
    engine = TrustEngine()
    agent = "did:web:acme.com:agents:perfect"
    for _ in range(50):
        engine.record_intent(agent, success=True)
    score = engine.score(agent)
    assert 0.0 <= score <= 1.0
    assert round(score, 4) == score


def test_revocations_and_attestation_instability_pull_the_score_down():
    engine = TrustEngine()
    agent = "did:web:acme.com:agents:flaky"
    for _ in range(10):
        engine.record_intent(agent, success=True)
    baseline = engine.score(agent)

    engine.record_revocation(agent)
    after_revocation = engine.score(agent)
    assert after_revocation < baseline


def test_attestation_change_only_counts_when_a_hash_actually_differs():
    engine = TrustEngine()
    agent = "did:web:acme.com:agents:bot"

    # First sighting establishes a baseline; it must not itself count as a change.
    engine.record_attestation(agent, build_hash="hash-a", system_prompt_hash="prompt-a")
    assert engine.get_history(agent).attestation_changes == 0

    # Same value again: still no change.
    engine.record_attestation(agent, build_hash="hash-a", system_prompt_hash="prompt-a")
    assert engine.get_history(agent).attestation_changes == 0

    # A genuinely different build_hash: one change.
    engine.record_attestation(agent, build_hash="hash-b", system_prompt_hash="prompt-a")
    assert engine.get_history(agent).attestation_changes == 1

    # None values must never register as a change either direction.
    engine.record_attestation(agent, build_hash=None, system_prompt_hash=None)
    assert engine.get_history(agent).attestation_changes == 1


def test_meets_threshold_is_inert_at_the_default_of_zero():
    engine = TrustEngine()
    assert engine.meets_threshold("did:web:acme.com:agents:unknown", 0.0) is True


def test_meets_threshold_gates_correctly_once_configured():
    engine = TrustEngine()
    agent = "did:web:acme.com:agents:bot"
    for _ in range(5):
        engine.record_intent(agent, success=True)
    score = engine.score(agent)
    assert engine.meets_threshold(agent, score) is True
    assert engine.meets_threshold(agent, score + 0.01) is False
    assert engine.meets_threshold("did:web:acme.com:agents:unknown", 0.1) is False


# ---- per-day ledger --------------------------------------------------------


def test_day_total_is_zero_for_an_agent_with_no_recorded_spend():
    engine = TrustEngine()
    assert engine.day_total("did:web:acme.com:agents:bot") == 0.0


def test_record_amount_accumulates_within_the_window():
    engine = TrustEngine()
    agent = "did:web:acme.com:agents:bot"
    reference = now()
    engine.record_amount(agent, 1000, now=reference)
    engine.record_amount(agent, 2500, now=reference + timedelta(hours=1))
    assert engine.day_total(agent, now=reference + timedelta(hours=2)) == 3500


def test_an_entry_older_than_24h_is_excluded_and_pruned():
    engine = TrustEngine()
    agent = "did:web:acme.com:agents:bot"
    reference = now()
    engine.record_amount(agent, 1000, now=reference)
    later = reference + timedelta(hours=25)
    assert engine.day_total(agent, now=later) == 0.0
    # Pruned, not just excluded from the sum — internal storage must not grow forever.
    assert engine._ledger.get(agent) is None


def test_the_window_is_a_trailing_24h_not_a_calendar_day():
    """23:59 and 00:01 the next day must not both be treated as fresh 'today' spend."""
    engine = TrustEngine()
    agent = "did:web:acme.com:agents:bot"
    at_2359 = datetime(2026, 1, 1, 23, 59, tzinfo=timezone.utc)
    at_0001 = datetime(2026, 1, 2, 0, 1, tzinfo=timezone.utc)
    engine.record_amount(agent, 5000, now=at_2359)
    # Only 2 minutes later, still well within the trailing 24h window.
    assert engine.day_total(agent, now=at_0001) == 5000
    # 24h + 1 minute after the original spend, it must have rolled off.
    assert engine.day_total(agent, now=at_2359 + timedelta(hours=24, minutes=1)) == 0.0


def test_concurrent_record_amount_calls_do_not_lose_updates():
    engine = TrustEngine()
    agent = "did:web:acme.com:agents:bot"
    reference = now()

    def worker():
        for _ in range(100):
            engine.record_amount(agent, 1, now=reference)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert engine.day_total(agent, now=reference) == 1000


def test_reserve_amount_succeeds_and_counts_toward_day_total():
    engine = TrustEngine()
    agent = "did:web:acme.com:agents:bot"
    reference = now()
    token, before = engine.reserve_amount(agent, 200, 1000, now=reference)
    assert token is not None
    assert before == 0.0
    assert engine.day_total(agent, now=reference) == 200


def test_reserve_amount_rejects_when_it_would_exceed_the_limit():
    engine = TrustEngine()
    agent = "did:web:acme.com:agents:bot"
    reference = now()
    engine.reserve_amount(agent, 800, 1000, now=reference)
    token, before = engine.reserve_amount(agent, 300, 1000, now=reference)
    assert token is None
    assert before == 800
    # A rejected reservation must not itself be recorded.
    assert engine.day_total(agent, now=reference) == 800


def test_reserve_amount_at_exactly_the_limit_succeeds():
    engine = TrustEngine()
    agent = "did:web:acme.com:agents:bot"
    token, _ = engine.reserve_amount(agent, 1000, 1000, now=now())
    assert token is not None


def test_reserve_amount_with_no_limit_always_succeeds():
    engine = TrustEngine()
    agent = "did:web:acme.com:agents:bot"
    token, _ = engine.reserve_amount(agent, 10**9, 0, now=now())
    assert token is not None


def test_release_amount_undoes_a_reservation():
    engine = TrustEngine()
    agent = "did:web:acme.com:agents:bot"
    reference = now()
    token, _ = engine.reserve_amount(agent, 500, 1000, now=reference)
    engine.release_amount(agent, token, now=reference)
    assert engine.day_total(agent, now=reference) == 0.0
    # And the budget is available again for a later reservation.
    token2, before = engine.reserve_amount(agent, 900, 1000, now=reference)
    assert token2 is not None
    assert before == 0.0


def test_release_amount_with_a_none_token_is_a_no_op():
    engine = TrustEngine()
    agent = "did:web:acme.com:agents:bot"
    engine.release_amount(agent, None)  # must not raise
    assert engine.day_total(agent) == 0.0


def test_release_amount_only_removes_the_matching_reservation():
    engine = TrustEngine()
    agent = "did:web:acme.com:agents:bot"
    reference = now()
    token_a, _ = engine.reserve_amount(agent, 100, 0, now=reference)
    token_b, _ = engine.reserve_amount(agent, 200, 0, now=reference)
    engine.release_amount(agent, token_a, now=reference)
    assert engine.day_total(agent, now=reference) == 200


def test_concurrent_reservations_never_together_exceed_the_limit():
    """The race the reserve/release protocol exists to close: many threads racing
    on the same agent's per-day budget must never collectively over-commit it,
    even though each individual reservation is only 100 and the limit is 1000."""
    engine = TrustEngine()
    agent = "did:web:acme.com:agents:bot"
    reference = now()
    accepted: list[str] = []
    lock = threading.Lock()

    def worker():
        token, _ = engine.reserve_amount(agent, 100, 1000, now=reference)
        if token is not None:
            with lock:
                accepted.append(token)

    threads = [threading.Thread(target=worker) for _ in range(30)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    # Exactly 10 of the 30 contenders can fit inside a 1000 budget at 100 each.
    assert len(accepted) == 10
    assert engine.day_total(agent, now=reference) == 1000


def test_concurrent_record_intent_calls_do_not_lose_updates():
    engine = TrustEngine()
    agent = "did:web:acme.com:agents:bot"

    def worker():
        for _ in range(100):
            engine.record_intent(agent, success=True)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert engine.get_history(agent).total_intents == 1000
