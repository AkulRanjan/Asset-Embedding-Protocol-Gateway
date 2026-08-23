from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from custos_protocol.models import RevocationStatus
from custos_protocol.revocation import RevocationStore, SubjectType


def store() -> RevocationStore:
    return RevocationStore()


def test_revoked_agent_is_reported():
    subject = RevocationStore()
    subject.revoke("did:web:acme.com:agents:bot", SubjectType.AGENT, reason="compromised")
    assert subject.is_revoked("did:web:acme.com:agents:bot") is True
    assert subject.is_suspended("did:web:acme.com:agents:bot") is False


def test_issuer_revocation_is_a_first_class_subject():
    subject = store()
    subject.revoke("Meridian", SubjectType.ISSUER, reason="fraud")
    record = subject.get_record("Meridian")
    assert subject.is_revoked("Meridian") is True
    assert record.subject_type is SubjectType.ISSUER


def test_unknown_subject_is_not_revoked():
    assert store().is_revoked("did:web:acme.com:agents:nobody") is False


def test_suspension_expires_on_its_own():
    subject = store()
    subject.suspend("agent", SubjectType.AGENT, duration_seconds=-1)
    assert subject.is_revoked("agent") is False
    assert subject.get_record("agent") is None


def test_active_suspension_blocks_and_is_distinguishable():
    subject = store()
    subject.suspend("agent", SubjectType.AGENT, duration_seconds=1800)
    assert subject.is_revoked("agent") is True
    assert subject.is_suspended("agent") is True


def test_reinstate_removes_the_record():
    subject = store()
    subject.revoke("agent", SubjectType.AGENT)
    assert subject.reinstate("agent") is True
    assert subject.is_revoked("agent") is False
    assert subject.reinstate("agent") is False


def test_revocation_count_tracks_active_records():
    subject = store()
    assert subject.revocation_count == 0
    subject.revoke("a", SubjectType.AGENT)
    subject.revoke("b", SubjectType.ISSUER)
    assert subject.revocation_count == 2


def test_nonce_is_accepted_once_then_rejected():
    subject = store()
    assert subject.check_nonce("nonce:" + "a" * 32) is True
    assert subject.check_nonce("nonce:" + "a" * 32) is False


def test_distinct_nonces_are_independent():
    subject = store()
    assert subject.check_nonce("nonce:" + "a" * 32) is True
    assert subject.check_nonce("nonce:" + "b" * 32) is True


def test_nonce_expires_after_its_ttl():
    subject = store()
    assert subject.check_nonce("nonce:x", ttl_seconds=0) is True
    time.sleep(0.01)
    assert subject.check_nonce("nonce:x", ttl_seconds=0) is True


def test_nonce_eviction_is_fifo_not_arbitrary():
    """The blueprint evicts arbitrary set members; the oldest must go first."""
    subject = RevocationStore(max_nonces=10)
    for index in range(10):
        assert subject.check_nonce(f"nonce:{index}") is True
    subject.check_nonce("nonce:overflow")
    assert subject.check_nonce("nonce:0") is True      # oldest was evicted, so it is new again
    assert subject.check_nonce("nonce:9") is False     # newest survived and is still remembered


def test_clear_nonces_empties_the_cache():
    subject = store()
    subject.check_nonce("nonce:a")
    subject.clear_nonces()
    assert subject.check_nonce("nonce:a") is True


def test_a_local_only_store_is_never_stale():
    """Failing closed on a store with no upstream would be a self-inflicted outage."""
    subject = RevocationStore(local_only=True)
    time.sleep(0.02)
    check = subject.freshness(max_staleness_ms=1)
    assert check.stale is False
    assert check.status is RevocationStatus.NOT_REVOKED


def test_a_synced_store_goes_stale_and_reports_it():
    subject = RevocationStore(local_only=False)
    subject.touch_sync()
    time.sleep(0.02)
    assert subject.freshness(max_staleness_ms=1).stale is True
    subject.touch_sync()
    assert subject.freshness(max_staleness_ms=10_000).stale is False


def test_freshness_reports_the_measured_age():
    subject = RevocationStore(local_only=False)
    subject.touch_sync()
    check = subject.freshness(max_staleness_ms=500)
    assert check.freshness_ms >= 0
    assert check.max_staleness_ms == 500
