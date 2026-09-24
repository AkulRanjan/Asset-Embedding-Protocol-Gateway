from __future__ import annotations

import threading

import pytest
from pydantic import ValidationError

from claims.registry import ClaimRegistry


@pytest.fixture
def registry():
    return ClaimRegistry()


def test_update_claim_revalidates_and_rejects_a_negative_yield(registry):
    """model_copy(update=...) skips Pydantic validators; the registry must not let a
    caller install a value the schema itself forbids."""
    asset_id = registry.list_claims()[0].asset_id
    with pytest.raises(ValidationError):
        registry.update_claim(asset_id, claimed_yield_bps=-1)


def test_update_claim_rejects_zero_tokens_outstanding(registry):
    """The drift engine divides by tokens_outstanding; zero must stay unreachable."""
    asset_id = registry.list_claims()[0].asset_id
    with pytest.raises(ValidationError):
        registry.update_claim(asset_id, tokens_outstanding="0")


def test_update_claim_accepts_a_valid_change(registry):
    asset_id = registry.list_claims()[0].asset_id
    updated = registry.update_claim(asset_id, claimed_yield_bps=410)
    assert updated is not None
    assert updated.claimed_yield_bps == 410
    assert registry.get_claim(asset_id).claimed_yield_bps == 410


def test_update_claim_on_an_unknown_asset_returns_none(registry):
    assert registry.update_claim("NOPE", claimed_yield_bps=410) is None


def test_concurrent_updates_to_different_assets_do_not_cross_contaminate(registry):
    """Simultaneous writers touching distinct assets must never see each other's value."""
    asset_ids = [claim.asset_id for claim in registry.list_claims()]
    assert len(asset_ids) >= 2

    def worker(asset_id: str, yield_bps: int) -> None:
        for _ in range(50):
            registry.update_claim(asset_id, claimed_yield_bps=yield_bps)

    threads = [
        threading.Thread(target=worker, args=(asset_id, 300 + index))
        for index, asset_id in enumerate(asset_ids)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    for index, asset_id in enumerate(asset_ids):
        assert registry.get_claim(asset_id).claimed_yield_bps == 300 + index


def test_concurrent_updates_to_the_same_asset_leave_it_in_a_consistent_state(registry):
    """A race on one asset_id must end with one of the attempted values, never a
    partially-applied or corrupted record."""
    asset_id = registry.list_claims()[0].asset_id
    attempted_values = list(range(400, 420))

    def worker(yield_bps: int) -> None:
        registry.update_claim(asset_id, claimed_yield_bps=yield_bps)

    threads = [threading.Thread(target=worker, args=(value,)) for value in attempted_values]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert registry.get_claim(asset_id).claimed_yield_bps in attempted_values
