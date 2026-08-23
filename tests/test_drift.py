from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from custos_protocol.drift import AssetTruthFailure, DriftConfig, check_asset_truth
from custos_protocol.errors import CustosErrorCode
from custos_protocol.models import AssetScores, Claim, Observation

CONFIG = DriftConfig()


def now() -> datetime:
    return datetime.now(timezone.utc)


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


def code(result) -> CustosErrorCode | None:
    return result.code if isinstance(result, AssetTruthFailure) else None


def test_healthy_claim_returns_scores():
    result = check_asset_truth(claim(), observation(), CONFIG)
    assert isinstance(result, AssetScores)
    assert result.yield_drift == 0
    assert result.backing_ratio == 1.0
    assert result.yield_drift_basis == "relative"


def test_scores_pair_every_metric_with_its_threshold():
    result = check_asset_truth(claim(), observation(), CONFIG)
    assert result.staleness_threshold_hours == CONFIG.staleness_threshold_hours
    assert result.yield_drift_threshold == CONFIG.drift_threshold
    assert result.backing_ratio_floor == CONFIG.backing_floor


def test_missing_claim_is_unknown_asset():
    assert code(check_asset_truth(None, observation(), CONFIG)) is CustosErrorCode.UNKNOWN_ASSET


def test_missing_observation_fails_closed():
    assert code(check_asset_truth(claim(), None, CONFIG)) is CustosErrorCode.ORACLE_UNAVAILABLE


def test_observation_older_than_tolerance_is_rejected():
    old = observation(record_date=(now() - timedelta(days=9)).date())
    assert code(check_asset_truth(claim(), old, CONFIG)) is CustosErrorCode.ORACLE_DATA_STALE


def test_future_dated_claim_is_rejected():
    """The old implementation clamped negative staleness to zero, so this passed."""
    future = claim(last_attested_at=now() + timedelta(days=1825))
    assert code(check_asset_truth(future, observation(), CONFIG)) is CustosErrorCode.CLAIM_FUTURE_DATED


def test_slightly_future_dated_claim_is_tolerated_within_skew_grace():
    fresh = claim(last_attested_at=now() + timedelta(seconds=2))
    assert isinstance(check_asset_truth(fresh, observation(), CONFIG), AssetScores)


def test_stale_claim_is_rejected():
    stale = claim(last_attested_at=now() - timedelta(hours=25))
    assert code(check_asset_truth(stale, observation(), CONFIG)) is CustosErrorCode.CLAIM_STALE


def test_staleness_short_circuits_before_drift():
    """The returned code must name the most fundamental problem, not an arbitrary one."""
    both_wrong = claim(last_attested_at=now() - timedelta(hours=25), claimed_yield_bps=1)
    assert code(check_asset_truth(both_wrong, observation(), CONFIG)) is CustosErrorCode.CLAIM_STALE


def test_negative_observed_yield_is_an_oracle_fault():
    bad = observation(observed_yield_bps=-5)
    assert code(check_asset_truth(claim(), bad, CONFIG)) is CustosErrorCode.ORACLE_DATA_STALE


def test_zero_observed_yield_is_legal_and_uses_absolute_basis():
    """Treasury bills printed 0.00% through 2020-2021; that is data, not a fault."""
    zero = observation(observed_yield_bps=0)
    passing = check_asset_truth(claim(claimed_yield_bps=5), zero, CONFIG)
    assert isinstance(passing, AssetScores)
    assert passing.yield_drift_basis == "absolute"
    assert passing.yield_drift == 5

    failing = check_asset_truth(claim(claimed_yield_bps=50), zero, CONFIG)
    assert code(failing) is CustosErrorCode.YIELD_DRIFT_EXCEEDED


def test_drift_boundary_is_inclusive_at_exactly_the_threshold():
    assert isinstance(check_asset_truth(claim(claimed_yield_bps=392), observation(), CONFIG), AssetScores)
    assert code(check_asset_truth(claim(claimed_yield_bps=391), observation(), CONFIG)) is CustosErrorCode.YIELD_DRIFT_EXCEEDED


def test_drift_is_normalised_by_the_observed_yield():
    result = check_asset_truth(claim(claimed_yield_bps=200), observation(observed_yield_bps=400), CONFIG)
    assert isinstance(result, AssetTruthFailure)
    assert result.scores.yield_drift == pytest.approx(0.5)


def test_under_backed_claim_is_rejected():
    thin = claim(claimed_backing_usd=Decimal("94"))
    assert code(check_asset_truth(thin, observation(), CONFIG)) is CustosErrorCode.BACKING_RATIO_BELOW_FLOOR


def test_backing_floor_is_inclusive():
    assert isinstance(check_asset_truth(claim(claimed_backing_usd=Decimal("100")), observation(), CONFIG), AssetScores)


def test_failure_carries_the_scores_computed_so_far_and_the_market_reference():
    result = check_asset_truth(claim(claimed_yield_bps=360), observation(), CONFIG)
    assert isinstance(result, AssetTruthFailure)
    assert result.scores.staleness_hours is not None
    assert result.scores.yield_drift is not None
    assert result.scores.backing_ratio is None       # never reached
    assert result.reference["observed_yield_bps"] == 400
    assert result.reference["claimed_yield_bps"] == 360
    assert "360" in result.detail and "400" in result.detail


def test_thresholds_come_from_the_config_object_not_the_environment():
    lenient = DriftConfig(drift_threshold=0.50)
    assert isinstance(check_asset_truth(claim(claimed_yield_bps=300), observation(), lenient), AssetScores)
