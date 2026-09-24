"""Asset truth: is this claim plausible against the live market for its tenor?

A pure function of (claim, observation, config). No I/O, no environment reads —
thresholds arrive as a value object so the layer is testable in isolation.

This is a plausibility check against market rates, not an audit of a fund's
private NAV or holdings.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from custos_protocol.errors import CustosErrorCode
from custos_protocol.models import AssetScores, Claim, Observation


@dataclass(frozen=True)
class DriftConfig:
    staleness_threshold_hours: float = 24.0
    drift_threshold: float = 0.02
    backing_floor: float = 1.0
    max_observation_age_days: int = 4
    zero_yield_abs_tolerance_bps: int = 10
    clock_skew_seconds: int = 5


@dataclass(frozen=True)
class AssetTruthFailure:
    code: CustosErrorCode
    detail: str
    scores: AssetScores | None = None
    reference: dict[str, Any] | None = None


def _reference(claim: Claim, observation: Observation) -> dict[str, Any]:
    return {
        "source": observation.source,
        "tenor": observation.tenor,
        "claimed_yield_bps": claim.claimed_yield_bps,
        "observed_yield_bps": observation.observed_yield_bps,
        "record_date": observation.record_date.isoformat(),
    }


def check_asset_truth(
    claim: Claim | None,
    observation: Observation | None,
    config: DriftConfig,
    *,
    now: datetime | None = None,
) -> AssetScores | AssetTruthFailure:
    now = now or datetime.now(timezone.utc)

    # 1. Unknown asset — nothing to evaluate.
    if claim is None:
        return AssetTruthFailure(
            CustosErrorCode.UNKNOWN_ASSET,
            "The requested asset is not present in the claim registry.",
        )

    # 2. No market data — fail closed. This is the load-bearing guarantee.
    if observation is None:
        return AssetTruthFailure(
            CustosErrorCode.ORACLE_UNAVAILABLE,
            "The market oracle could not be reached; Custos fails closed.",
        )

    reference = _reference(claim, observation)

    # 3. The observation itself is too old to be evidence.
    age_days = (now.date() - observation.record_date).days
    if age_days > config.max_observation_age_days:
        return AssetTruthFailure(
            CustosErrorCode.ORACLE_DATA_STALE,
            f"Market observation is {age_days} days old; maximum is {config.max_observation_age_days}.",
            reference=reference,
        )

    # 4. A future-dated claim must not defeat the staleness check.
    grace = timedelta(seconds=config.clock_skew_seconds)
    if claim.last_attested_at > now + grace:
        return AssetTruthFailure(
            CustosErrorCode.CLAIM_FUTURE_DATED,
            f"Claim is attested {(claim.last_attested_at - now).total_seconds():.0f}s in the future.",
            reference=reference,
        )

    # 5. Staleness.
    staleness_hours = max(0.0, (now - claim.last_attested_at).total_seconds() / 3600)
    scores = AssetScores(
        staleness_hours=round(staleness_hours, 2),
        staleness_threshold_hours=config.staleness_threshold_hours,
    )
    if staleness_hours > config.staleness_threshold_hours:
        return AssetTruthFailure(
            CustosErrorCode.CLAIM_STALE,
            f"Claim was last attested {staleness_hours:.2f} hours ago; "
            f"threshold is {config.staleness_threshold_hours:.1f} hours.",
            scores=scores,
            reference=reference,
        )

    # 6. A negative yield is impossible data. Zero is legal.
    observed = observation.observed_yield_bps
    if observed < 0:
        return AssetTruthFailure(
            CustosErrorCode.ORACLE_DATA_STALE,
            f"Market oracle returned a negative yield of {observed} bps.",
            scores=scores,
            reference=reference,
        )

    # 7. Yield drift. Relative drift is undefined at a zero observation, so fall
    #    back to an absolute basis-point comparison.
    if observed == 0:
        drift_value = float(abs(claim.claimed_yield_bps - observed))
        threshold: float = float(config.zero_yield_abs_tolerance_bps)
        basis = "absolute"
        exceeded = drift_value > threshold
        drift_detail = (
            f"Claimed yield {claim.claimed_yield_bps} bps differs by {drift_value:.0f} bps "
            f"from an observed {observation.tenor} yield of 0 bps; tolerance is {threshold:.0f} bps."
        )
    else:
        drift_value = abs(observed - claim.claimed_yield_bps) / observed
        threshold = config.drift_threshold
        basis = "relative"
        exceeded = drift_value > threshold
        drift_detail = (
            f"Claimed yield {claim.claimed_yield_bps} bps diverges {drift_value:.2%} from observed "
            f"{observation.tenor} yield of {observed} bps; threshold is {threshold:.1%}."
        )

    scores = scores.model_copy(update={
        "yield_drift": round(drift_value, 6),
        "yield_drift_threshold": threshold,
        "yield_drift_basis": basis,
    })
    if exceeded:
        return AssetTruthFailure(
            CustosErrorCode.YIELD_DRIFT_EXCEEDED, drift_detail,
            scores=scores, reference=reference,
        )

    # 8. Backing ratio. Exact Decimal arithmetic; the float cast is for reporting only.
    #
    # This is a floor check only, by design: a ratio far above the floor (e.g. 10x)
    # signals an implausible feed exactly as loudly as a ratio below it, but the
    # 30-code CUSTOS-Exxx taxonomy is fixed (see AGENTS.md) and has no code reserved
    # for "over-backed". `backing_ratio` is still returned in `scores` so a caller
    # can apply its own ceiling policy without Custos needing a new error code.
    implied_liability = claim.tokens_outstanding * claim.claimed_nav_per_token
    ratio = float(claim.claimed_backing_usd / implied_liability)
    scores = scores.model_copy(update={
        "backing_ratio": round(ratio, 6),
        "backing_ratio_floor": config.backing_floor,
    })
    if ratio < config.backing_floor:
        return AssetTruthFailure(
            CustosErrorCode.BACKING_RATIO_BELOW_FLOOR,
            f"Backing ratio is {ratio:.4f}; floor is {config.backing_floor:.4f}.",
            scores=scores, reference=reference,
        )

    return scores
