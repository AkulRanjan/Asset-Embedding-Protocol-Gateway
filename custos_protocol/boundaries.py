"""Boundary predicates — what actually stops the money.

Violations accumulate rather than short-circuiting, so one envelope can report
every boundary it broke in a single response.

Phase 1 implements predicates 1, 2, 3, 5, 6 and 7. Predicate 4
(CUSTOS-E203, rolling per-day limit) requires the ledger introduced in Phase 2.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from custos_protocol.errors import CustosErrorCode
from custos_protocol.models import Claim, CustosEnvelope


def _numeric(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def check_boundaries(
    envelope: CustosEnvelope,
    claim: Claim | None = None,
    *,
    request_geo: str | None = None,
    now: datetime | None = None,
) -> list[CustosErrorCode]:
    now = now or datetime.now(timezone.utc)
    boundaries = envelope.boundaries
    action = envelope.intent.action.value
    violations: list[CustosErrorCode] = []

    # 1. Deny list wins over the allow list.
    if action in boundaries.denied_actions:
        violations.append(CustosErrorCode.ACTION_DENIED)
    # 2. Allow list is only enforced once it is non-empty.
    elif boundaries.allowed_actions and action not in boundaries.allowed_actions:
        violations.append(CustosErrorCode.ACTION_NOT_ALLOWED)

    # 3. Per-transaction monetary limit. A limit of 0 means "no limit".
    amount = _numeric(envelope.intent.parameters.get("amount"))
    per_transaction = boundaries.monetary_limit.per_transaction
    if amount is not None and per_transaction > 0 and amount > per_transaction:
        violations.append(CustosErrorCode.MONETARY_LIMIT_PER_TXN)

    # 5. Time window.
    window = boundaries.time_window
    if window is not None and not (window.start <= now <= window.end):
        violations.append(CustosErrorCode.TIME_WINDOW_VIOLATION)

    # 6. Geography — inert unless the verifier supplies the caller's location.
    if boundaries.geo_restriction and request_geo:
        permitted = {part.strip().upper() for part in boundaries.geo_restriction.split(",")}
        if request_geo.strip().upper() not in permitted:
            violations.append(CustosErrorCode.GEO_RESTRICTION)

    # 7. Asset class — skipped when no claim was resolved.
    if boundaries.asset_classes and claim is not None:
        if claim.asset_class not in boundaries.asset_classes:
            violations.append(CustosErrorCode.ASSET_CLASS_NOT_ALLOWED)

    return violations
