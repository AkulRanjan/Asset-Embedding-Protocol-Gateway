"""Delegation chain validation: continuity, endpoints, expiry, depth, and boundary
monotonicity. A pure function of (envelope, config, now) — no I/O, per the protocol
contract.

Single fail-fast code (DELEGATION_INVALID), matching every other verification step
except boundaries.py, which deliberately accumulates.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from custos_protocol.errors import CustosErrorCode
from custos_protocol.models import Boundaries, CustosEnvelope, DelegationLink


@dataclass(frozen=True)
class DelegationConfig:
    clock_skew_seconds: int = 5
    max_delegation_depth: int = 8


@dataclass(frozen=True)
class DelegationFailure:
    code: CustosErrorCode
    detail: str


def _fail(detail: str) -> DelegationFailure:
    return DelegationFailure(CustosErrorCode.DELEGATION_INVALID, detail)


def _numeric_limit_contained(child: float, parent: float) -> bool:
    """`0` means "no limit" throughout the codebase. A child may only be equal or
    tighter, unless the parent itself declared no limit."""
    if parent == 0:
        return True
    return 0 < child <= parent


def _geo_set(value: str | None) -> set[str] | None:
    # Falsy (None or "") means unrestricted — matches boundaries.py's `if
    # boundaries.geo_restriction and request_geo:` truthiness check exactly, so the
    # two modules agree on what an empty geo_restriction string means.
    if not value:
        return None
    return {part.strip().upper() for part in value.split(",") if part.strip()}


def _window_contained(child, parent) -> bool:
    if parent is None:
        return True
    if child is None:
        return False
    return parent.start <= child.start and child.end <= parent.end


def _containment_violation(child: Boundaries, parent: Boundaries) -> str | None:
    """Returns a human-readable reason the child exceeds the parent, or None if the
    child's authority is contained within the parent's."""
    if parent.allowed_actions and (
        not child.allowed_actions or not set(child.allowed_actions) <= set(parent.allowed_actions)
    ):
        return "allowed_actions is not a subset of the delegating hop's allowed_actions"

    if not set(parent.denied_actions) <= set(child.denied_actions):
        return "denied_actions does not carry forward every action the delegating hop denied"

    if not _numeric_limit_contained(child.monetary_limit.per_transaction, parent.monetary_limit.per_transaction):
        return "monetary_limit.per_transaction exceeds the delegating hop's limit"

    if not _numeric_limit_contained(child.monetary_limit.per_day, parent.monetary_limit.per_day):
        return "monetary_limit.per_day exceeds the delegating hop's limit"

    parent_geo, child_geo = _geo_set(parent.geo_restriction), _geo_set(child.geo_restriction)
    if parent_geo is not None and (child_geo is None or not child_geo <= parent_geo):
        return "geo_restriction is broader than the delegating hop's"

    if parent.asset_classes and (
        not child.asset_classes or not set(child.asset_classes) <= set(parent.asset_classes)
    ):
        return "asset_classes is not a subset of the delegating hop's asset_classes"

    if not _window_contained(child.time_window, parent.time_window):
        return "time_window is not nested inside the delegating hop's time_window"

    return None


def check_delegation(
    envelope: CustosEnvelope,
    *,
    config: DelegationConfig | None = None,
    now: datetime | None = None,
) -> DelegationFailure | None:
    config = config or DelegationConfig()
    now = now or datetime.now(timezone.utc)
    chain: list[DelegationLink] = envelope.principal.delegation_chain

    if not chain:
        if envelope.principal.id == envelope.agent.id:
            return None  # self-sovereign agent; nothing above it to validate
        return _fail(
            f"Principal {envelope.principal.id} and agent {envelope.agent.id} differ, "
            "but the delegation chain is empty."
        )

    if len(chain) > config.max_delegation_depth:
        return _fail(f"Delegation chain length {len(chain)} exceeds the maximum of "
                     f"{config.max_delegation_depth}.")

    if chain[0].from_id != envelope.principal.id:
        return _fail(f"Delegation chain does not start at the principal {envelope.principal.id}.")
    if chain[-1].to_id != envelope.agent.id:
        return _fail(f"Delegation chain does not end at the agent {envelope.agent.id}.")

    for index, (previous, current) in enumerate(zip(chain, chain[1:])):
        if previous.to_id != current.from_id:
            return _fail(f"Delegation chain is discontinuous between hop {index} "
                         f"({previous.to_id}) and hop {index + 1} ({current.from_id}).")

    grace = timedelta(seconds=config.clock_skew_seconds)
    for index, link in enumerate(chain):
        if link.expires_at is not None and link.expires_at < now:
            return _fail(f"Delegation hop {index} ({link.from_id} -> {link.to_id}) expired "
                         f"at {link.expires_at.isoformat()}.")
        if link.granted_at > now + grace:
            return _fail(f"Delegation hop {index} ({link.from_id} -> {link.to_id}) is granted "
                         f"in the future ({link.granted_at.isoformat()}).")

    for index, (previous, current) in enumerate(zip(chain, chain[1:])):
        violation = _containment_violation(current.boundaries, previous.boundaries)
        if violation is not None:
            return _fail(f"Delegation hop {index + 1} ({current.from_id} -> {current.to_id}) "
                         f"widens its authority beyond hop {index}: {violation}.")

    violation = _containment_violation(envelope.boundaries, chain[-1].boundaries)
    if violation is not None:
        return _fail("The envelope's own boundaries exceed the authority granted by the "
                     f"final delegation hop: {violation}.")

    return None
