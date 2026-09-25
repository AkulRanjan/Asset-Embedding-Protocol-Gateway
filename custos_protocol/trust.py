"""Behavioural trust score engine and the per-day monetary ledger backing E203.

Thread-safe, in-memory, modeled on revocation.py's locking style. Two responsibilities
share this module because the spec pins them together: `TrustEngine` tracks an
agent's history for the score formula, and also holds the rolling per-day spend
ledger boundaries.py needs for CUSTOS-E203 (kept out of boundaries.py itself, which
stays a pure function — the ledger lookup happens in verification.py).
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from custos_protocol.models import AgentHistory

_DAY = timedelta(hours=24)


@dataclass
class _MutableHistory:
    agent_id: str
    total_intents: int = 0
    successful_intents: int = 0
    boundary_violations: int = 0
    revocation_count: int = 0
    attestation_changes: int = 0
    delegation_depth: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    _last_build_hash: str | None = field(default=None, repr=False)
    _last_prompt_hash: str | None = field(default=None, repr=False)


def _score(history: _MutableHistory) -> float:
    if history.total_intents == 0:
        return 0.0
    completion_rate = history.successful_intents / history.total_intents
    violation_rate = history.boundary_violations / history.total_intents
    value = (
        0.35 * completion_rate
        + 0.25 * (1 - violation_rate)
        + 0.15 * max(0.0, 1 - 0.30 * history.revocation_count)
        + 0.10 * max(0.0, 1 - 0.15 * history.attestation_changes)
        + 0.05 * max(0.0, 1 - 0.20 * (history.delegation_depth - 1))
        + 0.10 * min(1.0, history.total_intents / 100)
    )
    return round(min(1.0, max(0.0, value)), 4)


class TrustEngine:
    def __init__(self) -> None:
        self._history: dict[str, _MutableHistory] = {}
        self._ledger: dict[str, dict[str, tuple[datetime, float]]] = {}
        self._lock = threading.Lock()

    def _get_or_create(self, agent_id: str, now: datetime) -> _MutableHistory:
        history = self._history.get(agent_id)
        if history is None:
            history = _MutableHistory(agent_id=agent_id, first_seen=now, last_seen=now)
            self._history[agent_id] = history
        return history

    # ---- history mutation ---------------------------------------------

    def record_intent(self, agent_id: str, *, success: bool, now: datetime | None = None) -> None:
        now = now or datetime.now(timezone.utc)
        with self._lock:
            history = self._get_or_create(agent_id, now)
            history.total_intents += 1
            if success:
                history.successful_intents += 1
            history.last_seen = now

    def record_violation(self, agent_id: str, *, now: datetime | None = None) -> None:
        now = now or datetime.now(timezone.utc)
        with self._lock:
            history = self._get_or_create(agent_id, now)
            history.boundary_violations += 1
            history.last_seen = now

    def record_revocation(self, agent_id: str, *, now: datetime | None = None) -> None:
        now = now or datetime.now(timezone.utc)
        with self._lock:
            history = self._get_or_create(agent_id, now)
            history.revocation_count += 1
            history.last_seen = now

    def record_attestation(
        self, agent_id: str, build_hash: str | None, system_prompt_hash: str | None,
        *, now: datetime | None = None,
    ) -> None:
        now = now or datetime.now(timezone.utc)
        with self._lock:
            history = self._get_or_create(agent_id, now)
            if build_hash is not None and history._last_build_hash is not None and build_hash != history._last_build_hash:
                history.attestation_changes += 1
            if (
                system_prompt_hash is not None
                and history._last_prompt_hash is not None
                and system_prompt_hash != history._last_prompt_hash
            ):
                history.attestation_changes += 1
            if build_hash is not None:
                history._last_build_hash = build_hash
            if system_prompt_hash is not None:
                history._last_prompt_hash = system_prompt_hash
            history.last_seen = now

    def record_delegation_depth(self, agent_id: str, depth: int, *, now: datetime | None = None) -> None:
        now = now or datetime.now(timezone.utc)
        with self._lock:
            history = self._get_or_create(agent_id, now)
            history.delegation_depth = depth
            history.last_seen = now

    # ---- score ----------------------------------------------------------

    def score(self, agent_id: str) -> float:
        with self._lock:
            history = self._history.get(agent_id)
            if history is None:
                return 0.0
            return _score(history)

    def meets_threshold(self, agent_id: str, min_score: float) -> bool:
        if min_score <= 0.0:
            return True
        return self.score(agent_id) >= min_score

    def get_history(self, agent_id: str) -> AgentHistory | None:
        with self._lock:
            history = self._history.get(agent_id)
            if history is None:
                return None
            return AgentHistory(
                agent_id=history.agent_id,
                total_intents=history.total_intents,
                successful_intents=history.successful_intents,
                boundary_violations=history.boundary_violations,
                revocation_count=history.revocation_count,
                attestation_changes=history.attestation_changes,
                delegation_depth=history.delegation_depth,
                first_seen=history.first_seen,
                last_seen=history.last_seen,
            )

    # ---- per-day monetary ledger ----------------------------------------
    #
    # Reservation-based, to close a TOCTOU race: a plain "read day_total, decide,
    # write later" pattern lets two truly concurrent requests for the same agent
    # both read the same total, both pass predicate 4, and together exceed
    # per_day. reserve_amount() checks-and-reserves under one lock acquisition;
    # release_amount() undoes a reservation whose surrounding request later
    # failed for an unrelated reason, so budget is never permanently consumed by
    # a call that never executed.

    def _prune_locked(self, agent_id: str, now: datetime) -> dict[str, tuple[datetime, float]]:
        entries = self._ledger.get(agent_id)
        if not entries:
            return {}
        cutoff = now - _DAY
        fresh = {token: entry for token, entry in entries.items() if entry[0] > cutoff}
        if fresh:
            self._ledger[agent_id] = fresh
        else:
            self._ledger.pop(agent_id, None)
        return fresh

    def day_total(self, agent_id: str, *, now: datetime | None = None) -> float:
        now = now or datetime.now(timezone.utc)
        with self._lock:
            entries = self._prune_locked(agent_id, now)
            return sum(amount for _, amount in entries.values())

    def record_amount(self, agent_id: str, amount: float, *, now: datetime | None = None) -> str:
        """Unconditional reservation — records `amount` with no limit check.
        Returns the token, releasable like any other reservation."""
        now = now or datetime.now(timezone.utc)
        with self._lock:
            entries = self._prune_locked(agent_id, now)
            token = uuid.uuid4().hex
            entries[token] = (now, amount)
            self._ledger[agent_id] = entries
            return token

    def reserve_amount(
        self, agent_id: str, amount: float, per_day_limit: float, *, now: datetime | None = None,
    ) -> tuple[str | None, float]:
        """Atomically check `day_total + amount` against `per_day_limit` (<= 0
        means no limit) and, if within it, reserve `amount` under the same lock
        acquisition as the check.

        Returns `(token, day_total_before)`. `token` is `None` when the
        reservation was rejected; `day_total_before` is always the total
        *before* this call — the caller feeds it straight into
        `check_boundaries()` so the atomic decision here and the reported
        violation are computed from the exact same numbers, never a second,
        separately-read total.
        """
        now = now or datetime.now(timezone.utc)
        with self._lock:
            entries = self._prune_locked(agent_id, now)
            day_total_before = sum(amt for _, amt in entries.values())
            if per_day_limit > 0 and day_total_before + amount > per_day_limit:
                return None, day_total_before
            token = uuid.uuid4().hex
            entries[token] = (now, amount)
            self._ledger[agent_id] = entries
            return token, day_total_before

    def release_amount(self, agent_id: str, token: str | None, *, now: datetime | None = None) -> None:
        """Undo a reservation whose surrounding request did not ultimately
        succeed. A `None` token is a no-op, so callers can release
        unconditionally without checking first."""
        if token is None:
            return
        with self._lock:
            entries = self._ledger.get(agent_id)
            if entries and token in entries:
                del entries[token]
                if not entries:
                    self._ledger.pop(agent_id, None)
