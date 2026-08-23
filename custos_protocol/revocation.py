"""The kill switch and the replay cache, in one thread-safe object."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum

from custos_protocol.models import RevocationCheck, RevocationStatus

MAX_NONCE_CACHE = 1_000_000
DEFAULT_NONCE_TTL_SECONDS = 86_400


class SubjectType(str, Enum):
    AGENT = "agent"
    ISSUER = "issuer"


@dataclass(frozen=True)
class RevocationRecord:
    subject_id: str
    subject_type: SubjectType
    reason: str
    revoked_at: datetime
    revoked_by: str
    scope: str
    suspended_until: datetime | None   # None means permanent


class RevocationStore:
    def __init__(
        self,
        *,
        local_only: bool = True,
        max_nonces: int = MAX_NONCE_CACHE,
    ) -> None:
        self._records: dict[str, RevocationRecord] = {}
        self._nonces: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()
        self._local_only = local_only
        self._max_nonces = max_nonces
        self._last_sync = datetime.now(timezone.utc)

    # ---- kill switch -------------------------------------------------

    def revoke(self, subject_id: str, subject_type: SubjectType,
               reason: str = "", revoked_by: str = "", scope: str = "global") -> None:
        with self._lock:
            self._records[subject_id] = RevocationRecord(
                subject_id=subject_id, subject_type=subject_type, reason=reason,
                revoked_at=datetime.now(timezone.utc), revoked_by=revoked_by,
                scope=scope, suspended_until=None,
            )
            self._last_sync = datetime.now(timezone.utc)

    def suspend(self, subject_id: str, subject_type: SubjectType,
                duration_seconds: int = 1800, reason: str = "",
                revoked_by: str = "circuit_breaker", scope: str = "global") -> None:
        with self._lock:
            self._records[subject_id] = RevocationRecord(
                subject_id=subject_id, subject_type=subject_type, reason=reason,
                revoked_at=datetime.now(timezone.utc), revoked_by=revoked_by,
                scope=scope,
                suspended_until=datetime.now(timezone.utc) + timedelta(seconds=duration_seconds),
            )
            self._last_sync = datetime.now(timezone.utc)

    def _live_record(self, subject_id: str) -> RevocationRecord | None:
        record = self._records.get(subject_id)
        if record is None:
            return None
        if record.suspended_until is not None and record.suspended_until <= datetime.now(timezone.utc):
            self._records.pop(subject_id, None)   # lazily drop expired suspensions
            return None
        return record

    def is_revoked(self, subject_id: str) -> bool:
        with self._lock:
            return self._live_record(subject_id) is not None

    def is_suspended(self, subject_id: str) -> bool:
        with self._lock:
            record = self._live_record(subject_id)
            return record is not None and record.suspended_until is not None

    def reinstate(self, subject_id: str) -> bool:
        with self._lock:
            existed = self._records.pop(subject_id, None) is not None
            self._last_sync = datetime.now(timezone.utc)
            return existed

    def get_record(self, subject_id: str) -> RevocationRecord | None:
        with self._lock:
            return self._live_record(subject_id)

    @property
    def revocation_count(self) -> int:
        with self._lock:
            return len(self._records)

    # ---- freshness ---------------------------------------------------

    def touch_sync(self) -> None:
        with self._lock:
            self._last_sync = datetime.now(timezone.utc)

    @property
    def last_sync_time(self) -> datetime:
        return self._last_sync

    def freshness(self, max_staleness_ms: int) -> RevocationCheck:
        """A local-only store has no upstream and is never stale.

        The blueprint's store advances ``_last_sync`` only on mutation, so it is
        permanently stale in a long-running verifier — which silently disables its
        deep revocation check. Custos fails closed on stale data, so the same
        behaviour here would be a self-inflicted outage instead.
        """
        age_ms = (datetime.now(timezone.utc) - self._last_sync).total_seconds() * 1000
        stale = (not self._local_only) and age_ms > max_staleness_ms
        return RevocationCheck(
            status=RevocationStatus.NOT_REVOKED,
            freshness_ms=age_ms,
            max_staleness_ms=max_staleness_ms,
            stale=stale,
        )

    # ---- replay cache ------------------------------------------------

    def check_nonce(self, nonce: str, ttl_seconds: int = DEFAULT_NONCE_TTL_SECONDS) -> bool:
        """True if the nonce is new. Consumes it as a side effect."""
        with self._lock:
            cutoff = time.monotonic() - ttl_seconds
            while self._nonces:
                oldest_nonce, stored_at = next(iter(self._nonces.items()))
                if stored_at > cutoff:
                    break
                self._nonces.popitem(last=False)     # age-based eviction first

            if nonce in self._nonces:
                return False

            self._nonces[nonce] = time.monotonic()
            while len(self._nonces) > self._max_nonces:
                self._nonces.popitem(last=False)     # then pressure, oldest first
            return True

    def clear_nonces(self) -> None:
        with self._lock:
            self._nonces.clear()
