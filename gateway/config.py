"""Runtime configuration. The protocol package never reads the environment."""

from __future__ import annotations

import os

from custos_protocol.drift import DriftConfig


def _env(name: str, default: str) -> str:
    return os.getenv(name, default)


def load_drift_config() -> DriftConfig:
    return DriftConfig(
        staleness_threshold_hours=float(_env("CUSTOS_STALENESS_HOURS", "24.0")),
        drift_threshold=float(_env("CUSTOS_DRIFT_THRESHOLD", "0.02")),
        backing_floor=float(_env("CUSTOS_BACKING_FLOOR", "1.0")),
        max_observation_age_days=int(_env("CUSTOS_MAX_OBS_AGE_DAYS", "4")),
        zero_yield_abs_tolerance_bps=int(_env("CUSTOS_ZERO_YIELD_TOLERANCE_BPS", "10")),
        clock_skew_seconds=int(_env("CUSTOS_CLOCK_SKEW_SECONDS", "5")),
    )


# Treasury's OData feed answers in 8-10 s cold (measured 8.2 / 9.1 / 9.5 s on
# 2026-08-22). A 3 s budget times out before it can respond. The 60 s cache TTL
# means at most one request per tenor per minute pays this.
ORACLE_TIMEOUT_SECONDS = float(_env("CUSTOS_ORACLE_TIMEOUT", "15.0"))
DOWNSTREAM_TIMEOUT_SECONDS = float(_env("CUSTOS_DOWNSTREAM_TIMEOUT", "3.0"))
ORACLE_CACHE_TTL_SECONDS = int(_env("CUSTOS_CACHE_TTL", "60"))
ATTESTATION_TTL_SECONDS = int(_env("CUSTOS_ATTESTATION_TTL", "300"))
PRIVATE_KEY_PATH = os.getenv("CUSTOS_PRIVATE_KEY")
# Control-plane authentication is deliberately independent from envelope
# signatures: it protects the initial binding of an external agent identity to
# a public key. An empty value is treated as unconfigured and fails closed.
ADMIN_API_KEY = os.getenv("CUSTOS_ADMIN_API_KEY") or None
DEMO_MODE = _env("CUSTOS_DEMO_MODE", "").lower() in {"1", "true", "yes"}
