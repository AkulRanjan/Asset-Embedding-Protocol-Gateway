"""Every wire message and domain object, as Pydantic v2 models. This file is the schema."""

from __future__ import annotations

from datetime import date, datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)

from custos_protocol.errors import CustosErrorCode

PROTOCOL_VERSION = "1.0.0"
CONTEXT_URL = "https://custos.protocol/v1"
ENVELOPE_TYPE = "CustosEnvelope"


class VerificationTier(str, Enum):
    TIER_0 = "tier_0"   # authorization only — NO market check
    TIER_1 = "tier_1"   # + asset truth + attestation
    TIER_2 = "tier_2"   # + delegation + trust  (Phase 2)


class Action(str, Enum):
    BORROW_AGAINST = "borrow_against"
    TRADE = "trade"
    REDEEM = "redeem"
    READ = "read"


class AttestationMethod(str, Enum):
    SELF_REPORTED = "self_reported"
    FRAMEWORK_REGISTRY = "framework_registry"
    THIRD_PARTY_AUDIT = "third_party_audit"


class RevocationStatus(str, Enum):
    NOT_REVOKED = "not_revoked"
    REVOKED = "revoked"
    SUSPENDED = "suspended"


class CheckOutcome(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    NOT_RUN = "not_run"


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    return value.astimezone(timezone.utc)


class MonetaryLimit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    per_transaction: float = Field(default=0.0, ge=0)
    per_day: float = Field(default=0.0, ge=0)
    currency: str = "USD"


class TimeWindow(BaseModel):
    model_config = ConfigDict(extra="forbid")
    start: datetime
    end: datetime


class Boundaries(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allowed_actions: list[str] = Field(default_factory=list)
    denied_actions: list[str] = Field(default_factory=list)
    monetary_limit: MonetaryLimit = Field(default_factory=MonetaryLimit)
    asset_classes: list[str] = Field(default_factory=list)
    geo_restriction: str | None = None
    time_window: TimeWindow | None = None


class DelegationLink(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    from_id: str = Field(alias="from")
    to_id: str = Field(alias="to")
    scope: str = "default"
    boundary_monotonicity: bool = True
    granted_at: datetime
    expires_at: datetime | None = None


class Principal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = "organization"
    id: str
    delegation_chain: list[DelegationLink] = Field(default_factory=list)


class AgentAttestation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    method: AttestationMethod = AttestationMethod.SELF_REPORTED
    framework_id: str | None = None
    build_hash: str | None = None
    system_prompt_hash: str | None = None
    registry_signature: str | None = None


class AgentIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    version: str = "1.0.0"
    runtime: str = "custos-sdk/1.0.0"
    attestation: AgentAttestation = Field(default_factory=AgentAttestation)


class Intent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Action
    target: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)

    @field_validator("parameters")
    @classmethod
    def _amount_is_non_negative(cls, value: dict[str, Any]) -> dict[str, Any]:
        """A negative amount passes every `amount > limit` comparison. Reject it here."""
        amount = value.get("amount")
        if amount is None:
            return value
        if isinstance(amount, bool) or not isinstance(amount, (int, float)):
            raise ValueError("parameters['amount'] must be a number")
        if amount < 0:
            raise ValueError("parameters['amount'] must not be negative")
        return value


class Proof(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = "Ed25519Signature2020"
    created: datetime
    verification_method: str = ""
    proof_purpose: str = "assertionMethod"
    proof_value: str


class CustosEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    context: str = Field(default=CONTEXT_URL, alias="@context")
    type: str = Field(default=ENVELOPE_TYPE, alias="@type")
    protocol_version: str = PROTOCOL_VERSION

    agent: AgentIdentity
    principal: Principal
    intent: Intent
    boundaries: Boundaries

    verification_tier: VerificationTier = VerificationTier.TIER_1
    entropy: str = Field(default_factory=lambda: f"nonce:{uuid4().hex}")
    ttl: int = Field(default=300, ge=1, le=86400)
    issued_at: datetime
    expires_at: datetime
    proof: Proof | None = None

    @field_validator("issued_at", "expires_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return _require_aware(value)


class Claim(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: str
    issuer: str
    underlying_tenor: str
    asset_class: str = "treasury"
    claimed_nav_per_token: Decimal = Field(gt=0)
    claimed_backing_usd: Decimal = Field(ge=0)
    tokens_outstanding: Decimal = Field(gt=0)
    claimed_yield_bps: int = Field(ge=0)
    last_attested_at: datetime
    chain: str
    contract_address: str

    @field_validator("last_attested_at")
    @classmethod
    def _coerce_utc(cls, value: datetime) -> datetime:
        """Seed data is written naive; assume UTC rather than reject."""
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


class Observation(BaseModel):
    source: str
    dataset: str = "daily_treasury_yield_curve"
    tenor: str
    observed_yield_bps: int
    record_date: date
    fetched_at: datetime
    cache_hit: bool = False


class AssetScores(BaseModel):
    staleness_hours: float | None = None
    staleness_threshold_hours: float | None = None
    yield_drift: float | None = None
    yield_drift_threshold: float | None = None
    yield_drift_basis: str | None = None      # "relative" | "absolute"
    backing_ratio: float | None = None
    backing_ratio_floor: float | None = None


class RevocationCheck(BaseModel):
    status: RevocationStatus = RevocationStatus.NOT_REVOKED
    freshness_ms: float = 0.0
    max_staleness_ms: int = 500
    stale: bool = False


class VerificationResult(BaseModel):
    passed: bool = False
    checks: dict[str, CheckOutcome] = Field(default_factory=dict)
    revocation: RevocationCheck = Field(default_factory=RevocationCheck)
    trust_score: float = 0.0
    tier_used: VerificationTier = VerificationTier.TIER_1
    scores: AssetScores | None = None
    reference: dict[str, Any] | None = None
    errors: list[CustosErrorCode] = Field(default_factory=list)
    detail: str = ""
