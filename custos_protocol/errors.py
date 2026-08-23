"""The Custos error taxonomy: 30 codes across five families.

E1xx envelope/protocol · E2xx boundary · E3xx asset truth
E4xx revocation/trust  · E5xx infrastructure
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CustosErrorCode(str, Enum):
    # E1xx — envelope / protocol
    INVALID_SIGNATURE = "CUSTOS-E100"
    EXPIRED_ENVELOPE = "CUSTOS-E101"
    REPLAY_DETECTED = "CUSTOS-E102"
    SCHEMA_INVALID = "CUSTOS-E103"
    VERSION_UNSUPPORTED = "CUSTOS-E104"
    NONCE_INVALID = "CUSTOS-E105"
    CLOCK_SKEW = "CUSTOS-E106"

    # E2xx — boundary
    ACTION_NOT_ALLOWED = "CUSTOS-E200"
    ACTION_DENIED = "CUSTOS-E201"
    MONETARY_LIMIT_PER_TXN = "CUSTOS-E202"
    MONETARY_LIMIT_PER_DAY = "CUSTOS-E203"
    TIME_WINDOW_VIOLATION = "CUSTOS-E204"
    GEO_RESTRICTION = "CUSTOS-E205"
    ASSET_CLASS_NOT_ALLOWED = "CUSTOS-E206"

    # E3xx — asset truth
    CLAIM_STALE = "CUSTOS-E300"
    YIELD_DRIFT_EXCEEDED = "CUSTOS-E301"
    BACKING_RATIO_BELOW_FLOOR = "CUSTOS-E302"
    UNKNOWN_ASSET = "CUSTOS-E303"
    TENOR_UNSUPPORTED = "CUSTOS-E304"
    CLAIM_FUTURE_DATED = "CUSTOS-E305"
    ATTESTATION_MISMATCH = "CUSTOS-E306"

    # E4xx — revocation / delegation / trust
    AGENT_REVOKED = "CUSTOS-E400"
    AGENT_SUSPENDED = "CUSTOS-E401"
    ISSUER_REVOKED = "CUSTOS-E402"
    DELEGATION_INVALID = "CUSTOS-E403"
    TRUST_SCORE_LOW = "CUSTOS-E404"
    REVOCATION_STALE = "CUSTOS-E405"

    # E5xx — infrastructure
    ORACLE_UNAVAILABLE = "CUSTOS-E500"
    ORACLE_DATA_STALE = "CUSTOS-E501"
    DOWNSTREAM_UNREACHABLE = "CUSTOS-E502"


@dataclass(frozen=True)
class ErrorSpec:
    http_status: int
    description: str


ERROR_SPECS: dict[CustosErrorCode, ErrorSpec] = {
    CustosErrorCode.INVALID_SIGNATURE: ErrorSpec(401, "Envelope signature failed verification."),
    CustosErrorCode.EXPIRED_ENVELOPE: ErrorSpec(400, "Envelope expires_at is in the past."),
    CustosErrorCode.REPLAY_DETECTED: ErrorSpec(409, "Envelope nonce has already been used."),
    CustosErrorCode.SCHEMA_INVALID: ErrorSpec(400, "Envelope failed schema validation."),
    CustosErrorCode.VERSION_UNSUPPORTED: ErrorSpec(400, "Protocol version is not supported."),
    CustosErrorCode.NONCE_INVALID: ErrorSpec(400, "Envelope entropy is not a well-formed nonce."),
    CustosErrorCode.CLOCK_SKEW: ErrorSpec(400, "Envelope issued_at is implausibly far in the future."),
    CustosErrorCode.ACTION_NOT_ALLOWED: ErrorSpec(403, "Action is absent from the agent's allowed actions."),
    CustosErrorCode.ACTION_DENIED: ErrorSpec(403, "Action appears on the agent's denied actions."),
    CustosErrorCode.MONETARY_LIMIT_PER_TXN: ErrorSpec(403, "Amount exceeds the per-transaction monetary limit."),
    CustosErrorCode.MONETARY_LIMIT_PER_DAY: ErrorSpec(403, "Amount exceeds the rolling per-day monetary limit."),
    CustosErrorCode.TIME_WINDOW_VIOLATION: ErrorSpec(403, "Request falls outside the agent's permitted time window."),
    CustosErrorCode.GEO_RESTRICTION: ErrorSpec(403, "Request origin is outside the agent's permitted geography."),
    CustosErrorCode.ASSET_CLASS_NOT_ALLOWED: ErrorSpec(403, "Asset class is absent from the agent's permitted classes."),
    CustosErrorCode.CLAIM_STALE: ErrorSpec(403, "Claim was not attested within the staleness threshold."),
    CustosErrorCode.YIELD_DRIFT_EXCEEDED: ErrorSpec(403, "Claimed yield diverges from the observed market yield beyond threshold."),
    CustosErrorCode.BACKING_RATIO_BELOW_FLOOR: ErrorSpec(403, "Claimed backing does not cover the implied liability."),
    CustosErrorCode.UNKNOWN_ASSET: ErrorSpec(404, "Asset is not present in the claim registry."),
    CustosErrorCode.TENOR_UNSUPPORTED: ErrorSpec(422, "Claim references a tenor with no yield-curve mapping."),
    CustosErrorCode.CLAIM_FUTURE_DATED: ErrorSpec(403, "Claim was attested in the future."),
    CustosErrorCode.ATTESTATION_MISMATCH: ErrorSpec(403, "Agent build or prompt attestation does not match the expected value."),
    CustosErrorCode.AGENT_REVOKED: ErrorSpec(403, "Agent identity has been revoked."),
    CustosErrorCode.AGENT_SUSPENDED: ErrorSpec(403, "Agent identity is temporarily suspended."),
    CustosErrorCode.ISSUER_REVOKED: ErrorSpec(403, "The asset issuer has been revoked."),
    CustosErrorCode.DELEGATION_INVALID: ErrorSpec(403, "Delegation chain is broken, expired, or widens its scope."),
    CustosErrorCode.TRUST_SCORE_LOW: ErrorSpec(403, "Agent trust score is below the required minimum."),
    CustosErrorCode.REVOCATION_STALE: ErrorSpec(503, "Revocation data is too stale to rely on; Custos fails closed."),
    CustosErrorCode.ORACLE_UNAVAILABLE: ErrorSpec(503, "The market oracle could not be reached; Custos fails closed."),
    CustosErrorCode.ORACLE_DATA_STALE: ErrorSpec(503, "The market observation is older than tolerance."),
    CustosErrorCode.DOWNSTREAM_UNREACHABLE: ErrorSpec(502, "The downstream service could not be reached."),
}


def http_status_for(code: CustosErrorCode) -> int:
    return ERROR_SPECS[code].http_status


class CustosError(Exception):
    """Structured protocol error. `verify_intent` returns codes; this is for callers who raise."""

    def __init__(self, code: CustosErrorCode, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code.value} {code.name}: {detail}" if detail else f"{code.value} {code.name}")

    def to_dict(self) -> dict[str, str]:
        return {
            "error": self.code.value,
            "error_name": self.code.name,
            "description": ERROR_SPECS[self.code].description,
            "detail": self.detail,
        }
