"""The verification pipeline — the only module that composes every layer.

Ordered, tier-gated, fail-fast. The step order is API surface, not an
implementation detail: the returned code names the most fundamental problem.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from custos_protocol.boundaries import check_boundaries
from custos_protocol.canonical import get_signable_payload
from custos_protocol.crypto import hmac_verify, verify_signature
from custos_protocol.drift import AssetTruthFailure, DriftConfig, check_asset_truth
from custos_protocol.errors import CustosErrorCode
from custos_protocol.models import (
    AssetScores,
    CheckOutcome,
    Claim,
    CustosEnvelope,
    Observation,
    RevocationStatus,
    VerificationResult,
    VerificationTier,
)
from custos_protocol.revocation import RevocationStore

SUPPORTED_VERSIONS = frozenset({"1.0.0"})
NONCE_PATTERN = re.compile(r"^nonce:[0-9a-f]{32}$")

_STEPS = (
    "version", "schema", "expiry", "clock_skew", "signature",
    "nonce_format", "replay", "boundaries", "revocation",
    "asset_truth", "attestation", "delegation", "trust",
)

# Phase 1 implements Tier 0 and Tier 1. A Tier 2 request is served at Tier 1 and
# the result says so, rather than claiming a tier it did not perform.
_MAX_IMPLEMENTED_TIER = VerificationTier.TIER_1
_TIER_ORDER = {VerificationTier.TIER_0: 0, VerificationTier.TIER_1: 1, VerificationTier.TIER_2: 2}


def _effective_tier(requested: VerificationTier) -> VerificationTier:
    if _TIER_ORDER[requested] > _TIER_ORDER[_MAX_IMPLEMENTED_TIER]:
        return _MAX_IMPLEMENTED_TIER
    return requested


def verify_intent(
    envelope: CustosEnvelope,
    public_key: Ed25519PublicKey,
    *,
    claim: Claim | None = None,
    observation: Observation | None = None,
    revocation_store: RevocationStore | None = None,
    drift_config: DriftConfig | None = None,
    hmac_key: bytes | None = None,
    request_geo: str | None = None,
    clock_skew_seconds: int = 5,
    max_revocation_staleness_ms: int = 500,
    now: datetime | None = None,
) -> VerificationResult:
    now = now or datetime.now(timezone.utc)
    store = revocation_store if revocation_store is not None else RevocationStore()
    config = drift_config or DriftConfig()
    tier = _effective_tier(envelope.verification_tier)

    checks: dict[str, CheckOutcome] = {step: CheckOutcome.NOT_RUN for step in _STEPS}

    def fail(step: str, codes: list[CustosErrorCode], detail: str,
             *, scores: AssetScores | None = None,
             reference: dict | None = None) -> VerificationResult:
        checks[step] = CheckOutcome.FAILED
        return VerificationResult(
            passed=False, checks=checks, tier_used=tier, errors=codes,
            detail=detail, scores=scores, reference=reference,
            revocation=store.freshness(max_revocation_staleness_ms),
        )

    # 1. Version
    if envelope.protocol_version not in SUPPORTED_VERSIONS:
        return fail("version", [CustosErrorCode.VERSION_UNSUPPORTED],
                    f"Protocol version {envelope.protocol_version} is not supported.")
    checks["version"] = CheckOutcome.PASSED

    # 2. Schema — Pydantic did the structural work; these are the semantic minimums.
    if not envelope.agent.id or not envelope.intent.action:
        return fail("schema", [CustosErrorCode.SCHEMA_INVALID],
                    "Envelope is missing an agent identity or an action.")
    checks["schema"] = CheckOutcome.PASSED

    # 3. Expiry, with a grace window for clock skew.
    if envelope.expires_at < now - timedelta(seconds=clock_skew_seconds):
        return fail("expiry", [CustosErrorCode.EXPIRED_ENVELOPE],
                    "Envelope expires_at is in the past.")
    checks["expiry"] = CheckOutcome.PASSED

    # 3b. Clock skew on issued_at.
    if envelope.issued_at > now + timedelta(minutes=5):
        return fail("clock_skew", [CustosErrorCode.CLOCK_SKEW],
                    "Envelope issued_at is more than five minutes in the future.")
    checks["clock_skew"] = CheckOutcome.PASSED

    # 4. Signature — BEFORE replay, so an unauthenticated caller cannot burn a nonce.
    if envelope.proof is None:
        return fail("signature", [CustosErrorCode.INVALID_SIGNATURE], "Envelope carries no proof.")
    payload = get_signable_payload(envelope, exclude={"proof"})
    if tier is VerificationTier.TIER_0 and hmac_key is not None:
        signature_ok = hmac_verify(hmac_key, payload, envelope.proof.proof_value)
    else:
        signature_ok = verify_signature(public_key, payload, envelope.proof.proof_value)
    if not signature_ok:
        return fail("signature", [CustosErrorCode.INVALID_SIGNATURE],
                    "Envelope signature failed verification.")
    checks["signature"] = CheckOutcome.PASSED

    # 5. Nonce format.
    if not NONCE_PATTERN.match(envelope.entropy):
        return fail("nonce_format", [CustosErrorCode.NONCE_INVALID],
                    "Envelope entropy is not a well-formed nonce.")
    checks["nonce_format"] = CheckOutcome.PASSED

    # 5b. Replay — consumes the nonce.
    if not store.check_nonce(envelope.entropy):
        return fail("replay", [CustosErrorCode.REPLAY_DETECTED],
                    "Envelope nonce has already been used.")
    checks["replay"] = CheckOutcome.PASSED

    # 6. Boundaries — accumulates every violation.
    violations = check_boundaries(envelope, claim, request_geo=request_geo, now=now)
    if violations:
        return fail("boundaries", violations,
                    "Envelope violates the agent's declared boundaries.")
    checks["boundaries"] = CheckOutcome.PASSED

    # 7. Revocation — every tier, and fails closed on stale data.
    revocation = store.freshness(max_revocation_staleness_ms)
    if revocation.stale:
        return fail("revocation", [CustosErrorCode.REVOCATION_STALE],
                    "Revocation data is too stale to rely on; Custos fails closed.")
    if store.is_revoked(envelope.agent.id):
        code = (CustosErrorCode.AGENT_SUSPENDED if store.is_suspended(envelope.agent.id)
                else CustosErrorCode.AGENT_REVOKED)
        return fail("revocation", [code], f"Agent {envelope.agent.id} is not permitted to transact.")
    if claim is not None and store.is_revoked(claim.issuer):
        return fail("revocation", [CustosErrorCode.ISSUER_REVOKED],
                    f"Issuer {claim.issuer} has been revoked.")
    checks["revocation"] = CheckOutcome.PASSED

    def succeed(scores: AssetScores | None, reference: dict | None) -> VerificationResult:
        return VerificationResult(
            passed=True, checks=checks, tier_used=tier, errors=[],
            detail=f"{tier.value} verification passed.",
            scores=scores, reference=reference, revocation=revocation,
        )

    # ---- Tier 0 exits here: authorization only, no market check ----
    if tier is VerificationTier.TIER_0:
        return succeed(None, None)

    # 8. Asset truth.
    outcome = check_asset_truth(claim, observation, config, now=now)
    if isinstance(outcome, AssetTruthFailure):
        return fail("asset_truth", [outcome.code], outcome.detail,
                    scores=outcome.scores, reference=outcome.reference)
    checks["asset_truth"] = CheckOutcome.PASSED
    reference = {
        "source": observation.source,
        "tenor": observation.tenor,
        "claimed_yield_bps": claim.claimed_yield_bps,
        "observed_yield_bps": observation.observed_yield_bps,
        "record_date": observation.record_date.isoformat(),
    }

    # 9. Attestation — opt-in; nothing to check without expected hashes.
    checks["attestation"] = CheckOutcome.PASSED

    # ---- Tier 1 exits here. Delegation and trust arrive in Phase 2. ----
    return succeed(outcome, reference)
