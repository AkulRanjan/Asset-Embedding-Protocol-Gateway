"""HTTP surface. Parse, resolve domain inputs, verify, sign, render."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ValidationError

from claims import ClaimRegistry
from custos_protocol.attestation import RecordSigner
from custos_protocol.crypto import load_private_key
from custos_protocol.envelope import envelope_hash
from custos_protocol.errors import CustosErrorCode, http_status_for
from custos_protocol.models import CustosEnvelope, VerificationTier
from custos_protocol.revocation import RevocationStore, SubjectType
from custos_protocol.verification import verify_intent
from gateway import config
from gateway.auth import require_admin
from gateway.keys import AgentAlreadyRegistered, AgentKeyRegistry
from gateway.proxy import forward
from oracle.treasury import TreasuryOracle, UnsupportedTenor

app = FastAPI(
    title="Custos Gateway",
    version="1.0.0",
    description="Pre-transaction asset-truth attestation for autonomous agents.",
)

logger = logging.getLogger(__name__)

registry = ClaimRegistry()
oracle = TreasuryOracle(
    timeout_seconds=config.ORACLE_TIMEOUT_SECONDS,
    cache_ttl_seconds=config.ORACLE_CACHE_TTL_SECONDS,
)
revocations = RevocationStore()
agent_keys = AgentKeyRegistry()
drift_config = config.load_drift_config()
def _create_signer() -> RecordSigner:
    if config.PRIVATE_KEY_PATH:
        return RecordSigner(
            load_private_key(Path(config.PRIVATE_KEY_PATH)),
            ttl_seconds=config.ATTESTATION_TTL_SECONDS,
        )
    logger.warning(
        "CUSTOS_PRIVATE_KEY is not configured; using an ephemeral gateway signing key. "
        "Attestations will become unverifiable after restart."
    )
    return RecordSigner(ttl_seconds=config.ATTESTATION_TTL_SECONDS)


signer = _create_signer()


def _render(model: Any, status_code: int = 200) -> JSONResponse:
    return JSONResponse(status_code=status_code, content=jsonable_encoder(model))


def _deny(envelope_hash_value: str, agent_id: str, asset_id: str | None,
          errors: list[CustosErrorCode], detail: str,
          scores=None, reference=None) -> JSONResponse:
    denial = signer.sign_denial(
        envelope_hash=envelope_hash_value, agent_id=agent_id, asset_id=asset_id,
        errors=errors, detail=detail, scores=scores, reference=reference,
    )
    return _render(denial, http_status_for(errors[0]))


def _field_errors(exc: RequestValidationError) -> str:
    """Per-field loc/msg, never the submitted value — an error response must not
    echo back potentially sensitive input."""
    parts = [
        f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
        for error in exc.errors()
    ]
    return "; ".join(parts) or "Envelope failed schema validation."


@app.exception_handler(RequestValidationError)
async def _schema_error(_: Request, exc: RequestValidationError) -> JSONResponse:
    denial = signer.sign_denial(
        envelope_hash="", agent_id="", errors=[CustosErrorCode.SCHEMA_INVALID],
        detail=_field_errors(exc),
    )
    return _render(denial, http_status_for(CustosErrorCode.SCHEMA_INVALID))


class AgentRegistration(BaseModel):
    agent_id: str
    public_key: str


@app.post("/v1/agents", status_code=201)
async def register_agent(registration: AgentRegistration, _: None = Depends(require_admin)) -> dict:
    try:
        agent_keys.register(registration.agent_id, registration.public_key)
    except AgentAlreadyRegistered as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An Ed25519 public key is already registered for this agent.",
        ) from exc
    return {"registered": registration.agent_id}


async def _resolve(envelope: CustosEnvelope):
    """Returns (claim, observation, tenor_error)."""
    claim = registry.get_claim(envelope.intent.target)
    if claim is None:
        return None, None, None
    try:
        observation = await oracle.get_observation(claim.underlying_tenor)
    except UnsupportedTenor:
        return claim, None, CustosErrorCode.TENOR_UNSUPPORTED
    return claim, observation, None


def _log_decision(*, started: float, agent_id: str, asset_id: str | None,
                   tier: str, verdict: str, errors: list[CustosErrorCode]) -> None:
    latency_ms = (time.monotonic() - started) * 1000
    logger.info(
        "intent decision verdict=%s errors=%s agent_id=%s asset_id=%s tier=%s latency_ms=%.2f",
        verdict, [code.value for code in errors], agent_id, asset_id, tier, latency_ms,
    )


@app.post("/v1/intent", response_model=None)
async def post_intent(envelope: CustosEnvelope, request: Request):
    started = time.monotonic()
    digest = envelope_hash(envelope)
    tier = envelope.verification_tier.value

    public_key = agent_keys.get(envelope.agent.id)
    if public_key is None:
        _log_decision(started=started, agent_id=envelope.agent.id, asset_id=envelope.intent.target,
                      tier=tier, verdict="BLOCK", errors=[CustosErrorCode.INVALID_SIGNATURE])
        return _deny(digest, envelope.agent.id, envelope.intent.target,
                     [CustosErrorCode.INVALID_SIGNATURE],
                     f"No registered key for agent {envelope.agent.id}; signature cannot be verified.")

    claim = observation = None
    if envelope.verification_tier is not VerificationTier.TIER_0:
        claim, observation, tenor_error = await _resolve(envelope)
        if tenor_error is not None:
            _log_decision(started=started, agent_id=envelope.agent.id, asset_id=envelope.intent.target,
                          tier=tier, verdict="BLOCK", errors=[tenor_error])
            return _deny(digest, envelope.agent.id, envelope.intent.target,
                         [tenor_error],
                         f"Tenor {claim.underlying_tenor} has no yield-curve mapping.")

    result = verify_intent(
        envelope, public_key,
        claim=claim, observation=observation,
        revocation_store=revocations, drift_config=drift_config,
        request_geo=request.headers.get("X-Custos-Geo"),
        clock_skew_seconds=drift_config.clock_skew_seconds,
    )
    _log_decision(started=started, agent_id=envelope.agent.id, asset_id=envelope.intent.target,
                  tier=result.tier_used.value, verdict="ALLOW" if result.passed else "BLOCK",
                  errors=result.errors)

    if not result.passed:
        return _deny(digest, envelope.agent.id, envelope.intent.target,
                     result.errors, result.detail, result.scores, result.reference)

    attestation = signer.sign_attestation(
        envelope_hash=digest, agent_id=envelope.agent.id,
        asset_id=envelope.intent.target, action=envelope.intent.action.value,
        amount=envelope.intent.parameters.get("amount"),
        tier_used=result.tier_used, scores=result.scores, reference=result.reference,
    )

    downstream_url = envelope.intent.parameters.get("downstream")
    if not downstream_url:
        return _render(attestation)

    try:
        downstream = await forward(str(downstream_url), envelope, attestation)
    except ConnectionError:
        return _render(
            {"attestation": jsonable_encoder(attestation),
             "downstream": {"errors": [CustosErrorCode.DOWNSTREAM_UNREACHABLE.value],
                            "detail": "The downstream service could not be reached."}},
            http_status_for(CustosErrorCode.DOWNSTREAM_UNREACHABLE),
        )
    return _render({"attestation": attestation, "downstream": downstream})


@app.get("/v1/assets")
async def list_assets():
    return _render({"assets": registry.list_claims()})


@app.get("/v1/assets/{asset_id}", response_model=None)
async def get_asset(asset_id: str):
    claim = registry.get_claim(asset_id)
    if claim is None:
        return _deny("", "diagnostic", asset_id, [CustosErrorCode.UNKNOWN_ASSET],
                     "The requested asset is not present in the claim registry.")
    try:
        observation = await oracle.get_observation(claim.underlying_tenor)
    except UnsupportedTenor:
        observation = None

    from custos_protocol.drift import check_asset_truth

    evaluation = check_asset_truth(claim, observation, drift_config)
    return _render({"claim": claim, "observation": observation, "evaluation": evaluation})


@app.get("/v1/pubkey")
async def get_public_key():
    return {
        "algorithm": "Ed25519",
        "public_key": signer.public_key_b64,
        "public_key_pem": signer.public_key_pem,
    }


@app.get("/v1/health", response_model=None)
async def health():
    try:
        observation = await oracle.get_observation("3M")
    except UnsupportedTenor:  # pragma: no cover - impossible unless the map changes
        observation = None
    ok = observation is not None
    return _render(
        {"status": "ok" if ok else "degraded",
         "oracle_reachable": ok,
         "observation": observation},
        200 if ok else 503,
    )


@app.get("/demo", include_in_schema=False)
async def live_demo_page():
    return FileResponse(Path(__file__).resolve().parents[1] / "demo" / "live.html")


# ---- demo-only routes, mounted only when CUSTOS_DEMO_MODE is set ----

demo_router = APIRouter()


@demo_router.post("/v1/demo/sync", response_model=None)
async def sync_live_demo_claims(_: None = Depends(require_admin)):
    """Align simulated demo claims to current observations. Never touches a real source of truth."""
    observations: dict[str, Any] = {}
    for tenor in {claim.underlying_tenor for claim in registry.list_claims()}:
        try:
            observation = await oracle.get_observation(tenor)
        except UnsupportedTenor:
            return _render({"errors": [CustosErrorCode.TENOR_UNSUPPORTED.value]}, 422)
        if observation is None:
            return _render({"errors": [CustosErrorCode.ORACLE_UNAVAILABLE.value]}, 503)
        observations[tenor] = observation

    updated = []
    for claim in registry.list_claims():
        observed = observations[claim.underlying_tenor].observed_yield_bps
        if claim.asset_id == "TKN-UST-3M-003":
            yield_bps = max(1, observed - max(40, round(observed * 0.04)))
        else:
            yield_bps = observed
        synced = registry.update_claim(claim.asset_id, claimed_yield_bps=yield_bps)
        if synced:
            updated.append({"asset_id": synced.asset_id, "claimed_yield_bps": synced.claimed_yield_bps})

    return _render({
        "mode": "live-market-demo",
        "notice": "Market observations are live; claim records remain simulated in memory.",
        "observations": observations,
        "updated_claims": updated,
    })


if config.DEMO_MODE:
    app.include_router(demo_router)
