from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from custos_protocol.attestation import verify_record
from custos_protocol.crypto import b64_to_public_key, public_key_to_b64
from custos_protocol.envelope import create_envelope, sign_envelope
from custos_protocol.models import Action, Observation, VerificationTier
from custos_protocol.passport import AgentPassport
from custos_protocol.revocation import SubjectType
from gateway import server


class FixedOracle:
    async def get_observation(self, tenor: str) -> Observation:
        stamp = datetime.now(timezone.utc)
        return Observation(source="test-oracle", tenor=tenor, observed_yield_bps=400,
                           record_date=stamp.date(), fetched_at=stamp)


class DeadOracle:
    async def get_observation(self, tenor: str) -> None:
        return None


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(server, "oracle", FixedOracle())
    monkeypatch.setattr(server.config, "ADMIN_API_KEY", "test-admin-key")
    server.registry = server.ClaimRegistry()
    server.revocations = server.RevocationStore()
    server.agent_keys = server.AgentKeyRegistry()
    return TestClient(server.app)


def admin_headers() -> dict[str, str]:
    return {"X-Custos-Admin-Key": "test-admin-key"}


@pytest.fixture
def agent(client):
    passport = AgentPassport.create(
        domain="acme.com", agent_name="treasury-bot",
        allowed_actions=["borrow_against", "trade", "read"],
        monetary_limit_per_txn=100000.0, asset_classes=["treasury"],
    )
    response = client.post("/v1/agents", json={
        "agent_id": passport.agent.id,
        "public_key": public_key_to_b64(passport.public_key),
    }, headers=admin_headers())
    assert response.status_code == 201
    return passport


def envelope_json(passport, asset="TKN-UST-3M-001", action=Action.BORROW_AGAINST,
                  amount=50000, **kw):
    envelope = create_envelope(passport, action, asset, {"amount": amount, "currency": "USD"}, **kw)
    return sign_envelope(envelope, passport.private_key).model_dump(mode="json", by_alias=True)


def test_healthy_envelope_returns_a_signed_attestation(client, agent):
    response = client.post("/v1/intent", json=envelope_json(agent))
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "ALLOW"
    assert body["tier_used"] == VerificationTier.TIER_1.value


def test_allow_is_independently_verifiable_against_the_published_key(client, agent):
    served = client.post("/v1/intent", json=envelope_json(agent)).json()
    published = client.get("/v1/pubkey").json()["public_key"]
    assert verify_record(served, b64_to_public_key(published)) is True


def test_denial_is_signed_and_verifiable(client, agent):
    served = client.post("/v1/intent", json=envelope_json(agent, asset="TKN-UST-3M-003")).json()
    published = client.get("/v1/pubkey").json()["public_key"]
    assert served["verdict"] == "BLOCK"
    assert "CUSTOS-E301" in served["errors"]
    assert verify_record(served, b64_to_public_key(published)) is True


def test_malformed_envelope_is_a_structured_400(client):
    response = client.post("/v1/intent", json={})
    assert response.status_code == 400
    assert response.json()["errors"] == ["CUSTOS-E103"]


def test_malformed_envelope_detail_names_the_missing_fields_without_echoing_input(client):
    response = client.post("/v1/intent", json={"agent": {"id": "x"}, "entropy": "s3cr3t-value"})
    detail = response.json()["detail"]
    assert "intent" in detail
    assert "Field required" in detail
    # Per-field messages must never echo the submitted value back to the caller.
    assert "s3cr3t-value" not in detail


def test_unregistered_agent_cannot_be_verified(client):
    stranger = AgentPassport.create(domain="evil.com", agent_name="bot")
    response = client.post("/v1/intent", json=envelope_json(stranger))
    assert response.status_code == 401
    assert response.json()["errors"] == ["CUSTOS-E100"]


def test_stale_claim_is_blocked_with_403(client, agent):
    response = client.post("/v1/intent", json=envelope_json(agent, asset="TKN-UST-3M-002"))
    assert response.status_code == 403
    assert "CUSTOS-E300" in response.json()["errors"]


def test_under_backed_claim_is_blocked(client, agent):
    response = client.post("/v1/intent", json=envelope_json(agent, asset="TKN-UST-6M-004"))
    assert response.status_code == 403
    assert "CUSTOS-E302" in response.json()["errors"]


def test_unknown_asset_is_404_and_precedes_the_oracle(client, agent):
    response = client.post("/v1/intent", json=envelope_json(agent, asset="NOPE"))
    assert response.status_code == 404
    assert "CUSTOS-E303" in response.json()["errors"]


def test_replayed_envelope_is_409(client, agent):
    payload = envelope_json(agent)
    assert client.post("/v1/intent", json=payload).status_code == 200
    replayed = client.post("/v1/intent", json=payload)
    assert replayed.status_code == 409
    assert "CUSTOS-E102" in replayed.json()["errors"]


def test_revoked_agent_is_blocked(client, agent):
    server.revocations.revoke(agent.agent.id, SubjectType.AGENT, reason="compromised")
    response = client.post("/v1/intent", json=envelope_json(agent))
    assert response.status_code == 403
    assert "CUSTOS-E400" in response.json()["errors"]


def test_oracle_failure_fails_closed_with_503(client, agent, monkeypatch):
    monkeypatch.setattr(server, "oracle", DeadOracle())
    response = client.post("/v1/intent", json=envelope_json(agent))
    assert response.status_code == 503
    assert "CUSTOS-E500" in response.json()["errors"]


def test_read_action_needs_no_market_data(client, agent, monkeypatch):
    monkeypatch.setattr(server, "oracle", DeadOracle())
    response = client.post("/v1/intent", json=envelope_json(agent, action=Action.READ, amount=0))
    assert response.status_code == 200
    assert response.json()["tier_used"] == VerificationTier.TIER_0.value


def test_assets_endpoints(client):
    listing = client.get("/v1/assets")
    assert listing.status_code == 200
    assert len(listing.json()["assets"]) == 4

    detail = client.get("/v1/assets/TKN-UST-3M-001")
    assert detail.status_code == 200
    assert detail.json()["claim"]["asset_class"] == "treasury"
    assert detail.json()["evaluation"] is not None

    assert client.get("/v1/assets/NOPE").status_code == 404


def test_pubkey_exposes_both_encodings(client):
    body = client.get("/v1/pubkey").json()
    assert body["algorithm"] == "Ed25519"
    assert body["public_key_pem"].startswith("-----BEGIN PUBLIC KEY-----")


def test_health_reports_oracle_state(client, monkeypatch):
    assert client.get("/v1/health").json()["status"] == "ok"
    monkeypatch.setattr(server, "oracle", DeadOracle())
    degraded = client.get("/v1/health")
    assert degraded.status_code == 503
    assert degraded.json()["status"] == "degraded"


def test_demo_sync_is_absent_unless_demo_mode_is_enabled(client):
    """It rewrites every claim in the registry; it must not be exposed by default."""
    assert client.post("/v1/demo/sync").status_code == 404
    assert "/v1/demo/sync" not in client.get("/openapi.json").json()["paths"]


def test_the_configured_oracle_timeout_clears_the_measured_feed_latency(monkeypatch):
    """gateway.config supplies the timeout the server actually runs with, so a correct
    default on TreasuryOracle is not enough. Treasury's OData feed was measured at
    8.2-9.5 s cold on 2026-08-22; the former 3.0 s default cut every fetch short."""
    monkeypatch.delenv("CUSTOS_ORACLE_TIMEOUT", raising=False)
    import importlib

    from gateway import config as config_module

    reloaded = importlib.reload(config_module)
    try:
        assert reloaded.ORACLE_TIMEOUT_SECONDS >= 12.0
    finally:
        importlib.reload(config_module)
