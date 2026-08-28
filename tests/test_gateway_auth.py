from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from custos_protocol.crypto import public_key_to_b64
from custos_protocol.models import Observation
from custos_protocol.passport import AgentPassport
from gateway import server


class FixedOracle:
    async def get_observation(self, tenor: str) -> Observation:
        raise AssertionError(f"Registration must not contact the oracle for {tenor}")


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


def registration(passport: AgentPassport) -> dict[str, str]:
    return {
        "agent_id": passport.agent.id,
        "public_key": public_key_to_b64(passport.public_key),
    }


def test_agent_registration_requires_the_administrator_key(client):
    passport = AgentPassport.create(domain="acme.com", agent_name="unauthenticated")

    assert client.post("/v1/agents", json=registration(passport)).status_code == 401
    assert client.post(
        "/v1/agents", json=registration(passport),
        headers={"X-Custos-Admin-Key": "wrong-key"},
    ).status_code == 401
    assert client.post(
        "/v1/agents", json=registration(passport), headers=admin_headers(),
    ).status_code == 201


def test_agent_registration_fails_closed_without_a_configured_administrator_key(client, monkeypatch):
    monkeypatch.setattr(server.config, "ADMIN_API_KEY", None)
    passport = AgentPassport.create(domain="acme.com", agent_name="no-admin-key")

    response = client.post(
        "/v1/agents", json=registration(passport), headers=admin_headers(),
    )
    assert response.status_code == 503


def test_agent_key_binding_cannot_be_replaced(client):
    original = AgentPassport.create(domain="acme.com", agent_name="bound-agent")
    replacement = AgentPassport.create(domain="acme.com", agent_name="replacement")

    assert client.post(
        "/v1/agents", json=registration(original), headers=admin_headers(),
    ).status_code == 201
    response = client.post("/v1/agents", json={
        "agent_id": original.agent.id,
        "public_key": public_key_to_b64(replacement.public_key),
    }, headers=admin_headers())

    assert response.status_code == 409
    assert public_key_to_b64(server.agent_keys.get(original.agent.id)) == public_key_to_b64(
        original.public_key,
    )


def test_ephemeral_gateway_key_emits_a_startup_warning(monkeypatch, caplog):
    monkeypatch.setattr(server.config, "PRIVATE_KEY_PATH", None)

    with caplog.at_level(logging.WARNING, logger=server.__name__):
        server._create_signer()

    assert "CUSTOS_PRIVATE_KEY is not configured" in caplog.text
