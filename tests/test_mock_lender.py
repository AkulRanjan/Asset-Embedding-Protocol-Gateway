"""The reference downstream consumer must reject attestations that prove nothing about the asset."""

from __future__ import annotations

import base64
import json

import pytest
from fastapi.testclient import TestClient

from custos_protocol.attestation import RecordSigner
from custos_protocol.models import VerificationTier
from demo import mock_lender

LOAN = {"intent": {"action": "borrow_against", "target": "TKN-UST-3M-001",
                   "parameters": {"amount": 50000}}}


@pytest.fixture
def signer(monkeypatch):
    signer = RecordSigner()
    monkeypatch.setattr(mock_lender, "CUSTOS_PUBLIC_KEY", signer.public_key_b64)
    return signer


def submit(signer, *, action="borrow_against", tier=VerificationTier.TIER_1):
    attestation = signer.sign_attestation(
        envelope_hash="abc", agent_id="did:web:acme.com:agents:bot", asset_id="TKN-UST-3M-001",
        action=action, amount=50000, tier_used=tier, scores=None, reference=None,
    )
    header = base64.b64encode(json.dumps(attestation.model_dump(mode="json")).encode()).decode()
    return TestClient(mock_lender.app).post(
        "/loan", json=LOAN, headers={"X-Custos-Attestation": header}).json()


def test_a_tier_1_borrow_attestation_is_accepted(signer):
    assert submit(signer)["accepted"] is True


def test_a_tier_0_attestation_is_rejected_because_no_asset_check_ran(signer):
    assert submit(signer, tier=VerificationTier.TIER_0)["accepted"] is False


def test_an_attestation_for_another_action_is_rejected(signer):
    assert submit(signer, action="trade")["accepted"] is False
