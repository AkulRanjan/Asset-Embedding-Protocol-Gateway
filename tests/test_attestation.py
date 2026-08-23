from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from custos_protocol.attestation import Attestation, Denial, RecordSigner, verify_record
from custos_protocol.crypto import generate_keypair
from custos_protocol.errors import CustosErrorCode
from custos_protocol.models import AssetScores, VerificationTier


def signer() -> RecordSigner:
    return RecordSigner()


def allow_fields() -> dict:
    return {
        "envelope_hash": "a" * 64,
        "agent_id": "did:web:acme.com:agents:bot",
        "asset_id": "TKN-UST-3M-001",
        "action": "borrow_against",
        "amount": 50000,
        "tier_used": VerificationTier.TIER_1,
        "scores": AssetScores(staleness_hours=1.0, backing_ratio=1.0),
        "reference": {"source": "test", "observed_yield_bps": 400},
    }


def test_attestation_is_signed_and_verifies():
    record_signer = signer()
    attestation = record_signer.sign_attestation(**allow_fields())
    assert attestation.verdict == "ALLOW"
    assert attestation.proof is not None
    assert verify_record(attestation.model_dump(mode="json"), record_signer.public_key) is True


def test_denial_is_also_signed():
    """Today only ALLOW is signed, so a denial cannot be proved."""
    record_signer = signer()
    denial = record_signer.sign_denial(
        envelope_hash="b" * 64,
        agent_id="did:web:acme.com:agents:bot",
        asset_id="TKN-UST-3M-003",
        errors=[CustosErrorCode.YIELD_DRIFT_EXCEEDED],
        detail="drift 6.98% > 2.0%",
        scores=AssetScores(yield_drift=0.0698),
    )
    assert denial.verdict == "BLOCK"
    assert verify_record(denial.model_dump(mode="json"), record_signer.public_key) is True


def test_attestation_id_is_prefixed_and_unique():
    record_signer = signer()
    first = record_signer.sign_attestation(**allow_fields())
    second = record_signer.sign_attestation(**allow_fields())
    assert first.attestation_id.startswith("att_")
    assert first.attestation_id != second.attestation_id


def test_expires_at_follows_the_configured_ttl():
    attestation = RecordSigner(ttl_seconds=120).sign_attestation(**allow_fields())
    assert (attestation.expires_at - attestation.issued_at).total_seconds() == 120


def test_tampering_with_any_signed_field_breaks_verification():
    record_signer = signer()
    served = record_signer.sign_attestation(**allow_fields()).model_dump(mode="json")

    for field, replacement in [
        ("amount", 1),
        ("asset_id", "TKN-OTHER"),
        ("agent_id", "did:web:evil.com:agents:bot"),
        ("envelope_hash", "c" * 64),
    ]:
        tampered = dict(served)
        tampered[field] = replacement
        assert verify_record(tampered, record_signer.public_key) is False


def test_tampering_with_nested_scores_breaks_verification():
    record_signer = signer()
    served = record_signer.sign_attestation(**allow_fields()).model_dump(mode="json")
    tampered = dict(served)
    tampered["scores"] = dict(served["scores"])
    tampered["scores"]["backing_ratio"] = 99.0
    assert verify_record(tampered, record_signer.public_key) is False


def test_verify_record_rejects_a_foreign_key():
    """Key substitution must fail against a pinned key. Consumers MUST pin."""
    served = signer().sign_attestation(**allow_fields()).model_dump(mode="json")
    _, foreign_public = generate_keypair()
    assert verify_record(served, foreign_public) is False


def test_record_survives_a_json_round_trip():
    """The independent verifier receives JSON off the wire, not a model."""
    record_signer = signer()
    served = record_signer.sign_attestation(**allow_fields()).model_dump(mode="json")
    reparsed = json.loads(json.dumps(served))
    assert verify_record(reparsed, record_signer.public_key) is True


def test_signer_exposes_both_key_encodings():
    record_signer = signer()
    assert len(record_signer.public_key_b64) > 0
    assert record_signer.public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")


def test_records_declare_their_own_verification_procedure():
    attestation = signer().sign_attestation(**allow_fields())
    assert attestation.signature_alg == "Ed25519"
    assert attestation.canonicalization == "custos/canonical-v1"
