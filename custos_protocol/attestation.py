"""Signed verdict records.

Both verdicts are signed. A system that signs only approvals leaves a relying
party unable to prove it was denied.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, Field

from custos_protocol.canonical import canonical_bytes, get_signable_payload
from custos_protocol.crypto import (
    generate_keypair,
    public_key_to_b64,
    sign_data,
    verify_signature,
)
from custos_protocol.errors import CustosErrorCode
from custos_protocol.models import AssetScores, Proof, VerificationTier

CANONICALIZATION = "custos/canonical-v1"
_SIGNATURE_EXCLUDE = {"proof"}


class _SignedRecord(BaseModel):
    envelope_hash: str
    agent_id: str
    asset_id: str | None = None
    issued_at: datetime
    signature_alg: str = "Ed25519"
    canonicalization: str = CANONICALIZATION
    public_key: str
    proof: Proof | None = None


class Attestation(_SignedRecord):
    attestation_id: str
    verdict: Literal["ALLOW"] = "ALLOW"
    action: str
    amount: float | None = None
    tier_used: VerificationTier
    scores: AssetScores | None = None
    reference: dict[str, Any] | None = None
    expires_at: datetime


class Denial(_SignedRecord):
    denial_id: str
    verdict: Literal["BLOCK"] = "BLOCK"
    errors: list[CustosErrorCode] = Field(default_factory=list)
    detail: str = ""
    scores: AssetScores | None = None
    reference: dict[str, Any] | None = None


class RecordSigner:
    def __init__(self, private_key: Ed25519PrivateKey | None = None, *, ttl_seconds: int = 300) -> None:
        if private_key is None:
            private_key, _ = generate_keypair()
        self._private_key = private_key
        self._ttl_seconds = ttl_seconds

    @property
    def public_key_b64(self) -> str:
        return public_key_to_b64(self._private_key.public_key())

    @property
    def public_key_pem(self) -> str:
        from cryptography.hazmat.primitives import serialization

        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    def _attach_proof(self, record: _SignedRecord) -> Any:
        payload = get_signable_payload(record, exclude=_SIGNATURE_EXCLUDE)
        proof = Proof(
            created=record.issued_at,
            verification_method="custos-gateway#keys-1",
            proof_value=sign_data(self._private_key, payload),
        )
        return record.model_copy(update={"proof": proof})

    def sign_attestation(
        self,
        *,
        envelope_hash: str,
        agent_id: str,
        asset_id: str | None,
        action: str,
        amount: float | None,
        tier_used: VerificationTier,
        scores: AssetScores | None = None,
        reference: dict[str, Any] | None = None,
    ) -> Attestation:
        issued_at = datetime.now(timezone.utc).replace(microsecond=0)
        record = Attestation(
            attestation_id=f"att_{uuid.uuid4().hex}",
            envelope_hash=envelope_hash,
            agent_id=agent_id,
            asset_id=asset_id,
            action=action,
            amount=amount,
            tier_used=tier_used,
            scores=scores,
            reference=reference,
            issued_at=issued_at,
            expires_at=issued_at + timedelta(seconds=self._ttl_seconds),
            public_key=self.public_key_b64,
        )
        return self._attach_proof(record)

    def sign_denial(
        self,
        *,
        envelope_hash: str,
        agent_id: str,
        asset_id: str | None = None,
        errors: list[CustosErrorCode],
        detail: str = "",
        scores: AssetScores | None = None,
        reference: dict[str, Any] | None = None,
    ) -> Denial:
        record = Denial(
            denial_id=f"den_{uuid.uuid4().hex}",
            envelope_hash=envelope_hash,
            agent_id=agent_id,
            asset_id=asset_id,
            errors=errors,
            detail=detail,
            scores=scores,
            reference=reference,
            issued_at=datetime.now(timezone.utc).replace(microsecond=0),
            public_key=self.public_key_b64,
        )
        return self._attach_proof(record)


def verify_record(record: dict[str, Any], public_key: Ed25519PublicKey) -> bool:
    """Verify a served record against a **pinned** key.

    The caller must supply the key out-of-band (GET /v1/pubkey). Trusting the
    ``public_key`` embedded in the record authenticates nothing — an attacker can
    re-sign arbitrary content with their own key and update that field to match.
    """
    proof = record.get("proof")
    if not isinstance(proof, dict) or "proof_value" not in proof:
        return False
    payload = canonical_bytes(record, exclude=_SIGNATURE_EXCLUDE)
    return verify_signature(public_key, payload, proof["proof_value"])
