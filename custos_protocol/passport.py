"""The identity object: DID, keypair, and the policy cage that travels inside every envelope."""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from custos_protocol.crypto import (
    b64_to_public_key,
    generate_keypair,
    load_private_key,
    load_public_key,
    public_key_to_b64,
    save_private_key,
    save_public_key,
)
from custos_protocol.models import (
    AgentAttestation,
    AgentIdentity,
    AttestationMethod,
    Boundaries,
    DelegationLink,
    MonetaryLimit,
    Principal,
)


class AgentPassport:
    """Holds models plus live key objects. Deliberately not a Pydantic model."""

    def __init__(
        self,
        agent: AgentIdentity,
        principal: Principal,
        boundaries: Boundaries,
        public_key: Ed25519PublicKey,
        private_key: Ed25519PrivateKey | None = None,
    ) -> None:
        self.agent = agent
        self.principal = principal
        self.boundaries = boundaries
        self._public_key = public_key
        self._private_key = private_key

    @classmethod
    def create(
        cls,
        domain: str,
        agent_name: str | None = None,
        *,
        version: str = "1.0.0",
        principal_id: str | None = None,
        principal_type: str = "organization",
        allowed_actions: list[str] | None = None,
        denied_actions: list[str] | None = None,
        monetary_limit_per_txn: float = 0.0,
        monetary_limit_per_day: float = 0.0,
        currency: str = "USD",
        asset_classes: list[str] | None = None,
        geo_restriction: str | None = None,
        framework_id: str | None = None,
        system_prompt_hash: str | None = None,
    ) -> AgentPassport:
        agent_name = agent_name or f"agent-{secrets.token_hex(4)}"
        agent_id = f"did:web:{domain}:agents:{agent_name}"
        principal_id = principal_id or f"did:web:{domain}"

        private_key, public_key = generate_keypair()

        attestation = AgentAttestation(
            method=AttestationMethod.FRAMEWORK_REGISTRY if framework_id else AttestationMethod.SELF_REPORTED,
            framework_id=framework_id,
            system_prompt_hash=system_prompt_hash,
        )
        agent = AgentIdentity(id=agent_id, version=version, attestation=attestation)

        principal = Principal(
            type=principal_type,
            id=principal_id,
            delegation_chain=[
                DelegationLink(
                    from_id=principal_id,
                    to_id=agent_id,
                    scope="default",
                    boundary_monotonicity=True,
                    granted_at=datetime.now(timezone.utc),
                )
            ],
        )

        boundaries = Boundaries(
            allowed_actions=allowed_actions or [],
            denied_actions=denied_actions or [],
            monetary_limit=MonetaryLimit(
                per_transaction=monetary_limit_per_txn,
                per_day=monetary_limit_per_day,
                currency=currency,
            ),
            asset_classes=asset_classes or [],
            geo_restriction=geo_restriction,
        )

        return cls(agent, principal, boundaries, public_key, private_key)

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._public_key

    @property
    def private_key(self) -> Ed25519PrivateKey:
        if self._private_key is None:
            raise ValueError("No private key loaded — passport may be public-only")
        return self._private_key

    def to_dict(self) -> dict:
        return {
            "agent": self.agent.model_dump(mode="json"),
            "principal": self.principal.model_dump(mode="json", by_alias=True),
            "boundaries": self.boundaries.model_dump(mode="json"),
            "public_key": public_key_to_b64(self._public_key),
        }

    def save(self, directory: Path) -> None:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "passport.json").write_text(
            json.dumps(self.to_dict(), indent=2), encoding="utf-8"
        )
        save_public_key(self._public_key, directory / "public.pem")
        if self._private_key is not None:
            save_private_key(self._private_key, directory / "private.pem")

    @classmethod
    def load(cls, directory: Path) -> AgentPassport:
        directory = Path(directory)
        data = json.loads((directory / "passport.json").read_text(encoding="utf-8"))

        private_key: Ed25519PrivateKey | None = None
        private_path = directory / "private.pem"
        public_path = directory / "public.pem"

        # Key precedence: private.pem (derive public) -> public.pem -> passport.json
        if private_path.exists():
            private_key = load_private_key(private_path)
            public_key = private_key.public_key()
        elif public_path.exists():
            public_key = load_public_key(public_path)
        else:
            public_key = b64_to_public_key(data["public_key"])

        return cls(
            agent=AgentIdentity.model_validate(data["agent"]),
            principal=Principal.model_validate(data["principal"]),
            boundaries=Boundaries.model_validate(data["boundaries"]),
            public_key=public_key,
            private_key=private_key,
        )
