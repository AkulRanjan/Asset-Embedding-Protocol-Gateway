from __future__ import annotations

import json

import pytest

from custos_protocol.crypto import sign_data, verify_signature
from custos_protocol.models import AttestationMethod
from custos_protocol.passport import AgentPassport


def test_create_synthesises_did_identities():
    passport = AgentPassport.create(domain="acme.com", agent_name="treasury-bot")
    assert passport.agent.id == "did:web:acme.com:agents:treasury-bot"
    assert passport.principal.id == "did:web:acme.com"


def test_agent_name_defaults_to_random_suffix():
    passport = AgentPassport.create(domain="acme.com")
    assert passport.agent.id.startswith("did:web:acme.com:agents:agent-")
    assert len(passport.agent.id.rsplit("-", 1)[-1]) == 8


def test_create_ships_a_one_hop_delegation_chain():
    """Every passport is born with a well-formed principal to agent link."""
    passport = AgentPassport.create(domain="acme.com", agent_name="bot", allowed_actions=["trade"])
    assert len(passport.principal.delegation_chain) == 1
    link = passport.principal.delegation_chain[0]
    assert link.from_id == "did:web:acme.com"
    assert link.to_id == "did:web:acme.com:agents:bot"
    assert link.boundary_monotonicity is True
    # The auto-generated hop grants exactly the agent's own cage, so a fresh
    # passport trivially satisfies delegation monotonicity out of the box.
    assert link.boundaries == passport.boundaries


def test_attestation_method_depends_on_framework_id():
    assert AgentPassport.create(domain="a.com").agent.attestation.method is AttestationMethod.SELF_REPORTED
    framework = AgentPassport.create(domain="a.com", framework_id="langchain")
    assert framework.agent.attestation.method is AttestationMethod.FRAMEWORK_REGISTRY
    assert framework.agent.attestation.framework_id == "langchain"


def test_boundaries_are_built_from_flat_kwargs():
    passport = AgentPassport.create(
        domain="acme.com",
        allowed_actions=["borrow_against"],
        denied_actions=["redeem"],
        monetary_limit_per_txn=100000.0,
        monetary_limit_per_day=250000.0,
        asset_classes=["treasury"],
    )
    assert passport.boundaries.allowed_actions == ["borrow_against"]
    assert passport.boundaries.denied_actions == ["redeem"]
    assert passport.boundaries.monetary_limit.per_transaction == 100000.0
    assert passport.boundaries.monetary_limit.per_day == 250000.0
    assert passport.boundaries.asset_classes == ["treasury"]


def test_keys_are_usable_for_signing():
    passport = AgentPassport.create(domain="acme.com")
    signature = sign_data(passport.private_key, b"payload")
    assert verify_signature(passport.public_key, b"payload", signature) is True


def test_save_writes_three_files(tmp_path):
    AgentPassport.create(domain="acme.com", agent_name="bot").save(tmp_path)
    assert (tmp_path / "passport.json").exists()
    assert (tmp_path / "private.pem").exists()
    assert (tmp_path / "public.pem").exists()


def test_save_load_round_trip_preserves_identity_and_keys(tmp_path):
    original = AgentPassport.create(domain="acme.com", agent_name="bot",
                                    allowed_actions=["trade"])
    original.save(tmp_path)
    loaded = AgentPassport.load(tmp_path)
    assert loaded.agent.id == original.agent.id
    assert loaded.boundaries.allowed_actions == ["trade"]
    signature = sign_data(loaded.private_key, b"payload")
    assert verify_signature(original.public_key, b"payload", signature) is True


def test_public_only_passport_can_verify_but_not_sign(tmp_path):
    """Ship passport.json without the PEMs and you get a verifier-only passport."""
    AgentPassport.create(domain="acme.com", agent_name="bot").save(tmp_path)
    (tmp_path / "private.pem").unlink()
    (tmp_path / "public.pem").unlink()
    loaded = AgentPassport.load(tmp_path)
    assert loaded.public_key is not None
    with pytest.raises(ValueError, match="public-only"):
        _ = loaded.private_key


def test_to_dict_never_leaks_the_private_key(tmp_path):
    data = AgentPassport.create(domain="acme.com").to_dict()
    serialized = json.dumps(data)
    assert "PRIVATE" not in serialized
    assert "private_key" not in data
    assert "public_key" in data
