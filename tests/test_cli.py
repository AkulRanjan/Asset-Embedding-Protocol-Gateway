from __future__ import annotations

import json
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

import pytest
from click.testing import CliRunner

from custos_protocol.cli import cli
from custos_protocol.crypto import public_key_to_b64, save_public_key
from custos_protocol.passport import AgentPassport


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def test_create_passport_writes_three_files(runner: CliRunner, tmp_path: Path):
    out = tmp_path / "passport"
    result = runner.invoke(cli, [
        "create-passport", "-d", "acme.com", "-n", "treasury-bot",
        "-a", "trade", "-a", "read", "--deny", "redeem",
        "-m", "100000", "--daily-limit", "250000", "-o", str(out),
    ])
    assert result.exit_code == 0, result.output
    assert (out / "passport.json").exists()
    assert (out / "private.pem").exists()
    assert (out / "public.pem").exists()

    loaded = AgentPassport.load(out)
    assert loaded.agent.id == "did:web:acme.com:agents:treasury-bot"
    assert loaded.boundaries.allowed_actions == ["trade", "read"]
    assert loaded.boundaries.denied_actions == ["redeem"]
    assert loaded.boundaries.monetary_limit.per_transaction == 100000.0
    assert loaded.boundaries.monetary_limit.per_day == 250000.0


def test_create_passport_rejects_an_invalid_action(runner: CliRunner, tmp_path: Path):
    result = runner.invoke(cli, [
        "create-passport", "-d", "acme.com", "-a", "not-a-real-action", "-o", str(tmp_path / "p"),
    ])
    assert result.exit_code != 0


def _make_passport(tmp_path: Path, **kw) -> Path:
    out = tmp_path / "passport"
    holder = AgentPassport.create(domain="acme.com", agent_name="bot", **kw)
    holder.save(out)
    return out


def test_sign_intent_prints_a_signed_envelope(runner: CliRunner, tmp_path: Path):
    passport_dir = _make_passport(tmp_path, allowed_actions=["read"])
    result = runner.invoke(cli, [
        "sign-intent", "-p", str(passport_dir), "-a", "read", "-t", "TKN-UST-3M-001",
    ])
    assert result.exit_code == 0, result.output
    envelope = json.loads(result.output)
    assert envelope["@type"] == "CustosEnvelope"
    assert envelope["intent"]["action"] == "read"
    assert envelope["proof"] is not None


def test_sign_intent_writes_to_a_file_when_output_is_given(runner: CliRunner, tmp_path: Path):
    passport_dir = _make_passport(tmp_path, allowed_actions=["read"])
    out_file = tmp_path / "envelope.json"
    result = runner.invoke(cli, [
        "sign-intent", "-p", str(passport_dir), "-a", "read", "-o", str(out_file),
    ])
    assert result.exit_code == 0
    assert out_file.exists()
    json.loads(out_file.read_text())  # must be valid JSON


def test_sign_intent_refuses_a_public_only_passport(runner: CliRunner, tmp_path: Path):
    passport_dir = _make_passport(tmp_path)
    (passport_dir / "private.pem").unlink()
    result = runner.invoke(cli, ["sign-intent", "-p", str(passport_dir), "-a", "read"])
    assert result.exit_code != 0
    assert "public-only" in result.output or "private key" in result.output


def test_verify_a_healthy_tier0_envelope_exits_zero(runner: CliRunner, tmp_path: Path):
    passport_dir = _make_passport(tmp_path, allowed_actions=["read"])
    holder = AgentPassport.load(passport_dir)
    envelope_file = tmp_path / "envelope.json"
    sign_result = runner.invoke(cli, [
        "sign-intent", "-p", str(passport_dir), "-a", "read", "-o", str(envelope_file),
    ])
    assert sign_result.exit_code == 0

    public_key_file = tmp_path / "public.pem"
    save_public_key(holder.public_key, public_key_file)

    verify_result = runner.invoke(cli, [
        "verify", "-e", str(envelope_file), "-k", str(public_key_file),
    ])
    assert verify_result.exit_code == 0, verify_result.output
    assert "True" in verify_result.output


def test_verify_a_denied_action_exits_one(runner: CliRunner, tmp_path: Path):
    passport_dir = _make_passport(tmp_path, allowed_actions=["trade"])  # read not allowed
    holder = AgentPassport.load(passport_dir)
    envelope_file = tmp_path / "envelope.json"
    runner.invoke(cli, ["sign-intent", "-p", str(passport_dir), "-a", "read", "-o", str(envelope_file)])

    public_key_file = tmp_path / "public.pem"
    save_public_key(holder.public_key, public_key_file)

    verify_result = runner.invoke(cli, [
        "verify", "-e", str(envelope_file), "-k", str(public_key_file),
    ])
    assert verify_result.exit_code == 1
    assert "CUSTOS-E200" in verify_result.output


def test_verify_with_a_wrong_public_key_fails_signature(runner: CliRunner, tmp_path: Path):
    passport_dir = _make_passport(tmp_path, allowed_actions=["read"])
    stranger = AgentPassport.create(domain="evil.com", agent_name="stranger")
    envelope_file = tmp_path / "envelope.json"
    runner.invoke(cli, ["sign-intent", "-p", str(passport_dir), "-a", "read", "-o", str(envelope_file)])

    public_key_file = tmp_path / "public.pem"
    save_public_key(stranger.public_key, public_key_file)

    verify_result = runner.invoke(cli, [
        "verify", "-e", str(envelope_file), "-k", str(public_key_file),
    ])
    assert verify_result.exit_code == 1
    assert "CUSTOS-E100" in verify_result.output


def test_verify_with_a_claim_and_observation_runs_asset_truth(runner: CliRunner, tmp_path: Path):
    passport_dir = _make_passport(tmp_path, allowed_actions=["trade"])
    holder = AgentPassport.load(passport_dir)
    envelope_file = tmp_path / "envelope.json"
    runner.invoke(cli, [
        "sign-intent", "-p", str(passport_dir), "-a", "trade", "-t", "TKN-UST-3M-001",
        "--amount", "100", "-o", str(envelope_file),
    ])

    public_key_file = tmp_path / "public.pem"
    save_public_key(holder.public_key, public_key_file)

    now = datetime.now(timezone.utc)
    claim = {
        "asset_id": "TKN-UST-3M-001", "issuer": "Meridian", "underlying_tenor": "3M",
        "asset_class": "treasury", "claimed_nav_per_token": "1", "claimed_backing_usd": "100",
        "tokens_outstanding": "100", "claimed_yield_bps": 400,
        "last_attested_at": now.isoformat(), "chain": "ethereum", "contract_address": "0x1",
    }
    observation = {
        "source": "test", "tenor": "3M", "observed_yield_bps": 400,
        "record_date": now.date().isoformat(), "fetched_at": now.isoformat(),
    }
    claim_file = tmp_path / "claim.json"
    observation_file = tmp_path / "observation.json"
    claim_file.write_text(json.dumps(claim))
    observation_file.write_text(json.dumps(observation))

    result = runner.invoke(cli, [
        "verify", "-e", str(envelope_file), "-k", str(public_key_file),
        "--claim", str(claim_file), "--observation", str(observation_file),
    ])
    assert result.exit_code == 0, result.output


def test_inspect_a_passport_directory(runner: CliRunner, tmp_path: Path):
    passport_dir = _make_passport(tmp_path)
    result = runner.invoke(cli, ["inspect", str(passport_dir)])
    assert result.exit_code == 0
    assert "did:web:acme.com:agents:bot" in result.output


def test_inspect_an_envelope_file(runner: CliRunner, tmp_path: Path):
    passport_dir = _make_passport(tmp_path, allowed_actions=["read"])
    envelope_file = tmp_path / "envelope.json"
    runner.invoke(cli, ["sign-intent", "-p", str(passport_dir), "-a", "read", "-o", str(envelope_file)])
    result = runner.invoke(cli, ["inspect", str(envelope_file)])
    assert result.exit_code == 0
    assert "CustosEnvelope" in result.output
