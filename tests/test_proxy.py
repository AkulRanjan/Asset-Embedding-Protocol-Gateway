from __future__ import annotations

import base64
import json

import httpx
import pytest

from custos_protocol.attestation import RecordSigner
from custos_protocol.envelope import create_envelope, sign_envelope
from custos_protocol.models import Action, VerificationTier
from custos_protocol.passport import AgentPassport
from gateway.proxy import forward


def _envelope():
    passport = AgentPassport.create(domain="acme.com", agent_name="treasury-bot")
    envelope = create_envelope(
        passport, Action.TRADE, "TKN-UST-3M-001",
        {"amount": 50000, "currency": "USD"}, tier=VerificationTier.TIER_1,
    )
    return sign_envelope(envelope, passport.private_key)


def _attestation():
    signer = RecordSigner()
    return signer.sign_attestation(
        envelope_hash="abc123", agent_id="did:web:acme.com:agents:treasury-bot",
        asset_id="TKN-UST-3M-001", action="trade", amount=50000,
        tier_used=VerificationTier.TIER_1, scores=None, reference=None,
    )


def test_forward_returns_the_downstream_status_and_body():
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    result = _run_with_mock(handler)

    assert result["status_code"] == 200
    assert result["body"] == {"ok": True}


def _run_with_mock(handler):
    import asyncio

    async def run():
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        import gateway.proxy as proxy_module
        original = proxy_module.httpx.AsyncClient
        proxy_module.httpx.AsyncClient = lambda **kw: client
        try:
            return await forward("https://downstream.test/hook", _envelope(), _attestation())
        finally:
            proxy_module.httpx.AsyncClient = original

    return asyncio.run(run())


def test_the_attestation_header_is_base64_and_decodes_to_the_signed_record():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["header"] = request.headers["X-Custos-Attestation"]
        return httpx.Response(200, json={"ok": True})

    _run_with_mock(handler)

    decoded = json.loads(base64.b64decode(captured["header"]))
    assert decoded["verdict"] == "ALLOW"
    assert decoded["asset_id"] == "TKN-UST-3M-001"


def test_the_envelope_body_carries_json_ld_aliases():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"ok": True})

    _run_with_mock(handler)

    assert captured["body"]["@type"] == "CustosEnvelope"


def test_a_non_json_downstream_body_is_returned_as_text():
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="not json")

    result = _run_with_mock(handler)
    assert result["body"] == "not json"


def test_transport_failure_raises_connection_error():
    def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=httpx.Request("POST", "https://downstream.test/hook"))

    with pytest.raises(ConnectionError):
        _run_with_mock(handler)


def test_a_redirect_response_is_not_followed():
    """follow_redirects=False: a signed attestation must not reach an unvetted host
    reached only via a Location header the downstream chose."""
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return httpx.Response(302, headers={"Location": "https://evil.test/steal"})

    result = _run_with_mock(handler)

    assert result["status_code"] == 302
    assert captured["url"] == "https://downstream.test/hook"
