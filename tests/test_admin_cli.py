from __future__ import annotations

import json

import httpx
import pytest
from click.testing import CliRunner

from gateway import admin_cli


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _install_transport(monkeypatch, handler):
    def fake_request(method: str, url: str, **kwargs):
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            return client.request(method, url, **kwargs)

    monkeypatch.setattr(admin_cli.httpx, "request", fake_request)


def test_register_agent_sends_the_admin_key_header_and_body(runner, monkeypatch):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = request.headers
        captured["body"] = json.loads(request.content)
        return httpx.Response(201, json={"registered": "did:web:acme.com:agents:bot"})

    _install_transport(monkeypatch, handler)

    result = runner.invoke(admin_cli.cli, [
        "register-agent", "--agent-id", "did:web:acme.com:agents:bot",
        "--public-key", "abc123", "--admin-key", "secret", "--gateway-url", "https://gw.test",
    ])
    assert result.exit_code == 0, result.output
    assert captured["headers"]["x-custos-admin-key"] == "secret"
    assert captured["body"] == {"agent_id": "did:web:acme.com:agents:bot", "public_key": "abc123"}
    assert "Registered" in result.output


def test_revoke_defaults_to_permanent_revoke(runner, monkeypatch):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(201, json={"subject_id": "x", "subject_type": "agent", "action": "revoke"})

    _install_transport(monkeypatch, handler)

    result = runner.invoke(admin_cli.cli, [
        "revoke", "did:web:acme.com:agents:bot", "--admin-key", "secret",
    ])
    assert result.exit_code == 0, result.output
    assert captured["body"]["action"] == "revoke"
    assert captured["body"]["subject_type"] == "agent"


def test_revoke_with_suspend_flag_sends_suspend_action_and_duration(runner, monkeypatch):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(201, json={"subject_id": "x", "subject_type": "issuer", "action": "suspend"})

    _install_transport(monkeypatch, handler)

    result = runner.invoke(admin_cli.cli, [
        "revoke", "Meridian", "--subject-type", "issuer", "--suspend",
        "--duration", "3600", "--admin-key", "secret",
    ])
    assert result.exit_code == 0, result.output
    assert captured["body"] == {
        "subject_id": "Meridian", "subject_type": "issuer", "action": "suspend",
        "reason": "", "duration_seconds": 3600,
    }
    assert "Suspended" in result.output


def test_reinstate_calls_delete(runner, monkeypatch):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["path"] = request.url.path
        return httpx.Response(200, json={"reinstated": "x"})

    _install_transport(monkeypatch, handler)

    result = runner.invoke(admin_cli.cli, ["reinstate", "did:web:acme.com:agents:bot", "--admin-key", "secret"])
    assert result.exit_code == 0, result.output
    assert captured["method"] == "DELETE"
    assert captured["path"] == "/v1/revocations/did:web:acme.com:agents:bot"


def test_trust_requires_no_admin_key(runner, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert "x-custos-admin-key" not in request.headers
        return httpx.Response(200, json={
            "agent_id": "did:web:acme.com:agents:bot", "score": 0.5,
            "history": {"agent_id": "did:web:acme.com:agents:bot", "total_intents": 3},
        })

    _install_transport(monkeypatch, handler)

    result = runner.invoke(admin_cli.cli, ["trust", "did:web:acme.com:agents:bot"])
    assert result.exit_code == 0, result.output
    assert "0.5" in result.output


def test_register_framework(runner, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={"registered": "langchain"})

    _install_transport(monkeypatch, handler)

    result = runner.invoke(admin_cli.cli, [
        "register-framework", "langchain", "--admin-key", "secret",
    ])
    assert result.exit_code == 0, result.output
    assert "langchain" in result.output


def test_an_http_error_response_becomes_a_clean_cli_error(runner, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="Administrator authentication failed.")

    _install_transport(monkeypatch, handler)

    result = runner.invoke(admin_cli.cli, [
        "register-agent", "--agent-id", "x", "--public-key", "y", "--admin-key", "wrong",
    ])
    assert result.exit_code != 0
    assert "401" in result.output


def test_a_connection_failure_becomes_a_clean_cli_error(runner, monkeypatch):
    def broken_request(method, url, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(admin_cli.httpx, "request", broken_request)

    result = runner.invoke(admin_cli.cli, [
        "register-agent", "--agent-id", "x", "--public-key", "y", "--admin-key", "secret",
        "--gateway-url", "https://unreachable.test",
    ])
    assert result.exit_code != 0
    assert "could not reach" in result.output


def test_gateway_url_defaults_from_environment(runner, monkeypatch):
    captured = {}
    monkeypatch.setenv("CUSTOS_GATEWAY_URL", "https://env-configured.test")

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return httpx.Response(201, json={"registered": "x"})

    _install_transport(monkeypatch, handler)

    result = runner.invoke(admin_cli.cli, [
        "register-agent", "--agent-id", "x", "--public-key", "y", "--admin-key", "secret",
    ])
    assert result.exit_code == 0, result.output
    assert captured["url"].startswith("https://env-configured.test")


def test_admin_key_defaults_from_environment(runner, monkeypatch):
    captured = {}
    monkeypatch.setenv("CUSTOS_ADMIN_API_KEY", "env-secret")

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = request.headers
        return httpx.Response(201, json={"registered": "x"})

    _install_transport(monkeypatch, handler)

    result = runner.invoke(admin_cli.cli, ["register-agent", "--agent-id", "x", "--public-key", "y"])
    assert result.exit_code == 0, result.output
    assert captured["headers"]["x-custos-admin-key"] == "env-secret"
