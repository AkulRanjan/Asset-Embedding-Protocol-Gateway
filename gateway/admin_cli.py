"""The networked `custos-admin` CLI: thin HTTP wrappers over the gateway's
admin-gated routes. Deliberately a separate entry point from
`custos_protocol.cli` — that one is offline-only and cannot import httpx;
everything here that actually needs to persist (revoke, register) already has a
real, durable home in the live gateway's own HTTP API (Phase 2), so this file
only ever calls it rather than reimplementing a second, in-memory-only version.
"""

from __future__ import annotations

import os

import click
import httpx
from rich.console import Console

console = Console()

_DEFAULT_GATEWAY_URL = "http://127.0.0.1:8000"


def _gateway_url(value: str | None) -> str:
    return value or os.getenv("CUSTOS_GATEWAY_URL", _DEFAULT_GATEWAY_URL)


def _admin_key(value: str | None) -> str | None:
    return value or os.getenv("CUSTOS_ADMIN_API_KEY")


def _request(method: str, url: str, *, admin_key: str | None = None, **kwargs) -> httpx.Response:
    headers = {"X-Custos-Admin-Key": admin_key} if admin_key else {}
    try:
        response = httpx.request(method, url, headers=headers, timeout=10.0, **kwargs)
    except httpx.HTTPError as exc:
        raise click.ClickException(f"could not reach {url}: {exc}") from exc
    if response.status_code >= 400:
        raise click.ClickException(f"HTTP {response.status_code}: {response.text}")
    return response


_gateway_url_option = click.option(
    "--gateway-url", default=None, help=f"defaults to $CUSTOS_GATEWAY_URL or {_DEFAULT_GATEWAY_URL}",
)
_admin_key_option = click.option(
    "--admin-key", default=None, help="defaults to $CUSTOS_ADMIN_API_KEY",
)


@click.group()
def cli() -> None:
    """Administrative operations against a live Custos gateway."""


@cli.command("register-agent")
@click.option("--agent-id", required=True)
@click.option("--public-key", required=True, help="base64url-encoded Ed25519 public key")
@_gateway_url_option
@_admin_key_option
def register_agent_cmd(agent_id: str, public_key: str, gateway_url: str | None, admin_key: str | None) -> None:
    """Bind an agent id to a public key."""
    url = _gateway_url(gateway_url)
    response = _request("POST", f"{url}/v1/agents",
                         admin_key=_admin_key(admin_key), json={"agent_id": agent_id, "public_key": public_key})
    console.print(f"[green]Registered[/green] {response.json()['registered']}")


@cli.command("revoke")
@click.argument("subject_id")
@click.option("--subject-type", type=click.Choice(["agent", "issuer"]), default="agent")
@click.option("--suspend", is_flag=True, help="suspend instead of permanently revoking")
@click.option("--duration", "duration_seconds", type=int, default=1800, help="suspension length, in seconds")
@click.option("--reason", default="")
@_gateway_url_option
@_admin_key_option
def revoke_cmd(
    subject_id: str, subject_type: str, suspend: bool, duration_seconds: int,
    reason: str, gateway_url: str | None, admin_key: str | None,
) -> None:
    """Revoke (or suspend) an agent or issuer."""
    url = _gateway_url(gateway_url)
    body = {
        "subject_id": subject_id, "subject_type": subject_type,
        "action": "suspend" if suspend else "revoke",
        "reason": reason, "duration_seconds": duration_seconds,
    }
    _request("POST", f"{url}/v1/revocations", admin_key=_admin_key(admin_key), json=body)
    verb = "Suspended" if suspend else "Revoked"
    console.print(f"[yellow]{verb}[/yellow] {subject_id} ({subject_type})")


@cli.command("reinstate")
@click.argument("subject_id")
@_gateway_url_option
@_admin_key_option
def reinstate_cmd(subject_id: str, gateway_url: str | None, admin_key: str | None) -> None:
    """Clear a revocation or suspension."""
    url = _gateway_url(gateway_url)
    _request("DELETE", f"{url}/v1/revocations/{subject_id}", admin_key=_admin_key(admin_key))
    console.print(f"[green]Reinstated[/green] {subject_id}")


@cli.command("trust")
@click.argument("agent_id")
@_gateway_url_option
def trust_cmd(agent_id: str, gateway_url: str | None) -> None:
    """Look up an agent's current trust score. No admin key required — a read
    of a public reputation number, same posture as GET /v1/assets."""
    url = _gateway_url(gateway_url)
    response = _request("GET", f"{url}/v1/trust/{agent_id}")
    body = response.json()
    console.print(f"agent_id: {body['agent_id']}")
    console.print(f"score: {body['score']}")
    console.print_json(data=body["history"])


@cli.command("register-framework")
@click.argument("framework_id")
@_gateway_url_option
@_admin_key_option
def register_framework_cmd(framework_id: str, gateway_url: str | None, admin_key: str | None) -> None:
    """Register a framework_id as known, for the attestation check (CUSTOS-E306)."""
    url = _gateway_url(gateway_url)
    response = _request("POST", f"{url}/v1/frameworks",
                         admin_key=_admin_key(admin_key), json={"framework_id": framework_id})
    console.print(f"[green]Registered framework[/green] {response.json()['registered']}")


if __name__ == "__main__":
    cli()
