"""Drive a *running* Custos gateway over HTTP.

Unlike run_local_demo.py this talks to a real server process, so it exercises the
network path too. The agent registers its public key first: every envelope is
signed now, and the gateway will not verify a key it has never seen.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import httpx
from rich.console import Console
from rich.panel import Panel

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from custos_protocol.crypto import public_key_to_b64                 # noqa: E402
from custos_protocol.envelope import create_envelope, sign_envelope  # noqa: E402
from custos_protocol.models import Action                            # noqa: E402
from custos_protocol.passport import AgentPassport                   # noqa: E402


def main(base_url: str, admin_key: str) -> None:
    console = Console()
    passport = AgentPassport.create(
        domain="acme.com", agent_name="treasury-bot",
        allowed_actions=["borrow_against"], monetary_limit_per_txn=100000.0,
        asset_classes=["treasury"],
    )

    with httpx.Client(base_url=base_url, timeout=10) as client:
        registration = client.post("/v1/agents", json={
            "agent_id": passport.agent.id,
            "public_key": public_key_to_b64(passport.public_key),
        }, headers={"X-Custos-Admin-Key": admin_key})
        registration.raise_for_status()
        console.print(f"[dim]Registered {passport.agent.id} with the gateway.[/dim]")

        for asset_id in ("TKN-UST-3M-002", "TKN-UST-3M-003", "TKN-UST-3M-001"):
            envelope = create_envelope(passport, Action.BORROW_AGAINST, asset_id,
                                       {"amount": 50000, "currency": "USD"})
            signed = sign_envelope(envelope, passport.private_key)
            response = client.post("/v1/intent", json=signed.model_dump(mode="json", by_alias=True))
            payload = response.json()
            console.print(Panel.fit(json.dumps(payload, indent=2),
                                    title=f"{asset_id} · HTTP {response.status_code}"))
            if payload.get("verdict") == "ALLOW":
                Path("attestation.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
                key = client.get("/v1/pubkey").json()["public_key"]
                console.print(
                    "[green]Wrote attestation.json. Verify it independently:[/green]\n"
                    f"[dim]  python demo/verify_attestation.py attestation.json --public-key {key}[/dim]"
                )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument(
        "--admin-key", default=os.getenv("CUSTOS_ADMIN_API_KEY"),
        help="administrator API key (or set CUSTOS_ADMIN_API_KEY)",
    )
    args = parser.parse_args()
    if not args.admin_key:
        parser.error("--admin-key or CUSTOS_ADMIN_API_KEY is required to register an agent")
    main(args.base_url, args.admin_key)
