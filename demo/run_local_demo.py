"""Deterministic in-process demo. Substitutes only the observation.

Every route, model and signature in this run is the production one.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx
from rich.console import Console
from rich.table import Table

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from custos_protocol.crypto import public_key_to_b64          # noqa: E402
from custos_protocol.envelope import create_envelope, sign_envelope  # noqa: E402
from custos_protocol.models import Action, Observation        # noqa: E402
from custos_protocol.passport import AgentPassport            # noqa: E402
from demo.verify_attestation import verify                    # noqa: E402
from gateway import server                                    # noqa: E402


class DemoOracle:
    """A known-good 4.00% observation, so every presentation has the intended outcomes."""

    async def get_observation(self, tenor: str) -> Observation:
        stamp = datetime.now(timezone.utc)
        return Observation(source="demo.fixed-observation", tenor=tenor,
                           observed_yield_bps=400, record_date=stamp.date(), fetched_at=stamp)


async def run() -> None:
    admin_key = os.getenv("CUSTOS_ADMIN_API_KEY")
    if not admin_key:
        raise SystemExit("Set CUSTOS_ADMIN_API_KEY before running this demo.")

    console = Console()
    original = server.oracle
    server.oracle = DemoOracle()

    passport = AgentPassport.create(
        domain="acme.com", agent_name="treasury-bot",
        allowed_actions=["borrow_against"], monetary_limit_per_txn=100000.0,
        asset_classes=["treasury"],
    )

    scenarios = [
        ("Stale claim", "TKN-UST-3M-002", "CUSTOS-E300"),
        ("Recent but drifted", "TKN-UST-3M-003", "CUSTOS-E301"),
        ("Under-backed", "TKN-UST-6M-004", "CUSTOS-E302"),
        ("Healthy claim", "TKN-UST-3M-001", "ALLOW"),
    ]

    table = Table(title="Custos Gateway — deterministic local demo")
    for column in ("Scenario", "Asset", "HTTP", "Result", "Expected"):
        table.add_column(column)

    try:
        transport = httpx.ASGITransport(app=server.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://custos.demo") as client:
            await client.post("/v1/agents", json={
                "agent_id": passport.agent.id,
                "public_key": public_key_to_b64(passport.public_key),
            }, headers={"X-Custos-Admin-Key": admin_key})
            gateway_key = (await client.get("/v1/pubkey")).json()["public_key"]

            for name, asset_id, expected in scenarios:
                envelope = create_envelope(passport, Action.BORROW_AGAINST, asset_id,
                                           {"amount": 50000, "currency": "USD"})
                signed = sign_envelope(envelope, passport.private_key)
                response = await client.post("/v1/intent",
                                             json=signed.model_dump(mode="json", by_alias=True))
                body = response.json()
                result = body["errors"][0] if body.get("errors") else body.get("verdict", "UNKNOWN")
                style = "green" if result == expected else "red"
                table.add_row(name, asset_id, str(response.status_code),
                              f"[{style}]{result}[/{style}]", expected)

                if body.get("verdict") == "ALLOW":
                    output = Path(__file__).with_name("attestation.json")
                    output.write_text(json.dumps(body, indent=2), encoding="utf-8")
                    verify(body, gateway_key)
                    console.print(f"[green]Signature verified against the published key. Wrote {output}[/green]")
    finally:
        server.oracle = original

    console.print(table)
    console.print("[dim]Demo mode fixes the observation at 400 bps; the gateway remains live and fail-closed.[/dim]")


if __name__ == "__main__":
    asyncio.run(run())
