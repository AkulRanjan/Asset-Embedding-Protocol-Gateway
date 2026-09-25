"""The offline `custos` CLI: create a passport, sign an envelope, verify one
offline. No network I/O, no environment reads — this file is covered by
`tests/test_architecture.py`'s `test_protocol_package_performs_no_io` exactly
like every other module in this package. Revocation/registration/trust-lookup
against a live gateway is a *separate* CLI, `gateway/admin_cli.py` — this one
never imports httpx.
"""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from custos_protocol.crypto import load_public_key
from custos_protocol.envelope import create_envelope, sign_envelope
from custos_protocol.models import Action, Claim, CustosEnvelope, Observation
from custos_protocol.passport import AgentPassport
from custos_protocol.verification import verify_intent

console = Console()

_ACTION_CHOICES = [action.value for action in Action]


@click.group()
def cli() -> None:
    """Custos — pre-transaction asset-truth attestation for autonomous agents."""


@cli.command("create-passport")
@click.option("-d", "--domain", required=True, help="e.g. acme.com")
@click.option("-n", "--name", "agent_name", default=None, help="defaults to a random suffix")
@click.option("-a", "--allow", "allowed_actions", multiple=True, type=click.Choice(_ACTION_CHOICES))
@click.option("--deny", "denied_actions", multiple=True, type=click.Choice(_ACTION_CHOICES))
@click.option("-m", "--limit", "monetary_limit_per_txn", type=float, default=0.0,
              help="per-transaction limit; 0 means no limit")
@click.option("--daily-limit", "monetary_limit_per_day", type=float, default=0.0,
              help="rolling per-day limit; 0 means no limit")
@click.option("--geo", "geo_restriction", default=None, help='comma-separated, e.g. "US,CA"')
@click.option("-o", "--output", "output_dir", required=True, type=click.Path(path_type=Path))
def create_passport_cmd(
    domain: str, agent_name: str | None, allowed_actions: tuple[str, ...],
    denied_actions: tuple[str, ...], monetary_limit_per_txn: float,
    monetary_limit_per_day: float, geo_restriction: str | None, output_dir: Path,
) -> None:
    """Mint a new agent identity and write passport.json + both PEMs."""
    holder = AgentPassport.create(
        domain=domain, agent_name=agent_name,
        allowed_actions=list(allowed_actions), denied_actions=list(denied_actions),
        monetary_limit_per_txn=monetary_limit_per_txn, monetary_limit_per_day=monetary_limit_per_day,
        geo_restriction=geo_restriction,
    )
    holder.save(output_dir)
    console.print(f"[green]Created passport[/green] {holder.agent.id}")
    console.print(f"  written to {output_dir}")


@cli.command("sign-intent")
@click.option("-p", "--passport-dir", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("-a", "--action", required=True, type=click.Choice(_ACTION_CHOICES))
@click.option("-t", "--target", default="", help="the asset id")
@click.option("--amount", type=float, default=None)
@click.option("--ttl", type=int, default=300)
@click.option("-o", "--output", "output_file", type=click.Path(path_type=Path), default=None)
def sign_intent_cmd(
    passport_dir: Path, action: str, target: str, amount: float | None,
    ttl: int, output_file: Path | None,
) -> None:
    """Build and sign an intent envelope. Prints JSON, or writes it with -o."""
    holder = AgentPassport.load(passport_dir)
    try:
        private_key = holder.private_key
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    parameters = {"amount": amount} if amount is not None else {}
    envelope = create_envelope(holder, Action(action), target, parameters, ttl=ttl)
    signed = sign_envelope(envelope, private_key)
    rendered = json.dumps(signed.model_dump(mode="json", by_alias=True), indent=2)
    if output_file:
        output_file.write_text(rendered, encoding="utf-8")
        console.print(f"[green]Signed envelope written to[/green] {output_file}")
    else:
        # click.echo, not console.print: rich soft-wraps long lines by default,
        # which would insert a literal newline into the base64 signature and
        # corrupt this JSON for any caller piping or parsing stdout.
        click.echo(rendered)


@cli.command("verify")
@click.option("-e", "--envelope", "envelope_file", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("-k", "--public-key", "public_key_file", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--claim", "claim_file", type=click.Path(exists=True, path_type=Path), default=None,
              help="optional Claim JSON, needed for Tier 1+ asset-truth checks")
@click.option("--observation", "observation_file", type=click.Path(exists=True, path_type=Path), default=None,
              help="optional Observation JSON, needed alongside --claim")
def verify_cmd(
    envelope_file: Path, public_key_file: Path, claim_file: Path | None, observation_file: Path | None,
) -> None:
    """Run the verification pipeline offline. Exits 0 if passed, 1 if blocked —
    CI-friendly."""
    envelope = CustosEnvelope.model_validate(json.loads(envelope_file.read_text(encoding="utf-8")))
    public_key = load_public_key(public_key_file)
    claim = Claim.model_validate(json.loads(claim_file.read_text(encoding="utf-8"))) if claim_file else None
    observation = (
        Observation.model_validate(json.loads(observation_file.read_text(encoding="utf-8")))
        if observation_file else None
    )

    result = verify_intent(envelope, public_key, claim=claim, observation=observation)

    table = Table(title="Custos verification")
    table.add_column("field")
    table.add_column("value")
    table.add_row("passed", "[green]True[/green]" if result.passed else "[red]False[/red]")
    table.add_row("tier_used", result.tier_used.value)
    table.add_row("errors", ", ".join(code.value for code in result.errors) or "-")
    table.add_row("detail", result.detail)
    console.print(table)

    raise SystemExit(0 if result.passed else 1)


@cli.command("inspect")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
def inspect_cmd(path: Path) -> None:
    """Pretty-print a passport directory or an envelope/attestation file."""
    if path.is_dir():
        console.print_json(data=AgentPassport.load(path).to_dict())
    else:
        console.print_json(data=json.loads(path.read_text(encoding="utf-8")))


if __name__ == "__main__":
    cli()
