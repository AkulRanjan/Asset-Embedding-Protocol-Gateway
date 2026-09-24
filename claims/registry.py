from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from custos_protocol.models import Claim


class ClaimRegistry:
    """In-memory seeded registry; offsets keep demo claims relative to load time."""

    def __init__(self, seed_path: Path | None = None) -> None:
        path = seed_path or Path(__file__).with_name("seed.json")
        raw_claims = json.loads(path.read_text(encoding="utf-8"))
        now = datetime.now(timezone.utc)
        self._claims: dict[str, Claim] = {}
        for raw in raw_claims:
            offset = raw.pop("last_attested_offset_hours")
            raw["last_attested_at"] = now + timedelta(hours=float(offset))
            claim = Claim.model_validate(raw)
            self._claims[claim.asset_id] = claim

    def get_claim(self, asset_id: str) -> Claim | None:
        return self._claims.get(asset_id)

    def list_claims(self) -> list[Claim]:
        return list(self._claims.values())

    def update_claim(self, asset_id: str, **updates: object) -> Claim | None:
        """Replace a simulated claim in memory; used only by the interactive demo sync."""
        claim = self._claims.get(asset_id)
        if claim is None:
            return None
        # model_copy(update=...) would skip validators entirely; merge into the
        # existing dump and re-validate so an update can never install a value the
        # schema itself forbids (e.g. a negative yield or zero tokens_outstanding).
        updated = Claim.model_validate({**claim.model_dump(), **updates})
        self._claims[asset_id] = updated
        return updated
