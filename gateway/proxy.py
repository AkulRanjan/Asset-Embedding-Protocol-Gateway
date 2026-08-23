from __future__ import annotations

import base64
import json

import httpx

from custos_protocol.attestation import Attestation
from custos_protocol.models import CustosEnvelope
from gateway import config


async def forward(url: str, envelope: CustosEnvelope, attestation: Attestation) -> dict:
    """Forward an allowed intent with its signed proof in a header-safe encoding."""
    serialized = json.dumps(attestation.model_dump(mode="json"), separators=(",", ":"), ensure_ascii=True)
    headers = {"X-Custos-Attestation": base64.b64encode(serialized.encode("utf-8")).decode("ascii")}
    timeout = httpx.Timeout(config.DOWNSTREAM_TIMEOUT_SECONDS, connect=config.DOWNSTREAM_TIMEOUT_SECONDS)
    body = envelope.model_dump(mode="json", by_alias=True)
    try:
        # follow_redirects=False keeps a signed attestation from reaching an unvetted host.
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            response = await client.post(url, json=body, headers=headers)
        try:
            payload = response.json()
        except ValueError:
            payload = response.text
        return {"status_code": response.status_code, "body": payload}
    except httpx.HTTPError as exc:
        raise ConnectionError("downstream could not be reached") from exc
