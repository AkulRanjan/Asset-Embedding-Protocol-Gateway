from __future__ import annotations

import base64
import json

import httpx

from custos_protocol.attestation import Attestation
from custos_protocol.models import CustosEnvelope
from gateway import config


def is_allowed(url: str, allowlist: tuple[str, ...]) -> bool:
    """Exact (scheme, host, port) match. A prefix check would let
    http://allowed:9000@evil.test through, since that host is evil.test."""
    def origin(value: str) -> tuple:
        parsed = httpx.URL(value)
        return parsed.scheme, parsed.host, parsed.port

    try:
        return origin(url) in {origin(entry) for entry in allowlist}
    except httpx.InvalidURL:
        return False


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
