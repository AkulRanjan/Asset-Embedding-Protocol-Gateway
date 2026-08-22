"""Reference downstream consumer. Implements all five checks a real one must do."""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone

from fastapi import FastAPI, Header, Request

from demo.verify_attestation import verify

app = FastAPI(title="Custos demo lender")

# Pinned out of band from GET /v1/pubkey. Without this, verification proves nothing.
CUSTOS_PUBLIC_KEY = os.getenv("CUSTOS_GATEWAY_PUBKEY", "")


@app.post("/loan")
async def loan(request: Request, x_custos_attestation: str | None = Header(default=None)):
    # 1. Present?
    if not x_custos_attestation:
        return {"accepted": False, "reason": "missing Custos attestation"}
    record = json.loads(base64.b64decode(x_custos_attestation))

    # 2. Signature valid against the PINNED key?
    if not CUSTOS_PUBLIC_KEY:
        return {"accepted": False, "reason": "no pinned Custos key configured"}
    try:
        verify(record, CUSTOS_PUBLIC_KEY)
    except Exception:
        return {"accepted": False, "reason": "attestation signature did not verify"}

    # 3. Still valid?
    if datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00")) < datetime.now(timezone.utc):
        return {"accepted": False, "reason": "attestation expired"}

    # 4. Verdict is ALLOW?
    if record.get("verdict") != "ALLOW":
        return {"accepted": False, "reason": "attestation is not an ALLOW"}

    # 5. Does it describe THIS request?
    envelope = await request.json()
    if record["asset_id"] != envelope["intent"]["target"]:
        return {"accepted": False, "reason": "attestation is for a different asset"}
    if record["amount"] != envelope["intent"]["parameters"].get("amount"):
        return {"accepted": False, "reason": "attestation is for a different amount"}

    return {"accepted": True, "message": "loan approved against a verified Custos attestation"}
