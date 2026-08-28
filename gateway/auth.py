"""Authentication for administrative gateway operations.

Custos envelopes authenticate an agent's request at ``POST /v1/intent``. A
separate administrator credential protects the mutable control-plane routes
that establish or alter the identity-to-key binding.
"""

from __future__ import annotations

import hmac
from typing import Annotated

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from gateway import config


ADMIN_API_KEY_HEADER = "X-Custos-Admin-Key"
_admin_api_key = APIKeyHeader(name=ADMIN_API_KEY_HEADER, auto_error=False)


async def require_admin(
    presented_key: Annotated[str | None, Security(_admin_api_key)],
) -> None:
    """Require the configured administrator API key, failing closed if absent."""
    configured_key = config.ADMIN_API_KEY
    if not configured_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Custos administrator API key is not configured.",
        )
    if presented_key is None or not hmac.compare_digest(presented_key, configured_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Administrator authentication failed.",
        )
