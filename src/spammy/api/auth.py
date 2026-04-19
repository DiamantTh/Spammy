"""API-Key authentication dependency for the FastAPI external layer.

The key is read from ``config.external_api.key``.
An empty key disables authentication (only appropriate on loopback/LAN).
"""

from __future__ import annotations

import secrets

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader

_HEADER_SCHEME = APIKeyHeader(name="X-API-Key", auto_error=False)


def api_key_auth(configured_key: str):
    """Return a FastAPI dependency that validates ``X-API-Key``.

    If *configured_key* is empty, authentication is skipped (open access).
    """

    async def _check(key: str | None = Depends(_HEADER_SCHEME)) -> None:
        if not configured_key:
            return  # auth disabled
        if not key or not secrets.compare_digest(key, configured_key):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing X-API-Key",
                headers={"WWW-Authenticate": "ApiKey"},
            )

    return _check
