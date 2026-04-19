"""Security helpers for the Spammy web UI.

Covers:
- CSRF token generation + validation (session-cookie based)
- Security-header middleware (CSP, X-Frame-Options, Referrer-Policy, …)

HSTS is deliberately not set here – TLS termination happens at the reverse
proxy (nginx/Caddy/…), not inside the app.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from typing import Any

from quart import abort, request, session

_CSRF_SESSION_KEY = "_csrf"
CSRF_FORM_FIELD = "_csrf"


def get_csrf_token() -> str:
    """Return the CSRF token for the current session; create it on demand."""
    if _CSRF_SESSION_KEY not in session:
        session[_CSRF_SESSION_KEY] = secrets.token_hex(32)
    return session[_CSRF_SESSION_KEY]  # type: ignore[return-value]


async def validate_csrf(base_url: str) -> None:
    """Validate the CSRF token; abort 403 on mismatch.

    Accepts tokens from:
      1. HTML form hidden-field ``_csrf``
      2. AJAX header ``X-CSRF-Token``

    Additionally checks Origin/Referer as a second layer (defense-in-depth).
    """
    origin = request.headers.get("Origin") or request.headers.get("Referer", "")
    if origin and not origin.startswith(base_url):
        abort(403, "Cross-origin request rejected")

    expected = session.get(_CSRF_SESSION_KEY)
    form = await request.form
    submitted = form.get(CSRF_FORM_FIELD) or request.headers.get("X-CSRF-Token", "")
    if not expected or not submitted or not secrets.compare_digest(expected, submitted):
        abort(403, "CSRF token missing or invalid")


# ---------------------------------------------------------------------------
# Security-header ASGI middleware (applied after Quart builds the response)
# ---------------------------------------------------------------------------

_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self';"
)

_NO_STORE = "no-store, no-cache, must-revalidate, private"


class SecurityHeadersMiddleware:
    """ASGI middleware that injects security headers on every response."""

    def __init__(self, app: Any) -> None:
        self._app = app

    async def __call__(
        self, scope: dict, receive: Callable, send: Callable
    ) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self._app(scope, receive, send)
            return

        async def send_with_headers(message: dict) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                path = scope.get("path", "")
                headers += [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"strict-origin-when-cross-origin"),
                    (b"x-permitted-cross-domain-policies", b"none"),
                    (b"content-security-policy", _CSP.encode()),
                ]
                # No-store for all non-static routes
                if not path.startswith("/static/"):
                    headers.append(
                        (b"cache-control", _NO_STORE.encode())
                    )
                message = {**message, "headers": headers}
            await send(message)

        await self._app(scope, receive, send_with_headers)
