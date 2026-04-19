"""FastAPI application factory for the public external API."""

from __future__ import annotations

from fastapi import Depends, FastAPI

from ..config_loader import SpammyConfig
from ..version import get_version
from .auth import api_key_auth
from .models import HealthResponse
from .routes import router as v1_router


def create_api(config: SpammyConfig) -> FastAPI:
    """Return a configured FastAPI ASGI application."""

    ext = config.external_api
    auth_dep = api_key_auth(ext.key)

    app = FastAPI(
        title="Spammy External API",
        description=(
            "Public REST API for spam analysis. "
            "Authenticate with an ``X-API-Key`` header."
        ),
        version=get_version(),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        dependencies=[Depends(auth_dep)],
    )

    # Store config for use in route handlers
    app.state.spammy_config = config

    # Health (no auth)
    @app.get(
        "/health",
        response_model=HealthResponse,
        tags=["Health"],
        include_in_schema=True,
        dependencies=[],  # override global auth for health check
    )
    async def health() -> HealthResponse:
        return HealthResponse(version=get_version())

    app.include_router(v1_router, prefix="/api/v1", tags=["Analysis"])

    return app
