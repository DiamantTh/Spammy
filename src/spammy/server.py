"""Spammy server entry point.

Starts the Quart web UI (and optionally the FastAPI external API) using
Hypercorn.
"""

from __future__ import annotations

import asyncio
import logging
import signal
from typing import Optional

from .config_loader import SpammyConfig, load_config

logger = logging.getLogger(__name__)


def run(
    config: Optional[SpammyConfig] = None,
    host: Optional[str] = None,
    port: Optional[int] = None,
    api_host: Optional[str] = None,
    api_port: Optional[int] = None,
    with_api: bool = False,
    debug: bool = False,
) -> None:
    """Start Quart UI + optional FastAPI external API with Hypercorn."""

    try:
        import hypercorn  # noqa: F401
    except ImportError:
        raise SystemExit(
            "hypercorn is required to run the web server.\n"
            "Install it with: pip install 'spammy[web]'"
        )

    if config is None:
        config = load_config()

    web_host = host or config.web.host
    web_port = port or config.web.port
    debug_mode = debug or config.web.debug

    asyncio.run(
        _serve_all(
            config=config,
            web_host=web_host,
            web_port=web_port,
            api_host=api_host,
            api_port=api_port,
            with_api=with_api,
            debug=debug_mode,
        )
    )


async def _serve_all(
    config: SpammyConfig,
    web_host: str,
    web_port: int,
    api_host: Optional[str],
    api_port: Optional[int],
    with_api: bool,
    debug: bool,
) -> None:
    from hypercorn.asyncio import serve
    from hypercorn.config import Config as HypercornConfig

    from .web.app import create_app

    tasks: list[asyncio.Task] = []

    # ── Quart web UI ──────────────────────────────────────────────────
    quart_cfg = HypercornConfig()
    quart_cfg.bind = [f"{web_host}:{web_port}"]
    quart_cfg.debug = debug
    quart_app = create_app(config)

    logger.info("Starting Spammy web UI on http://%s:%s", web_host, web_port)
    shutdown = asyncio.Event()

    tasks.append(
        asyncio.ensure_future(
            serve(quart_app, quart_cfg, shutdown_trigger=shutdown.wait)
        )
    )

    # ── FastAPI external API (optional) ──────────────────────────────
    if with_api or config.external_api.enabled:
        try:
            from fastapi import FastAPI  # noqa: F401
        except ImportError:
            raise SystemExit(
                "fastapi is required for the external API.\n"
                "Install it with: pip install 'spammy[api]'"
            )

        from .api.app import create_api

        ext_host = api_host or config.external_api.host
        ext_port = api_port or config.external_api.port

        api_cfg = HypercornConfig()
        api_cfg.bind = [f"{ext_host}:{ext_port}"]
        api_cfg.debug = debug
        fastapi_app = create_api(config)

        logger.info(
            "Starting Spammy external API on http://%s:%s", ext_host, ext_port
        )
        tasks.append(
            asyncio.ensure_future(
                serve(fastapi_app, api_cfg, shutdown_trigger=shutdown.wait)
            )
        )

    # ── Graceful shutdown on SIGINT / SIGTERM ─────────────────────────
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown.set)

    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        pass
    finally:
        logger.info("Spammy server stopped.")
