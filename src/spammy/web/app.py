"""Quart application factory for the Spammy web UI."""

from __future__ import annotations

from pathlib import Path

from quart import Quart

from ..config_loader import SpammyConfig
from .security import SecurityHeadersMiddleware, get_csrf_token

_PKG_ROOT = Path(__file__).parent


def create_app(config: SpammyConfig) -> Quart:
    app = Quart(
        __name__,
        template_folder=str(_PKG_ROOT / "templates"),
        static_folder=str(_PKG_ROOT / "static"),
        static_url_path="/static",
    )

    app.secret_key = config.web.secret_key
    app.config["MAX_CONTENT_LENGTH"] = 30 * 1024 * 1024  # 30 MB (EML uploads)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
    app.config["SESSION_COOKIE_SECURE"] = config.web.base_url.startswith("https")
    app.config["SPAMMY_CONFIG"] = config

    from ..service import AnalysisService
    app.config["SPAMMY_SERVICE"] = AnalysisService(config)

    # Jinja2 globals
    app.jinja_env.globals["csrf_token"] = get_csrf_token
    app.jinja_env.globals["app_version"] = _get_version()

    # Register blueprints
    from .routes.health import health_bp
    from .routes.internal import internal_bp
    from .routes.ui import ui_bp

    app.register_blueprint(health_bp)
    app.register_blueprint(ui_bp)
    app.register_blueprint(internal_bp, url_prefix="/api/v1")

    # Wrap with security-header middleware
    app.asgi_app = SecurityHeadersMiddleware(app.asgi_app)  # type: ignore[assignment]

    return app


def _get_version() -> str:
    try:
        from .. import __version__
        return __version__
    except Exception:
        return "dev"
