"""Health-check endpoint – used by container probes and load balancers."""

from __future__ import annotations

from quart import Blueprint, jsonify

health_bp = Blueprint("health", __name__)


@health_bp.get("/health")
async def health() -> tuple:
    return jsonify({"status": "ok"}), 200
