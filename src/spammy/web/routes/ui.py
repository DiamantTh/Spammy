"""UI routes – thin HTML-shell renderer.

These routes only render static Jinja2 shells.  All business logic and data
fetching is performed in JavaScript via the internal REST API (/api/v1/).
"""

from __future__ import annotations

from quart import Blueprint, render_template

ui_bp = Blueprint("ui", __name__)


@ui_bp.get("/")
async def dashboard():
    return await render_template("dashboard.html")


@ui_bp.get("/analyze")
async def analyze_form():
    return await render_template("analyze.html")


@ui_bp.get("/report/<job_id>")
async def report_view(job_id: str):
    return await render_template("report.html", job_id=job_id)
