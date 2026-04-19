"""Internal REST API Blueprint – consumed by the Web UI (AJAX) and TUI.

All business logic is delegated to :mod:`spammy.service`.
UI routes stay completely decoupled from analysis/storage code.

Endpoints:
  POST /api/v1/analyze               – submit EML, returns {job_id}
  GET  /api/v1/jobs/<job_id>         – poll job state
  GET  /api/v1/reports/<job_id>      – full JSON analysis result
  GET  /api/v1/reports/<job_id>/html – rendered HTML report
  GET  /api/v1/reports/<job_id>/text – rendered plain-text report
  GET  /api/v1/history               – paginated stored messages
"""

from __future__ import annotations

import base64

from quart import Blueprint, abort, current_app, jsonify, make_response, request

from ...service import MAX_EML_BYTES, AnalysisService

internal_bp = Blueprint("internal", __name__)


def _svc() -> AnalysisService:
    return current_app.config["SPAMMY_SERVICE"]


# ---------------------------------------------------------------------------
# Submit analysis
# ---------------------------------------------------------------------------


@internal_bp.post("/analyze")
async def api_analyze():
    """Submit an EML; returns ``{job_id, state}`` 202 immediately."""
    raw: bytes | None = None
    content_type = request.content_type or ""

    if "multipart" in content_type or "form" in content_type:
        files = await request.files
        forms = await request.form
        eml_file = files.get("eml_file")
        raw_text = forms.get("raw_text", "").strip()
        if eml_file and eml_file.filename:
            raw = await eml_file.read(MAX_EML_BYTES + 1)
        elif raw_text:
            raw = raw_text.encode("utf-8", errors="replace")
    elif "json" in content_type:
        data = await request.get_json(silent=True) or {}
        eml_b64 = data.get("eml_b64", "")
        raw_text = data.get("raw_text", "")
        if eml_b64:
            try:
                raw = base64.b64decode(eml_b64)
            except Exception:
                abort(400, "eml_b64 is not valid base64")
        elif raw_text:
            raw = raw_text.encode("utf-8", errors="replace")

    if raw is None:
        abort(400, "No EML content provided")
    if len(raw) > MAX_EML_BYTES:
        abort(413, "EML exceeds 25 MB limit")

    job = _svc().submit(raw)
    return jsonify({"job_id": job.job_id, "state": job.state}), 202


# ---------------------------------------------------------------------------
# Job status
# ---------------------------------------------------------------------------


@internal_bp.get("/jobs/<job_id>")
async def api_job_status(job_id: str):
    job = _svc().get_job(job_id)
    if job is None:
        abort(404, "Job not found")
    payload: dict = {
        "job_id": job.job_id,
        "state": job.state,
        "created_at": job.created_at.isoformat(),
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
    }
    if job.state == "error":
        payload["error"] = job.error
    return jsonify(payload)


# ---------------------------------------------------------------------------
# Analysis result (JSON / HTML / plain-text)
# ---------------------------------------------------------------------------


@internal_bp.get("/reports/<job_id>")
async def api_report_json(job_id: str):
    job = _svc().get_job(job_id)
    if job is None:
        abort(404, "Job not found")
    if job.state == "error":
        abort(500, job.error or "Analysis failed")
    if job.state != "done":
        return jsonify({"job_id": job_id, "state": job.state}), 202
    return jsonify(job.result.to_dict())  # type: ignore[union-attr]


@internal_bp.get("/reports/<job_id>/html")
async def api_report_html(job_id: str):
    svc = _svc()
    result = svc.get_result(job_id)
    if result is None:
        job = svc.get_job(job_id)
        if job is None:
            abort(404, "Job not found")
        if job.state == "error":
            abort(500, job.error or "Analysis failed")
        abort(202, "Not ready")
    html = svc.render_html(result)
    resp = await make_response(html)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


@internal_bp.get("/reports/<job_id>/text")
async def api_report_text(job_id: str):
    svc = _svc()
    result = svc.get_result(job_id)
    if result is None:
        job = svc.get_job(job_id)
        if job is None:
            abort(404, "Job not found")
        if job.state == "error":
            abort(500, job.error or "Analysis failed")
        abort(202, "Not ready")
    text = svc.render_text(result)
    resp = await make_response(text)
    resp.headers["Content-Type"] = "text/plain; charset=utf-8"
    return resp


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------


@internal_bp.get("/history")
async def api_history():
    try:
        limit = min(int(request.args.get("limit", 25)), 100)
    except ValueError:
        abort(400, "limit must be an integer")

    messages = _svc().get_history(limit=limit)
    return jsonify(
        [
            {
                "message_id": m.message_id,
                "subject": m.subject,
                "sender": m.sender,
                "recipient": m.recipient,
                "category": m.category,
                "created_at": m.created_at.isoformat(),
            }
            for m in messages
        ]
    )


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@internal_bp.get("/stats")
async def api_stats():
    """Return job counters and storage message count."""
    return jsonify(_svc().get_stats())


# ---------------------------------------------------------------------------
# System info
# ---------------------------------------------------------------------------


@internal_bp.get("/system")
async def api_system():
    """Return runtime and hardware info (CPU, RAM, disk if psutil is available)."""
    return jsonify(_svc().get_system_info())


# ---------------------------------------------------------------------------
# Prometheus-compatible metrics
# ---------------------------------------------------------------------------


@internal_bp.get("/metrics")
async def api_metrics():
    """Expose metrics in Prometheus text exposition format 0.0.4."""
    stats = _svc().get_stats()
    jobs = stats["jobs"]
    storage = stats["storage"]
    sys_info = _svc().get_system_info()

    def _g(name: str, help_: str, value) -> list[str]:
        return [
            f"# HELP {name} {help_}",
            f"# TYPE {name} gauge",
            f"{name} {value}",
        ]

    def _c(name: str, help_: str, value) -> list[str]:
        return [
            f"# HELP {name} {help_}",
            f"# TYPE {name} counter",
            f"{name}_total {value}",
        ]

    lines: list[str] = []
    lines += _g("spammy_jobs_pending",  "Pending analysis jobs",                       jobs["pending"])
    lines += _g("spammy_jobs_running",  "Currently running analysis jobs",             jobs["running"])
    lines += _g("spammy_jobs_done",     "Completed analysis jobs held in memory",      jobs["done"])
    lines += _g("spammy_jobs_error",    "Failed analysis jobs held in memory",         jobs["error"])
    lines += _c("spammy_jobs_submitted","Total analysis jobs submitted since startup", jobs["total_submitted"])
    lines += _g("spammy_uptime_seconds","Server uptime in seconds",                    jobs["uptime_seconds"])
    lines += _g("spammy_storage_messages","Total messages in persistent storage",      storage["total_messages"])

    if sys_info.get("cpu_percent") is not None:
        lines += _g("spammy_cpu_percent",     "CPU usage percentage",      sys_info["cpu_percent"])
    if sys_info.get("memory_percent") is not None:
        lines += _g("spammy_memory_percent",  "Memory usage percentage",   sys_info["memory_percent"])
    if sys_info.get("memory_used_mb") is not None:
        lines += _g("spammy_memory_used_mb",  "Used memory in MiB",        sys_info["memory_used_mb"])
    if sys_info.get("disk_free_mb") is not None:
        lines += _g("spammy_disk_free_mb",    "Free disk space in MiB",    sys_info["disk_free_mb"])

    body = "\n".join(lines) + "\n"
    resp = await make_response(body)
    resp.headers["Content-Type"] = "text/plain; version=0.0.4; charset=utf-8"
    return resp


# ---------------------------------------------------------------------------
# Job management
# ---------------------------------------------------------------------------


@internal_bp.delete("/jobs/<job_id>")
async def api_cancel_job(job_id: str):
    """Cancel a *pending* job.  Returns 409 if the job is not in pending state."""
    svc = _svc()
    cancelled = await svc.cancel_job(job_id)
    if not cancelled:
        job = svc.get_job(job_id)
        if job is None:
            abort(404, "Job not found")
        abort(409, f"Job is already in state '{job.state}'; only pending jobs can be cancelled")
    return jsonify({"job_id": job_id, "state": "cancelled", "message": "Job cancelled"})
