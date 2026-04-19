"""Internal REST API Blueprint – consumed by the Web UI (AJAX) and TUI.

All endpoints are same-origin only (enforced via CSRF/Referer in the security
middleware for state-changing routes). No separate authentication is required
for the internal API since it only listens on 127.0.0.1.

Endpoints:
  POST /api/v1/analyze          – submit EML, returns {job_id}
  GET  /api/v1/jobs/<job_id>    – poll job state
  GET  /api/v1/reports/<job_id> – full JSON analysis result
  GET  /api/v1/history          – paginated list of stored messages
"""

from __future__ import annotations

import asyncio
import base64

from quart import Blueprint, abort, current_app, jsonify, request

from ...config_loader import SpammyConfig
from ...jobs import get_store
from ...rdap_client import RDAPClient
from ...storage import StorageError, build_storage
from ..routes.ui import MAX_EML_BYTES, _persist, _run_analysis

internal_bp = Blueprint("internal", __name__)


# ---------------------------------------------------------------------------
# Submit analysis
# ---------------------------------------------------------------------------


@internal_bp.post("/analyze")
async def api_analyze():
    """Submit an EML for analysis; returns a job ID immediately.

    Accepts:
      - multipart/form-data  with field ``eml_file``
      - application/json     with field ``eml_b64`` (base64-encoded EML)
    """
    cfg: SpammyConfig = current_app.config["SPAMMY_CONFIG"]
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

    store = get_store()
    job = store.create()
    asyncio.ensure_future(
        _run_analysis(job.job_id, raw, cfg),
        loop=asyncio.get_event_loop(),
    )

    return jsonify({"job_id": job.job_id, "state": job.state}), 202


# ---------------------------------------------------------------------------
# Job status
# ---------------------------------------------------------------------------


@internal_bp.get("/jobs/<job_id>")
async def api_job_status(job_id: str):
    store = get_store()
    job = store.get(job_id)
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
# Full analysis result
# ---------------------------------------------------------------------------


@internal_bp.get("/reports/<job_id>")
async def api_report(job_id: str):
    store = get_store()
    job = store.get(job_id)
    if job is None:
        abort(404, "Job not found")
    if job.state != "done":
        return jsonify({"job_id": job_id, "state": job.state}), 202
    return jsonify(job.result.to_dict())  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# History (from persistent storage)
# ---------------------------------------------------------------------------


@internal_bp.get("/history")
async def api_history():
    cfg: SpammyConfig = current_app.config["SPAMMY_CONFIG"]
    try:
        limit = min(int(request.args.get("limit", 25)), 100)
    except ValueError:
        abort(400, "limit must be an integer")

    try:
        storage = build_storage(cfg.storage)
        messages = list(storage.list_messages(limit=limit))
    except (StorageError, Exception):
        messages = []

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
