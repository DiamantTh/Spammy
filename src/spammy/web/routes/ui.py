"""Server-rendered UI routes: dashboard, analyze form, report view."""

from __future__ import annotations

import asyncio
from pathlib import Path

from quart import (
    Blueprint,
    current_app,
    redirect,
    render_template,
    request,
    url_for,
)

from ...analysis import analyze_message
from ...config_loader import SpammyConfig
from ...jobs import Job, get_store
from ...rdap_client import RDAPClient
from ...reporting import ReportBuilder
from ...storage import (
    AbuseContactRecord,
    AnalysisRecord,
    MessageRecord,
    StorageError,
    build_storage,
)
from ..security import validate_csrf

ui_bp = Blueprint("ui", __name__)

MAX_EML_BYTES = 25 * 1024 * 1024  # 25 MB


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


@ui_bp.get("/")
async def dashboard():
    cfg: SpammyConfig = current_app.config["SPAMMY_CONFIG"]
    try:
        storage = build_storage(cfg.storage)
        recent = list(storage.list_messages(limit=25))
    except (StorageError, Exception):
        recent = []

    store = get_store()
    active_jobs = [
        j for j in store._jobs.values() if j.state in ("pending", "running")
    ]

    return await render_template(
        "dashboard.html",
        recent=recent,
        active_jobs=active_jobs,
    )


# ---------------------------------------------------------------------------
# Analyze
# ---------------------------------------------------------------------------


@ui_bp.get("/analyze")
async def analyze_form():
    return await render_template("analyze.html")


@ui_bp.post("/analyze")
async def analyze_submit():
    cfg: SpammyConfig = current_app.config["SPAMMY_CONFIG"]
    await validate_csrf(cfg.web.base_url)

    raw: bytes | None = None

    files = await request.files
    forms = await request.form
    eml_file = files.get("eml_file")
    raw_text = forms.get("raw_text", "").strip()

    if eml_file and eml_file.filename:
        raw = await eml_file.read(MAX_EML_BYTES + 1)
        if len(raw) > MAX_EML_BYTES:
            return await render_template(
                "analyze.html",
                error="Die EML-Datei überschreitet das Limit von 25 MB.",
            )
    elif raw_text:
        raw = raw_text.encode("utf-8", errors="replace")
        if len(raw) > MAX_EML_BYTES:
            return await render_template(
                "analyze.html",
                error="Die eingefügte E-Mail überschreitet das Limit von 25 MB.",
            )
    else:
        return await render_template(
            "analyze.html",
            error="Bitte eine EML-Datei hochladen oder den Quelltext einfügen.",
        )

    store = get_store()
    job = store.create()

    # Run analysis as background task
    asyncio.ensure_future(
        _run_analysis(job.job_id, raw, cfg),
        loop=asyncio.get_event_loop(),
    )

    return redirect(url_for("ui.report_view", job_id=job.job_id))


# ---------------------------------------------------------------------------
# Report view
# ---------------------------------------------------------------------------


@ui_bp.get("/report/<job_id>")
async def report_view(job_id: str):
    store = get_store()
    job = store.get(job_id)
    if job is None:
        return await render_template("error.html", message="Job nicht gefunden.", code=404), 404

    result_dict = None
    html_report = None
    text_report = None
    if job.state == "done" and job.result:
        result_dict = job.result.to_dict()
        cfg: SpammyConfig = current_app.config["SPAMMY_CONFIG"]
        builder = ReportBuilder(template_dir=cfg.reporting.template_dir)
        html_report = builder.render_html(job.result)
        text_report = builder.render_text(job.result)

    return await render_template(
        "report.html",
        job=job,
        result=result_dict,
        html_report=html_report,
        text_report=text_report,
    )


# ---------------------------------------------------------------------------
# Background analysis worker
# ---------------------------------------------------------------------------


async def _run_analysis(job_id: str, raw: bytes, cfg: SpammyConfig) -> None:
    store = get_store()
    await store.mark_running(job_id)
    try:
        client = RDAPClient(
            timeout=cfg.rdap.timeout,
            rdap_base=cfg.rdap.base_url,
        )
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None, lambda: analyze_message(raw, rdap_client=client)
        )
        await store.mark_done(job_id, result)
        # Persist to storage backend
        try:
            storage = build_storage(cfg.storage)
            _persist(storage, result)
        except (StorageError, Exception):
            pass  # storage failure must not break job result
    except Exception as exc:
        await store.mark_error(job_id, str(exc))


def _persist(storage, result) -> None:
    from datetime import datetime, timezone
    from uuid import uuid4

    now = datetime.now(timezone.utc)
    msg_id = result.metadata.message_id or str(uuid4())
    spam_score = getattr(result, "spam_score", None)
    severity = None
    if spam_score:
        t = spam_score.total
        severity = "high" if t >= 0.7 else "medium" if t >= 0.4 else "low"

    msg = MessageRecord(
        message_id=msg_id,
        subject=result.metadata.subject,
        sender=result.metadata.sender,
        recipient=result.metadata.recipient,
        category=severity,
        mailbox=result.metadata.recipient,
        created_at=now,
    )
    import json
    analysis = AnalysisRecord(
        message_id=msg_id,
        origin_ip=result.candidate_ip,
        rdap_network=result.rdap_record.owner.name if (result.rdap_record and result.rdap_record.owner) else None,
        severity=severity,
        metadata_json=json.dumps(result.metadata.headers, default=str),
        created_at=now,
    )
    contacts = [
        AbuseContactRecord(
            message_id=msg_id,
            address=c.address,
            role=c.source,
            confidence=c.confidence,
        )
        for c in result.abuse_contacts
    ]
    storage.store_message(msg, analysis, contacts)
