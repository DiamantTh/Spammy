"""FastAPI routes for the public external API (v1)."""

from __future__ import annotations

import base64
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, status

from ...service import MAX_EML_BYTES, AnalysisService
from ..models import (
    AnalyzeRequest,
    CancelJobResponse,
    HistoryItem,
    HistoryResponse,
    JobCreatedResponse,
    JobStatusResponse,
    StatsResponse,
    SystemInfoResponse,
)

router = APIRouter()


def _svc(request: Request) -> AnalysisService:
    return request.app.state.spammy_service


# ---------------------------------------------------------------------------
# Submit analysis
# ---------------------------------------------------------------------------


@router.post(
    "/analyze",
    response_model=JobCreatedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit EML for analysis",
)
async def api_analyze(
    body: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    request: Request,
) -> JobCreatedResponse:
    try:
        raw = base64.b64decode(body.eml_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="eml_b64 is not valid base64")
    if len(raw) > MAX_EML_BYTES:
        raise HTTPException(status_code=413, detail="EML exceeds 25 MB limit")

    svc = _svc(request)
    job = svc.submit(raw)
    return JobCreatedResponse(job_id=job.job_id)


# ---------------------------------------------------------------------------
# Job status
# ---------------------------------------------------------------------------


@router.get(
    "/jobs/{job_id}",
    response_model=JobStatusResponse,
    summary="Poll analysis job status",
)
async def api_job_status(job_id: str, request: Request) -> JobStatusResponse:
    job = _svc(request).get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return JobStatusResponse(
        job_id=job.job_id,
        state=job.state,
        created_at=job.created_at,
        finished_at=job.finished_at,
        error=job.error,
    )


# ---------------------------------------------------------------------------
# Full result
# ---------------------------------------------------------------------------


@router.get(
    "/reports/{job_id}",
    summary="Retrieve full analysis result",
)
async def api_report(job_id: str, request: Request) -> Any:
    svc = _svc(request)
    job = svc.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.state == "error":
        raise HTTPException(status_code=500, detail=job.error or "Analysis failed")
    if job.state != "done":
        return {"job_id": job_id, "state": job.state}
    return job.result.to_dict()  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------


@router.get(
    "/history",
    response_model=HistoryResponse,
    summary="List recent analysis history",
)
async def api_history(request: Request, limit: int = 25) -> HistoryResponse:
    if limit < 1 or limit > 100:
        raise HTTPException(status_code=400, detail="limit must be 1–100")

    messages = _svc(request).get_history(limit=limit)
    return HistoryResponse(
        items=[
            HistoryItem(
                message_id=m.message_id,
                subject=m.subject,
                sender=m.sender,
                recipient=m.recipient,
                category=m.category,
                created_at=m.created_at,
            )
            for m in messages
        ],
        total=len(messages),
    )


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get(
    "/stats",
    response_model=StatsResponse,
    summary="Job counters and storage statistics",
    tags=["Stats"],
)
async def api_stats(request: Request) -> StatsResponse:
    data = _svc(request).get_stats()
    jobs = data["jobs"]
    storage = data["storage"]
    from ..models import JobStatsDetail, StorageStatsDetail
    return StatsResponse(
        jobs=JobStatsDetail(**jobs),
        storage=StorageStatsDetail(**storage),
    )


# ---------------------------------------------------------------------------
# System info
# ---------------------------------------------------------------------------


@router.get(
    "/system",
    response_model=SystemInfoResponse,
    summary="Runtime and hardware information",
    tags=["Stats"],
)
async def api_system(request: Request) -> SystemInfoResponse:
    return SystemInfoResponse(**_svc(request).get_system_info())


# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------


@router.get(
    "/metrics",
    summary="Prometheus-compatible metrics (text/plain 0.0.4)",
    tags=["Stats"],
    response_class=None,
)
async def api_metrics(request: Request):
    from fastapi.responses import PlainTextResponse

    stats = _svc(request).get_stats()
    jobs = stats["jobs"]
    storage = stats["storage"]
    sys_info = _svc(request).get_system_info()

    def _g(name: str, help_: str, value) -> list[str]:
        return [f"# HELP {name} {help_}", f"# TYPE {name} gauge", f"{name} {value}"]

    def _c(name: str, help_: str, value) -> list[str]:
        return [f"# HELP {name} {help_}", f"# TYPE {name} counter", f"{name}_total {value}"]

    lines: list[str] = []
    lines += _g("spammy_jobs_pending",   "Pending analysis jobs",                       jobs["pending"])
    lines += _g("spammy_jobs_running",   "Currently running analysis jobs",             jobs["running"])
    lines += _g("spammy_jobs_done",      "Completed jobs held in memory",               jobs["done"])
    lines += _g("spammy_jobs_error",     "Failed jobs held in memory",                  jobs["error"])
    lines += _c("spammy_jobs_submitted", "Total analysis jobs submitted since startup", jobs["total_submitted"])
    lines += _g("spammy_uptime_seconds", "Server uptime in seconds",                    jobs["uptime_seconds"])
    lines += _g("spammy_storage_messages", "Total messages in persistent storage",      storage["total_messages"])
    if sys_info.get("cpu_percent") is not None:
        lines += _g("spammy_cpu_percent",    "CPU usage percentage",    sys_info["cpu_percent"])
    if sys_info.get("memory_percent") is not None:
        lines += _g("spammy_memory_percent", "Memory usage percentage", sys_info["memory_percent"])
    if sys_info.get("disk_free_mb") is not None:
        lines += _g("spammy_disk_free_mb",   "Free disk space in MiB",  sys_info["disk_free_mb"])

    return PlainTextResponse(
        "\n".join(lines) + "\n",
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


# ---------------------------------------------------------------------------
# Job management
# ---------------------------------------------------------------------------


@router.delete(
    "/jobs/{job_id}",
    response_model=CancelJobResponse,
    summary="Cancel a pending analysis job",
    tags=["Analysis"],
)
async def api_cancel_job(job_id: str, request: Request) -> CancelJobResponse:
    svc = _svc(request)
    cancelled = await svc.cancel_job(job_id)
    if not cancelled:
        job = svc.get_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Job not found")
        raise HTTPException(
            status_code=409,
            detail=f"Job is already in state '{job.state}'; only pending jobs can be cancelled",
        )
    return CancelJobResponse(job_id=job_id, state="cancelled")
