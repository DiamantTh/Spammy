"""FastAPI routes for the public external API (v1)."""

from __future__ import annotations

import base64
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, status

from ...service import MAX_EML_BYTES, AnalysisService
from ..models import (
    AnalyzeRequest,
    HistoryItem,
    HistoryResponse,
    JobCreatedResponse,
    JobStatusResponse,
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
