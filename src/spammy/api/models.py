"""Pydantic models for the external FastAPI layer."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------


class AnalyzeRequest(BaseModel):
    """Submit an EML for analysis via JSON body."""

    eml_b64: str = Field(..., description="Base64-encoded raw EML/RFC-822 message.")


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------


class JobCreatedResponse(BaseModel):
    job_id: str
    state: Literal["pending"] = "pending"
    message: str = "Analysis queued"


class JobStatusResponse(BaseModel):
    job_id: str
    state: Literal["pending", "running", "done", "error"]
    created_at: datetime
    finished_at: Optional[datetime] = None
    error: Optional[str] = None


class HistoryItem(BaseModel):
    message_id: str
    subject: Optional[str] = None
    sender: Optional[str] = None
    recipient: Optional[str] = None
    category: Optional[str] = None
    created_at: datetime


class HistoryResponse(BaseModel):
    items: List[HistoryItem]
    total: int


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    version: str


# ---------------------------------------------------------------------------
# Stats & System
# ---------------------------------------------------------------------------


class JobStatsDetail(BaseModel):
    pending: int
    running: int
    done: int
    error: int
    total_submitted: int
    in_memory: int
    uptime_seconds: float
    started_at: datetime


class StorageStatsDetail(BaseModel):
    total_messages: int


class StatsResponse(BaseModel):
    jobs: JobStatsDetail
    storage: StorageStatsDetail


class SystemInfoResponse(BaseModel):
    version: str
    python: str
    platform: str
    platform_release: str
    cpu_count: Optional[int] = None
    cpu_percent: Optional[float] = None
    memory_total_mb: Optional[int] = None
    memory_used_mb: Optional[int] = None
    memory_percent: Optional[float] = None
    disk_free_mb: Optional[int] = None
    disk_total_mb: Optional[int] = None


class CancelJobResponse(BaseModel):
    job_id: str
    state: str
    message: str = "Job cancelled"
