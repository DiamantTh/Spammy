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
