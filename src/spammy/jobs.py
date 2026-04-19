"""In-memory job store for async analysis tasks.

Each Spammy server process keeps its own asyncio-safe job registry.
Jobs are not persisted across restarts; completed results are written to the
configured storage backend by the analysis worker.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Literal, Optional
from uuid import uuid4

from .models import AnalysisResult

JobState = Literal["pending", "running", "done", "error"]


@dataclass
class Job:
    job_id: str
    state: JobState
    created_at: datetime
    finished_at: Optional[datetime] = None
    result: Optional[AnalysisResult] = None
    error: Optional[str] = None


class JobStore:
    """Thread-safe (asyncio) in-memory job registry."""

    _MAX_JOBS = 500  # oldest entries pruned beyond this limit

    def __init__(self) -> None:
        self._jobs: Dict[str, Job] = {}
        self._lock = asyncio.Lock()

    def create(self) -> Job:
        """Create a new *pending* job and return it synchronously."""
        job = Job(
            job_id=str(uuid4()),
            state="pending",
            created_at=datetime.now(timezone.utc),
        )
        self._jobs[job.job_id] = job
        self._maybe_prune()
        return job

    def get(self, job_id: str) -> Optional[Job]:
        return self._jobs.get(job_id)

    async def mark_running(self, job_id: str) -> None:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job:
                job.state = "running"

    async def mark_done(self, job_id: str, result: AnalysisResult) -> None:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job:
                job.state = "done"
                job.result = result
                job.finished_at = datetime.now(timezone.utc)

    async def mark_error(self, job_id: str, error: str) -> None:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job:
                job.state = "error"
                job.error = error
                job.finished_at = datetime.now(timezone.utc)

    def _maybe_prune(self) -> None:
        if len(self._jobs) > self._MAX_JOBS:
            # Drop oldest finished jobs first; keep pending/running ones
            finished = sorted(
                (j for j in self._jobs.values() if j.state in ("done", "error")),
                key=lambda j: j.created_at,
            )
            to_remove = len(self._jobs) - self._MAX_JOBS
            for job in finished[:to_remove]:
                del self._jobs[job.job_id]


# Module-level singleton – shared within one process
_store: Optional[JobStore] = None


def get_store() -> JobStore:
    global _store
    if _store is None:
        _store = JobStore()
    return _store
