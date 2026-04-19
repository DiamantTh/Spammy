"""Spammy backend service layer.

All business logic lives here – the Quart internal API blueprint and the
FastAPI external API both delegate to this module.  UI routes are completely
decoupled from analysis/storage code.
"""

from __future__ import annotations

import asyncio
import logging
import os
import platform
import sys
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from .analysis import analyze_message
from .config_loader import SpammyConfig
from .jobs import Job, get_store
from .models import AnalysisResult
from .rdap_client import RDAPClient
from .reporting import ReportBuilder
from .storage import (
    AbuseContactRecord,
    AnalysisRecord,
    MessageRecord,
    StorageError,
    build_storage,
)

logger = logging.getLogger(__name__)

MAX_EML_BYTES = 25 * 1024 * 1024  # 25 MB hard limit


class AnalysisService:
    """Thin service façade used by the API layers."""

    def __init__(self, config: SpammyConfig) -> None:
        self._config = config

    # ------------------------------------------------------------------
    # Job management
    # ------------------------------------------------------------------

    def submit(self, raw: bytes) -> Job:
        """Create a job and schedule analysis; returns immediately."""
        store = get_store()
        job = store.create()
        asyncio.ensure_future(
            _run_analysis(job.job_id, raw, self._config),
            loop=asyncio.get_event_loop(),
        )
        return job

    def get_job(self, job_id: str) -> Optional[Job]:
        return get_store().get(job_id)

    def get_result(self, job_id: str) -> Optional[AnalysisResult]:
        job = get_store().get(job_id)
        if job and job.state == "done":
            return job.result
        return None

    # ------------------------------------------------------------------
    # History
    # ------------------------------------------------------------------

    def get_history(self, limit: int = 25) -> list:
        limit = max(1, min(limit, 100))
        try:
            storage = build_storage(self._config.storage)
            return list(storage.list_messages(limit=limit))
        except (StorageError, Exception):
            return []

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def render_html(self, result: AnalysisResult, lang: str | None = None) -> str:
        builder = ReportBuilder(template_dir=self._config.reporting.template_dir)
        return builder.render_html(result, lang=lang or result.preferred_language)

    def render_text(self, result: AnalysisResult, lang: str | None = None) -> str:
        builder = ReportBuilder(template_dir=self._config.reporting.template_dir)
        return builder.render_text(result, lang=lang or result.preferred_language)

    # ------------------------------------------------------------------
    # Stats & System
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        """Return job counters + storage count."""
        job_stats = get_store().stats()
        storage_total: int = -1
        try:
            storage = build_storage(self._config.storage)
            storage_total = storage.count_messages()
        except Exception:
            pass
        return {
            "jobs": job_stats,
            "storage": {"total_messages": storage_total},
        }

    def get_system_info(self) -> dict:
        """Return runtime + hardware info (psutil optional)."""
        from .version import get_version

        info: dict = {
            "version": get_version(),
            "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "platform": platform.system(),
            "platform_release": platform.release(),
            "cpu_count": os.cpu_count(),
            "cpu_percent": None,
            "memory_total_mb": None,
            "memory_used_mb": None,
            "memory_percent": None,
            "disk_free_mb": None,
            "disk_total_mb": None,
        }
        try:
            import psutil  # type: ignore[import-untyped]

            info["cpu_percent"] = psutil.cpu_percent(interval=0.1)
            vm = psutil.virtual_memory()
            info["memory_total_mb"] = round(vm.total / 1024 / 1024)
            info["memory_used_mb"] = round(vm.used / 1024 / 1024)
            info["memory_percent"] = round(vm.percent, 1)
            disk = psutil.disk_usage("/")
            info["disk_free_mb"] = round(disk.free / 1024 / 1024)
            info["disk_total_mb"] = round(disk.total / 1024 / 1024)
        except ImportError:
            pass
        return info

    async def cancel_job(self, job_id: str) -> bool:
        """Cancel a *pending* job.  Returns True if successfully cancelled."""
        store = get_store()
        job = store.get(job_id)
        if job is None or job.state != "pending":
            return False
        await store.mark_error(job_id, "Cancelled by user")
        return True


# ---------------------------------------------------------------------------
# Internal: async analysis worker (used by AnalysisService.submit)
# ---------------------------------------------------------------------------


async def _run_analysis(job_id: str, raw: bytes, config: SpammyConfig) -> None:
    store = get_store()
    await store.mark_running(job_id)
    try:
        client = RDAPClient(
            timeout=config.rdap.timeout,
            rdap_base=config.rdap.base_url,
        )
        loop = asyncio.get_event_loop()
        result: AnalysisResult = await loop.run_in_executor(
            None, lambda: analyze_message(raw, rdap_client=client)
        )
        await store.mark_done(job_id, result)
        try:
            storage = build_storage(config.storage)
            _persist(storage, result)
        except (StorageError, Exception) as exc:
            logger.warning("Could not persist analysis result: %s", exc)
    except Exception as exc:
        logger.exception("Analysis job %s failed", job_id)
        await store.mark_error(job_id, str(exc))


def _persist(storage, result: AnalysisResult) -> None:
    now = datetime.now(timezone.utc)
    msg_id = result.metadata.message_id or str(uuid4())
    message = MessageRecord(
        message_id=msg_id,
        subject=result.metadata.subject,
        sender=result.metadata.sender,
        recipient=result.metadata.recipient,
        category=None,
        mailbox=result.metadata.recipient,
        created_at=now,
    )
    rdap_owner = (
        result.rdap_record.owner.name
        if result.rdap_record and result.rdap_record.owner
        else None
    )
    import json

    analysis = AnalysisRecord(
        message_id=msg_id,
        origin_ip=result.candidate_ip,
        rdap_network=rdap_owner,
        severity=None,
        metadata_json=json.dumps(result.to_dict(), ensure_ascii=False),
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
    storage.store_message(message, analysis, contacts)
