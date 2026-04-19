"""HTTP client for the Spammy TUI (``spammy client`` subcommand).

Communicates with a running Spammy server via the internal REST API
(/api/v1/).  Requires ``httpx`` (already a runtime dependency).
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import httpx

DEFAULT_SERVER = "http://127.0.0.1:5000"
DEFAULT_POLL_INTERVAL = 2.0  # seconds
DEFAULT_TIMEOUT = 60  # seconds to wait for analysis to complete


class SpammyClientError(Exception):
    """Raised on any communication or API error."""


class SpammyClient:
    """Thin client over the Spammy internal REST API."""

    def __init__(
        self,
        base_url: str = DEFAULT_SERVER,
        api_key: str | None = None,
        http_timeout: float = 10.0,
    ) -> None:
        headers: dict[str, str] = {"Accept": "application/json"}
        if api_key:
            headers["X-API-Key"] = api_key
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers=headers,
            timeout=http_timeout,
            follow_redirects=True,
        )

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def analyze(
        self,
        raw: bytes,
        poll_timeout: float = DEFAULT_TIMEOUT,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
    ) -> dict[str, Any]:
        """Submit EML bytes, poll until done, and return the full result dict.

        Raises :class:`SpammyClientError` on any error.
        """
        job_id = self._submit(raw)
        return self._wait_for_result(job_id, poll_timeout, poll_interval)

    def _submit(self, raw: bytes) -> str:
        try:
            resp = self._client.post(
                "/api/v1/analyze",
                files={"eml_file": ("message.eml", raw, "message/rfc822")},
            )
        except httpx.RequestError as exc:
            raise SpammyClientError(f"Could not connect to server: {exc}") from exc
        if resp.status_code not in (200, 202):
            raise SpammyClientError(f"Submit failed: {resp.status_code} – {resp.text}")
        return resp.json()["job_id"]

    def _wait_for_result(
        self, job_id: str, timeout: float, interval: float
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                resp = self._client.get(f"/api/v1/jobs/{job_id}")
            except httpx.RequestError as exc:
                raise SpammyClientError(f"Polling failed: {exc}") from exc
            if resp.status_code != 200:
                raise SpammyClientError(f"Poll error: {resp.status_code} – {resp.text}")
            job = resp.json()
            if job["state"] == "done":
                return self._fetch_result(job_id)
            if job["state"] == "error":
                raise SpammyClientError(f"Analysis failed: {job.get('error', 'unknown error')}")
            time.sleep(interval)
        raise SpammyClientError(f"Timed out waiting for job {job_id}")

    def _fetch_result(self, job_id: str) -> dict[str, Any]:
        try:
            resp = self._client.get(f"/api/v1/reports/{job_id}")
        except httpx.RequestError as exc:
            raise SpammyClientError(f"Could not fetch result: {exc}") from exc
        if resp.status_code != 200:
            raise SpammyClientError(f"Fetch result failed: {resp.status_code} – {resp.text}")
        return resp.json()

    # ------------------------------------------------------------------
    # History
    # ------------------------------------------------------------------

    def history(self, limit: int = 25) -> list[dict[str, Any]]:
        """Return recent analysis records from the server's storage."""
        try:
            resp = self._client.get("/api/v1/history", params={"limit": limit})
        except httpx.RequestError as exc:
            raise SpammyClientError(f"Could not connect to server: {exc}") from exc
        if resp.status_code != 200:
            raise SpammyClientError(f"History failed: {resp.status_code} – {resp.text}")
        return resp.json()

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> SpammyClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
