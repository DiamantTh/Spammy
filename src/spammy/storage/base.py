from __future__ import annotations

import abc
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Optional, Protocol


class StorageError(RuntimeError):
    """Raised when a storage backend cannot persist or fetch data."""


@dataclass(slots=True)
class MessageRecord:
    message_id: str
    subject: Optional[str]
    sender: Optional[str]
    recipient: Optional[str]
    category: Optional[str]
    created_at: datetime
    mailbox: Optional[str] = None


@dataclass(slots=True)
class AnalysisRecord:
    message_id: str
    origin_ip: Optional[str]
    rdap_network: Optional[str]
    severity: Optional[str]
    metadata_json: str
    created_at: datetime


@dataclass(slots=True)
class AbuseContactRecord:
    message_id: str
    address: str
    role: Optional[str]
    confidence: Optional[float]


class StorageBackend(Protocol):
    """Interface all storage implementations must satisfy."""

    def store_message(
        self,
        message: MessageRecord,
        analysis: AnalysisRecord,
        contacts: Iterable[AbuseContactRecord],
    ) -> None:
        """Persist a message with its analysis and contacts."""

    def list_messages(
        self,
        *,
        limit: int = 50,
        category: Optional[str] = None,
    ) -> Iterable[MessageRecord]:
        """Return recently stored messages, optionally filtered by category."""

    def count_messages(self) -> int:
        """Return the total number of stored messages."""

