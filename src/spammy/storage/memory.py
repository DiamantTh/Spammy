from __future__ import annotations

from collections import deque
from datetime import datetime
from typing import Deque, Iterable, Optional

from .base import AbuseContactRecord, AnalysisRecord, MessageRecord, StorageBackend


class InMemoryStorage(StorageBackend):
    """Non-persistent storage useful for tests or demo setups."""

    def __init__(self, capacity: int = 500):
        self.capacity = capacity
        self._messages: Deque[MessageRecord] = deque(maxlen=capacity)
        self._analyses: Deque[AnalysisRecord] = deque(maxlen=capacity)
        self._contacts: Deque[AbuseContactRecord] = deque(maxlen=capacity * 5)

    def store_message(
        self,
        message: MessageRecord,
        analysis: AnalysisRecord,
        contacts: Iterable[AbuseContactRecord],
    ) -> None:
        self._messages.append(message)
        self._analyses.append(analysis)
        for contact in contacts:
            self._contacts.append(contact)

    def list_messages(
        self,
        *,
        limit: int = 50,
        category: Optional[str] = None,
    ) -> Iterable[MessageRecord]:
        results = list(self._messages)
        if category:
            results = [msg for msg in results if msg.category == category]
        return list(reversed(results))[:limit]

    def count_messages(self) -> int:
        return len(self._messages)
