"""
Storage package defining interfaces and shared data structures for DB backends.
"""

from .base import AbuseContactRecord, AnalysisRecord, MessageRecord, StorageBackend, StorageError
from .factory import build_storage
from .memory import InMemoryStorage
from .sqlite import SQLiteStorage

__all__ = [
    "StorageBackend",
    "StorageError",
    "MessageRecord",
    "AnalysisRecord",
    "AbuseContactRecord",
    "build_storage",
    "InMemoryStorage",
    "SQLiteStorage",
]
