"""
Storage package defining interfaces and shared data structures for DB backends.
"""

from .base import (
    AbuseContactRecord,
    AnalysisRecord,
    MessageRecord,
    StorageBackend,
    StorageError,
)

__all__ = [
    "StorageBackend",
    "StorageError",
    "MessageRecord",
    "AnalysisRecord",
    "AbuseContactRecord",
]
