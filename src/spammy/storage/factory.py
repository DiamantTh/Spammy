from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..config_loader import StorageSettings
from .base import StorageBackend, StorageError
from .memory import InMemoryStorage
from .sqlite import SQLiteStorage


def build_storage(settings: StorageSettings) -> Optional[StorageBackend]:
    backend = (settings.backend or "memory").lower()
    if backend in {"none", "disabled"}:
        return None
    if backend == "memory":
        return InMemoryStorage()
    if backend == "sqlite":
        db_path = Path(settings.database or "var/spammy.sqlite3")
        return SQLiteStorage(db_path.expanduser())
    raise StorageError(f"Unsupported storage backend '{backend}'")
