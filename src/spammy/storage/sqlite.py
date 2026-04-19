from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

from .base import AbuseContactRecord, AnalysisRecord, MessageRecord, StorageBackend, StorageError

SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_uuid TEXT NOT NULL UNIQUE,
    subject TEXT,
    sender TEXT,
    recipient TEXT,
    mailbox TEXT,
    category TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_uuid TEXT NOT NULL REFERENCES messages(message_uuid) ON DELETE CASCADE,
    origin_ip TEXT,
    rdap_network TEXT,
    severity TEXT,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS abuse_contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_uuid TEXT NOT NULL REFERENCES messages(message_uuid) ON DELETE CASCADE,
    address TEXT NOT NULL,
    role TEXT,
    confidence REAL
);

CREATE INDEX IF NOT EXISTS idx_messages_category_created ON messages(category, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_analyses_message_uuid ON analyses(message_uuid);
CREATE INDEX IF NOT EXISTS idx_contacts_message_uuid ON abuse_contacts(message_uuid);
"""


class SQLiteStorage(StorageBackend):
    def __init__(self, database: Path):
        self.path = database
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    def store_message(
        self,
        message: MessageRecord,
        analysis: AnalysisRecord,
        contacts: Iterable[AbuseContactRecord],
    ) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO messages (message_uuid, subject, sender, recipient, mailbox, category, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(message_uuid) DO UPDATE SET
                        subject=excluded.subject,
                        sender=excluded.sender,
                        recipient=excluded.recipient,
                        mailbox=excluded.mailbox,
                        category=excluded.category,
                        created_at=excluded.created_at
                    """,
                    (
                        message.message_id,
                        message.subject,
                        message.sender,
                        message.recipient,
                        message.mailbox,
                        message.category,
                        message.created_at.isoformat(),
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO analyses (message_uuid, origin_ip, rdap_network, severity, metadata_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        analysis.message_id,
                        analysis.origin_ip,
                        analysis.rdap_network,
                        analysis.severity,
                        analysis.metadata_json,
                        analysis.created_at.isoformat(),
                    ),
                )
                conn.execute("DELETE FROM abuse_contacts WHERE message_uuid = ?", (message.message_id,))
                conn.executemany(
                    """
                    INSERT INTO abuse_contacts (message_uuid, address, role, confidence)
                    VALUES (?, ?, ?, ?)
                    """,
                    [
                        (
                            contact.message_id,
                            contact.address,
                            contact.role,
                            contact.confidence,
                        )
                        for contact in contacts
                    ],
                )
        except sqlite3.DatabaseError as exc:  # pragma: no cover - requires I/O
            raise StorageError(str(exc)) from exc

    def list_messages(
        self,
        *,
        limit: int = 50,
        category: Optional[str] = None,
    ):
        query = "SELECT message_uuid, subject, sender, recipient, mailbox, category, created_at FROM messages"
        params: list = []
        if category:
            query += " WHERE category = ?"
            params.append(category)
        query += " ORDER BY datetime(created_at) DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        for row in rows:
            yield MessageRecord(
                message_id=row[0],
                subject=row[1],
                sender=row[2],
                recipient=row[3],
                mailbox=row[4],
                category=row[5],
                created_at=datetime.fromisoformat(row[6]),
            )

    def count_messages(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) FROM messages").fetchone()
        return int(row[0]) if row else 0
