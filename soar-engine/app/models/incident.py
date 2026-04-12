"""
SQLite persistence for SOAR incidents (indicator, verdict, actions, timestamp).
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from app import config


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    """Create incidents table if it does not exist."""
    config.ensure_directories()
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT NOT NULL,
                verdict TEXT NOT NULL,
                severity TEXT NOT NULL,
                action_taken TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
            """
        )
        conn.commit()


@contextmanager
def get_connection():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def insert_incident(
    indicator: str,
    verdict: str,
    severity: str,
    action_taken: str,
    timestamp: str | None = None,
) -> int:
    """Insert one incident row; return new row id."""
    ts = timestamp or _utc_now()
    with get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO incidents (indicator, verdict, severity, action_taken, timestamp)
            VALUES (?, ?, ?, ?, ?)
            """,
            (indicator, verdict, severity, action_taken, ts),
        )
        conn.commit()
        return int(cur.lastrowid)


def get_all_incidents(limit: int = 500) -> list[dict[str, Any]]:
    """Return recent incidents newest first."""
    with get_connection() as conn:
        cur = conn.execute(
            """
            SELECT id, indicator, verdict, severity, action_taken, timestamp
            FROM incidents
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cur.fetchall()
    return [dict(r) for r in rows]
