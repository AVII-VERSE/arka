"""
Disk-backed SQLite FIFO Queue for Agent Event Buffering.
Provides offline storage resilience during backend network outages.
"""

import json
import sqlite3
from typing import Any


class SQLiteQueue:
    def __init__(self, db_path: str = "agent_queue.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS event_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            conn.commit()

    def push(self, event: dict[str, Any]) -> None:
        event_id = event.get("event_id")
        if not event_id:
            return
        payload_str = json.dumps(event)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO event_queue (event_id, payload) VALUES (?, ?);",
                (event_id, payload_str),
            )
            conn.commit()

    def pop_batch(self, batch_size: int = 50) -> list[dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT id, payload FROM event_queue ORDER BY id ASC LIMIT ?;",
                (batch_size,),
            )
            rows = cursor.fetchall()
            events = []
            for row in rows:
                events.append(json.loads(row[1]))
            return events

    def delete_batch(self, batch_size: int = 50) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                DELETE FROM event_queue WHERE id IN (
                    SELECT id FROM event_queue ORDER BY id ASC LIMIT ?
                );
                """,
                (batch_size,),
            )
            conn.commit()

    def size(self) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM event_queue;")
            return cursor.fetchone()[0]
