"""Bounded, persistent agent memory and goal tracking for GhostCorp.

This module stores ordinary project facts and work state only. It deliberately
rejects credential-like material and is not a secrets manager.
"""
from __future__ import annotations

import json
import re
import sqlite3
import time
import uuid
from dataclasses import dataclass
from typing import Any


_SECRET_KEY = re.compile(
    r"(password|passwd|secret|private.?key|seed.?phrase|recovery.?code|"
    r"api.?key|access.?token|refresh.?token|credential)",
    re.IGNORECASE,
)
_SECRET_VALUE = re.compile(
    r"(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    r"\bsk_(?:live|test)_[A-Za-z0-9]{12,}|"
    r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,})",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Memory:
    key: str
    value: Any
    source: str
    confidence: float
    sensitivity: str = "internal"
    expires_at: float | None = None


class MemoryStore:
    """SQLite memory with provenance, confidence, expiry, and bounded size."""

    MAX_RECORDS = 1000
    MAX_VALUE_BYTES = 16_384
    SENSITIVITY = {"public", "internal", "restricted"}

    def __init__(self, database: str = "ghostcorp-memory.sqlite3"):
        self._db = sqlite3.connect(database, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._db:
            self._db.executescript("""
                PRAGMA foreign_keys = ON;
                CREATE TABLE IF NOT EXISTS memories (
                    memory_id TEXT PRIMARY KEY,
                    memory_key TEXT NOT NULL UNIQUE,
                    value_json TEXT NOT NULL,
                    source TEXT NOT NULL,
                    confidence REAL NOT NULL CHECK(confidence >= 0 AND confidence <= 1),
                    sensitivity TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    expires_at REAL
                );
                CREATE TABLE IF NOT EXISTS goals (
                    goal_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    status TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    due_at TEXT,
                    blockers_json TEXT NOT NULL,
                    completion_reason TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_goals_status_priority
                    ON goals(status, priority DESC, created_at);
            """)

    def close(self) -> None:
        self._db.close()

    @staticmethod
    def _validate_memory(memory: Memory) -> str:
        if not memory.key.strip() or not memory.source.strip():
            raise ValueError("Memory key and provenance source are required")
        if _SECRET_KEY.search(memory.key):
            raise ValueError("Credential-like memory keys are not allowed")
        if memory.sensitivity not in MemoryStore.SENSITIVITY:
            raise ValueError("Invalid sensitivity label")
        if not 0.0 <= memory.confidence <= 1.0:
            raise ValueError("Confidence must be between 0 and 1")
        value_json = json.dumps(memory.value, ensure_ascii=False, sort_keys=True)
        if len(value_json.encode("utf-8")) > MemoryStore.MAX_VALUE_BYTES:
            raise ValueError("Memory value exceeds the size limit")
        if _SECRET_VALUE.search(value_json):
            raise ValueError("Credential-like material must use a secrets manager")
        if memory.expires_at is not None and memory.expires_at <= time.time():
            raise ValueError("Expiry must be in the future")
        return value_json

    def remember(self, memory: Memory) -> int:
        """Create or replace a fact; returns its monotonically increasing version."""
        value_json = self._validate_memory(memory)
        now = time.time()
        with self._db:
            count = self._db.execute("SELECT COUNT(*) FROM memories").fetchone()[0]
            exists = self._db.execute(
                "SELECT version FROM memories WHERE memory_key=?", (memory.key,)
            ).fetchone()
            if exists is None and count >= self.MAX_RECORDS:
                raise ValueError("Memory capacity reached; expire or forget old records")
            version = (exists["version"] + 1) if exists else 1
            self._db.execute("""
                INSERT INTO memories(
                    memory_id, memory_key, value_json, source, confidence,
                    sensitivity, version, created_at, updated_at, expires_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(memory_key) DO UPDATE SET
                    value_json=excluded.value_json,
                    source=excluded.source,
                    confidence=excluded.confidence,
                    sensitivity=excluded.sensitivity,
                    version=excluded.version,
                    updated_at=excluded.updated_at,
                    expires_at=excluded.expires_at
            """, (
                str(uuid.uuid4()), memory.key, value_json, memory.source,
                memory.confidence, memory.sensitivity, version, now, now,
                memory.expires_at,
            ))
        return version

    def recall(self, key: str, now: float | None = None) -> dict[str, Any] | None:
        now = time.time() if now is None else now
        row = self._db.execute(
            "SELECT * FROM memories WHERE memory_key=? AND (expires_at IS NULL OR expires_at>?)",
            (key, now),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["value"] = json.loads(result.pop("value_json"))
        return result

    def list_memories(self, limit: int = 100, now: float | None = None) -> list[dict[str, Any]]:
        if not 1 <= limit <= self.MAX_RECORDS:
            raise ValueError("Limit must be between 1 and MAX_RECORDS")
        now = time.time() if now is None else now
        rows = self._db.execute("""
            SELECT * FROM memories
            WHERE expires_at IS NULL OR expires_at>?
            ORDER BY updated_at DESC LIMIT ?
        """, (now, limit)).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            item["value"] = json.loads(item.pop("value_json"))
            output.append(item)
        return output

    def forget(self, key: str) -> bool:
        with self._db:
            result = self._db.execute(
                "DELETE FROM memories WHERE memory_key=?", (key,)
            )
            return result.rowcount == 1

    def prune_expired(self, now: float | None = None) -> int:
        now = time.time() if now is None else now
        with self._db:
            result = self._db.execute(
                "DELETE FROM memories WHERE expires_at IS NOT NULL AND expires_at<=?",
                (now,),
            )
            return result.rowcount

    def create_goal(
        self, title: str, description: str = "", priority: int = 50,
        due_at: str | None = None, blockers: list[str] | None = None,
    ) -> str:
        if not title.strip():
            raise ValueError("Goal title is required")
        if not 0 <= priority <= 100:
            raise ValueError("Priority must be between 0 and 100")
        blocker_list = blockers or []
        if any(not isinstance(item, str) or not item.strip() for item in blocker_list):
            raise ValueError("Blockers must be non-empty strings")
        goal_id = str(uuid.uuid4())
        now = time.time()
        with self._db:
            self._db.execute("""
                INSERT INTO goals(
                    goal_id, title, description, status, priority, due_at,
                    blockers_json, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
            """, (
                goal_id, title, description, "active", priority, due_at,
                json.dumps(blocker_list), now, now,
            ))
        return goal_id

    def update_goal(
        self, goal_id: str, status: str | None = None,
        blockers: list[str] | None = None, completion_reason: str | None = None,
    ) -> None:
        allowed = {"active", "blocked", "completed", "abandoned"}
        if status is not None and status not in allowed:
            raise ValueError("Invalid goal status")
        if blockers is not None and any(
            not isinstance(item, str) or not item.strip() for item in blockers
        ):
            raise ValueError("Blockers must be non-empty strings")
        if status in {"completed", "abandoned"} and not (completion_reason or "").strip():
            raise ValueError("Completion or abandonment requires a reason")
        updates = ["updated_at=?"]
        values: list[Any] = [time.time()]
        if status is not None:
            updates.append("status=?")
            values.append(status)
        if blockers is not None:
            updates.append("blockers_json=?")
            values.append(json.dumps(blockers))
        if completion_reason is not None:
            updates.append("completion_reason=?")
            values.append(completion_reason)
        values.append(goal_id)
        with self._db:
            result = self._db.execute(
                f"UPDATE goals SET {', '.join(updates)} WHERE goal_id=?", values
            )
            if result.rowcount != 1:
                raise KeyError(goal_id)

    def goals(self, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= limit <= 500:
            raise ValueError("Limit must be between 1 and 500")
        if status is not None and status not in {"active", "blocked", "completed", "abandoned"}:
            raise ValueError("Invalid goal status")
        if status is None:
            rows = self._db.execute(
                "SELECT * FROM goals ORDER BY priority DESC, created_at LIMIT ?", (limit,)
            ).fetchall()
        else:
            rows = self._db.execute(
                "SELECT * FROM goals WHERE status=? ORDER BY priority DESC, created_at LIMIT ?",
                (status, limit),
            ).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            item["blockers"] = json.loads(item.pop("blockers_json"))
            output.append(item)
        return output


__all__ = ["Memory", "MemoryStore"]
