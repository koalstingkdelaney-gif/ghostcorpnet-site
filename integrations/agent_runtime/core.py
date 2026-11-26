"""Small, dependency-free governed runtime core for GhostCorp.

This module is a local/sandbox foundation. It does not connect to payment
processors, wallets, email providers, or production systems.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class ActionRequest:
    actor_id: str
    action: str
    permissions: tuple[str, ...] = ()
    requested_permissions: tuple[str, ...] = ()
    risk: str = "low"
    estimated_spend_minor: int = 0
    revenue_recorded: bool = False
    approval_granted: bool = False  # Deprecated; never trusted by the policy engine.
    approval_id: str | None = None


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    requires_approval: bool
    reason: str


@dataclass(frozen=True)
class JournalLine:
    account: str
    debit_minor: int = 0
    credit_minor: int = 0


class RuntimeStore:
    """SQLite-backed agent registry, audit journal, policy gate and ledger."""

    RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    AUTONOMOUS_ACTIONS = {"research", "create_artifact", "run_tests"}

    def __init__(self, database: str = ":memory:", paid_api_spend_cap_minor: int = 0):
        if paid_api_spend_cap_minor < 0:
            raise ValueError("Spend cap cannot be negative")
        self._db = sqlite3.connect(database, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self.paid_api_spend_cap_minor = paid_api_spend_cap_minor
        self.kill_switch_enabled = False
        self._initialize()

    def _initialize(self) -> None:
        with self._db:
            self._db.executescript("""
                PRAGMA foreign_keys = ON;
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    role TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    permissions_json TEXT NOT NULL DEFAULT '[]',
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    actor_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS journal_entries (
                    entry_id TEXT PRIMARY KEY,
                    description TEXT NOT NULL,
                    currency TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS journal_lines (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry_id TEXT NOT NULL REFERENCES journal_entries(entry_id),
                    account TEXT NOT NULL,
                    debit_minor INTEGER NOT NULL CHECK(debit_minor >= 0),
                    credit_minor INTEGER NOT NULL CHECK(credit_minor >= 0)
                );
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY,
                    actor_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    permissions_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    requested_by TEXT NOT NULL,
                    granted_by TEXT,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    consumed_at REAL
                );
            """)

    def close(self) -> None:
        self._db.close()

    def create_agent(self, agent_id: str, role: str, permissions: Iterable[str] = ()) -> None:
        if not agent_id.strip() or not role.strip():
            raise ValueError("Agent ID and role are required")
        grants = sorted(set(permissions))
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO agents(agent_id, role, permissions_json, created_at) VALUES(?,?,?,?)",
                (agent_id, role, json.dumps(grants), time.time()),
            )
        self.record_event(agent_id, "agent_created", {"role": role, "permissions": grants})

    def agent(self, agent_id: str) -> dict[str, Any] | None:
        row = self._db.execute("SELECT * FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["permissions"] = json.loads(result.pop("permissions_json"))
        return result

    def set_agent_status(self, agent_id: str, status: str) -> None:
        if status not in {"active", "paused", "disabled"}:
            raise ValueError("Invalid agent status")
        with self._lock, self._db:
            cur = self._db.execute("UPDATE agents SET status=? WHERE agent_id=?", (status, agent_id))
            if cur.rowcount != 1:
                raise KeyError(agent_id)
        self.record_event(agent_id, "agent_status_changed", {"status": status})

    def record_event(self, actor_id: str, event_type: str, payload: dict[str, Any]) -> str:
        event_id = str(uuid.uuid4())
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO events(event_id, actor_id, event_type, payload_json, created_at) VALUES(?,?,?,?,?)",
                (event_id, actor_id, event_type, json.dumps(payload, sort_keys=True), time.time()),
            )
        return event_id

    def events(self, limit: int = 100) -> list[dict[str, Any]]:
        if limit < 1:
            raise ValueError("Limit must be positive")
        rows = self._db.execute(
            "SELECT * FROM events ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [
            {**dict(row), "payload": json.loads(row["payload_json"])}
            for row in rows
        ]

    def request_approval(
        self, actor_id: str, action: str, requested_permissions: Iterable[str],
        requested_by: str = "owner", expires_in_seconds: int = 900,
    ) -> str:
        """Create a scoped, expiring approval request for the trusted host UI."""
        if self.agent(actor_id) is None:
            raise KeyError(actor_id)
        if not action.strip() or not requested_by.strip():
            raise ValueError("Action and requester are required")
        if not 30 <= expires_in_seconds <= 3600:
            raise ValueError("Approval request expiry must be 30..3600 seconds")
        approval_id = str(uuid.uuid4())
        permissions = sorted(set(requested_permissions))
        now = time.time()
        with self._lock, self._db:
            self._db.execute(
                """INSERT INTO approvals(
                    approval_id, actor_id, action, permissions_json, status,
                    requested_by, created_at, expires_at
                ) VALUES(?,?,?,?,?,?,?,?)""",
                (approval_id, actor_id, action, json.dumps(permissions), "pending",
                 requested_by, now, now + expires_in_seconds),
            )
        self.record_event(requested_by, "approval_requested", {
            "approval_id": approval_id, "actor_id": actor_id,
            "action": action, "permissions": permissions,
        })
        return approval_id

    def grant_approval(
        self, approval_id: str, approved_by: str, expires_in_seconds: int = 300,
    ) -> None:
        """Grant an approval from an authenticated, trusted owner-facing host."""
        if not approved_by.strip():
            raise ValueError("Approver identity is required")
        if not 30 <= expires_in_seconds <= 900:
            raise ValueError("Granted approval expiry must be 30..900 seconds")
        now = time.time()
        with self._lock, self._db:
            row = self._db.execute(
                "SELECT status, expires_at FROM approvals WHERE approval_id=?",
                (approval_id,),
            ).fetchone()
            if row is None:
                raise KeyError(approval_id)
            if row["status"] != "pending" or row["expires_at"] <= now:
                raise ValueError("Approval request is no longer pending")
            self._db.execute(
                """UPDATE approvals SET status='approved', granted_by=?, expires_at=?
                   WHERE approval_id=?""",
                (approved_by, min(row["expires_at"], now + expires_in_seconds), approval_id),
            )
        self.record_event(approved_by, "approval_granted", {"approval_id": approval_id})

    def _consume_approval(self, request: ActionRequest) -> bool:
        """Consume one exact, unexpired approval; approvals cannot be replayed."""
        if not request.approval_id:
            return False
        now = time.time()
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                row = self._db.execute(
                    "SELECT * FROM approvals WHERE approval_id=?",
                    (request.approval_id,),
                ).fetchone()
                expected_permissions = sorted(set(request.requested_permissions))
                if (
                    row is None
                    or row["status"] != "approved"
                    or row["expires_at"] <= now
                    or row["actor_id"] != request.actor_id
                    or row["action"] != request.action
                    or json.loads(row["permissions_json"]) != expected_permissions
                ):
                    self._db.rollback()
                    return False
                self._db.execute(
                    "UPDATE approvals SET status='consumed', consumed_at=? WHERE approval_id=?",
                    (now, request.approval_id),
                )
                self._db.commit()
                self.record_event(row["granted_by"] or "approval_system", "approval_consumed", {
                    "approval_id": request.approval_id, "actor_id": request.actor_id,
                    "action": request.action,
                })
                return True
            except Exception:
                self._db.rollback()
                raise

    def evaluate(self, request: ActionRequest) -> PolicyDecision:
        agent = self.agent(request.actor_id)
        if self.kill_switch_enabled:
            decision = PolicyDecision(False, False, "global kill switch is enabled")
        elif agent is None:
            decision = PolicyDecision(False, False, "unknown agent")
        elif agent["status"] != "active":
            decision = PolicyDecision(False, False, "agent is not active")
        elif not set(request.requested_permissions).issubset(set(agent["permissions"])):
            decision = PolicyDecision(False, False, "requested permission is not granted")
        elif request.estimated_spend_minor < 0:
            decision = PolicyDecision(False, False, "spend estimate cannot be negative")
        elif request.estimated_spend_minor > self.paid_api_spend_cap_minor:
            decision = PolicyDecision(False, False, "estimated spend exceeds the configured per-action cap")
        elif request.estimated_spend_minor > 0 and not request.revenue_recorded:
            decision = PolicyDecision(False, False, "pre-revenue spend is disabled")
        elif (
            request.action not in self.AUTONOMOUS_ACTIONS
            or self.RISK_ORDER.get(request.risk, 99) > self.RISK_ORDER["low"]
        ):
            approved = self._consume_approval(request)
            decision = PolicyDecision(
                approved, True,
                "scoped owner approval consumed" if approved
                else "a valid, unexpired, action-scoped owner approval is required",
            )
        else:
            decision = PolicyDecision(True, False, "permitted")

        self.record_event(request.actor_id, "policy_decision", {
            "action": request.action, "allowed": decision.allowed,
            "requires_approval": decision.requires_approval, "reason": decision.reason,
        })
        return decision

    def post_journal(
        self, entry_id: str, description: str, lines: Iterable[JournalLine],
        currency: str = "USD",
    ) -> bool:
        """Post a balanced, idempotent journal entry using integer minor units."""
        normalized = list(lines)
        if not entry_id.strip() or not description.strip():
            raise ValueError("Entry ID and description are required")
        if len(currency) != 3 or not currency.isalpha():
            raise ValueError("Currency must be a three-letter code")
        if len(normalized) < 2:
            raise ValueError("A journal entry needs at least two lines")
        for line in normalized:
            if not line.account.strip():
                raise ValueError("Account is required")
            if line.debit_minor < 0 or line.credit_minor < 0:
                raise ValueError("Amounts cannot be negative")
            if (line.debit_minor == 0) == (line.credit_minor == 0):
                raise ValueError("Each line must contain exactly one debit or credit")
        debits = sum(line.debit_minor for line in normalized)
        credits = sum(line.credit_minor for line in normalized)
        if debits == 0 or debits != credits:
            raise ValueError("Journal entry is not balanced")

        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                exists = self._db.execute(
                    "SELECT 1 FROM journal_entries WHERE entry_id=?", (entry_id,)
                ).fetchone()
                if exists:
                    self._db.rollback()
                    return False
                self._db.execute(
                    "INSERT INTO journal_entries(entry_id, description, currency, created_at) VALUES(?,?,?,?)",
                    (entry_id, description, currency.upper(), time.time()),
                )
                self._db.executemany(
                    "INSERT INTO journal_lines(entry_id, account, debit_minor, credit_minor) VALUES(?,?,?,?)",
                    [(entry_id, line.account, line.debit_minor, line.credit_minor) for line in normalized],
                )
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise
        self.record_event("ledger", "journal_posted", {
            "entry_id": entry_id, "currency": currency.upper(),
            "debits_minor": debits, "credits_minor": credits,
        })
        return True

    def account_balance_minor(self, account: str, currency: str = "USD") -> int:
        row = self._db.execute("""
            SELECT COALESCE(SUM(
                CASE WHEN jl.debit_minor > 0 THEN jl.debit_minor ELSE -jl.credit_minor END
            ), 0) AS balance
            FROM journal_lines jl
            JOIN journal_entries je ON je.entry_id = jl.entry_id
            WHERE jl.account=? AND je.currency=?
        """, (account, currency.upper())).fetchone()
        return int(row["balance"])


__all__ = ["ActionRequest", "JournalLine", "PolicyDecision", "RuntimeStore"]
