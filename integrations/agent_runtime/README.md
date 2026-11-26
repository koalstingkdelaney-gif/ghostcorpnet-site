# Governed Agent Runtime Core

A dependency-free Python foundation for GhostCorp's agent system. It provides a SQLite-backed agent registry, explicit capability checks, fail-closed policy decisions, audit events, a global kill switch, a balanced idempotent double-entry journal, bounded persistent memory with provenance, and durable goal tracking.

## Quick start

```python
from integrations.agent_runtime import (
    ActionRequest, JournalLine, Memory, MemoryStore, RuntimeStore,
)

store = RuntimeStore("ghostcorp-runtime.sqlite3", paid_api_spend_cap_minor=0)
store.create_agent("researcher-1", "researcher", ["web.read", "workspace.write"])
decision = store.evaluate(ActionRequest(
    actor_id="researcher-1", action="research",
    requested_permissions=("web.read",),
))
assert decision.allowed

store.post_journal("payment-123", "Example simulated payment", [
    JournalLine("cash_clearing", debit_minor=1250),
    JournalLine("sales_revenue", credit_minor=1250),
])

memory = MemoryStore("ghostcorp-memory.sqlite3")
memory.remember(Memory(
    key="project_direction", value="Build on the existing GhostCorp site",
    source="owner instruction", confidence=1.0,
))
assert memory.recall("project_direction")["value"].startswith("Build on")
goal_id = memory.create_goal("Connect the Action Center", priority=90)
```

Run tests with `python -m unittest discover -s integrations/agent_runtime -v`.

## Memory and goals

- Facts retain their source, confidence, sensitivity label, version, and optional expiry.
- Corrections increment the fact version; expired facts are excluded from recall and can be pruned.
- Memory has a fixed record and value-size limit. Credential-like keys and common secret formats are rejected.
- Goals persist with priority, due-date metadata, blockers, lifecycle status, and a required reason when completed or abandoned.
- This is a bounded project memory store, not a secrets manager, vector database, or substitute for user-controlled retention and deletion policies.

## Current limits

- This is a local core, not a hosted multi-user service.
- The ledger is an internal accounting journal, not a bank balance or payment processor.
- Approval records are an enforcement primitive, not proof of owner identity. Only an authenticated host may expose approval-grant operations.
- It does not custody keys, create financial accounts, contact customers, execute payouts, or connect to live providers.
- Elevated actions now require a scoped, expiring, one-time approval record bound to the exact agent, action, and permission set. The legacy `approval_granted` boolean is ignored. The Action Center must authenticate the owner before calling `grant_approval`; this local core does not authenticate users or expose a network API.
- Positive estimated spend is blocked until revenue is explicitly recorded by a trusted integration.
- SQLite events are operational audit records, not tamper-proof compliance storage. Production deployment needs access controls, backups, integrity protection, and external log retention.

All external side effects must remain behind provider adapters, verified webhooks, a separate policy service, owner-approved onboarding, and explicit spend/destination limits.
