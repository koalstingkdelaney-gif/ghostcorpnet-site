# Governed Agent Runtime Core

A dependency-free Python foundation for GhostCorp's persistent agent system. It provides a SQLite-backed agent registry, explicit capability checks, a fail-closed policy decision, event records, a global kill switch, and a balanced idempotent double-entry journal using integer minor currency units.

## Quick start

```python
from integrations.agent_runtime import ActionRequest, JournalLine, RuntimeStore

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
```

Run tests with `python -m unittest discover -s integrations/agent_runtime -v`.

## Current limits

- This is a local core, not a hosted multi-user service.
- The ledger is an internal accounting journal, not a bank balance or payment processor.
- It does not custody keys, create financial accounts, contact customers, execute payouts, or connect to live providers.
- Approval is supplied by a trusted host caller; a production Action Center must authenticate the owner and persist approval records before passing `approval_granted=True`.
- Positive estimated spend is blocked until revenue is explicitly recorded by a trusted integration.
- SQLite events are operational audit records, not tamper-proof compliance storage. Production deployment needs access controls, backups, integrity protection, and external log retention.

All external side effects must remain behind provider adapters, verified webhooks, a separate policy service, owner-approved onboarding, and explicit spend/destination limits.
