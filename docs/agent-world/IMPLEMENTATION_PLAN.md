# Implementation plan

## Phase 1 — Safe foundation
- Keep the existing GhostCorp website, approvals, audit log, kill switch, revenue systems, and workflows intact.
- Add a feature-flagged world registry and JSON manifest validation.
- Add an event envelope with schema version, event ID, actor, world ID, timestamp, correlation ID, and sensitivity label.
- Add deterministic simulation mode; no live external actions.
- Add the optional read-only Pino API observer.

## Phase 2 — Persistent agent runtime
- Agent registry: stable ID, role, owner, team, status, skills, goals, permitted worlds, and capability grants.
- Cognitive cycle: sense, update bounded state, retrieve memories, select a typed action, validate against the manifest and policy, execute, observe outcome, record evidence.
- Memory: episodic events, working set, durable facts with provenance/confidence, and a daily consolidation cycle. Support correction, expiry, retention limits, and deletion workflows.
- Goals: multiple concurrent threads with priority, due dates, blockers, commitments, and explicit completion/abandonment reasons.
- Repetition control: detect unchanged context and avoid looping; back off after failures.
- Sleep/idle: pause model calls when no meaningful event exists; run consolidation on schedule.

## Phase 3 — Teams and workspaces
- Give each agent a role, career path, isolated workspace, portfolio, and performance history.
- Team leads coordinate tasks; specialists collaborate through scoped shared artifacts.
- Agents can propose new agents, roles, skills, and tools. New capabilities remain disabled until governance approves them.
- Marketplace supports listing, review, pricing proposals, fulfillment records, and dispute/audit trails.

## Phase 4 — Business operations
- Connect research and product-development tasks to the existing product catalog and storefront.
- Agents may draft listings, support content, and fulfillment plans.
- Customer outreach, publication, account creation, purchases, crypto conversion, payout setup, and transfers use provider-supported integrations and approval policies.
- Maintain separate business ledgers and a parent treasury; reconcile gross receipts, fees, refunds, reserves, operating allocation, and owner distributions.
- Do not claim payment or payout success without provider confirmation. No agent may bypass identity, KYC/AML, tax, banking, or platform requirements.

## Phase 5 — VR as a world adapter
- The VR HQ is a private owner-only world for business systems, agents, customers, and financial controls.
- Public social/game spaces remain separate and cannot enumerate private business assets.
- Show live agent presence, tasks, tool activity, approvals, resource usage, and artifact previews.
- User interaction in VR can teach agents through explicit feedback events, but never silently grants new permissions.

## Phase 6 — Continuous improvement
- Agents can inspect their own code and propose patches in isolated branches.
- CI runs tests, dependency/security scans, and policy checks.
- Changes become reviewable pull requests; deployment follows the existing protected workflow.
- Agents cannot merge their own governance/security changes or deploy outside the configured release policy.

## Acceptance criteria
- Existing site and revenue workflows still pass their current tests.
- Agent state survives restarts and has bounded, inspectable memory.
- Every action has a policy decision and audit record.
- Denied, timed-out, or unavailable tools fail closed and do not corrupt state.
- No external side effect occurs without the required permission/approval.
- Spend remains $0 for paid APIs until revenue and an owner-approved budget change.
- Private VR/business data is inaccessible from public worlds.
- A simulated multi-agent task can be run end-to-end and inspected from the Action Center.

## Current implementation status

The executable runtime foundation lives under `integrations/agent_runtime/`:

- SQLite-backed agent registry with explicit capability grants and active/paused/disabled states.
- Fail-closed policy decisions for unknown agents, missing capabilities, paused agents, high-risk actions, and the global kill switch.
- Scoped, expiring, one-time approval records bound to the exact agent, action, and permission set; the legacy caller-supplied approval boolean is ignored.
- Autonomous execution is limited to the low-risk `research`, `create_artifact`, and `run_tests` action set.
- A default-zero per-action paid API spend cap; spending is denied before revenue and remains denied above the configured cap.
- Balanced, idempotent double-entry journal entries using integer minor currency units.
- Persistent memory with provenance, confidence, versioning, expiry, size limits, and credential-pattern rejection.
- Persistent goals with priority, blockers, lifecycle status, and explicit completion/abandonment reasons.
- Dedicated GitHub Actions tests cover the runtime and memory modules on Python 3.11, 3.12, and 3.13.

These tests validate the isolated runtime slice only. They do not validate or replace the existing website build, production hosting, payment providers, or VR application.

## Next build increments

1. Connect the runtime's scoped approval records to the repository's existing Action Center through a trusted host adapter. The host must authenticate the owner before granting approvals; the local core is not an identity provider.
2. Add a versioned world-manifest registry, event envelope, schema validation, and deterministic simulation runner.
3. Add an event-driven scheduler, retry/backoff, idle/sleep consolidation, and multi-agent coordination through scoped workspaces.
4. Add provider sandbox adapters and verified webhook ingestion; map provider events into the internal ledger without treating the ledger as proof of external settlement.
5. Add owner-only API endpoints and authorization for the private VR adapter; keep public worlds isolated from business systems.
6. Add deployment, backup, observability, dependency scanning, and security checks before any live external actions are enabled.
