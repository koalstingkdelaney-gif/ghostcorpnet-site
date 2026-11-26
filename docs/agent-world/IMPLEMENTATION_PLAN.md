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
- Memory: episodic events, working set, durable facts with provenance/confidence, and daily consolidation. Support correction, expiry, retention limits, and deletion workflows.
- Goals: multiple concurrent threads with priority, due dates, blockers, commitments, and explicit completion/abandonment reasons.
- Repetition control: detect unchanged context and avoid looping; backoff after failures.
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
