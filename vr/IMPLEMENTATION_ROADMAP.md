# GhostCorp paired implementation roadmap

Status: plan committed; implementation and deployment are not implied by this document.

## Decision

Build operational persistence and revenue capability together. They are not competing priorities: persistence, identity, permissions, audit, task recovery, and observability are the foundation that makes revenue workflows safe and repeatable. Revenue workflows are the first meaningful business workload used to prove that foundation.

## Track A — Persistent operating core

1. Inventory existing site, backend source, deployment configuration, connected integrations, and tests. Preserve existing architecture; do not create a replacement project.
2. Establish a small authenticated backend API with health/readiness endpoints, owner roles, scoped service identities, request validation, and audit events.
3. Add durable storage for tasks, task events, checkpoints, agent assignments, projects, and integration connection metadata. Never store provider secrets in browser code or repository files.
4. Add a persistent queue with idempotency, retry limits, dead-letter handling, lease recovery, and safe resume after process restart.
5. Add backups, retention rules, restore testing, and status reporting. Headset/browser shutdown must not stop backend work.
6. Connect the Quest 3 VR workspace to these real APIs. Show explicit offline/degraded states; never fabricate live agents or business data.
7. Add desktop/mobile access to the same data so the headset is not a single point of access.

Acceptance: create a task in VR, see it from another authorized client, disconnect the headset, restart a worker, and verify the task resumes from its last durable checkpoint without duplication or data loss.

## Track B — First real revenue workflow

1. Inventory the existing storefront, products, payment methods, customer-facing pages, and provider integration state. Reuse existing connected payment methods; do not collect or expose credentials in chat.
2. Select one existing product/service that can be sold and fulfilled honestly with current capabilities.
3. Implement a compliant product and offer record, customer inquiry/lead record, and consent-aware follow-up queue.
4. Implement checkout handoff using the existing provider-hosted checkout/payment flow. Never store card data.
5. Treat provider-confirmed payment webhooks/API records as the source of truth; never infer payment from a browser redirect or screenshot.
6. Track fulfillment, refunds/disputes as provider events, fees, gross receipts, net receipts, and payout status separately.
7. Keep outreach, refunds, payouts, bank changes, spending, legal commitments, and other consequential actions behind explicit configured approvals.
8. Add a revenue dashboard sourced from verified events, not demo numbers.

Acceptance: a test-mode or otherwise authorized end-to-end transaction is created, provider-confirmed, recorded once, fulfilled in the agreed way, reconciled with fees/net amount, and visible in the VR headquarters and ordinary website. Production launch requires the payment provider's required account verification and the owner's approval.

## Shared control and safety

- $0 personal spending and no paid API fallback by default.
- Free tiers are used only within provider terms and documented quotas; no duplicate-account or quota-evasion behavior.
- Local models are used where authorized hardware can run them; hosted inference is optional and privacy-filtered.
- Third-party compute is used only with explicit permission and verified availability.
- Agents get least-privilege capabilities, bounded resource budgets, isolated workspaces, and audit trails.
- The system may autonomously perform reversible low-risk tasks. External communications, purchases, transfers, destructive changes, legal commitments, and account/permission changes require their configured approval.
- Every status is labeled implemented, partial, planned, blocked, or verified-deployed and backed by test/deployment evidence.

## Delivery order

**Milestone 0 — Repository and deployment inventory:** identify the real current backend, website, deployment target, integration state, and tests.

**Milestone 1 — Shared operational spine:** authentication, policy, audit, durable task state, queue, checkpoint/recovery, health, and backups.

**Milestone 2 — First revenue vertical slice:** one existing offer, compliant customer intake, provider-hosted checkout, verified payment event, fulfillment tracking, and net-revenue reconciliation.

**Milestone 3 — VR operational integration:** live task/agent/revenue/status panels connected to the same backend; create and manage approved work from inside Quest 3.

**Milestone 4 — Expand safely:** more departments, products, model providers, workers, offline synchronization, research and product-development loops, and measured performance improvements.

## Progress reporting

For each milestone, record changed files, commit, tests actually run and their results, deployment run and result, and remaining blockers. A commit is not a deployment; a successful static-site deployment is not proof that the private backend or payment workflow is live.
