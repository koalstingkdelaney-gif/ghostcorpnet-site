# GhostCorp Unified Virtual Operating Ecosystem

Status: architecture requirement recorded; implementation not yet verified.

## Product principle

GhostCorp is one persistent business operating system presented as an immersive world. The VR world is the primary operational headquarters and control surface, not a decorative lobby or a collection of disconnected pages. Departments, agents, projects, data, workflows, and customer operations share one identity, event model, permissions system, and durable state.

## Critical reality boundary

The world can be the place where people and agents operate the business, but software still executes on physical compute somewhere. Quest 3 is a client, not the production server: it cannot safely or reliably host the entire always-on business, databases, model fleet, payment processing, backups, and customer services. GhostCorp should minimize dependence on owner-owned hardware by using authorized free/low-cost hosted services where sustainable, local/offline capability where available, and portable self-hosted deployment when authorized compute exists. No third-party server or free tier is assumed permanent or available until verified.

A legal business entity, payment-provider accounts, tax obligations, customer consent, and provider-required identity checks also remain real-world requirements. The virtual HQ can manage these workflows; it cannot make them disappear.

## Unified architecture

1. **Immersive client:** Quest 3 WebXR now; native OpenXR application as a separately validated future target. Desktop/mobile owner interfaces provide continuity.
2. **Control plane:** authenticated API, policy engine, capability registry, task scheduler, event bus, and agent orchestrator. The headset never contains privileged service secrets.
3. **Persistent data plane:** durable database for projects, tasks, customers, products, orders, inventory, agent state, world state, audit events, and checkpoints; encrypted backups and tested restore.
4. **Execution plane:** isolated workers for research, coding, product creation, marketing, support, fulfillment coordination, analytics, and world simulation. Each worker has scoped permissions, resource limits, and a recoverable workspace.
5. **AI plane:** local models first where hardware permits; legitimate free provider quotas as optional burst capacity; provider/model routing, quota tracking, privacy filtering, durable handoffs, and no paid fallback without explicit budget authorization.
6. **Integration plane:** GitHub, website/storefront, payment provider, email, analytics, and other services through documented APIs and owner-authorized OAuth/service identities. Integrations are capability-scoped and monitored.
7. **VR world plane:** rooms are live views and interaction surfaces over the same underlying services—not independent copies of business logic. A task created in VR is the same task visible on web/mobile and processed by the same backend.
8. **Observability and recovery:** service health, queue depth, worker activity, spend/quota, deployment state, world events, audit log, alerts, snapshots, rollback, and disaster recovery.

## Operational departments

- Executive Command: priorities, goals, approvals, risks, and business-wide status.
- Research & Frontier Lab: customer problems, market research, experiments, evidence, and publishable learning.
- Product & Engineering: roadmap, design, code, testing, releases, and rollback.
- Sales & Customer Success: consent-based lead discovery, CRM, customer support, and human-reviewed outreach.
- Commerce & Fulfillment: catalog, orders, payment confirmation, fulfillment status, refunds workflow, and reconciliation.
- Finance & Treasury: read-only reporting by default; owner approval for payouts, bank changes, borrowing, or material spending.
- Security & Compliance: identity, access, secrets, audit, privacy, retention, and incident response.
- World Operations: environment building, NPC/agent presence, simulation, asset management, and performance.

## Autonomy and safety

Agents may autonomously perform reversible, low-risk work within explicit scopes. External communications, purchases, financial transfers, legal commitments, account creation, permission changes, and destructive production actions require the configured approval gates. No agent may grant itself permissions, use another party's compute without permission, evade provider quotas, or claim work is live without evidence.

## Resilience requirements

- Core task state and checkpoints survive browser/headset shutdown.
- The headset may disconnect without stopping backend jobs.
- Offline mode provides cached read access and local drafts/queues, then safely reconciles on reconnect.
- If all models or quotas are unavailable, deterministic workflows continue where possible and AI-dependent work queues without losing context.
- Backups are encrypted, versioned, geographically separate where feasible, and restore-tested.
- Deployments are staged, health-checked, and reversible.

## Implementation sequence and acceptance gates

1. Inventory existing VR pages, APIs, repository workflows, and integrations; distinguish verified code from mock/local-only behavior.
2. Define shared domain entities, event contracts, authentication, roles, permissions, and audit records.
3. Deploy a minimal durable backend and database with health checks, backup/restore, and a persistent task queue.
4. Connect the existing VR workspace to real project/task/status APIs; remove any control that implies unavailable functionality.
5. Add isolated workers and a capability registry; prove one end-to-end task survives headset disconnect and backend restart.
6. Connect provider integrations one by one with least privilege and explicit approval gates.
7. Build department workspaces over the same services and verify cross-client state consistency.
8. Add offline cache/queue reconciliation and recovery drills.
9. Improve visual fidelity and brain visualization only when its displayed activity is sourced from real backend events.
10. Validate Quest 3 comfort, frame rate, interaction reliability, security, deployment, and restore procedures.

## Current verified baseline

The existing `vr/README.md` describes a Quest 3 WebXR website workspace, local browser project board, local WebGPU chat, and an Action Center that remains unavailable until a private backend is deployed. This is not yet a unified live business backend, native Quest application, or fully autonomous business. Keep that distinction visible in all status reporting.
