# GhostCorp Long-Term Continuity, Resilience, and Succession Program

**Status:** Design specification and implementation backlog  
**Repository:** `koalstingkdelaney-gif/ghostcorpnet-site`  
**Owner:** Founder / legally designated business owner  
**Version:** 2.0  
**Important:** This plan is not a legal instrument, a deployed failover system, or proof that any provider supports account transfer. It defines what GhostCorp should build and what humans and qualified professionals must arrange.

---

## 1. Mission and definition of success

GhostCorp must be built so the work, knowledge, customer obligations, intellectual property, and lawful business value can survive the founder's temporary or permanent absence. The system should continue only within pre-authorized limits, preserve evidence of what it did, and make it possible for a properly authorized human to take over.

"Continue running" does **not** mean agents can independently inherit property, decide that the founder has died, spend unlimited money, access personal accounts, or override laws and provider terms. The design goal is durable operations with clear human authority.

A successful continuity program means:

- A clean recovery environment can be rebuilt from documented source and backups.
- The website and any supported customer-facing service can be restored without the founder's phone or Quest headset.
- Work queues, decisions, and agent checkpoints survive a process or server restart.
- Local/offline capability can keep safe internal work moving when cloud services fail.
- No paid service is activated or spending cap raised without explicit authorization.
- A verified, legally authorized successor can receive scoped access through a logged process.
- If no successor can lawfully act, GhostCorp can preserve records and wind down safely.
- Customers, employees, contractors, and beneficiaries are treated according to contracts and applicable law.

## 2. Non-negotiable governance principles

1. **Legal authority before privileged access.** A technical account invitation is not proof of legal authority. Succession requires the documents, provider process, and identity checks applicable to each asset.
2. **No death inference.** Silence, missed check-ins, inactivity, lost devices, failed health checks, or an expired session never prove death or incapacity.
3. **No unilateral AI succession.** No model or agent may appoint a successor, change ownership, distribute assets, or grant itself authority.
4. **Least privilege and separation of duties.** Separate code maintenance, customer support, finance, security, and owner administration. Sensitive actions require a designated human.
5. **Zero unauthorized spending.** The pre-revenue operating budget remains $0/month unless the owner or authorized successor explicitly approves a bounded budget. No automatic paid fallback, subscription, credit purchase, or quota upgrade.
6. **Reversible work by default.** Agents may draft, test, classify, research, and prepare changes in isolated branches or sandboxes. Production changes, customer commitments, money movement, and access changes require the appropriate approval.
7. **Auditability.** Every privileged action records actor, timestamp, target, reason, approval, result, and correlation ID. Logs must not contain passwords, raw API keys, payment data, or unnecessary personal information.
8. **Privacy by design.** Business data is private by default. Public game/social areas and the VR world must never expose private customer records, finances, credentials, or confidential agent conversations.
9. **Graceful degradation.** When a dependency fails, disable only the affected capability, preserve durable state, and provide an honest degraded-mode status.
10. **No false health claims.** A green dashboard means a defined check passed recently; it does not guarantee future availability or prove a full disaster recovery.

## 3. Operating modes and transition rules

### Mode A — Founder Active

- Founder retains the owner role and controls privileged approvals.
- Agents operate within their role permissions, project scope, and budget.
- Owner authentication uses strong MFA and recovery methods.
- Routine tasks may proceed automatically if explicitly allowlisted.
- The system records approvals and keeps an exportable activity history.

### Mode B — Founder Unavailable / Unconfirmed

Triggers may include a missed optional check-in, a device outage, or failed contact attempts. These are operational signals only, not legal findings.

Allowed:
- Continue previously approved, low-risk, reversible internal work.
- Run backups, health checks, security monitoring, tests, and incident alerts.
- Keep already-authorized services operating if doing so does not require new spending or new legal commitments.
- Queue drafts, releases, refunds, outreach, purchases, and other actions that require human approval.
- Notify designated contacts using channels already authorized by the founder.

Blocked:
- Changing ownership, trustees, beneficiaries, payout destinations, bank details, legal representatives, or recovery contacts.
- Creating new paid subscriptions or increasing budgets.
- Sending unapproved marketing or sales messages.
- Signing contracts, accepting material new obligations, deleting records, or making irreversible production changes.
- Unlocking private data for a contact who has not been authorized.

### Mode C — Succession Hold

Entered only through the documented human/legal process, not an AI inference.

- Freeze ownership, treasury, payout, and privileged-access changes.
- Preserve logs, backups, contracts, and current system state.
- Keep customer-critical services running only where lawful, safe, and financially authorized.
- Require a designated representative to present the evidence and provider-specific authority required for the relevant action.
- Have a second authorized human review especially sensitive changes when practical.

### Mode D — Verified Successor Administration

- Provision a new named account; do not share the founder's login.
- Verify authority separately for the company, repositories, domains, hosting, payment providers, financial accounts, and intellectual property.
- Start with read-only access and expand only to the documented role.
- Require MFA, recovery enrollment, and credential rotation.
- Set a successor-approved operating budget and approval matrix.
- Record every privileged change and periodically review access.

### Mode E — Preservation / Orderly Wind-Down

Used when there is no authorized successor, the business cannot safely operate, or legal direction requires preservation or closure.

- Stop new sales and external commitments where required.
- Fulfill, refund, or otherwise resolve existing customer obligations under applicable contracts and law.
- Preserve tax, accounting, employment, privacy, and corporate records for required retention periods.
- Revoke unused credentials and disable agent actions.
- Maintain encrypted backups and a final asset inventory.
- Follow the instructions of the executor, trustee, court, regulator, or other legally authorized party as applicable.

## 4. Authority and role model

Roles are examples for implementation; the legal documents and actual provider permissions control.

| Role | Intended access | Explicitly excluded |
|---|---|---|
| Founder / owner | Full owner controls while authorized | Cannot bypass law or provider terms |
| Successor manager | Scoped business administration after verification | No automatic personal-account access |
| Trustee / executor | Only powers granted by governing legal documents | No powers beyond those documents |
| Technical custodian | Source, infrastructure, backup and incident recovery | No treasury, beneficiary, or ownership authority |
| Finance approver | Approved invoices, reconciliations, bounded budget | No unilateral payout-destination changes |
| Agent / bot | Narrow task-scoped API permissions | No legal authority, unrestricted shell, or funds movement |
| Auditor / advisor | Read-only evidence relevant to engagement | No production write access by default |

Use separate identities for people and services. Service accounts must be named, scoped, rotated, and revocable. No shared administrator account.

## 5. Agent autonomy and approval matrix

### Tier 0 — Observe

Read approved documentation, metrics, health status, and task metadata. No writes.

### Tier 1 — Prepare

Draft code, research, plans, customer replies, product concepts, and proposed changes. Store drafts in private workspaces or branches.

### Tier 2 — Execute reversible internal work

Run tests, update non-production indexes, organize internal tasks, produce reports, and create isolated prototypes within resource limits.

### Tier 3 — Controlled production operations

Deploy an approved release, restart a service, or modify a production configuration only through a documented approval, tested rollback, and logged deployment pipeline.

### Tier 4 — Restricted human-only actions

Ownership changes, legal filings, contracts, bank or payout changes, withdrawals, purchases, subscription changes, sensitive data exports, account recovery, customer refunds above an approved threshold, and deletion of retained records. Agents may prepare evidence but may not approve or execute these actions independently.

Every agent action must have:
- A task ID and named accountable human owner.
- A permitted resource list and time limit.
- A budget and rate limit.
- An allowed operation list.
- A timeout and retry policy.
- A durable checkpoint and audit record.
- A stop mechanism and rollback path where possible.

## 6. System architecture for resilience

The target architecture is deliberately independent of any one headset, phone, model vendor, or hosting provider.

### 6.1 Source of truth

- Keep the canonical application source in the existing GhostCorp repository.
- Use protected branches, reviewed pull requests, tagged releases, and reproducible build instructions.
- Store deployment configuration separately from secrets.
- Keep infrastructure-as-code and migration scripts versioned.
- Maintain a software bill of materials and license/provenance records for dependencies and models.

### 6.2 Runtime separation

Separate these components so one failure does not take everything down:

1. Public website and static assets.
2. Authenticated application/API gateway.
3. Persistent application backend and database.
4. Durable task queue and scheduler.
5. Agent/model orchestration service.
6. File/object storage and backup service.
7. Monitoring, audit log, and alerting service.
8. WebXR/Quest client, treated as a replaceable client rather than the server of record.

The Quest headset must never be the only place where the world, agent memory, or business state exists. Closing the browser, powering off the headset, or losing the phone must not erase server-side progress.

### 6.3 Durable state

Persist, with versioning and access control:
- Tasks, task dependencies, owners, status, retries, and deadlines.
- Agent checkpoints and handoff notes.
- World scene definitions, object records, revisions, and event cursors.
- Approved project memory and source references.
- Deployment and incident history.
- Customer/order records only in the systems and retention model authorized for them.

Do not store model chain-of-thought or sensitive internal reasoning as a substitute for concise, auditable decisions. Store task summaries, evidence, decisions, and outputs.

### 6.4 Queue guarantees

- A task is acknowledged only after durable storage succeeds.
- Workers claim tasks with leases; expired leases can be recovered.
- Retries use bounded exponential backoff and idempotency keys.
- A task that repeatedly fails enters a dead-letter queue with its error context.
- A restart resumes from the last safe checkpoint, not from an assumption that the previous step completed.
- External actions must be idempotent or require reconciliation before retrying.

### 6.5 Model and provider independence

- Keep a provider-neutral model adapter and capability registry.
- Prefer local models when supported hardware is available and the model is appropriately licensed.
- Use free hosted tiers only within their actual terms, quotas, and limits.
- Record provider, model/version, license, context limit, capability, quota observations, and fallback eligibility.
- If a free quota is exhausted, pause or switch to an approved local option; never silently switch to a paid plan.
- Do not create duplicate accounts or evade provider limits.
- Treat provider availability and free quotas as external dependencies, not guarantees.

### 6.6 VR world continuity

- The world state is server-authoritative; the headset renders a client-side view.
- Persist world changes as validated scene/object revisions and events.
- Agents may edit only their assigned zones through scoped APIs.
- The owner can inspect a change history and roll back a zone revision.
- The Quest client reconnects with backoff and resumes from a durable event cursor.
- Cache only non-sensitive scene data; do not cache business secrets, customer records, or private financial data.
- If offline, clearly label the world as cached/offline and queue no privileged mutation unless a safe offline protocol is explicitly implemented.

## 7. Backup and recovery policy

### 7.1 Backup classes

**Class A — Critical**
Source code, infrastructure configuration, database snapshots, encryption-key recovery metadata, audit logs, domain/DNS inventory, and signed release artifacts.

**Class B — Operational**
Task queues, agent checkpoints, world revisions, runbooks, monitoring configuration, and model/provider registry.

**Class C — Business records**
Contracts, customer/order records, invoices, accounting exports, tax records, and licenses. These require a documented lawful basis, access controls, and retention schedule.

**Class D — Re-creatable**
Caches, temporary build files, generated previews, and disposable test data. Back up only when their recreation cost justifies it.

### 7.2 Backup design

Adopt a 3-2-1 style strategy where feasible:
- At least three copies of critical data.
- At least two different storage media or systems.
- At least one encrypted copy isolated from the primary runtime.
- Keep a separate offline recovery copy for the most critical materials.
- Use immutable/versioned backups where supported.
- Encrypt in transit and at rest.
- Keep encryption-key recovery instructions separate from the encrypted backup; restrict access to designated custodians.

A backup is not proven until a restore test succeeds.

### 7.3 Initial recovery objectives

These are proposed engineering targets, not current guarantees. Adjust after measuring costs and service criticality.

| Service/data | Initial RPO target | Initial RTO target |
|---|---:|---:|
| Source repository | Last pushed commit | 4 hours |
| Core application database | 24 hours | 8 hours |
| Durable task queue/checkpoints | 15 minutes | 4 hours |
| World scene/revision data | 1 hour | 8 hours |
| Customer/order records | Provider-specific; minimize loss | 1 business day |
| Audit/security records | 1 hour | 1 business day |
| Public static site | Last successful release | 4 hours |

RPO means the maximum tolerable data-loss window. RTO means the target time to restore service. A free hosting tier may not meet these targets; measure actual behavior and disclose gaps.

### 7.4 Restore procedure

1. Declare an incident and appoint an incident lead.
2. Stop unsafe writes and preserve the failed system's evidence.
3. Select a known-good backup and verify its integrity.
4. Provision a clean, patched environment.
5. Restore database and object data in dependency order.
6. Apply migrations and validate schema versions.
7. Restore secrets from the authorized secret manager or recovery procedure; never from Git.
8. Run smoke tests, permission tests, and data-integrity checks.
9. Reconcile tasks and external actions to avoid duplicate customer actions or payments.
10. Reopen service gradually and monitor.
11. Document data loss, duration, cause, and corrective actions.

## 8. Security and account recovery

- Require MFA for GitHub, domain registrar, hosting, payment, and identity providers.
- Use hardware security keys or passkeys where supported, with separate recovery methods.
- Store service credentials in a secret manager; never commit secrets, private keys, recovery codes, or tokens.
- Use short-lived tokens and minimum scopes where available.
- Rotate credentials after suspected compromise, personnel changes, or succession activation.
- Maintain a provider inventory with official recovery links and account owner identity.
- Monitor unusual logins, permission changes, new tokens, public repository changes, DNS changes, and payout edits.
- Separate production and development credentials.
- Keep production data out of test environments unless appropriately minimized or anonymized.
- Test incident containment: revoke a token, disable a worker, isolate a service, and restore from clean artifacts.
- Keep security alerts actionable and route them to authorized contacts only.

Never put actual passwords, recovery codes, API keys, private addresses, or full financial account numbers in the repository or this document.

## 9. Business and customer continuity

Before automating customer-facing operations, maintain:
- A product/service catalog with accurate descriptions and terms.
- A record of accepted orders and fulfillment state.
- Refund, cancellation, complaint, and support procedures.
- A contact route for customers if the main service is unavailable.
- A way to pause sales without destroying order history.
- A clear owner for every customer obligation.
- A reconciliation procedure for payment processor events and fulfillment events.

Payment processors and banks control their own account access, verification, transfer, and payout rules. GhostCorp must not assume that a successor can inherit or transfer an account. Any payout destination change requires provider-approved verification and human authorization.

If GhostCorp cannot fulfill a service, the system must stop accepting new orders where appropriate and route existing obligations to the authorized human. It must never fabricate fulfillment or revenue.

## 10. Financial controls and zero-cost policy

- Default authorized recurring spend: **$0/month** until explicitly changed by the owner or lawful successor.
- Keep separate ledgers for gross receipts, refunds, fees, taxes, operating reserves, and owner distributions.
- Do not equate a payment notification with settled, withdrawable funds.
- Never let agents move money, withdraw funds, change payout destinations, or approve their own spending.
- Require a human approval for each new paid vendor, plan upgrade, paid model, and material purchase.
- Set per-vendor caps, total monthly caps, and expiry dates on approvals.
- Alert before any cap is reached; fail closed when the limit is unknown.
- Keep owner-withdrawable funds distinct from a GhostCorp operating reserve only where the legal entity, payment provider, and accounting setup support that separation.
- Reconcile payment processor records with orders, refunds, fees, and bank/payment destination statements.

## 11. Daughter / beneficiary protection and estate planning

The goal is to preserve the possibility that the founder's daughter benefits from the value created, without assuming that she should personally operate a company as a child.

The founder should consult an estate-planning attorney and business attorney about:
- Which legal entity should own the business assets and intellectual property.
- Whether a will, revocable trust, irrevocable trust, buy-sell agreement, or other structure is appropriate.
- Who should serve as executor, trustee, successor manager, and backup.
- How a beneficiary's interests are protected while she is a minor.
- How distributions, education/support needs, taxes, and management costs should be handled.
- What happens if a named fiduciary cannot or will not serve.
- Whether the operating agreement, shareholder agreement, IP assignments, and provider terms align with the estate plan.

A trustee is a person or institution with fiduciary duties to manage trust property under the trust document and applicable law. An executor or personal representative administers an estate under applicable law. A business manager operates the business under the authority granted to them. These roles are not interchangeable.

Do not place a minor in operational control or assume that naming someone in software makes them a legal trustee or beneficiary. The governing documents and applicable state law determine the result. The technical system should record the authorized representative's identity and scope only after proper verification; it should not store unnecessary sensitive estate documents in ordinary application logs.

## 12. Human contacts and communication tree

Maintain a sealed, access-controlled continuity contact record outside the public repository. It should identify:
- Primary successor / legal representative.
- Backup successor / alternate fiduciary.
- Technical custodian.
- Business or estate attorney.
- Accountant / tax professional.
- Hosting and domain emergency support routes.
- Customer support contact for service interruption.

For each contact, record their role, permitted notification channel, verification method, and the conditions under which they may be contacted. Do not publish personal contact information in public files. The system should not disclose private business data in an alert.

Notification sequence:
1. Notify the founder through configured channels when the account appears unavailable.
2. If the configured unavailability procedure expires, notify only designated contacts with a minimal message.
3. Do not disclose secrets or grant access in the notification.
4. Require the authorized person's independent verification before access provisioning.
5. Log the request, evidence checked, approver, and resulting permission changes.

## 13. Monitoring, service objectives, and incident response

Monitor:
- Website/API availability and latency.
- Database health, backup age, restore-test age, and storage capacity.
- Queue depth, oldest task age, retry counts, and dead-letter count.
- Agent heartbeat and checkpoint age.
- Model/provider quota and error state, without relying on a provider being continuously available.
- TLS/domain/DNS expiry.
- Authentication failures, token issuance, permission changes, and suspicious access.
- Payment webhook delivery and reconciliation gaps, if payments are enabled.
- VR connection state, event cursor lag, and stale cached-world status.

Each alert should include severity, affected service, first observed time, last known good state, safe action, and accountable human. Avoid noisy alerts that train operators to ignore them.

Incident severity:
- **SEV-1:** Security breach, data loss, unauthorized financial action, or major customer-impacting outage. Stop risky automation, preserve evidence, notify authorized humans.
- **SEV-2:** Core service degraded, backups failing, queue stuck, or provider outage with no safe fallback. Freeze affected workflows and recover.
- **SEV-3:** Noncritical feature failure or delayed internal task. Queue and repair during normal operations.
- **SEV-4:** Cosmetic issue or low-risk improvement. Track in backlog.

Every incident gets a timeline, impact assessment, root-cause analysis, recovery record, and follow-up tasks. Do not erase logs to make a dashboard look healthy.

## 14. Disaster scenarios and expected behavior

| Scenario | Required response |
|---|---|
| Founder phone lost | Revoke device sessions; use pre-enrolled recovery; no ownership changes |
| Quest 3 broken | Replace headset; restore client from repository; server state remains intact |
| Internet outage | Local/offline mode for safe work; queue external actions |
| Model provider outage | Switch only to approved local/free provider; otherwise pause |
| Free quota exhausted | Stop that provider; no paid fallback |
| Hosting provider outage | Restore from documented export to an approved alternative if available |
| Database corruption | Stop writes, preserve evidence, restore last verified backup, reconcile events |
| GitHub account compromised | Revoke tokens, use provider recovery, restore trusted repository state |
| Domain account inaccessible | Follow registrar recovery and legal ownership process; do not spoof or seize domain |
| Agent behaves unexpectedly | Disable its token/worker, quarantine output, inspect logs, restore last safe checkpoint |
| Payment webhook duplication | Use idempotency and reconciliation; do not fulfill or refund twice |
| Founder unavailable | Continue only pre-approved low-risk operations; do not infer death |
| No authorized successor | Preserve assets and follow legal wind-down direction |

## 15. Implementation roadmap and acceptance criteria

### Phase 0 — Inventory and ownership map
- Inventory repositories, domains, DNS, hosting, databases, model providers, payment services, and customer obligations.
- Identify the actual owner and recovery route for each.
- Mark unknown or unverified items explicitly.
- **Acceptance:** Every critical asset has an owner, provider, recovery path, and status; no secrets are included.

### Phase 1 — Durable source and documentation
- Protect main branch and require reviewed changes for production.
- Add architecture, deployment, rollback, and incident runbooks.
- Record dependency and model licenses.
- **Acceptance:** A clean developer environment can reproduce the tested build from documented steps.

### Phase 2 — Persistent backend and queues
- Confirm a persistent backend deployment and durable database.
- Implement task leases, idempotency, bounded retries, dead-letter handling, and checkpoints.
- **Acceptance:** Kill/restart workers and backend processes; queued work resumes without duplicate external actions.

### Phase 3 — Backup and restore
- Automate encrypted snapshots and independent copies.
- Add integrity verification and scheduled restore drills.
- **Acceptance:** Restore into a clean environment and pass data-integrity and permission tests within measured RPO/RTO.

### Phase 4 — Safe operating modes
- Implement founder-active, unavailable/unconfirmed, succession-hold, successor-admin, and preservation modes.
- Enforce server-side policy on every privileged endpoint.
- **Acceptance:** Automated tests prove inactivity cannot activate succession and that blocked actions fail closed.

### Phase 5 — Security and successor workflow
- Add strong MFA, scoped roles, approval records, credential rotation, and provider-specific checklist tracking.
- **Acceptance:** An authorized test successor can receive limited access without sharing founder credentials; unauthorized requests are denied and logged.

### Phase 6 — Customer and finance safeguards
- Add order/fulfillment reconciliation, support continuity, spending caps, payout-change approval, and sales pause.
- **Acceptance:** Duplicate webhook, refund, failed fulfillment, and payout-change scenarios are tested without double action or unauthorized money movement.

### Phase 7 — Quest/world continuity
- Make server world state authoritative, sync validated revisions/events, and restrict agent changes to assigned zones.
- Add offline/cached labeling and privacy filtering.
- **Acceptance:** A Quest client can disconnect/reconnect and recover the latest authorized scene without losing server state or exposing business data.

### Phase 8 — Operations and handover exercises
- Run tabletop exercises for outage, credential compromise, founder unavailability, and successor handover.
- **Acceptance:** A person other than the founder can follow the runbooks to restore a staging system and explain what they are legally authorized to do.

## 16. Test plan

Required automated and manual tests:

- **No false succession:** Simulate missed check-ins, long downtime, and disconnected devices; succession remains inactive.
- **Authorization:** Anonymous and underprivileged users cannot read private state or perform privileged actions.
- **Approval enforcement:** Agent requests for spending, payout changes, ownership changes, or legal commitments are rejected.
- **Backup integrity:** Corrupt a test backup and verify the system rejects it.
- **Restore:** Restore a recent valid backup into a clean environment and compare record counts/checksums.
- **Queue recovery:** Terminate a worker during a task; verify safe lease recovery and idempotency.
- **Provider failure:** Exhaust a mock quota; verify no paid provider is called.
- **Privacy:** Verify public website and VR scene responses contain no secrets, customer records, or private finance data.
- **Audit:** Verify privileged actions have complete audit metadata without secret leakage.
- **Rollback:** Deploy a known-bad staging release and restore the prior version.
- **Successor drill:** Use fictional test identities and test assets; do not use real estate documents or live financial accounts in a drill.
- **Wind-down drill:** Pause new orders, preserve records, and produce a customer-obligation report.

## 17. Required operational artifacts

The repository should eventually contain:
- `GHOSTCORP_CONTINUITY_AND_SUCCESSION.md` — this policy.
- `continuity/continuity-policy.example.json` — non-secret policy template.
- `continuity/ASSET_REGISTER_TEMPLATE.md` — asset ownership and recovery inventory.
- `continuity/RESTORE_RUNBOOK.md` — tested restore instructions.
- `continuity/INCIDENT_RUNBOOK.md` — security and availability response.
- `continuity/SUCCESSOR_HANDOVER_CHECKLIST.md` — human verification and least-privilege handover.
- Automated tests for safe mode, permissions, budgets, backup integrity, and queue recovery.

Templates must contain placeholders, never real secrets or personal identifying information.

## 18. Current implementation status — honest baseline

The policy document is committed to the repository. That commit does **not** mean the following are already live:
- No legal trust, will, beneficiary designation, or succession authority is created by this file.
- No successor has been named or granted access by this file.
- No automatic failover, independent hosting, encrypted backup schedule, or restore test is proven by this file.
- No permanent model capacity or free hosting availability is guaranteed.
- No Quest 3 live connection or world-state recovery is certified by this file.
- No payment or bank continuity is established by this file.

The next engineering step is to add the non-secret policy template and asset/runbook templates, then implement and test the backend enforcement and recovery workflows. Legal/provider setup must proceed in parallel with qualified human professionals.

## 19. Change control

Changes to this policy require a reviewed repository change and an accountable human approver. Changes affecting spending, succession authority, personal data, customer obligations, or access control require explicit owner or legally authorized successor approval. Agents may propose changes but may not approve their own policy changes.

Review this plan at least quarterly and after any material change to the business, legal structure, hosting provider, payment provider, domain ownership, or security posture.
