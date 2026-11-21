# GHOSTCORP — UNIVERSAL SERVICE ECOSYSTEM
## Master architecture, operating model, reuse strategy, and staged deployment plan

**Owner:** GhostCorp  
**Primary domain:** https://ghostcorpnet.com  
**Primary website repository:** https://github.com/koalstingkdelaney-gif/ghostcorpnet-site  
**Default branch:** main  
**Planning baseline:** 2026-11-21  
**Document status:** Living master specification. Proposed capabilities are not claims of implementation.

---

## 0. Executive mission

GhostCorp is intended to become a universal AI-assisted service platform: one place where people and businesses can describe a problem, request an outcome, and have GhostCorp coordinate the appropriate software, AI agents, human specialists, and existing service providers to help solve it.

The customer-facing promise is simple:

> Bring GhostCorp the problem. GhostCorp will assess the request, identify a responsible path, explain the scope and cost, and coordinate the work if it can legitimately and reliably be delivered.

GhostCorp is not to pretend that it can already perform every service. It must distinguish current offers, experimental capabilities, partner referrals, and future ideas. The platform expands by proving one capability at a time.

### Permanent strategy

1. Reuse before reinventing.
2. Intelligence before autonomy.
3. Evidence before claims.
4. Customer trust before growth.
5. Verified revenue before spending.
6. Owner authority before agent convenience.
7. Build a useful working core before scaling agent counts.
8. Keep the existing website and working features intact.

---

## 1. Existing project baseline and preservation rules

The existing public website is ghostcorpnet.com and its GitHub source repository is koalstingkdelaney-gif/ghostcorpnet-site.

The repository contains a large existing website, catalog, articles, brand/ecosystem pages, games, tools, and other material. The homepage currently promotes the governed-agent playbook, existing digital products, and published service offers. The public site also identifies existing AI agency and AI break-test services.

### Do not:
- Replace the homepage wholesale.
- Delete or silently rewrite existing product, game, catalog, brand, article, or business features.
- Change payment destinations or checkout configuration without owner authorization.
- Add trackers or unnecessary third-party scripts to new pages.
- Claim that a new backend, customer portal, AI collective, or partner network is live unless it has been implemented and tested.
- Treat roadmap items as completed functionality.

### Safe expansion pattern
- Add new capabilities as separate routes, modules, or services.
- Preserve existing URLs and content.
- Add navigation links without removing existing links.
- Use small, reviewable commits.
- Test each change before publishing.
- Record deployment status and rollback instructions.
- Keep a changelog of real changes.

---

## 2. Product concept: one customer entry point

Build a Universal Request Engine as the main customer entry point.

Customers may describe requests in ordinary language. The system should not force customers to understand internal departments, AI agents, software tools, or partner organizations.

### Request input types
- Text.
- Voice, when supported.
- Images.
- Documents.
- Structured details.
- Follow-up conversation.
- Video, when supported and useful.

### Request lifecycle
1. Receive the request.
2. Identify the desired outcome.
3. Detect missing information.
4. Ask only necessary questions.
5. Classify task type, complexity, and risk.
6. Search existing GhostCorp capabilities.
7. Search approved external software, APIs, and providers.
8. Identify whether human expertise or regulated qualifications are required.
9. Estimate scope, time, cost, and uncertainty.
10. Prepare a written proposal.
11. Obtain customer acceptance.
12. Obtain any additional owner or provider authorization required.
13. Execute approved work.
14. Independently verify deliverables.
15. Deliver files, instructions, and results.
16. Record customer acceptance and support needs.
17. Offer relevant maintenance or follow-up only with consent.

### Request statuses
- Received.
- Needs clarification.
- Under review.
- Researching options.
- Partner required.
- Proposal being prepared.
- Awaiting customer approval.
- Awaiting owner approval.
- Approved.
- In progress.
- Blocked.
- Quality review.
- Delivered.
- Accepted.
- Rejected.
- Cancelled.
- Referred externally.

A request is not a paid order merely because it was submitted. No work is represented as started until the required agreement and authorizations exist.

---

## 3. Service ecosystem

The following are service families to investigate and progressively enable. Each service must have an explicit capability status.

### A. Websites and digital presence
- Business websites.
- Landing pages.
- Portfolio sites.
- Restaurant websites.
- Appointment and booking sites.
- E-commerce storefronts.
- Accessible redesigns.
- Website maintenance.
- Hosting and domain guidance.
- Content migration.
- Website performance review.

### B. Software and development
- Web applications.
- Mobile-friendly applications.
- Internal dashboards.
- APIs and integrations.
- Database design.
- Workflow automation.
- Debugging.
- Testing.
- Documentation.
- Deployment planning.
- Software maintenance.

### C. AI and agent systems
- Agent workflow design.
- Agent governance.
- Model evaluation.
- Prompt and tool safety reviews.
- Retrieval and knowledge-base design.
- Human approval workflows.
- AI customer-support prototypes.
- AI integration planning.
- Cost and usage controls.
- Independent agent-output evaluation.

### D. Business operations
- Business research.
- Process mapping.
- Customer workflow design.
- Inventory and appointment workflow planning.
- Reporting.
- Product planning.
- Customer support process design.
- Business automation.
- Operational dashboards.

### E. Creative and communication work
- Brand research.
- Original logos and visual assets.
- Presentation design.
- Documentation.
- Marketing content.
- Video editing and production planning.
- Podcast production support.
- Original media.

### F. Research and education
- Public-source research.
- Technology comparisons.
- Software discovery.
- Research summaries.
- Study support.
- Training materials.
- Technical explainers.
- Product and market research.

### G. Security and privacy assistance
- Authorized application security reviews.
- Website security configuration reviews.
- Dependency and license review.
- Backup verification.
- Access-control reviews.
- Privacy process documentation.
- Incident report preparation.
- Secure integration guidance.

### H. Partner-assisted and physical services
- Repair and maintenance provider discovery.
- Qualified trade professional discovery.
- Accounting and legal professional referrals.
- Tutoring and consulting referrals.
- Hardware and equipment sourcing.
- Local service provider discovery.
- Delivery and logistics provider discovery.

GhostCorp must not imply that it performs physical, licensed, regulated, or high-consequence professional work itself when it does not. It may help with research, administrative preparation, software, and referrals to appropriately qualified providers.

---

## 4. Capability registry: what GhostCorp can actually do

Every service and tool must have a registry record.

Required fields:
- Capability ID.
- Name.
- Description.
- Status: live, beta, internal-only, partner-dependent, planned, or retired.
- Owner department.
- Required agents and tools.
- Required human expertise.
- Data permissions.
- Risk tier.
- Cost model.
- Supported inputs.
- Expected outputs.
- Quality checks.
- Known limitations.
- Current availability.
- Last tested date.
- Evidence links.
- Rollback or disable procedure.

The customer-facing interface may only promise capabilities whose status and evidence support the promise.

---

## 5. Reuse-first software and hardware strategy

GhostCorp should act as an integration and coordination layer over existing technology.

### Discovery order
1. Existing GhostCorp code and infrastructure.
2. Maintained open-source software with compatible licenses.
3. Existing APIs and provider integrations.
4. Existing plugins and adapters.
5. Existing hosted model endpoints.
6. Compatible local models and hardware.
7. Legitimate service and infrastructure partnerships.
8. New custom development only when the above are insufficient.

### Software reuse catalog
Record:
- Project and official source.
- License and commercial-use permissions.
- Maintainer and release activity.
- Security advisories.
- Dependencies.
- API availability.
- Hosting requirements.
- Hardware requirements.
- Cost and free-tier restrictions.
- Data handling and privacy implications.
- Integration method.
- Replacement options.
- Adoption decision and reviewer.

Do not assume that a public repository is open-source or that public visibility grants reuse rights. Review the actual license and terms.

### Initial technology candidates
These are evaluation candidates, not mandatory dependencies or claims of connection:
- GitHub for source control and collaboration.
- LangGraph and CrewAI for agent orchestration comparisons.
- PostgreSQL for structured application data.
- pgvector or another retrieval system for semantic search.
- FastAPI for Python APIs where appropriate.
- Cloudflare Workers and related services for lightweight edge functionality.
- Ollama for compatible local inference.
- Hugging Face model ecosystem for model discovery.
- Firecrawl for approved research and extraction workflows.
- Pytest for automated testing.
- OpenTelemetry-compatible monitoring where useful.

Every provider must be checked for current pricing, terms, limits, maintenance, security, and suitability before use.

### Hardware reuse
A distributed worker network may eventually use:
- Owner-operated desktops.
- Workstations.
- Gaming PCs.
- Servers.
- Spare laptops.
- Contracted cloud compute.
- Partner-contributed infrastructure.

Every worker must be explicitly enrolled by its owner. The owner controls CPU, GPU, memory, storage, bandwidth, schedule, task categories, and disconnection. No hidden compute, unauthorized storage, mining, or personal-file access.

Worker enrollment must include:
- Verified identity.
- Explicit consent.
- Resource limits.
- Task allowlist.
- Isolation.
- Usage reporting.
- Security updates.
- Disconnect and data deletion.
- Incident handling.

---

## 6. AI collective and agent organization

Long-term organizational target: 1,200+ registered specialist agent identities across 24 departments.

This is an identity and organizational target, not a requirement to run 1,200 model sessions simultaneously.

### Departments
1. AI Research.
2. Engineering.
3. Business Development.
4. Cybersecurity.
5. Marketing.
6. Sales.
7. Quality Assurance.
8. Data Intelligence.
9. Product Design.
10. Financial Intelligence.
11. Operations.
12. Infrastructure.
13. Customer Support.
14. Legal Research.
15. Documentation.
16. Automation.
17. Scientific Research.
18. Education.
19. Analytics.
20. Competitive Intelligence.
21. Creative Studio.
22. Risk Management.
23. Project Management.
24. Executive Oversight.

### Agent identity
Every agent record includes:
- Stable agent ID.
- Name and role.
- Department.
- Supervisor.
- Mission.
- Instructions and policy version.
- Assigned model and fallback.
- Tool permissions.
- Data-access scope.
- Spending authority (default: none).
- Task history.
- Evidence and citations.
- Performance results.
- Error history.
- Cost history.
- Current status.

Agents are logical specialists. Multiple agents may use the same underlying model. Model replacement must not erase role identity or verified task history.

### Scaling
- Stage 1: 5–10 core roles.
- Stage 2: 25 registered agents.
- Stage 3: 50–100.
- Stage 4: 250.
- Stage 5: 500.
- Stage 6: 1,200.
- Later: larger registries only when measured workload justifies them.

Do not scale agent count to create impressive but meaningless numbers. Measure useful work, cost, latency, correctness, and quality.

---

## 7. Shared memory and learning

Use six memory layers:

1. Individual agent memory.
2. Department knowledge.
3. Approved organization-wide knowledge.
4. External research memory with source, date, license, and reliability.
5. Experiment memory containing successes and failures.
6. Knowledge graph linking projects, tools, providers, products, and evidence.

### Knowledge promotion workflow
- Capture the claim.
- Record source and date.
- Identify whether it is fact, estimate, opinion, or hypothesis.
- Check source quality.
- Seek independent confirmation for important claims.
- Record disagreement and uncertainty.
- Set expiration/revalidation dates for changing facts.
- Promote only reviewed information into shared memory.

An agent must not rewrite policies, owner decisions, verified financial records, or audit evidence.

---

## 8. Agent collaboration and independent review

Use temporary project teams rather than broadcasting every task to every agent.

Example: selecting a database:
- Research agent finds candidates.
- License reviewer checks permitted use.
- Security reviewer checks advisories.
- Engineering tests integration.
- Infrastructure checks operations.
- Finance estimates cost.
- Independent verifier reproduces key tests.

The coordinator creates a decision record with evidence, dissent, uncertainty, and a recommendation.

Consensus is not proof. Majority voting must never override reproducible evidence or safety controls.

---

## 9. Customer accounts, projects, and marketplace

### Customer workspace
- Profile and communication preferences.
- Requests and project status.
- Quotes and accepted scope.
- Orders and invoices.
- Payment status.
- Messages.
- Files and deliverables.
- Support tickets.
- Partner details.
- Subscription and maintenance records.
- Privacy, export, and deletion controls.

### Partner directory
- Provider onboarding.
- Business identity verification.
- Qualifications and licensing checks when applicable.
- Services and geographic coverage.
- Pricing and availability.
- Work samples and references.
- Contract and service terms.
- Customer feedback.
- Dispute and escalation process.
- Transparent referral fees.

### Marketplace listing types
1. GhostCorp-delivered services.
2. Partner-delivered services.
3. Digital products.
4. Software and subscriptions.
5. Hardware and equipment recommendations.

Clearly identify who is responsible for delivery. Disclose commissions and fees. Do not fabricate reviews or provider qualifications.

---

## 10. Command center

Build a modular owner dashboard with:
- Overview.
- Universal Request Engine.
- Customer projects.
- Collective chat.
- Agent directory.
- Departments.
- Task queue.
- Knowledge base.
- Research center.
- Software reuse catalog.
- Model catalog.
- Hardware worker registry.
- Partner directory.
- Marketplace.
- Product factory.
- Development and testing.
- Security center.
- Finance and reconciliation.
- Action Center.
- Analytics.
- Audit center.
- Settings.

Only display real measured activity. Label demos and sample data clearly.

### Action Center
Every consequential proposed action must show:
- Proposing agent.
- Exact action.
- Reason.
- Target system.
- Permissions used.
- Data involved.
- Expected cost.
- Risk.
- Reversibility.
- Evidence.
- Required approval.
- Result and verification.

Approval must be specific to the action. Do not treat one approval as blanket permission for future actions.

---

## 11. Financial controls — permanent

These rules are mandatory:

- Bots do not use the owner's personal money by default.
- API spending cap remains $0/month until verified business revenue exists and the owner explicitly authorizes a defined budget.
- No paid subscriptions, hosting upgrades, or contractors without authorization.
- Paper-only operation for financial/trading systems until eligible business revenue and required authorization exist.
- No spending against projected revenue.
- No unrestricted agent withdrawals.
- No changing payout destinations without owner approval.
- Pending payments are not settled revenue.
- Exchange/payment provider records are authoritative for their respective balances and transaction status.
- Unknown or mismatched financial state blocks further financial action until reconciled.

Maintain separate accounting categories:
- Customer gross payments.
- Processing fees.
- Refunds and chargebacks.
- Settled revenue.
- Tax and other reserves.
- Operating treasury.
- Owner-withdrawable earnings.
- Approved operating expenses.
- Payouts and reconciliation.

The operating treasury and owner earnings are accounting categories; do not imply separate bank accounts unless configured and verified.

---

## 12. Security, privacy, and governance

- Least-privilege permissions.
- Separate customer data by tenant.
- No cross-customer memory leakage.
- Secure credential storage.
- No secrets in source code or public logs.
- Scoped API keys.
- External content is untrusted input.
- Prompt-injection defenses.
- Sandboxed code execution.
- Network egress controls.
- Rate limits and task budgets.
- Audit logging.
- Backup and restore testing.
- Dependency and license scanning.
- Security review before production changes.
- Data retention and deletion policies.
- Incident response and disclosure.
- Emergency stop at agent, department, project, provider, worker, and network levels.

Sensitive customer actions, public communications, financial actions, production deployments, and changes to access control require the appropriate approval.

---

## 13. Model routing and cost controls

Create a model router that selects a model based on:
- Task difficulty.
- Required accuracy.
- Data sensitivity.
- Tool availability.
- Provider terms.
- Latency.
- Token and usage limits.
- Actual cost.
- Fallback availability.

Use small models for simple classification and extraction when suitable. Use stronger models for complex reasoning and independent review when justified. Use retrieval for large document collections. Do not send private data to external providers without appropriate permission and disclosure.

Free access is not guaranteed. Enforce a hard budget and fail closed when a provider requires unauthorized paid usage.

---

## 14. Product factory

Standard lifecycle:
1. Discover a customer problem.
2. Validate demand with evidence.
3. Search existing solutions.
4. Check licenses and terms.
5. Define customer and scope.
6. Estimate delivery cost and support burden.
7. Design a prototype.
8. Build in an isolated branch or sandbox.
9. Run automated tests.
10. Conduct independent security and quality review.
11. Obtain owner approval for production release.
12. Publish accurate product descriptions.
13. Deliver and support.
14. Collect feedback with consent.
15. Improve or retire the product.

Do not launch speculative products as if demand were proven.

---

## 15. Initial revenue strategy

Prioritize a narrow service that can be delivered honestly and cheaply.

Candidate initial offers should be evaluated against:
- Existing public service pages.
- Demonstrable delivery capability.
- Customer demand.
- Time to completion.
- Gross margin after fees and support.
- Refund and dispute risk.
- Legal and privacy requirements.
- Ability to reuse existing tools.

The website currently has published digital products and service pages. Preserve those existing offers. New universal requests should initially be treated as inquiries for review, not guaranteed orders.

---

## 16. Deployment and reliability

### Website deployment
- Preserve the existing root homepage.
- Add new pages as separate routes.
- Use the current repository and domain.
- Keep commits small and attributable.
- Verify the deployed URL after each publication.
- Test mobile and desktop.
- Test links, forms, keyboard navigation, and accessibility.
- Verify that no existing route has regressed.
- Maintain rollback instructions.

### Backend deployment
Do not assume a static website can run a private database, model inference, payment processing, or durable background jobs.

Add backend services only after selecting a provider and verifying:
- Account ownership and permissions.
- Free-tier limits and cost.
- Secret management.
- Data location and retention.
- Authentication.
- Backups.
- Monitoring.
- Rate limits.
- Security controls.

The user's Android phone should be a control surface, not the primary server. Avoid large model downloads and unnecessary local storage.

---

## 17. Phased implementation roadmap

### Phase 0 — Preserve and document
- Inventory current repository and live routes.
- Record existing services and integrations.
- Establish baseline screenshots and smoke tests.
- Maintain this master specification.
- Create a deployment/rollback record.

### Phase 1 — Customer request landing page
- Separate request route.
- Clear current-service versus future-capability language.
- Privacy-conscious inquiry workflow.
- No false promise of instant fulfillment.
- Add navigation without replacing homepage.
- Verify live deployment.

### Phase 2 — Request intake backend
- Secure request submission API.
- Spam controls.
- Consent and privacy notice.
- Request IDs.
- Durable storage.
- Owner notification.
- Admin review queue.
- Retention and deletion controls.

### Phase 3 — Request triage
- Category detection.
- Clarifying questions.
- Risk and complexity classification.
- Capability registry lookup.
- Human escalation.
- Structured scope draft.

### Phase 4 — Agent coordination
- Core coordinator.
- Researcher.
- Software reuse researcher.
- Engineer.
- QA reviewer.
- Security reviewer.
- Documentation writer.
- Independent verifier.
- Task history and cost records.

### Phase 5 — Software reuse catalog
- Searchable tool registry.
- License review.
- Security status.
- Pricing and quota records.
- Integration adapters.
- Replacement strategy.

### Phase 6 — Customer workspace
- Accounts.
- Project timeline.
- Messages.
- File delivery.
- Support.
- Consent and privacy controls.

### Phase 7 — Partner network
- Partner applications.
- Verification.
- Service catalog.
- Availability.
- Referral and contract terms.
- Disputes and quality monitoring.

### Phase 8 — Marketplace and payments
- Listings.
- Quotes.
- Checkout through supported provider.
- Payment verification.
- Fulfillment.
- Refunds.
- Reconciliation.
- Owner-controlled payouts.

### Phase 9 — Shared memory and research
- Provenance-aware memory.
- Retrieval.
- Knowledge graph.
- Expiration and revalidation.
- Independent verification.

### Phase 10 — Voluntary worker network
- Worker enrollment.
- Owner consent.
- Resource limits.
- Isolation.
- Workload assignment.
- Usage accounting.
- Disconnect and deletion.

### Phase 11 — Scale departments
- 25 agents.
- 50–100.
- 250.
- 500.
- 1,200 registered identities.
- Expand only when utilization and quality justify it.

### Phase 12 — Broader service ecosystem
- Add service families based on validated demand.
- Add external providers.
- Expand software and hardware integrations.
- Build subscription and maintenance products.
- Improve customer retention and quality.

---

## 18. Acceptance criteria

A phase is not complete because code exists. It is complete only when evidence demonstrates:

- The feature works on the intended environment.
- Automated tests pass.
- Relevant manual tests pass.
- Security and permissions are reviewed.
- Costs and quotas are known.
- Failure cases are handled.
- Logs and audit records are correct.
- Existing website routes still work.
- Documentation matches actual behavior.
- Deployment is verified.
- Rollback is possible.

For customer work, completion also requires a verified deliverable matching the agreed scope.

---

## 19. Operating metrics

Track:
- Requests received.
- Requests qualified.
- Proposals sent.
- Proposal acceptance rate.
- Delivery time.
- On-time delivery.
- Customer satisfaction.
- Refund and dispute rate.
- Partner completion quality.
- Verified revenue.
- Actual costs.
- Gross margin.
- Agent task success.
- Independent review failure rate.
- Cost per completed task.
- Model/provider availability.
- Security incidents.
- Backup restoration success.
- Worker utilization and owner opt-outs.

Never use vanity metrics such as registered-agent count as a substitute for delivered customer value.

---

## 20. New expansion ideas backlog

Evaluate, do not automatically implement:
- Universal request engine.
- Partner marketplace.
- Software reuse exchange.
- Hardware contribution program.
- Agent training academy.
- Model tournament.
- Research replication lab.
- Product factory.
- Customer knowledge workspace.
- Business operations automation.
- API marketplace.
- Open-source contribution program.
- Hardware and cloud comparison engine.
- Accessibility audit service.
- Software license and dependency intelligence.
- Customer feedback engine.
- Incident command center.
- Disaster recovery lab.
- Multilingual support.
- Industry-specific workflow packages.
- Verified provider directory.
- Customer self-service automation.
- Developer portal.
- Public status page.
- Service quality scorecards.
- Transparent referral and commission system.

---

## 21. First engineering assignment

Do not attempt to implement the entire roadmap in one change.

Start by:
1. Inspecting the current repository and live site.
2. Preserving all existing features.
3. Verifying the new request landing page and navigation.
4. Creating a test plan for the static inquiry flow.
5. Documenting what is live versus planned.
6. Designing the secure request API without enabling public submission until privacy, spam, storage, authentication, and owner review are ready.
7. Returning a concise implementation report with commits, test evidence, deployment URL, blockers, and next steps.

**The first useful product is a trustworthy request intake and review process. The larger AI collective grows behind it.**
