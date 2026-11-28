# GhostCorp Incident Response Runbook

**Status:** Operational template; adapt to the deployed environment and rehearse before relying on it.

## Objectives
Protect people and customers, contain harm, preserve evidence, restore trusted service, and prevent recurrence. Do not prioritize uptime over security, legal compliance, or data integrity.

## First response
1. Record who detected the issue, when, affected services, and observed symptoms.
2. Assign an incident lead and a technical lead.
3. Classify severity using the continuity policy.
4. Freeze affected high-risk automation and financial actions.
5. Preserve relevant logs, deployment identifiers, alerts, and provider incident references.
6. Notify designated contacts through approved channels using minimal necessary information.

## Security compromise
- Revoke or disable suspected tokens, sessions, and service identities.
- Isolate compromised workers and affected environments.
- Preserve forensic evidence before rebuilding.
- Rotate credentials from a clean device and trusted environment.
- Review repository, domain/DNS, hosting, payment, and model-provider permission changes.
- Determine whether personal data, customer data, funds, or intellectual property were affected.
- Follow applicable legal and contractual notification requirements with qualified counsel.

## Availability or data incident
- Identify the last known good release and backup.
- Stop writes if corruption or duplicate actions are possible.
- Restore only from verified artifacts.
- Reconcile queues and external side effects before replay.
- Reopen service in stages with monitoring.

## Communication
- Only the designated human spokesperson may make public incident statements.
- Do not speculate about cause, scope, data exposure, or recovery time.
- Do not disclose private customer information or security details in public status updates.
- Keep an internal timestamped incident timeline.

## Exit criteria
- Threat or failure is contained.
- Critical services pass health and authorization checks.
- Data integrity is validated.
- Customer obligations are reconciled.
- Credentials and permissions are reviewed.
- A post-incident report and corrective tasks are assigned.

## Post-incident review
Within a reasonable period, document impact, root cause, detection gaps, decisions, actual recovery time, data loss, and prevention work. Focus on system improvements rather than blame. Track each corrective action to completion.
