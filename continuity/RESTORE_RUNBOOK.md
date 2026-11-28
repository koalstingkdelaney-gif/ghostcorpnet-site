# GhostCorp Disaster Recovery Restore Runbook

**Status:** Procedure template; validate against the actual deployed stack before relying on it.

## Before an incident

Maintain a current service inventory, architecture diagram, deployment instructions, backup locations, restore credentials custody instructions, and contact tree. Keep secrets in the approved secret manager. Test this runbook in staging at least quarterly and after major infrastructure changes.

## Declare and contain

1. Identify the incident lead and record the start time.
2. Classify severity and identify affected systems and customer impact.
3. Stop unsafe automation and suspend writes if data integrity is uncertain.
4. Revoke compromised tokens or isolate affected workers when appropriate.
5. Preserve logs and evidence before rebuilding or deleting resources.
6. Notify only authorized contacts; do not include secrets in alerts.

## Select recovery point

1. List available backups and their timestamps.
2. Verify backup signatures/checksums and expected schema/version.
3. Reject incomplete, corrupted, or suspicious backups.
4. Select the latest known-good recovery point consistent with the incident.
5. Record expected data loss against the approved RPO.

## Restore into a clean environment

1. Provision a clean, patched runtime from reviewed infrastructure definitions.
2. Restore database and object storage from verified backups.
3. Apply documented migrations in order.
4. Restore secrets only through the authorized secret manager/recovery process.
5. Disable external side effects until reconciliation is complete.
6. Restore queues and checkpoints; mark uncertain external tasks for manual reconciliation.
7. Run unit, integration, authorization, privacy, and data-integrity checks.
8. Confirm owner/admin access and audit logging.
9. Re-enable services gradually and monitor error rates, queue age, and data consistency.

## Reconcile external actions

Before replaying tasks, reconcile payment events, orders, refunds, emails, outreach, and deployments with their provider records. Use idempotency keys where supported. Never assume a timed-out request failed; verify before retrying.

## Closeout

- Record actual RPO and RTO.
- List data lost, duplicated, or manually reconciled.
- Document root cause and corrective actions.
- Update backups, runbooks, monitoring, and asset register.
- Schedule a restore drill if the incident exposed a gap.

## Stop conditions

Stop and escalate if backup integrity is uncertain, legal authority is unclear, credentials may be compromised, customer records may be exposed, or the proposed recovery would incur unapproved costs. Do not invent missing secrets or bypass provider verification.
