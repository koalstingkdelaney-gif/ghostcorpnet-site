# GhostCorp Long-Term Continuity and Succession Plan

## Purpose

GhostCorp should be designed to remain safe, maintainable, and useful if its founder is incapacitated or dies. This is a business-continuity requirement, not a claim that software can establish death, inherit property, or make legal decisions.

## Governing principles

1. **Legal authority comes first.** A successor may administer GhostCorp only after the required legal authority and identity checks are verified. The system must not infer death from inactivity, missed check-ins, device loss, or an outage.
2. **No automatic transfer of ownership.** Repositories, domains, hosting, payment accounts, customer contracts, intellectual property, and data remain subject to their actual owners' terms and applicable law. A will, trust, operating agreement, and provider-specific succession procedures must be prepared with qualified professionals.
3. **Least privilege.** A successor receives only the access needed for their documented role. No agent receives unrestricted authority over banking, payouts, legal commitments, customer data, or account ownership.
4. **No spending without authorization.** Maintain a hard operating budget and disable paid AI/API fallbacks. No agent may raise limits, add payment methods, transfer funds, or change payout destinations.
5. **Continuity without unsafe autonomy.** Agents may continue approved, reversible work within written policies. High-impact actions remain queued for an authorized human.
6. **Privacy and security.** Encrypt backups; keep secrets out of Git; rotate credentials during succession; preserve audit logs; honor customer privacy and retention obligations.
7. **Graceful degradation.** If hosting, internet, APIs, or credits disappear, use local models and cached non-sensitive knowledge where available, queue work, and resume from durable checkpoints when service returns.

## Operating modes

- **Founder active:** Founder retains owner controls. Agents work within configured permissions and approval gates.
- **Founder unavailable / unconfirmed:** Continue only pre-approved low-risk operations. Do not change ownership, financial settings, access rights, or external commitments. Alert designated contacts through configured channels. Do not assume death.
- **Verified incapacity or death:** Enter succession hold. Require confirmation by the designated legal representative and the documented verification process before enabling successor administration.
- **Successor administration:** A legally authorized successor can review the business, rotate credentials, maintain services, approve budgets, and appoint human operators. All privileged actions are logged.
- **Shutdown / preservation:** If no authorized successor is available, stop new external commitments, preserve records and backups, disable risky automation, and follow legal instructions for winding down.

## What must be backed up

- Source code, infrastructure definitions, deployment instructions, and release artifacts.
- Encrypted database backups and tested restore procedures.
- Project decisions, task queues, agent checkpoints, and operational runbooks.
- Domain, hosting, repository, and provider inventory (never passwords or raw API keys in the repository).
- License records, model provenance, customer contracts, privacy notices, and business records where lawful to retain.
- A recovery manifest listing where credentials and recovery materials are held, without containing the secrets themselves.

Backups should be encrypted, versioned, stored in at least two independently controlled locations, and restore-tested on a schedule. Keep a documented offline recovery copy.

## Required human/legal setup

The founder should work with an estate-planning attorney and business attorney to decide whether a trust, will, business entity documents, or other instruments should own or control the relevant assets. Name the appropriate executor, trustee, successor manager, and backup contact as applicable. A trustee is a person or institution legally responsible for managing trust property under the trust's terms; the roles and powers must be defined by the actual documents.

Create an asset schedule covering the GitHub organization/repositories, domain registrar, DNS, hosting, databases, payment processors, bank/payment destinations, intellectual property, and any customer or vendor agreements. Confirm each provider's permitted business-transfer, recovery, and successor-access process. Do not share passwords informally or assume a provider permits account transfer.

If the founder wants their daughter to benefit from the business, the legal documents must specify how and when that benefit is held and managed. Do not assume a minor can directly operate the business or act as trustee; obtain qualified legal advice.

## Implementation milestones

1. Add this policy to the central GhostCorp repository.
2. Build a machine-readable continuity configuration with explicit allowlists, budgets, approval thresholds, contacts, and operating modes; store no secrets in it.
3. Implement durable encrypted backups and automated restore tests.
4. Add a founder-unavailable safe mode that never treats inactivity as proof of death.
5. Add a successor access workflow requiring documented human/legal verification and least-privilege provisioning.
6. Build a read-only succession dashboard showing service health, assets, backup age, pending work, and recovery instructions.
7. Test disaster recovery and successor handover using a tabletop exercise before relying on it.

## Current status

This document defines the policy and implementation target. It does not itself configure legal succession, transfer ownership, deploy backups, grant successor access, or make the live system continue running. Those require separate implementation, provider setup, legal documents, and tests.
