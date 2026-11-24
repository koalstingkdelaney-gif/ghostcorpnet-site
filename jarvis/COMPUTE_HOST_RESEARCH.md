# Public and Volunteer Compute Host Research

Research date: 2026-11-24

## Findings

### GitHub Actions
Official GitHub documentation says standard GitHub-hosted runners are free and unlimited for public repositories. A standard Linux public runner is 4 CPU / 16 GB RAM / 14 GB SSD. Each job uses a new VM and is temporary. Use for CI, tests, packaging, scheduled checks, and short model smoke tests—not persistent serving.

### Cloudflare Free
Official documentation currently lists Workers Free at 100,000 requests/day, 10 ms CPU time/request, and 128 MB memory. D1 Free currently allows 10 databases, 500 MB per database, 5 GB total storage, and 7 days of Time Travel. Good fit for small queues, metadata, status and lightweight authenticated APIs; not model inference.

### Volunteer compute candidates
- Lettuce: https://github.com/jring-o/lettuce-compute — open-beta volunteer-computing project. It describes independent head operators and volunteers donating spare CPU/GPU. Before use, audit source, trust/validation design, workload isolation, resource caps, node identity, and operator consent.
- BOINC: https://github.com/BOINC/boinc — volunteers donate compute to specific BOINC projects. It is not general-purpose remote hosting for Jarvis.
- c0mpute: https://c0mpute.com/ — a compute marketplace with provider nodes and paid job settlement. Do not assume it is free; keep outside the $0 architecture unless terms explicitly establish a no-cost volunteer tier.

## Enrollment checklist
1. Identify a public, explicit invitation to accept third-party workloads.
2. Read current terms, owner/operator docs, privacy, resource caps, allowed workloads, payment requirements, and revocation method.
3. Verify source and install artifacts; pin versions and hashes.
4. Run only stateless, non-sensitive, sandboxed, bounded, verifiable jobs.
5. Never transfer secrets, business/customer records, private memory, or signing keys.
6. Obtain explicit owner approval for any node enrollment that grants a third party access to GhostCorp tasks or data.
7. Record host status as DISCOVERED, PREPARED, ACTIVE_UNVERIFIED, VERIFIED, or BLOCKED.

No external volunteer host has been enrolled or connected.
