# Jarvis Resilience, Offline Operation, and Recovery

Status: **architecture and implementation requirements committed; no persistent runtime or backup destination has yet been verified.**

## Operating objective

Jarvis must preserve its work and remain useful when any one dependency fails: VR headset, internet, model host, GitHub Actions, a model, an inference provider, or an external API. The headset is a client, never the host or source of truth.

## Operating modes

1. **ONLINE_LOCAL** — durable server-side queue and database available; local inference preferred; internet integrations available only when authorized.
2. **ONLINE_DEGRADED** — one or more model/host/provider dependencies unavailable; route to another installed local model, deterministic code, or cached data.
3. **OFFLINE** — no network. Continue with local models, local read-only knowledge/cache, deterministic operations, and local queue. No fresh web/provider/database reads are possible.
4. **NO_MODEL** — all LLMs unavailable. Keep scheduling, queue state, audit, retry, backups, rules, and status endpoints working. Respond with a concise deterministic status/help interface.
5. **NO_CREDITS** — paid inference is disabled by policy; continue local/free paths. Never try a billable endpoint.
6. **RECOVERY** — restore durable state, reconcile pending idempotent jobs, verify integrity, then resume from the last completed checkpoint.

A response must distinguish stale cached data from live data. Never imply that an offline answer includes fresh internet information.

## Required durable state

- mission/job queue with stable IDs, idempotency keys, checkpoints, attempts, and last error;
- project registry, model registry, routing decisions, and evaluated model scores;
- memory records with timestamps, source/provenance, and retention class;
- user-approved permissions and provider connection metadata (never raw secrets);
- business operational state in its own business repository/service boundary;
- audit trail and backup manifest.

## Backup policy

- Use SQLite's online backup API or a database-native consistent snapshot; do not copy a live WAL database file by ordinary file copy.
- Encrypt every business/customer/owner-data backup before it leaves the trusted host. Never commit plaintext backups or keys to Git.
- Keep at least three generations and a separate off-host copy when a destination is available and authorized.
- Keep encryption keys outside the backup and outside Git; restore requires the owner-controlled key.
- Verify each backup by decrypting into an isolated temporary location, running database integrity checks, and recording a checksum/manifest.
- Run restore drills on a disposable copy; do not overwrite production automatically.
- Keep public Git repositories limited to source, tests, non-sensitive configuration templates, and documentation.
- GitHub commit history is not a backup of runtime databases, model weights, customer records, secrets, or durable queues.

## Free-first internet services (candidate architecture)

- GitHub Actions: public-repository CI, scheduled integrity checks, release packaging, and smoke tests. Runners are ephemeral; never use them as a permanent daemon or model host.
- Cloudflare Workers Free: small stateless API, health/status, authenticated queue gateway, and scheduled triggers within published limits.
- Cloudflare D1 Free: small durable operational metadata/queue index within published size/query limits; keep encrypted backup snapshots elsewhere.
- Cloudflare R2/KV/Durable Objects: evaluate only after current plan limits and retention behavior are checked; do not assume all storage is free or permanent.
- Public static data: pin immutable snapshots in Git or releases when licensing allows; cache source, retrieval time, and freshness.
- Local model host: required for actual inference; a serverless Worker is not a substitute for a local LLM runtime.

No Cloudflare connection, account, database, secret, or deployment is claimed by this document.

## Compute contribution rules

Only enroll hosts when the owner has explicitly offered compute for third-party workloads, the workload class and limits are documented, and the node can be safely isolated. No scanning for exposed servers, guessing credentials, installing on public machines, or treating a public IP/repository as permission.

Candidate projects:
- Lettuce (jring-o/lettuce-compute): open-beta volunteer CPU/GPU work network; evaluate its protocol, trust model, workload restrictions, and operator consent before any enrollment.
- BOINC: volunteer compute for participating scientific projects; not a general-purpose Jarvis hosting pool.
- c0mpute: appears to operate a priced compute marketplace; not a $0 volunteer-hosting assumption.

Volunteer nodes may run only stateless, non-sensitive, independently verifiable tasks. Never place business databases, credentials, customer data, private memory, or signing keys on volunteer nodes.

## Recovery sequence

1. Detect dependency failure and enter the correct degraded mode.
2. Stop retries to the failed dependency; do not spin in a cost-generating loop.
3. Persist the current task checkpoint and mark unfinished jobs resumable.
4. Route to another installed local model if appropriate; otherwise use deterministic fallback or queue the task.
5. When connectivity returns, verify provider health and credentials, reconcile idempotency keys, and resume only unfinished work.
6. Record what was missed while offline and which cached sources may be stale.

## Acceptance tests

- Disconnect internet: local chat, memory lookup, task queue, and status still function.
- Stop the primary model: router selects an installed fallback or enters NO_MODEL without billing.
- Remove all API keys: no billable API request is attempted.
- Restart the worker during a job: it resumes from checkpoint without duplicating side effects.
- Restore a backup into an isolated environment: database integrity passes and queue state is reconciled.
- Turn off VR: server-side work continues and a later client reconnects to the same world and mission state.
- Exhaust a free quota: tasks queue or degrade; no paid plan is activated.

## Current verified state

- The policy and architecture are committed.
- A local Ollama adapter scaffold exists under `jarvis/model-fleet/`.
- A GitHub Actions model smoke-test workflow has been queued; it is not yet evidence of a persistent host.
- No persistent Jarvis worker, production database, backup destination, Cloudflare deployment, or volunteer compute node is currently verified.
