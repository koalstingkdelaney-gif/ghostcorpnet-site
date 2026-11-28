# GhostCorp Unified Operating System

Status: architecture contract and implementation plan. This document does not claim that unbuilt services are running.

## Product rule
GhostCorp is one operating system with multiple connected surfaces—not a collection of unrelated demos, websites, repositories, or agents. The existing website, immersive VR client, Jarvis runtime, AI fleet, research lab, academy, business operations, and owner controls must share one identity, one API contract, one event model, one persistent data layer, and one release pipeline.

## Canonical project
- Existing public site and VR source repository: koalstingkdelaney-gif/ghostcorpnet-site.
- Existing immersive entry point: vr/index.html.
- Existing web surfaces include the VR headquarters, AI chat, and Action Center.
- Do not create a second VR app or duplicate repository for the same product. New components belong in this repository unless a concrete deployment/security boundary requires a separate service; any such service must be linked here and use the same contracts.

## Shared architecture
1. Experience layer: website, Quest immersive client, and future desktop/mobile clients. Clients render and send commands; they do not own durable state.
2. API gateway: one versioned authenticated API for identity, world state, agents, tasks, research, business workflows, telemetry, and publishing.
3. Jarvis orchestrator: persistent task queue, scheduler, agent coordination, capability registry, policy checks, checkpoints, retries, and recovery.
4. World service: server-authoritative world state, room/scene definitions, object transforms, NPC state, interaction events, world revisions, and per-agent workspaces. VR disconnect must not stop this service.
5. AI model router: local models first when available; approved free quotas as optional burst capacity; explicit quota/rate-limit tracking; no paid fallback. Model outputs are artifacts/checkpoints, not the only copy of memory.
6. Persistent data: durable database for users, permissions, tasks, checkpoints, world revisions, agent state, research artifacts, and audit events. Backups are encrypted; secrets and customer data are never committed to Git.
7. Capability/integration layer: provider adapters, tool permissions, health checks, and evidence records. No third-party compute or accounts without the owner's/provider's authorization.
8. Build/release pipeline: one source of truth, automated lint/test/build, artifact versioning, staged deployment, health checks, and rollback. Website edits and VR updates flow through the same release process.

## Movement and visual quality are first-class features
The VR client should have responsive, high-speed locomotion: smooth stick movement, sprint, air control, jump, momentum-aware acceleration/deceleration, and optional dash. Include comfort controls: snap/smooth turning, vignette, seated mode, and adjustable speed. Fast movement must not cause motion sickness by default. The visual pass follows the locomotion foundation: coherent art direction, high-quality lighting/materials, environmental depth, readable wayfinding, optimized geometry, animation, restrained particles, and Quest performance budgets. Do not copy another game's assets or distinctive design.

## Shared event and state contract
All surfaces consume the same versioned entities and events:
- TaskCreated / TaskUpdated / TaskCheckpointed / TaskCompleted / TaskFailed
- AgentStatusChanged / CapabilityVerified / CapabilityUnavailable
- WorldRevisionCreated / WorldObjectChanged / WorldScenePublished
- ResearchArtifactCreated / ExperimentResultRecorded
- ApprovalRequested / ApprovalGranted / ApprovalDenied
- ReleaseBuilt / ReleaseDeployed / ReleaseRolledBack

Every event has an ID, timestamp, actor, correlation ID, schema version, and audit reference. Idempotent commands and checkpointed tasks prevent duplicate work after reconnects.

## Authority and safety
- Jarvis may autonomously perform reversible, low-risk operations within explicitly configured permissions.
- Owner approval remains required for spending, payouts, legal agreements, identity checks, account ownership changes, granting third-party access, and destructive or externally consequential actions.
- World-building authority does not imply authority over business funds, customer data, or third-party infrastructure.
- Secrets stay in server-side secret storage. Never put tokens in browser code, VR assets, logs, or Git.
- Public/academy areas are separated from private owner and business systems by server-side authorization—not merely hidden UI.

## Offline and resilience behavior
- The VR client can disconnect without stopping Jarvis or the world service.
- The client caches only safe public assets and explicitly approved offline data.
- When internet or inference is unavailable, local deterministic services continue: saved chat context, task queue, world state, notes, and status. AI-dependent tasks checkpoint and wait for a local model or eligible free quota.
- On reconnect, clients reconcile from server revisions; conflicts are surfaced rather than silently overwriting newer state.
- Restore tests must prove backups can be recovered.

## Definition of done
A feature is not working because a file exists. It must have:
1. An implemented path connected to the shared API/data model.
2. Automated tests for normal, failure, reconnect, and permission cases.
3. A deployed build and health check where deployment is available.
4. A recorded test result and version/commit.
5. A rollback path for changes to production.

## Ordered implementation sequence
1. Inventory existing routes, scripts, assets, workflows, and deployment configuration; identify the actual live entry points.
2. Establish shared API schemas, identity/authorization middleware, persistent task/event storage, and health endpoints.
3. Connect Jarvis task orchestration and checkpoint/recovery to the shared backend.
4. Connect the VR client to server-authoritative world state and shared identity; prove the world survives headset shutdown.
5. Implement and test fast locomotion, comfort settings, and Quest performance telemetry.
6. Apply the unified visual overhaul to the existing world, not a new project.
7. Connect AI chat, model routing, research lab, academy, and Action Center through the same backend contracts.
8. Add encrypted backups, restore drills, release automation, staged deployment, and rollback.
9. Run end-to-end tests across website, backend, Jarvis, and Quest client; publish an evidence-based status report.

## Current verified state
- The existing repository contains vr/index.html.
- This document records the unified architecture and sequence.
- This document alone does not establish that a persistent backend, Jarvis daemon, database, model fleet, native Quest package, or end-to-end integration is deployed. Those must be implemented and independently tested.
