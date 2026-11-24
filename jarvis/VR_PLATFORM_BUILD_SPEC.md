# GhostCorp Native VR Platform — Build & Deployment Specification

Status: SPECIFICATION / NOT DEPLOYED
Owner surface: existing GhostCorp website (ghostcorpnet.com)
Source of truth: this repository and its versioned release artifacts
Primary target: Meta Quest-class Android/OpenXR headset; exact model and OS must be detected before device-specific packaging.

## 1. Product goal

Build one persistent GhostCorp world that can be edited from the existing website and experienced through an installed native VR application. The website is the owner control surface and release console; it is not the world runtime. Jarvis operates the world through a typed, authenticated API and durable jobs. The headset renders and interacts with the world. World state, user projects, checkpoints, and job history live server-side and survive headset shutdowns.

The experience should feel seamless: owner edits a scene or gives Jarvis a natural-language instruction on the website; the system creates a versioned change; previews it; runs checks; packages a build or content-only update; then delivers it to an authorized headset agent when the device is reachable. The headset receives the update, validates it, applies it, and reports the result. Failed updates roll back to the last known-good version.

## 2. Architecture

- Existing website: public pages remain public; the owner builder is a private route backed by server-side authentication. Never put owner tokens, provider keys, device credentials, or privileged API calls in browser code.
- Owner Builder: scene tree, world map, asset library, prompt-to-edit workspace, visual preview, diff/version history, test results, deployment channel, device status, and rollback controls.
- Control API: authenticated, typed operations only. No general-purpose shell or arbitrary code execution from browser prompts.
- Jarvis orchestrator: durable mission queue, idempotency keys, checkpoints, retry/backoff, audit events, model/provider routing, artifact handoffs, and recovery after restart.
- World service: authoritative scene graph, world metadata, entity state, permissions, snapshots, and event history. Client rendering is not authoritative.
- Asset/build workers: isolated, reproducible builds; dependency pinning; license/provenance records; static checks; performance budgets; APK signing through protected CI secrets only after a signing identity is intentionally provisioned.
- VR client: native Android/OpenXR application; reconnects, downloads compatible signed manifests/assets, verifies hashes/signatures, applies safe content updates, and reports health.
- Device relay: an owner-authorized local desktop/host agent using official Android/Meta device tooling. It initiates outbound authenticated connections to the control plane. Never expose ADB, device debug ports, or a headset management port to the public internet.
- Persistence: database plus encrypted off-host backups; object storage for immutable builds/assets; retention and restore tests.

## 3. Owner website workflow

1. Owner signs in through server-side authentication with MFA where supported.
2. Builder loads the current world snapshot, capabilities, device inventory, and last known-good release.
3. Owner uses visual editing or natural-language instructions. Jarvis converts requests into a typed change plan and explains affected scenes/assets.
4. Changes are applied in a sandbox branch/world copy. Every change has an author, timestamp, source, diff, and rollback point.
5. Preview runs in browser/desktop simulator where practical; device-specific checks run against the supported target profile.
6. CI runs formatting, schema validation, unit/integration tests, asset/license checks, APK build, signing verification, package size/performance gates, and security scans.
7. A release candidate appears in the website with test evidence, compatibility, known limitations, and exact change list.
8. On an explicit owner publish action, the release is marked eligible for deployment. Routine content-only releases may be auto-deployed only after a separate owner-configured policy enables that channel.
9. When an authorized device relay is online, it downloads the signed release, checks version/hash/signature/compatibility, installs or applies it, smoke-tests launch, and reports VERIFIED or FAILED.
10. If installation or smoke test fails, keep or restore the last known-good app/content version and preserve diagnostic logs without secrets.

## 4. Update types

- Content update: scenes, meshes, textures, audio, world data, non-executable assets. Prefer this path for fast iteration; signed manifest plus immutable asset bundle.
- Application update: native code, engine, plugins, permissions, native SDK, renderer, or runtime changes. Requires a new APK and device installation.
- Server update: world service, API, orchestration, queue, or database migration. Deploy independently with health checks and rollback.
- Never represent a content update as an APK install. Never silently replace native binaries.

## 5. Native VR target and deployment

Initial engine candidate: Godot 4 with OpenXR, pending a small device compatibility spike. Keep renderer, input, hand tracking, controller mapping, guardian/comfort, and Android packaging behind adapters so another engine can be evaluated without redesigning world data.

Meta's current developer workflow requires a developer account/team, account verification, Developer Mode, USB debugging authorization, and a data-capable USB connection for first-time device deployment. Official Meta documentation recommends Meta VR Developer Hub (MVDH) for device management and deployment; ADB or Meta VR CLI can install APKs after the owner authorizes the device. Wi-Fi ADB is permitted only on a trusted local network and must not be exposed publicly.

The unattended path is: CI builds APK -> immutable release artifact -> owner-authorized relay fetches release -> validates -> installs via official device tooling -> launches -> checks logs/health -> reports status. Cloud CI cannot directly install onto a headset that is offline or not reachable through an authorized relay. Queue deployment until the relay reconnects.

## 6. Security and authority

- Public site visitors have zero access to owner builder, private scenes, customer data, business systems, model/provider credentials, or deployment controls.
- Enforce authorization server-side on every API request; use short-lived sessions/tokens, CSRF protections, rate limits, audit trails, and explicit device enrollment.
- Store secrets in a server-side secret store or protected CI secrets. Never commit secrets or place them in HTML, JS bundles, VR assets, logs, or model prompts.
- Typed world operations use schemas, allowlists, size limits, resource limits, and sandboxing. No model-generated arbitrary shell commands.
- Jarvis may draft, build, test, preview, and prepare releases autonomously within configured permissions. Initial production headset installation, signing-key provisioning, developer account verification, and any new permission/consent gate require the relevant owner action.
- No paid services or API credits; $0 spend remains the default. Do not enable billing, paid fallbacks, auto-recharge, or paid trials.
- Never send secrets, private business data, or personal data to volunteer compute. Use local models for sensitive/private work.

## 7. Persistence, offline, and recovery

- World snapshots, event log, asset manifests, job queue, provider handoff bundles, and last known-good release are durable.
- VR client caches the last compatible world snapshot and permitted assets for read/interaction while offline; queue owner-approved local edits with conflict metadata.
- On reconnect, reconcile using version vectors or explicit conflict resolution; never overwrite newer server state blindly.
- Jarvis resumes queued jobs after process/host restart using idempotent checkpoints.
- Backups are encrypted, versioned, integrity-checked, and restore-tested. Model weights are not included unless independently reproducible and license-permitted.
- Headset power-off must not stop world simulation or orchestration that is intended to persist server-side.

## 8. Acceptance gates

A release is not VERIFIED until evidence proves:
- Owner-only builder authentication and denial for anonymous/public users.
- Scene edits create durable versions, diffs, and rollback points.
- World state survives headset shutdown and service restart.
- CI builds a reproducible native Android package for the detected headset profile.
- Package signature and asset hashes verify before install.
- An enrolled device receives and installs an update through the authorized relay.
- Launch smoke test passes and the app reports version/device/health.
- Failed update preserves the previous working release.
- Offline mode loads cached world state and safely queues supported edits.
- No secrets or privileged endpoints are present in public website bundles.
- $0 spend governor remains enforced.

## 9. Delivery phases

P0 — Inventory: locate existing VR source projects and determine exact headset model, OS, architecture, and existing deployment access. Do not recreate existing work.
P1 — Foundation: create native app skeleton, world schema, typed API contract, owner-only builder shell, release manifest format, and test harness.
P2 — Persistent world: server-side scene graph, snapshots, event log, job queue, offline cache, and recovery tests.
P3 — Builder: website scene editor, prompt-to-plan workflow, preview, diffs, version history, and asset pipeline.
P4 — Native client: OpenXR interaction, rendering, authentication, asset sync, reconnect, telemetry, comfort, and device profile.
P5 — CI/CD: free GitHub Actions build/test, signed release pipeline, immutable artifacts, compatibility gates, and rollback.
P6 — Device relay: authorized local agent, device enrollment, update polling, install/launch/health verification.
P7 — Frontier lab: controlled experiments in multi-agent world building, learned scene optimization, procedural worlds, local/hosted model handoffs, and publishable educational research with reproducible benchmarks.

## 10. Current truth

This file is a build specification, not proof of a deployed native app. The repository tree must be checked for existing VR projects before creating a replacement. No headset install, device relay, native APK, or production owner builder is claimed until each is independently tested and evidenced.
