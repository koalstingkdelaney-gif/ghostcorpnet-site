# GhostCorp Native VR Environment — Architecture Requirement

Status: REQUIRED ARCHITECTURE / NOT YET IMPLEMENTED
Owner: GhostCorp owner
Environment operator: Jarvis

## 1. Product definition

GhostCorp's primary immersive environment must be a real-time VR application that runs as an installed application on the headset, not a website displayed inside a browser, not a WebXR page, and not a flat dashboard wrapped in a headset.

Target experience: standalone Meta Quest-class headset, with OpenXR as the portability layer. Preferred initial engine: Godot 4 with its OpenXR/Android export path, subject to a tested headset compatibility spike. The engine decision must be validated against actual headset capabilities before committing to production.

The website remains a separate public portal and optional account/status surface. It is not the VR runtime.

## 2. Jarvis environment authority

Jarvis is the environment's delegated world operator and may, within the project's policy:

- Create, load, save, duplicate, version, and retire scenes and environments.
- Build and modify buildings, rooms, terrain, roads, interiors, props, lighting, sky, weather, soundscapes, materials, and visual effects.
- Create, configure, animate, and coordinate NPCs, robots, agents, vehicles, and simulations.
- Manage physics, collision, navigation meshes, spawn points, interactions, portals, triggers, and world events.
- Create separate game worlds and link them through controlled portals or a hub.
- Inspect scene graphs, assets, performance, errors, and runtime state.
- Generate/import approved assets, optimize geometry and textures, and manage asset libraries.
- Create development sandboxes, build new games, launch test instances, run automated playtests, capture test results, and roll back failed changes.
- Manage environment configuration, version history, backups, and deployment packages.
- Operate the environment when the owner is absent and present a concise activity report on return.

Routine environment design and technical implementation should not require owner intervention. Jarvis should decide and execute reversible creative/engineering tasks independently.

## 3. Runtime control architecture

The installed VR application exposes a narrow, authenticated **World Control API** to Jarvis. It is not an unrestricted remote shell.

Components:

1. **Native VR client** — renders the world, tracks headset/controllers, handles spatial interaction, audio, locomotion, and comfort settings.
2. **World runtime** — authoritative scene state, entities, physics, interactions, world transitions, and persistence.
3. **Jarvis world orchestrator** — plans and executes scene changes through typed, validated commands.
4. **Asset/build pipeline** — imports assets, validates content, builds scenes, packages application updates, and runs tests.
5. **Private owner command interface** — in-world controls for reviewing activity, inspecting changes, and handling genuinely sensitive approvals.
6. **Audit and recovery service** — records world changes, snapshots, versions, errors, and rollback points.

The World Control API should support typed operations such as:
- `scene.create / scene.load / scene.save / scene.snapshot / scene.rollback`
- `entity.spawn / entity.update / entity.remove`
- `environment.set_lighting / set_weather / set_audio`
- `navigation.rebuild / physics.configure`
- `portal.create / portal.link / portal.disable`
- `asset.import / asset.validate / asset.optimize`
- `simulation.start / simulation.stop / simulation.inspect`
- `build.validate / build.package / build.test`

Every operation must validate inputs, enforce scope and permissions, and produce an audit event. Destructive operations should use snapshots and recoverable deletion.

## 4. Control boundaries

Jarvis has broad operational control over the simulated environment, not unlimited control over the physical headset or the owner's accounts.

Jarvis may autonomously change ordinary world content and reversible environment configuration. It must not:
- Access headset sensors, microphone, camera, files, or network beyond app permissions and disclosed functions.
- Install or update privileged software without an authorized deployment path.
- bypass OS security, platform policies, account ownership, or user consent.
- expose private business rooms, customer data, financial systems, credentials, or owner-only controls to public visitors.
- silently publish disruptive changes to a live multiplayer environment without staging and compatibility checks.
- make irreversible destructive changes without a recoverable snapshot and appropriate approval.

Physical safety and comfort: respect guardian/boundary systems, locomotion comfort, motion-sickness settings, audio limits, and platform restrictions. No forced movement, hidden tracking, or attempts to bypass safety boundaries.

## 5. World separation and access

The main VR hub is a native 3D environment with distinct destinations. Each major experience/game is a separately loadable world or scene.

Public social/game spaces and private GhostCorp operations are separate security domains. Public users may only access explicitly public spaces. The business campus, operations center, developer workspaces, finances, customer information, source code, infrastructure controls, and owner quarters require server-side authentication and authorization.

A room being visually hidden is not security. Every world transition and API request must enforce permissions server-side.

## 6. In-world development studio

The VR application should include a spatial development center where the owner can observe Jarvis working and, when desired, intervene.

Jarvis must be able to:
- Open projects and inspect source/assets through authorized repository tools.
- Build a scene/game in a sandbox.
- Show live previews and test instances.
- Run automated checks and performance profiling.
- Compare versions and restore prior builds.
- Promote a tested build to the live environment under deployment policy.

The user should not have to type commands or edit code to keep routine work moving.

## 7. Performance and quality gates

Do not call the environment production-ready until tested on the actual target headset.

Acceptance gates:
- Runs as an installed native application; no browser required.
- OpenXR headset pose and controller tracking work.
- Stable locomotion, interaction, audio, and scene transitions.
- World Control API can create/update/remove test entities and save/reload scene state.
- Jarvis can make a reversible scene change, inspect the result, and roll it back.
- Public account cannot access private business worlds or APIs.
- Runtime remains within target headset frame-time, memory, thermal, and storage budgets.
- Offline/error states are understandable and do not corrupt saved worlds.
- App updates are signed and recoverable through an authorized installation/update route.

## 8. Honest deployment status

Current status: architecture requirement documented only. This commit does not create a native headset application, connect Jarvis to a live world, or install software on the headset. The previous browser/WebXR prototypes are prototypes and must not be described as satisfying this native-app requirement.

Next engineering sequence:
1. Inspect the existing VR prototype repositories and assets; preserve useful work.
2. Run a Godot/OpenXR compatibility spike for the exact target headset.
3. Create a native application skeleton and scene-loading pipeline.
4. Implement the authenticated World Control API and audit trail.
5. Connect Jarvis through typed world operations.
6. Build the hub, private operations campus, and separate world scenes.
7. Add sandboxed in-world development and automated playtesting.
8. Test on the physical headset and publish evidence for every acceptance gate.
