# THE LAST SURVIVORS — Release Readiness

## Current build
- Build: 0.4.0 (development)
- Runtime: browser-based Babylon.js 3D prototype
- Target: desktop browsers and Xbox browser/controller testing
- Entry point: `index.html`

## Playable mission loop
1. Start a new district run or continue a locally saved run.
2. Search all five marked supply caches.
3. Defeat the five infected in the district.
4. Reach the extraction beacon at the far end of the district and interact to complete the mission.

## Implemented systems
- Xbox gamepad movement, camera look, sprint, aim, fire, melee, interaction, crafting, construction, pause and menu navigation.
- First- and third-person camera modes and adjustable look sensitivity.
- Loot caches, timber salvage, ammunition, scrap, medkits, crafting and buildable structures.
- Local save data for player resources/position, searched caches, salvaged timber, defeated infected and constructed structures.
- Background release manifest checks with a player-controlled apply/defer prompt.

## Known limitations — not a commercial release yet
- The district still uses primitive/procedural placeholder geometry and simple character shapes.
- Animations, sound design, enemy variety, advanced pathfinding, mission narrative, accessibility, localization and content volume are incomplete.
- Browser/Xbox compatibility, performance, controller edge cases, save recovery and security need a real device test matrix.
- Babylon.js currently loads from a public CDN; offline operation and dependency pinning are not complete.
- This is not an Xbox Store package and has not passed Xbox certification or platform review.
- No price, sales, revenue, or commercial-readiness claim is justified yet.

## Release gates
- Test on the actual target Xbox browser at normal play resolution for a full mission.
- Verify every controller action, camera mode, reload, healing, crafting, building, pause/resume, save/continue and mission completion.
- Test refresh/reopen recovery and corrupted/old save handling.
- Profile frame rate and memory through a full session.
- Replace placeholder art/audio with original or properly licensed assets; document all third-party dependencies and licenses.
- Add privacy/terms/support information and a clear distribution route before taking payment.
- Fix all blocker and high-severity defects before labeling a build release-ready.

## Save model
Progress is stored in browser localStorage on the device/browser profile. It is not cloud-synced and may be lost if browser data is cleared. The update prompt is optional; major code changes still require a reload when the player chooses to apply them.
