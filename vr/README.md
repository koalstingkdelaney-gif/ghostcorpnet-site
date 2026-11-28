# GhostCorp VR workspace

The existing website's immersive experience lives at /vr/ and is designed for the Meta Quest 3 Browser as a WebXR site.

## What works in the website code

- A large 3D GhostCorp headquarters scene with department portals and a neural-network visualization.
- Immersive WebXR entry with controller rays, smooth left-stick movement, right-stick snap turns and desktop fallback.
- Direct controller-trigger navigation: point at a department portal and press Trigger; point at the floor and press Trigger to teleport.
- An in-world operations console with launchers for local AI chat, the owner Action Center, developer workbench, local project board, GitHub and the public website.
- A local-first project board for tasks, status, priority, and export/import backup.
- A separate WebGPU local chat page using a small quantized model, loaded only after the owner presses Initialize.

## Use on Quest 3

1. Open https://ghostcorpnet.com/vr/ in Meta Quest Browser.
2. Wait for the 3D world to report ready.
3. Press ENTER QUEST VR.
4. Point either controller at the floating operations console and press Trigger to launch a tool.
5. Point at a department portal and press Trigger to move there. Point at the floor and press Trigger to teleport.
6. Use the left thumbstick to move and the right thumbstick for snap turns.

## Important limits

- The VR page is a browser-based WebXR workspace, not a native Quest APK.
- The frontend has no live private backend connection until the FastAPI service is deployed with durable storage and the domain routes /auth/* and /api/* to it.
- Agent presence and private business data are never fabricated. The page reports backend unavailability rather than claiming simulated agents are live.
- The Action Center will remain unavailable for private operations until that server-side deployment and owner OAuth configuration are complete.
- The local Project Board stores data in this browser's local storage only. Export a backup to move it to another device.
- Local AI chat uses the device's WebGPU runtime. Actual model compatibility, memory and thermal performance must still be verified on the headset.
- The developer workbench saves a local draft; publishing production code still requires authenticated GitHub access.
- No paid services, paid API fallback, or automatic billing are enabled by this frontend.