# GhostCorp VR prototype

Open the live preview at `https://ghostcorpnet.com/vr/` after the GitHub Pages deployment finishes.

## What this prototype does
- Renders a navigable 3D GhostCorp hub in a browser.
- Offers immersive WebXR entry when the browser and headset support it.
- Supports desktop pointer navigation and headset controller-ray selection.
- Includes three demo zones: Command Deck, Frontier Lab, and Creator District.
- Includes a local scene editor that can add labeled hologram nodes and save them in this browser's local storage.

## Important boundaries
- This is a browser-based prototype, not a signed native Quest APK.
- The scene editor saves only to the current browser/device. It does not publish, sync, or alter the production world.
- It has no Jarvis credentials, private API, payment access, or server-side persistence.
- A native Android/OpenXR build, authenticated owner builder, durable world service, release signing, and device relay are separate work items.
- The Three.js modules load from jsDelivr, so first launch requires network access.

## Run
Open `/vr/` on desktop to inspect the 3D scene. On a compatible headset browser, use the immersive button to enter WebXR. For native sideloading, follow the official Meta developer-mode and USB-debugging flow; never expose ADB to the public internet.
