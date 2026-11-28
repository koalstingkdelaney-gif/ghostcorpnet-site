# GhostCorp VR: update and install workflow

## Existing foundation

The existing Quest experience is `vr/index.html` in this repository. Keep extending it; do not replace it with a separate prototype. It is currently a browser-based Three.js/WebXR experience for Meta Quest Browser, not a native Android APK.

## Website-to-headset update loop

1. Open the existing website and enter the VR headquarters.
2. Open **DEV WORKBENCH** and choose **OPEN GITHUB EDITOR**. This opens the exact `vr/index.html` file in GitHub's browser editor.
3. Sign in to the existing GitHub account if prompted, edit the file, review the diff, and commit the change to the existing repository.
4. The existing GitHub Pages workflow deploys the website from the repository. A new service-worker version activates after deployment and updates cached VR pages on the next visit/reload.
5. Open `https://ghostcorpnet.com/vr/` in Meta Quest Browser. Enter Quest VR.

The workbench's local Save Draft and Preview controls remain local-only. They do not publish code. Publishing uses GitHub's authenticated editor so no GitHub token is placed in headset JavaScript.

## Installable web app

The VR route now includes a web app manifest and service worker. A compatible browser may offer installation. The install control uses the browser's native install prompt if available; otherwise it explains the supported fallback.

Meta documents two distribution paths:
- Hosted WebXR: open the HTTPS URL directly in Meta Quest Browser.
- Quest PWA package: create a Meta Quest Bubblewrap Android project from the hosted manifest, then sign and test the package.

A signed native-style PWA package requires a Meta Horizon developer app setup, package identifier, signing key, Digital Asset Links, and developer-mode sideload or store distribution. These cannot be silently generated or installed onto a headset from a website. Do not claim native APK installation until the package is built, signed, and tested on the target headset.

## Offline behavior and limitations

The service worker precaches the local VR pages and icon and caches same-origin static resources and the Three.js CDN module after first successful fetch. It never caches `/api/*` or `/auth/*` responses. This supports offline shell access after a successful online visit; live private operations, remote model downloads, and network-backed services still require connectivity.

## Deployment verification

A Git commit is not proof of deployment. Confirm the Pages workflow succeeded, open the deployed manifest and service worker over HTTPS, then test the updated experience on the actual Quest headset. Confirm WebXR entry, controller inputs, comfort, rendering performance, service-worker update, and offline shell behavior.
