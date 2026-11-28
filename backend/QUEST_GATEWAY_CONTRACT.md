# Quest world connection gateway contract

The Quest browser must never receive the backend bearer token. The static Pages site
cannot securely proxy private API requests by itself. Deploy an authenticated
same-origin gateway at the GhostCorp website origin (or configure the VR client
with a trusted same-origin gateway origin) before enabling live private sync.

## Required browser-facing routes

All routes require an owner-authenticated, secure, same-site session cookie.
They must enforce owner authorization on the server for every request.

- GET /api/vr/session
  - Returns { "authenticated": true } only for an authorized owner session.
- GET /api/vr/world/snapshot
  - Proxies the backend GET /api/v1/world/snapshot using a server-side bearer token.
  - Returns { "entities": [...], "event_cursor": 0 }.
- GET /api/vr/events?after=<sequence>
  - Proxies backend GET /api/v1/events?after=<sequence>.
  - Returns { "items": [...] }.

Reject unauthenticated requests with 401/403. Do not enable permissive CORS,
public read access to private world state, token forwarding, or client-supplied
authorization headers. Set HttpOnly, Secure, SameSite cookies; add CSRF protection
to any future mutation route. Keep private business and agent data out of the
offline browser cache; the current Quest bridge caches only the world snapshot
returned after owner authentication.

## Client behavior

`vr/world-connection.js` polls the snapshot and event cursor every five seconds,
retries after reconnect, and displays cached/offline status if the gateway is
unavailable. It dispatches `ghostcorp:world-event` browser events for later
scene-renderer integration. The current 3D scene is not yet hydrated from these
records, and no live gateway is deployed by this repository commit.

## Acceptance tests before calling Quest connected

1. Anonymous requests receive 401/403 and reveal no world data.
2. Owner session receives a snapshot and incremental events.
3. The Quest client reconnects after Wi-Fi loss and resumes from its event cursor.
4. A newer server revision wins; stale writes are rejected with 409.
5. No backend token appears in HTML, JavaScript, source maps, or network responses.
6. Restart the backend and prove world state survives using persistent storage.
