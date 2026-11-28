# GhostCorp Shared Backend and Persistent World Core

This service is the first executable shared foundation for the existing GhostCorp website and VR client. It lives in the existing site repository; it is not a separate product.

## Run locally

From the repository root:

    python -m venv .venv
    . .venv/bin/activate
    pip install -r backend/requirements.txt
    export GHOSTCORP_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
    export GHOSTCORP_DB_PATH="./data/ghostcorp.db"
    cd backend
    uvicorn app.main:app --host 127.0.0.1 --port 8000

Health check: GET /health
OpenAPI docs: /api/docs

## Authentication

All /api/v1 routes require Authorization: Bearer <GHOSTCORP_API_TOKEN>. The token must be configured in the hosting platform's secret manager. If it is missing, API routes return 503 rather than silently running unprotected. Never put the token in website JavaScript, the VR bundle, Git, or chat. Use a server-side authenticated proxy/session for browser and Quest clients; do not expose the service token to clients.

## API v1

- GET /api/v1/status — task counts, agent count, world revision and last event.
- POST /api/v1/tasks — create a durable queued task.
- GET /api/v1/tasks — list tasks; optional status and limit.
- PUT /api/v1/tasks/{id}/checkpoint — persist checkpoint and task status.
- GET /api/v1/world/entities/{entity_id} — retrieve a generic world entity.
- PUT /api/v1/world/entities/{entity_id} — upsert a generic entity and increment revision.
- PUT /api/v1/agents/{agent_id} — persist agent status and metadata.
- GET /api/v1/events?after=<sequence> — read append-only event history.

The SQLite database uses WAL mode and stores tasks, world entities, agent state, and events. Mount a persistent volume at the configured database path in production. SQLite is a practical single-instance starting point; migrate to managed PostgreSQL before horizontal scaling or high write concurrency.

## Deployment and current limits

Dockerfile is included. Build/test runs on GitHub Actions; GitHub Actions is CI, not an always-on application host. To make the API continuously available, deploy the container to an authorized persistent host, configure GHOSTCORP_API_TOKEN, and attach durable storage. This repository change does not create a hosting account, provision a host, or claim the service is live.

The first world core stores versioned JSON entities and event records. It does not yet run physics, render scenes, simulate NPCs, execute Jarvis agents, or connect the Quest client. Those are subsequent integrations against this stable API contract.

## World engine scene APIs

All routes below require the same bearer token:

- GET /api/v1/world/snapshot — consistent point-in-time list of persisted world entities and revisions.
- GET /api/v1/world/scenes — list scene records.
- POST /api/v1/world/scenes — create a scene with name, description, metadata, and an empty object collection.
- GET /api/v1/world/scenes/{scene_id} — retrieve a scene and its object transforms.
- PUT /api/v1/world/scenes/{scene_id} — update scene metadata with an expected_revision.
- PUT /api/v1/world/scenes/{scene_id}/objects/{object_id} — create or update an object with asset reference, position, rotation, scale, properties, and expected_revision.
- DELETE /api/v1/world/scenes/{scene_id}/objects/{object_id}?expected_revision=N — remove an object with revision protection.

Every successful scene/object mutation increments the scene revision and emits an event. Stale writes return HTTP 409 so a reconnecting Quest client cannot silently overwrite newer changes. The server stores scene/object metadata and asset references; actual 3D asset files, rendering, collision/physics simulation, and live Quest synchronization still need their own client/runtime integration.


## Owner-authenticated Quest gateway

The backend includes a same-origin GitHub OAuth owner-session gateway for the Quest browser. It never returns the backend bearer token to browser JavaScript. Configure these values in the backend host's secret/environment settings:

- `GITHUB_OAUTH_CLIENT_ID`: OAuth App client ID.
- `GITHUB_OAUTH_CLIENT_SECRET`: OAuth App client secret; secret only.
- `GHOSTCORP_OWNER_GITHUB_LOGIN`: exact GitHub login allowed to administer this GhostCorp instance.
- `GHOSTCORP_SESSION_SECRET`: long random secret used to sign owner sessions.
- `GHOSTCORP_PUBLIC_ORIGIN`: exact HTTPS origin, e.g. `https://ghostcorpnet.com`.
- `GHOSTCORP_API_TOKEN`: separate backend service bearer token.
- `GHOSTCORP_DB_PATH`: path on a persistent disk/volume.

Set the GitHub OAuth App callback URL to `https://YOUR-ORIGIN/auth/github/callback`. Use the actual production origin; do not use a wildcard. The OAuth app must request only `read:user`. The server verifies the returned GitHub login against `GHOSTCORP_OWNER_GITHUB_LOGIN`, uses a signed, HttpOnly, Secure, SameSite=Lax session cookie, and exposes the private Quest snapshot/events only to that owner session.

Browser/Quest routes:
- `GET /auth/status`
- `GET /auth/github/start`
- `GET /auth/github/callback`
- `GET /auth/me`
- `POST /auth/logout`
- `GET /api/vr/session`
- `GET /api/vr/world/snapshot`
- `GET /api/vr/events?after=<sequence>`

The VR snapshot intentionally returns only world and scene entities; it does not expose task payloads, agent metadata, finance records, or customer records. Never enable permissive CORS or put the bearer token in the Quest bundle.

**Deployment prerequisite:** The static website must route these same-origin paths to the FastAPI backend (or an equivalent trusted gateway) over HTTPS. The OAuth secrets and persistent database volume must be configured in the hosting provider. The repository changes alone do not create that routing, configure OAuth credentials, provision persistent storage, or deploy the backend.
