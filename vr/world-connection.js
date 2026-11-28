// GhostCorp Quest world bridge.
// The browser talks only to a same-origin authenticated gateway. Never place
// GHOSTCORP_API_TOKEN in this file or in any browser/Quest bundle.
const statusNode = document.getElementById("agentStatus");
const CACHE_KEY = "ghostcorp.world.snapshot.v1";
const POLL_MS = 5000;
let cursor = 0;
let stopped = false;
let timer = null;

function label(text) {
  if (statusNode) statusNode.textContent = text;
}
function safeSnapshot(snapshot) {
  if (!snapshot || !Array.isArray(snapshot.entities)) throw new Error("Invalid world snapshot");
  return snapshot;
}
async function request(path) {
  const response = await fetch(path, {
    credentials: "same-origin",
    cache: "no-store",
    headers: { "Accept": "application/json" }
  });
  if (response.status === 401 || response.status === 403) throw new Error("OWNER_SESSION_REQUIRED");
  if (!response.ok) throw new Error("GATEWAY_" + response.status);
  const type = response.headers.get("content-type") || "";
  if (!type.includes("application/json")) throw new Error("GATEWAY_NOT_JSON");
  return response.json();
}
function showCached() {
  try {
    const cached = JSON.parse(localStorage.getItem(CACHE_KEY) || "null");
    if (cached) {
      label("OFFLINE · CACHED WORLD R" + (cached.max_revision || 0));
      return true;
    }
  } catch (_) {}
  label("WORLD OFFLINE · WAITING FOR SECURE BACKEND");
  return false;
}
async function syncOnce() {
  const session = await request("/api/vr/session");
  if (!session || session.authenticated !== true) throw new Error("OWNER_SESSION_REQUIRED");

  const snapshot = safeSnapshot(await request("/api/vr/world/snapshot"));
  const maxRevision = snapshot.entities.reduce((n, entity) =>
    Math.max(n, Number(entity.revision) || 0), 0);
  localStorage.setItem(CACHE_KEY, JSON.stringify({
    saved_at: Date.now(), max_revision: maxRevision, snapshot
  }));
  if (Number.isInteger(snapshot.event_cursor)) cursor = Math.max(cursor, snapshot.event_cursor);
  label("WORLD CONNECTED · " + snapshot.entities.length + " ENTITIES · R" + maxRevision);

  // Event polling is additive: snapshot remains the recovery source of truth.
  const events = await request("/api/vr/events?after=" + encodeURIComponent(cursor));
  if (Array.isArray(events.items)) {
    for (const event of events.items) {
      if (Number.isInteger(event.seq)) cursor = Math.max(cursor, event.seq);
      window.dispatchEvent(new CustomEvent("ghostcorp:world-event", { detail: event }));
    }
  }
}
async function tick() {
  if (stopped) return;
  try {
    await syncOnce();
  } catch (error) {
    if (String(error.message).includes("OWNER_SESSION_REQUIRED")) {
      label("OWNER SIGN-IN REQUIRED · WORLD DATA LOCKED");
    } else {
      showCached();
    }
  } finally {
    if (!stopped) timer = setTimeout(tick, POLL_MS);
  }
}
window.addEventListener("online", () => {
  if (timer) clearTimeout(timer);
  tick();
});
window.addEventListener("pagehide", () => {
  stopped = true;
  if (timer) clearTimeout(timer);
});
tick();
