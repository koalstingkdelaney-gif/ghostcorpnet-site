/**
 * poll.js — polling, ordering, dedup for the ghostcorpnet encrypted chat (ecc-1).
 *
 * Worker C9. Implements FILE-MAP §3 (store / manifest) + D11 (polling) and
 * UI-SPEC §6 (polling / refresh behaviour and ordering), as overridden by
 * the FILE-MAP where the two conflict (see "Conflicts honoured" below).
 *
 * What this module does:
 *   - Polls chat/manifest.json every 5 s while the page is visible
 *     (P4 fast-reads patch, STATE-OF-THE-ART-BAR pillar 2; supersedes
 *     FILE-MAP D11's 15 s — see "Conflicts honoured" below).
 *   - Backs off 5 s -> 15 s -> 30 s -> 60 s (capped) on consecutive failures.
 *   - Reads the store FRESH, bypassing the GitHub Pages inline log
 *     (which refreshes only on the ~2-3 min publish cycle): the GitHub
 *     Contents API first when the owner's PAT is present (fresh,
 *     authoritative, immediate after any write lands in the repo),
 *     falling back to raw.githubusercontent.com with a cache-buster
 *     query (?t=<epoch>) when no PAT is present, and finally re-reading
 *     the inline <script id="chat-log"> snapshot already in the page
 *     (first paint needs no fetch; the inline log is the initial
 *     snapshot, and a re-read can only ever re-surface what the page
 *     was published with — it is a stale-snapshot fallback, never a
 *     live source). Read order: API -> raw+cache-buster -> inline.
 *   - Uses the relay-sequence cursor: only fetches messages with
 *     seq greater than the last seen seq.
 *   - Dedups by msg_id (same ID twice = ignored; same ID with different
 *     bytes = replay suspect, never delivered).
 *   - Orders by relay seq (never by sender clock) and delivers verified
 *     messages to the thread view in seq order.
 *   - Fetches each new message file (chat/messages/<msg_id>.json) and hands
 *     the envelope to the verification path (app/js/envelope.js + crypto
 *     modules) BEFORE it reaches the thread view.
 *   - On reconnect after a gap, re-fetches the manifest and fills missing
 *     seqs (every entry with seq > last seen seq is fetched, in seq order).
 *
 * What this module NEVER does:
 *   - It never renders anything. It has no DOM rendering at all; the only
 *     way a message reaches the thread view is the caller's `onVerified`
 *     callback, which this module invokes only after verification passes.
 *   - It never delivers, logs, or stores plaintext. It logs only routing
 *     metadata (msg_id, seq, sender) — never envelope crypto fields.
 *   - It never invents a verification verdict. If no verifier is available
 *     (no `verifyEnvelope` option and no envelope.js loaded), new messages
 *     are held unverified and NOT delivered, and the status
 *     `verifier-missing` is reported via `onStatus`.
 *
 * Transport (FILE-MAP D1/D2, wins over UI-SPEC §8 op 1 and RELAY-SPEC §4.3):
 * the store is static files in the public site repo, published through
 * site-sync. There is no `GET /messages?since=` endpoint. Polling reads
 * `chat/manifest.json` and each message `chat/messages/<msg_id>.json`
 * (the `url` field of a manifest entry, resolved under the repo's
 * `chat/` dir) — but NOT through GitHub Pages: live reads go to the
 * GitHub Contents API when the owner's PAT is present, else to
 * raw.githubusercontent.com with a cache-buster (P4; see
 * `fetchStoreText`). The Pages URLs (`manifestUrl` / `messageUrlFor`)
 * are kept only as the legacy path, used when the caller passes
 * `useTieredReads: false`. The PAT is never held in this file's source:
 * it comes from the caller's `getToken` option, or — when that is
 * absent — from the same IndexedDB record pat.js (C13) stores it in
 * (`ghostcorp-chat-pat` / `secrets` / `github-pat`); the token is sent
 * ONLY to https://api.github.com as an `Authorization: Bearer` header,
 * is never logged, and is dropped from memory on a 401. pat.js exposes
 * no token getter by design, so the IndexedDB read is the only way to
 * honour the API-first read order without an app.js change.
 *
 * Envelope shape (FILE-MAP §3 / D5, wins over RELAY-SPEC §2):
 * `ecc-1`, AES-256-CBC + HMAC-SHA-256 (`A256CBC-HS256`), integer `iat`/`exp`,
 * `wrapped_keys` as an array of {"recipient","wk"}, `sig` as one base64url
 * string. This module treats the envelope as opaque: it does not parse
 * crypto fields itself, it only checks the routing shape (v, msg_id, seq)
 * needed to fetch/order/dedup, and passes the whole envelope object to
 * the verifier. `seq` is relay-assigned and is never part of the signed
 * bytes (FILE-MAP §3).
 *
 * Expiry: this module does NOT pre-filter by `exp`. An expired entry is
 * still fetched and handed to the verifier, whose step-2 expiry check
 * (FILE-MAP §3, verification order) rejects it; the rejection is reported
 * via `onProblem` and nothing is delivered. (That also preserves the
 * UI-SPEC Expired badge path: the verifier, not the poller, decides.)
 * A 404/410 on a message file means expired/purged (tombstone): the seq
 * is marked skipped so the cursor can advance, and no retry is made.
 *
 * Conflicts honoured (FILE-MAP wins; see report for the full list):
 *   - P4 (STATE-OF-THE-ART-BAR pillar 2, owner order 2026-11-16):
 *     poll interval 5 s while visible, NOT FILE-MAP D11's 15 s. The bar
 *     is the newer owner order and the task brief orders 5 s, so 5 s is
 *     implemented here; D11's 15 s is flagged as superseded in the P4
 *     report. Backoff stays 5 s -> 60 s (D11's range, UI-SPEC §6's
 *     5/15/30/60 steps), unchanged.
 *   - P4 fresh reads: FILE-MAP D4 says the app JS "also fetches
 *     manifest.json + messages/*.json for live polling" without naming
 *     the host. The bar names it: Contents API when a PAT is present,
 *     raw.githubusercontent.com with a cache-buster when not. The
 *     GitHub Pages host is deliberately NOT a live-read tier (it lags
 *     the publish cycle ~2-3 min); it survives only as the legacy path
 *     behind `useTieredReads: false` and as the inline-log seed.
 *   - UI-SPEC §6 / RELAY-SPEC §4.3 `GET /messages?since=<seq>` does not
 *     exist on the static store; polling fetches manifest.json instead.
 *   - UI-SPEC §6 backoff is written as 5 s, then 15 s, 30 s, 60 s cap;
 *     FILE-MAP D11 says 5 s -> 60 s. The sequence 5/15/30/60 satisfies
 *     both, so it is used here.
 *   - RELAY-SPEC envelope fields (`v: 1`, AES-256-GCM `cipher`, `part`/
 *     `parts`, `created_at`/`expires_at` strings, `wrapped_keys` object,
 *     `sig` object) are superseded by FILE-MAP D5 (`ecc-1`); this module
 *     never assumes them.
 *   - RELAY-SPEC §3.3 says gaps in seq are expected (expired messages);
 *     a gap therefore never stalls the cursor — only a transient fetch
 *     failure for a listed entry does.
 *
 * Usage (app.js / view-thread.js, workers C3/C6 — not this file):
 *
 *   var poller = GhostChatPoll.createPoller({
 *     manifestUrl: 'chat/manifest.json',          // or 'manifest.json' when served from /chat/
 *     verifyEnvelope: GhostChatEnvelope.verifyAndDecrypt, // (envelope, ctx) -> Promise<{ok, ...}>
 *     onVerified: function (envelope, result, seq) { renderMessage(result); },
 *     onProblem: function (problem) { ... }, // {msg_id, seq, reason, detail} — no plaintext
 *     onStatus: function (state) { ... } // banner / diagnostics
 *   });
 *   poller.start();
 *   // ... later: poller.stop(); poller.destroy();
 *
 * If `verifyEnvelope` is omitted, the poller looks for
 * `window.GhostChatEnvelope.verifyAndDecrypt` (A4 envelope.js, loaded as
 * a classic script before poll.js). No dynamic import is attempted: the
 * FILE-MAP D18 CSP has no 'unsafe-eval', so an eval-based import would
 * be blocked.
 * A verifier must resolve to an object with boolean `ok`. `ok: true`
 * means the envelope passed the FULL FILE-MAP §3 verification order
 * (shape, expiry, pinned sender, replay-ledger, signature, unwrap,
 * HMAC, decrypt) and the result may carry the plaintext for the caller
 * to render. `ok: false` means reject: the poller reports it via
 * `onProblem` and never calls `onVerified`. A verifier that throws is
 * treated as `ok: false` with reason `verifier-error`.
 *
 * No external dependencies. No keys, no plaintext, no secrets in this
 * file. $0 spend. Runs in a browser; also loads under Node >= 18
 * (CommonJS) for tests, with `fetch`/`document` injected via options.
 */

'use strict';

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    // Node / CommonJS (used by test harnesses; the page loads this as a
    // plain <script> and gets window.GhostChatPoll).
    module.exports = factory();
  } else {
    root.GhostChatPoll = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {

  // ---------------------------------------------------------------------------
  // Constants — P4 fast reads (STATE-OF-THE-ART-BAR pillar 2) + FILE-MAP D11
  // ---------------------------------------------------------------------------

  /** Poll interval while visible and healthy (ms). P4: 5 s (was 15 s). */
  var POLL_INTERVAL_MS = 5000;

  /**
   * Backoff delays on consecutive failures (ms). First failure 5 s, then
   * 15 s, 30 s, 60 s cap — UI-SPEC §6 sequence, inside FILE-MAP D11's
   * "5 s -> 60 s" range. Stays at 60 s until a success resets it.
   */
  var BACKOFF_MS = [5000, 15000, 30000, 60000];

  /** Per-fetch timeout (ms). UI-SPEC §5: first fetch resolves or fails ~10 s. */
  var FETCH_TIMEOUT_MS = 10000;

  /**
   * Fresh-read endpoints (P4). Store layout per FILE-MAP D2 / §3, verified
   * against site/publish.sh + relay/manifest.py: repo
   * koalstingkdelaney-gif/ghostcorpnet-site, branch main, store dir chat/,
   * manifest chat/manifest.json, messages chat/messages/<msg_id>.json.
   * The Contents API path shape was confirmed live 2026-11-16 with an
   * unauthenticated probe (404 JSON from the API for the not-yet-published
   * chat/manifest.json — the repo exists, the path shape is right).
   */
  var GITHUB_API_BASE = 'https://api.github.com';
  var GITHUB_OWNER = 'koalstingkdelaney-gif';
  var GITHUB_REPO = 'ghostcorpnet-site';
  var GITHUB_BRANCH = 'main';
  var GITHUB_CHAT_DIR = 'chat';
  var RAW_BASE_URL = 'https://raw.githubusercontent.com';

  /** IndexedDB record pat.js (C13) stores the owner's PAT in. */
  var PAT_DB_NAME = 'ghostcorp-chat-pat';
  var PAT_STORE_NAME = 'secrets';
  var PAT_RECORD_KEY = 'github-pat';
  /** Re-check IndexedDB for a newly saved PAT at most this often (ms). */
  var TOKEN_RECHECK_MS = 60000;
  /** Give up an IndexedDB open after this long (ms) — never stall a poll. */
  var TOKEN_IDB_TIMEOUT_MS = 1500;

  /** Store cap (RELAY-SPEC §3.3 / FILE-MAP §3): bound the dedup tables. */
  var MAX_SEEN_IDS = 10000;

  /** Envelope version (FILE-MAP §3). Unknown `v` is never fetched further. */
  var ENVELOPE_VERSION = 'ecc-1';

  /** Lowercase UUIDv4 (FILE-MAP §3: msg_id is a UUIDv4, lowercase). */
  var MSG_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

  // ---------------------------------------------------------------------------
  // Small helpers (no crypto, no network)
  // ---------------------------------------------------------------------------

  function isPlainObject(v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
  }

  function isNonNegativeInt(v) {
    return typeof v === 'number' && Number.isFinite(v) &&
      Math.floor(v) === v && v >= 0;
  }

  function isPositiveInt(v) {
    return isNonNegativeInt(v) && v > 0;
  }

  /** Resolve a manifest entry's `url` (e.g. "messages/<id>.json") against the manifest URL. */
  function resolveUrl(manifestUrl, entryUrl) {
    if (typeof entryUrl !== 'string' || entryUrl.length === 0) return null;
    // Absolute URL or absolute path: use as-is.
    if (/^(https?:)?\/\//i.test(entryUrl) || entryUrl.charAt(0) === '/') return entryUrl;
    var base = String(manifestUrl || '');
    var slash = base.lastIndexOf('/');
    var dir = slash >= 0 ? base.slice(0, slash + 1) : '';
    return dir + entryUrl;
  }

  function defaultMessageUrl(manifestUrl, msgId) {
    var base = String(manifestUrl || '');
    var slash = base.lastIndexOf('/');
    var dir = slash >= 0 ? base.slice(0, slash + 1) : '';
    return dir + 'messages/' + msgId + '.json';
  }

  /**
   * Derive the manifest's repo path (e.g. 'chat/manifest.json') from the
   * manifest URL the caller passes (usually the Pages URL,
   * https://ghostcorpnet.com/chat/manifest.json). Only the URL's path is
   * used; the host is discarded — the tiered reader fetches from the
   * Contents API / raw.githubusercontent.com, never from Pages. Returns
   * `<chatDir>/manifest.json` when the URL cannot be parsed or does not
   * end in manifest.json.
   */
  function deriveManifestRepoPath(manifestUrl, chatDir) {
    var fallback = String(chatDir || 'chat').replace(/^\/|\/$/g, '') + '/manifest.json';
    try {
      var path = String(manifestUrl || '');
      // Absolute URL: take the pathname. Relative URL: use as-is.
      if (/^https?:\/\//i.test(path)) {
        var u = new URL(path);
        path = u.pathname || '';
      }
      path = path.replace(/^\/+/, '');
      if (/manifest\.json$/.test(path) && path.indexOf('..') === -1) return path;
    } catch (e) { /* fall through to the canonical path */ }
    return fallback;
  }

  /**
   * Decode a base64 string (whitespace tolerated — the Contents API wraps
   * content at 60 columns) to a UTF-8 string. Node path via Buffer,
   * browser path via atob + TextDecoder. Throws on malformed input.
   */
  function base64ToUtf8(b64) {
    var clean = String(b64 || '').replace(/\s/g, '');
    if (typeof Buffer !== 'undefined' && Buffer.from) {
      return Buffer.from(clean, 'base64').toString('utf-8');
    }
    var bin = atob(clean);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  }

  /**
   * Cheap fingerprint of fetched envelope bytes, used ONLY to notice that
   * a re-delivered msg_id now carries different bytes (replay suspect).
   * SHA-256 via WebCrypto when available would be ideal, but this check
   * must stay synchronous and dependency-free; the authoritative replay
   * protection is the verifier's signature + seen-ledger check
   * (FILE-MAP §3, verification order steps 4-5 — a forged second copy
   * cannot carry a valid signature over the new bytes). FNV-1a is a
   * tripwire here, not a security boundary.
   */
  function fingerprintText(text) {
    var h1 = 0x811c9dc5;
    for (var i = 0; i < text.length; i++) {
      h1 ^= text.charCodeAt(i);
      h1 = Math.imul(h1, 0x01000193) >>> 0;
    }
    return 'fnv1a:' + text.length + ':' + h1.toString(16);
  }

  // ---------------------------------------------------------------------------
  // Poller
  // ---------------------------------------------------------------------------

  /**
   * Create a poller.
   *
   * options:
   *   manifestUrl   string, default 'chat/manifest.json'. P4: the tiered
   *                 reader derives the repo path from this URL (its path,
   *                 e.g. /chat/manifest.json -> chat/manifest.json); the
   *                 Pages host itself is never fetched in tiered mode.
   *   messageUrlFor function(msgId, entry) -> string; default derived from
   *                 the manifest entry's `url`, else chat/messages/<id>.json.
   *                 Used ONLY when `useTieredReads` is false (legacy Pages
   *                 path). In tiered mode the message repo path comes from
   *                 the entry's `url` under the manifest's repo dir.
   *   useTieredReads boolean, default true. false = legacy behaviour:
   *                 fetch manifestUrl / messageUrlFor directly (GitHub
   *                 Pages). true = P4 fresh reads: Contents API (PAT) ->
   *                 raw.githubusercontent.com + cache-buster -> inline log.
   *   getToken      function() -> string | null | Promise<string | null>;
   *                 returns the owner's GitHub PAT for Contents-API reads.
   *                 If omitted, the poller reads the PAT from the same
   *                 IndexedDB record pat.js (C13) stores it in. May return
   *                 null (no PAT -> raw tier). The token is never logged.
   *   githubApiBase string, default 'https://api.github.com'
   *   githubOwner   string, default 'koalstingkdelaney-gif'
   *   githubRepo    string, default 'ghostcorpnet-site'
   *   githubBranch  string, default 'main'
   *   githubChatDir string, default 'chat' (store dir inside the repo)
   *   rawBaseUrl    string, default 'https://raw.githubusercontent.com'
   *   inlineLogElementId string, default 'chat-log' (the <script
   *                 type="application/json" id="chat-log"> snapshot)
   *   verifyEnvelope async function(envelope, ctx) -> {ok: boolean, ...}
   *                 ctx is {msg_id, seq, sender, manifestEntry}. If omitted,
   *                 the poller looks for window.GhostChatEnvelope (A4) and
   *                 then tries a dynamic import of './js/envelope.js'.
   *   onVerified    function(envelope, verifiedResult, seq) — ONLY delivery
   *                 channel to the thread view; called only for ok === true.
   *   onProblem     function({msg_id, seq, reason, detail}) — rejected /
   *                 skipped / replay-suspect envelopes. Never carries
   *                 plaintext or envelope crypto fields.
   *   onStatus      function(state) — state snapshots on every transition.
   *   pollIntervalMs number, default 5000 (P4 fast reads; was 15000)
   *   backoffMs     array, default BACKOFF_MS
   *   fetchTimeoutMs number, default 10000
   *   fetchFn       function(url, init) -> Promise<Response>; default fetch
   *   doc           document-like object; default global document (if any)
   *   nowFn         function() -> ms epoch; default Date.now
   *   initialLastSeq number, default 0 — relay seq already seen/rendered
   *                 (e.g. from the inline <script id="chat-log"> log, C15)
   *   initialSeen   array of {msg_id, seq} already rendered — marked seen
   *                 so they are never re-fetched or re-delivered.
   *   envelopeModuleUrl string, reserved for a future module build;
   *                 NOT used in the classic-script build (no dynamic
   *                 import under the D18 CSP — see resolveVerifier).
   */
  function createPoller(options) {
    options = options || {};

    var manifestUrl = options.manifestUrl || 'chat/manifest.json';
    var messageUrlFor = typeof options.messageUrlFor === 'function'
      ? options.messageUrlFor
      : function (msgId, entry) {
          if (entry && typeof entry.url === 'string' && entry.url.length > 0) {
            return resolveUrl(manifestUrl, entry.url);
          }
          return defaultMessageUrl(manifestUrl, msgId);
        };
    var verifyEnvelopeOpt = typeof options.verifyEnvelope === 'function'
      ? options.verifyEnvelope : null;
    var onVerified = typeof options.onVerified === 'function' ? options.onVerified : null;
    var onProblem = typeof options.onProblem === 'function' ? options.onProblem : null;
    var onStatus = typeof options.onStatus === 'function' ? options.onStatus : null;
    var pollIntervalMs = isPositiveInt(options.pollIntervalMs)
      ? options.pollIntervalMs : POLL_INTERVAL_MS;
    var backoffMs = Array.isArray(options.backoffMs) && options.backoffMs.length > 0
      ? options.backoffMs : BACKOFF_MS;
    var fetchTimeoutMs = isPositiveInt(options.fetchTimeoutMs)
      ? options.fetchTimeoutMs : FETCH_TIMEOUT_MS;
    var fetchFn = typeof options.fetchFn === 'function'
      ? options.fetchFn
      : (typeof fetch === 'function' ? fetch : null);
    var doc = options.doc || (typeof document !== 'undefined' ? document : null);
    var nowFn = typeof options.nowFn === 'function' ? options.nowFn : Date.now;
    var envelopeModuleUrl = options.envelopeModuleUrl || './js/envelope.js';

    // --- P4 fresh-read options (defaults = the live store; see constants) ---
    var useTieredReads = options.useTieredReads !== false;
    var getTokenFn = typeof options.getToken === 'function' ? options.getToken : null;
    var githubApiBase = typeof options.githubApiBase === 'string' && options.githubApiBase
      ? options.githubApiBase.replace(/\/$/, '') : GITHUB_API_BASE;
    var githubOwner = typeof options.githubOwner === 'string' && options.githubOwner
      ? options.githubOwner : GITHUB_OWNER;
    var githubRepo = typeof options.githubRepo === 'string' && options.githubRepo
      ? options.githubRepo : GITHUB_REPO;
    var githubBranch = typeof options.githubBranch === 'string' && options.githubBranch
      ? options.githubBranch : GITHUB_BRANCH;
    var githubChatDir = typeof options.githubChatDir === 'string' && options.githubChatDir
      ? options.githubChatDir.replace(/^\/|\/$/g, '') : GITHUB_CHAT_DIR;
    var rawBaseUrl = typeof options.rawBaseUrl === 'string' && options.rawBaseUrl
      ? options.rawBaseUrl.replace(/\/$/, '') : RAW_BASE_URL;
    var inlineLogElementId = typeof options.inlineLogElementId === 'string' && options.inlineLogElementId
      ? options.inlineLogElementId : 'chat-log';
    // Repo path of the manifest, derived from manifestUrl when it looks
    // like the published store URL (…/chat/manifest.json), else the
    // canonical store path. The Pages host is never fetched in tiered
    // mode — only the path is reused, so a caller that passes the live
    // https://ghostcorpnet.com/chat/manifest.json gets the right repo
    // path (chat/manifest.json) with no extra configuration.
    var manifestRepoPath = deriveManifestRepoPath(manifestUrl, githubChatDir);
    var manifestRepoDir = manifestRepoPath.slice(0, manifestRepoPath.lastIndexOf('/')) || githubChatDir;

    // --- PAT cache (in-memory only; never logged, never persisted here) ---
    var cachedToken = null; // string | null; null = none found on last check
    var tokenCheckedAt = 0; // ms epoch of the last IndexedDB check (0 = never)

    // --- Cursor + dedup state (in-memory only; no plaintext is stored) ---
    // lastSeq is the highest CONTIGUOUS seq fully processed (verified or
    // definitively rejected/skipped). It only ever moves forward.
    var lastSeq = isNonNegativeInt(options.initialLastSeq) ? options.initialLastSeq : 0;
    // msg_id -> { seq, bytesFingerprint } for every envelope ever accepted
    // into processing (verified or rejected). Bounded by the store cap.
    var seen = new Map();
    // seq numbers of listed entries that are gone (404/410: expired/purged).
    // Kept so a re-fetched manifest does not re-attempt them forever.
    var skippedSeqs = new Set();
    // seq numbers currently held because an earlier seq failed transiently
    // is implicit: lastSeq simply does not advance past the failure.

    var running = false;
    var timer = null;
    var inFlight = false;
    var consecutiveFailures = 0;
    var lastPollAt = null;
    var lastSuccessAt = null;
    var lastError = null;
    // Last tier that served a successful store read (P4 diagnostics):
    // 'api' | 'raw' | 'inline' | null (nothing served yet).
    var readSource = null;
    var status = 'idle'; // idle | polling | backoff | hidden | verifier-missing | stopped
    var destroyed = false;
    var verifierMissingReported = false;
    var cachedVerifier = verifyEnvelopeOpt; // resolved verifier, once found

    if (Array.isArray(options.initialSeen)) {
      options.initialSeen.forEach(function (entry) {
        if (entry && typeof entry.msg_id === 'string' && isPositiveInt(entry.seq)) {
          markSeen(entry.msg_id, entry.seq, null);
          if (entry.seq > lastSeq) lastSeq = entry.seq;
        }
      });
    }

    // -------------------------------------------------------------------------
    // State helpers
    // -------------------------------------------------------------------------

    function markSeen(msgId, seq, bytesFingerprint) {
      if (seen.size >= MAX_SEEN_IDS) {
        // Store cap: evict the oldest entry (Map preserves insertion order).
        // The cursor (lastSeq) still protects against re-fetching old seqs;
        // eviction only weakens the same-ID-different-bytes tripwire for
        // the very oldest messages, never the delivery gate.
        var oldest = seen.keys().next();
        if (!oldest.done) seen.delete(oldest.value);
      }
      seen.set(msgId, { seq: seq, bytesFingerprint: bytesFingerprint || null });
    }

    function getState() {
      return {
        running: running,
        visible: isVisible(),
        status: status,
        lastSeq: lastSeq,
        seenCount: seen.size,
        skippedSeqCount: skippedSeqs.size,
        consecutiveFailures: consecutiveFailures,
        nextDelayMs: nextDelayMs(),
        lastPollAt: lastPollAt,
        lastSuccessAt: lastSuccessAt,
        lastError: lastError,
        manifestUrl: manifestUrl,
        // P4 fresh-read diagnostics.
        readSource: readSource,
        pollIntervalMs: pollIntervalMs,
        githubRepo: githubOwner + '/' + githubRepo,
        manifestRepoPath: manifestRepoPath
      };
    }

    function emitStatus() {
      if (onStatus) {
        try { onStatus(getState()); } catch (e) { /* status listeners must never break polling */ }
      }
    }

    function setStatus(next) {
      if (status !== next) {
        status = next;
        emitStatus();
      }
    }

    function reportProblem(msgId, seq, reason, detail) {
      if (onProblem) {
        try {
          onProblem({ msg_id: msgId || null, seq: seq || null, reason: reason, detail: detail || null });
        } catch (e) { /* problem listeners must never break polling */ }
      }
    }

    function nextDelayMs() {
      if (consecutiveFailures <= 0) return pollIntervalMs;
      var idx = Math.min(consecutiveFailures - 1, backoffMs.length - 1);
      return backoffMs[idx];
    }

    function isVisible() {
      if (!doc || typeof doc.visibilityState === 'undefined') return true;
      return doc.visibilityState === 'visible';
    }

    // -------------------------------------------------------------------------
    // Scheduling — pause while hidden, one fetch on return (UI-SPEC §6)
    // -------------------------------------------------------------------------

    function clearTimer() {
      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
      }
    }

    function schedule(delayMs) {
      clearTimer();
      if (!running || destroyed) return;
      timer = setTimeout(function () {
        timer = null;
        tick();
      }, delayMs);
    }

    function onVisibilityChange() {
      if (destroyed) return;
      if (!running) return;
      if (isVisible()) {
        // Reconnect after a gap: re-fetch the manifest now and fill any
        // missing seqs (tick() processes every entry with seq > lastSeq).
        setStatus('polling');
        tick();
      } else {
        // Hidden: stop the timer; no polling while hidden (battery/data).
        clearTimer();
        setStatus('hidden');
      }
    }

    function onOnline() {
      if (destroyed || !running) return;
      // Network returned: re-fetch immediately rather than waiting out
      // a backoff delay.
      consecutiveFailures = 0;
      tick();
    }

    function onOffline() {
      if (destroyed || !running) return;
      clearTimer();
      setStatus('backoff');
      emitStatus();
    }

    // -------------------------------------------------------------------------
    // Fetch helpers
    // -------------------------------------------------------------------------

    function fetchWithTimeout(url, extraInit) {
      if (!fetchFn) {
        return Promise.reject(new Error('no fetch available'));
      }
      var controller = null;
      var timeoutId = null;
      var signal;
      if (typeof AbortController !== 'undefined') {
        controller = new AbortController();
        signal = controller.signal;
        timeoutId = setTimeout(function () {
          try { controller.abort(); } catch (e) { /* ignore */ }
        }, fetchTimeoutMs);
      }
      var init = { cache: 'no-store' };
      if (extraInit) {
        var k;
        for (k in extraInit) {
          if (Object.prototype.hasOwnProperty.call(extraInit, k)) init[k] = extraInit[k];
        }
      }
      if (signal) init.signal = signal;
      var p;
      try {
        p = fetchFn(url, init);
      } catch (e) {
        if (timeoutId !== null) clearTimeout(timeoutId);
        return Promise.reject(e);
      }
      return Promise.resolve(p).then(function (res) {
        if (timeoutId !== null) clearTimeout(timeoutId);
        return res;
      }, function (err) {
        if (timeoutId !== null) clearTimeout(timeoutId);
        throw err;
      });
    }

    function fetchText(url, extraInit) {
      return fetchWithTimeout(url, extraInit).then(function (res) {
        if (!res) throw new Error('empty response');
        if (res.status === 404 || res.status === 410) {
          var gone = new Error('gone');
          gone.code = res.status === 410 ? 'EXPIRED' : 'NOT_FOUND';
          gone.httpStatus = res.status;
          throw gone;
        }
        if (res.status === 401) {
          var auth = new Error('unauthorized');
          auth.code = 'UNAUTHORIZED';
          auth.httpStatus = 401;
          throw auth;
        }
        if (!res.ok) {
          var httpErr = new Error('http ' + res.status);
          httpErr.code = 'HTTP_' + res.status;
          httpErr.httpStatus = res.status;
          throw httpErr;
        }
        if (typeof res.text === 'function') return res.text();
        throw new Error('unreadable response');
      });
    }

    function fetchJson(url) {
      return fetchWithTimeout(url).then(function (res) {
        if (!res) throw new Error('empty response');
        if (res.status === 404 || res.status === 410) {
          var gone = new Error('gone');
          gone.code = res.status === 410 ? 'EXPIRED' : 'NOT_FOUND';
          gone.httpStatus = res.status;
          throw gone;
        }
        if (!res.ok) {
          var httpErr = new Error('http ' + res.status);
          httpErr.code = 'HTTP_' + res.status;
          httpErr.httpStatus = res.status;
          throw httpErr;
        }
        // Response may be a real Response (has .text) or a test double.
        if (typeof res.text === 'function') return res.text();
        if (typeof res.json === 'function') return res.json().then(function (v) { return JSON.stringify(v); });
        throw new Error('unreadable response');
      }).then(function (text) {
        if (typeof text !== 'string') return text;
        try {
          return { data: JSON.parse(text), rawText: text };
        } catch (e) {
          var parseErr = new Error('invalid JSON');
          parseErr.code = 'MALFORMED_JSON';
          throw parseErr;
        }
      });
    }

    // -------------------------------------------------------------------------
    // P4 fresh reads — Contents API (PAT) -> raw + cache-buster -> inline
    // -------------------------------------------------------------------------

    /**
     * Read the owner's PAT from the IndexedDB record pat.js (C13) stores
     * it in. Same database/store/key as pat.js; read-only here, and the
     * value is never logged, never persisted anywhere else, and sent
     * only to api.github.com. Resolves null when IndexedDB is absent,
     * the record is absent, or the open times out — every one of those
     * just means "no PAT", i.e. the raw tier. Opening a missing database
     * creates an empty one (pat.js does the same on loadToken at app
     * startup); no record is ever written here.
     */
    function readTokenFromIdb() {
      return new Promise(function (resolve) {
        var done = false;
        function finish(value) {
          if (done) return;
          done = true;
          clearTimeout(timerId);
          resolve(value);
        }
        var timerId = setTimeout(function () { finish(null); }, TOKEN_IDB_TIMEOUT_MS);
        var idb = null;
        try {
          idb = (typeof indexedDB !== 'undefined') ? indexedDB : null;
        } catch (e) { idb = null; }
        if (!idb) { finish(null); return; }
        var req;
        try {
          req = idb.open(PAT_DB_NAME, 1);
        } catch (e) { finish(null); return; }
        req.onerror = function () { finish(null); };
        req.onblocked = function () { finish(null); };
        req.onsuccess = function () {
          var db = req.result;
          var tx;
          try {
            tx = db.transaction(PAT_STORE_NAME, 'readonly');
          } catch (e) {
            try { db.close(); } catch (ignored) { /* ignore */ }
            finish(null);
            return;
          }
          var getReq;
          try {
            getReq = tx.objectStore(PAT_STORE_NAME).get(PAT_RECORD_KEY);
          } catch (e) {
            try { db.close(); } catch (ignored) { /* ignore */ }
            finish(null);
            return;
          }
          getReq.onsuccess = function () {
            var record = getReq.result;
            try { db.close(); } catch (ignored) { /* ignore */ }
            if (record && typeof record.token === 'string' && record.token) {
              finish(record.token);
            } else {
              finish(null);
            }
          };
          getReq.onerror = function () {
            try { db.close(); } catch (ignored) { /* ignore */ }
            finish(null);
          };
        };
      });
    }

    /**
     * Resolve the PAT for this poll cycle. The caller's `getToken`
     * option wins when present (it is called fresh each cycle, so a
     * caller can rotate). Otherwise the cached IndexedDB result is
     * reused: a found token is kept until a 401 drops it; a miss is
     * re-checked at most once per TOKEN_RECHECK_MS so a PAT saved
     * mid-session is picked up within a minute. Never throws.
     */
    function resolveToken() {
      if (getTokenFn) {
        return Promise.resolve().then(function () {
          return getTokenFn();
        }).then(function (token) {
          return (typeof token === 'string' && token) ? token : null;
        }).catch(function () { return null; });
      }
      if (cachedToken) return Promise.resolve(cachedToken);
      var now = nowFn();
      if (tokenCheckedAt && (now - tokenCheckedAt) < TOKEN_RECHECK_MS) {
        return Promise.resolve(null);
      }
      return readTokenFromIdb().then(function (token) {
        tokenCheckedAt = nowFn();
        cachedToken = token;
        return token;
      }).catch(function () { return null; });
    }

    /** Drop the cached PAT (called on a 401 — the token is dead/revoked). */
    function invalidateToken() {
      cachedToken = null;
      tokenCheckedAt = 0;
    }

    /**
     * One Contents-API file read.
     * GET {apiBase}/repos/{owner}/{repo}/contents/{repoPath}?ref={branch}
     * with Accept + X-GitHub-Api-Version (as in pat.js) and
     * Authorization: Bearer <token>. The response body is JSON
     * {content: base64, encoding: 'base64', sha, ...}; the content is
     * decoded to the exact stored UTF-8 text. A 401 invalidates the
     * cached token (the caller falls through to the raw tier).
     */
    function fetchApiFile(repoPath, token) {
      var path = String(repoPath || '').split('/').map(encodeURIComponent).join('/');
      var url = githubApiBase + '/repos/' + encodeURIComponent(githubOwner) +
        '/' + encodeURIComponent(githubRepo) + '/contents/' + path +
        '?ref=' + encodeURIComponent(githubBranch);
      return fetchText(url, {
        headers: {
          'Accept': 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
          'Authorization': 'Bearer ' + token
        }
      }).then(function (text) {
        var body;
        try {
          body = JSON.parse(text);
        } catch (e) {
          var parseErr = new Error('invalid JSON from Contents API');
          parseErr.code = 'MALFORMED_JSON';
          throw parseErr;
        }
        if (Array.isArray(body)) {
          var dirErr = new Error('Contents API returned a directory listing');
          dirErr.code = 'UNEXPECTED_LISTING';
          throw dirErr;
        }
        if (!body || typeof body.content !== 'string') {
          var shapeErr = new Error('Contents API reply has no content field');
          shapeErr.code = 'MALFORMED_API';
          throw shapeErr;
        }
        var decoded;
        try {
          decoded = base64ToUtf8(body.content);
        } catch (e) {
          var b64Err = new Error('Contents API content is not valid base64');
          b64Err.code = 'MALFORMED_API';
          throw b64Err;
        }
        return { text: decoded, source: 'api' };
      }).catch(function (err) {
        if (err && err.code === 'UNAUTHORIZED') invalidateToken();
        throw err;
      });
    }

    /**
     * One raw.githubusercontent.com file read, with a cache-buster so a
     * CDN edge cannot serve a stale copy after a write lands in the repo:
     * GET {rawBase}/{owner}/{repo}/{branch}/{repoPath}?t=<epoch ms>.
     */
    function fetchRawFile(repoPath) {
      var path = String(repoPath || '').split('/').map(encodeURIComponent).join('/');
      var url = rawBaseUrl + '/' + encodeURIComponent(githubOwner) +
        '/' + encodeURIComponent(githubRepo) + '/' +
        encodeURIComponent(githubBranch) + '/' + path +
        '?t=' + String(nowFn());
      return fetchText(url).then(function (text) {
        return { text: text, source: 'raw' };
      });
    }

    /**
     * Fresh read of one store file, in P4 order: Contents API when a PAT
     * is present, then raw + cache-buster. Any API failure (401, 403
     * rate-limit, 404, 5xx, timeout) falls through to raw — the raw tier
     * is public and unauthenticated, so it can still serve when the API
     * is rate-limited, and a 404 on both tiers is the authoritative
     * "file is gone" answer. Resolves {text, source}; rejects only when
     * both tiers fail (the caller's inline fallback / backoff decides).
     * `readSource` records the tier that served, for getState().
     */
    function fetchStoreText(repoPath) {
      return resolveToken().then(function (token) {
        if (token) {
          return fetchApiFile(repoPath, token).catch(function () {
            return fetchRawFile(repoPath);
          });
        }
        return fetchRawFile(repoPath);
      }).then(function (result) {
        readSource = result.source;
        return result;
      });
    }

    /**
     * Fetch + parse one store file as JSON through the tiered reader.
     * Returns {data, rawText, source}. JSON-shape errors reject (a
     * malformed manifest/message is a poll failure, not an inline
     * fallback trigger — the inline log holds the same bytes).
     */
    function fetchStoreJson(repoPath) {
      return fetchStoreText(repoPath).then(function (result) {
        var parsed;
        try {
          parsed = JSON.parse(result.text);
        } catch (e) {
          var parseErr = new Error('invalid JSON');
          parseErr.code = 'MALFORMED_JSON';
          throw parseErr;
        }
        return { data: parsed, rawText: result.text, source: result.source };
      });
    }

    /**
     * Fetch + parse the manifest. Tiered mode: the Contents API / raw
     * reader over the manifest's repo path. Legacy mode: the caller's
     * manifestUrl fetched directly (GitHub Pages, pre-P4 behaviour).
     */
    function fetchManifest() {
      if (!useTieredReads) return fetchJson(manifestUrl);
      return fetchStoreJson(manifestRepoPath);
    }

    /**
     * Fetch + parse one message file. Tiered mode: the Contents API /
     * raw reader over the message's repo path (the manifest entry's
     * `url`, e.g. "messages/<id>.json", under the manifest's repo dir).
     * Legacy mode: the caller's messageUrlFor (GitHub Pages).
     * Returns {data, rawText, source}; a 404/410 rejects with code
     * NOT_FOUND/EXPIRED so the caller can mark the seq skipped.
     */
    function fetchMessageFile(msgId, entry) {
      if (!useTieredReads) return fetchJson(messageUrlFor(msgId, entry));
      var entryUrl = (entry && typeof entry.url === 'string' && entry.url.length > 0)
        ? entry.url.replace(/^\/+/, '')
        : 'messages/' + msgId + '.json';
      // Defence: an entry url must stay under the store dir (no '..').
      if (entryUrl.indexOf('..') !== -1) {
        return Promise.reject(Object.assign(new Error('entry url escapes the store dir'), { code: 'MANIFEST_INVALID' }));
      }
      return fetchStoreJson(manifestRepoDir + '/' + entryUrl);
    }

    /**
     * Read the inline <script type="application/json" id="chat-log">
     * snapshot already in the page (C15 embed; the first-paint history,
     * no fetch needed). Returns the parsed envelope array, or null when
     * the element is absent, empty, or unparseable. The snapshot is
     * static per page load — it can only re-surface what the page was
     * published with — so it is the last tier, never a live source.
     */
    function readInlineLog() {
      try {
        if (!doc || typeof doc.getElementById !== 'function') return null;
        var el = doc.getElementById(inlineLogElementId);
        if (!el) return null;
        var text = el.textContent || el.innerText || '';
        if (!text || !text.trim()) return null;
        var parsed = JSON.parse(text);
        if (!Array.isArray(parsed)) return null;
        return parsed;
      } catch (e) {
        return null;
      }
    }

    // -------------------------------------------------------------------------
    // Verifier resolution
    // -------------------------------------------------------------------------

    function resolveVerifier() {
      if (cachedVerifier) return Promise.resolve(cachedVerifier);
      // A4 envelope.js, if loaded as a plain script, exposes a global.
      var g = (typeof root !== 'undefined' ? root : null) ||
        (typeof globalThis !== 'undefined' ? globalThis : null);
      var mod = g && (g.GhostChatEnvelope || g.GhostCorpEnvelope);
      if (mod) {
        var fn = mod.verifyAndDecrypt || mod.verifyEnvelope || mod.verify;
        if (typeof fn === 'function') {
          cachedVerifier = fn.bind(mod);
          return Promise.resolve(cachedVerifier);
        }
      }
      // Dynamic import is deliberately NOT attempted here: poll.js loads
      // as a classic script under the FILE-MAP D18 CSP (script-src 'self',
      // no 'unsafe-eval'), so `new Function('return import(...)')` would
      // be blocked. The supported paths are: pass `verifyEnvelope`
      // explicitly, or load app/js/envelope.js as a classic script before
      // poll.js so window.GhostChatEnvelope exists (see header).
      return Promise.resolve(null);
    }

    // -------------------------------------------------------------------------
    // Manifest validation (FILE-MAP §3 store / manifest)
    // -------------------------------------------------------------------------

    function validateManifest(data) {
      if (!isPlainObject(data)) return 'manifest is not an object';
      if (data.v !== ENVELOPE_VERSION) return 'manifest v is not ecc-1';
      if (!isNonNegativeInt(data.seq)) return 'manifest seq is not an integer';
      if (!Array.isArray(data.messages)) return 'manifest messages is not an array';
      return null;
    }

    function validateManifestEntry(entry) {
      if (!isPlainObject(entry)) return 'entry is not an object';
      if (typeof entry.msg_id !== 'string' || !MSG_ID_RE.test(entry.msg_id)) {
        return 'entry msg_id is not a lowercase UUIDv4';
      }
      if (!isPositiveInt(entry.seq)) return 'entry seq is not a positive integer';
      if (entry.sender !== undefined && typeof entry.sender !== 'string') {
        return 'entry sender is not a string';
      }
      if (entry.url !== undefined && typeof entry.url !== 'string') {
        return 'entry url is not a string';
      }
      return null;
    }

    // -------------------------------------------------------------------------
    // One poll cycle
    // -------------------------------------------------------------------------

    function tick() {
      if (!running || destroyed || inFlight) return;
      if (!isVisible()) {
        // Hidden mid-schedule: do not poll; a single fetch fires on return.
        setStatus('hidden');
        return;
      }
      if (!fetchFn) {
        lastError = 'no fetch available';
        consecutiveFailures += 1;
        setStatus('backoff');
        schedule(nextDelayMs());
        return;
      }
      inFlight = true;
      lastPollAt = nowFn();
      setStatus('polling');
      fetchManifest().then(function (result) {
        var manifestError = validateManifest(result.data);
        if (manifestError) {
          throw Object.assign(new Error(manifestError), { code: 'MANIFEST_INVALID' });
        }
        return processManifest(result.data);
      }).catch(function (err) {
        // The manifest fetch failed on every network tier (or the
        // manifest is invalid): last resort is the inline snapshot
        // already in the page (P4 read order, third tier). It can only
        // re-surface publish-time messages, but delivering one the
        // poller has not seen yet is still progress — the cycle then
        // counts as a success. When the snapshot holds nothing new,
        // the original error stands and the cycle backs off.
        if (!useTieredReads) throw err;
        return processInlineLog().then(function (delivered) {
          if (delivered > 0) return { inlineRecovered: true, transientFailure: null };
          throw err;
        });
      }).then(function (outcome) {
        inFlight = false;
        // Success = the manifest was fetched and parsed. A cycle in which
        // individual messages were rejected by the verifier still counts
        // as a successful poll (the rejection is per-message, reported via
        // onProblem; it must not trigger backoff or stall later seqs).
        // A transient message-fetch failure, by contrast, leaves
        // outcome.transientFailure set and is treated as a poll failure.
        if (outcome && outcome.transientFailure) {
          throw outcome.transientFailure;
        }
        consecutiveFailures = 0;
        lastSuccessAt = nowFn();
        lastError = null;
        verifierMissingReported = false;
        setStatus('polling');
        schedule(pollIntervalMs);
      }).catch(function (err) {
        inFlight = false;
        consecutiveFailures += 1;
        lastError = (err && err.message) || 'poll failed';
        setStatus('backoff');
        emitStatus();
        schedule(nextDelayMs());
      });
    }

    /**
     * Process one manifest: fetch + verify + deliver every listed entry
     * with seq > lastSeq, in seq order. Returns {transientFailure} — null
     * on a clean cycle, or the Error that aborted the cycle on a transient
     * message-fetch failure (cursor is left at the failed seq so the next
     * poll retries it and fills the gap).
     */
    function processManifest(manifest) {
      // Stale manifest (relay seq went backwards, e.g. a republished old
      // copy): never rewind the cursor — dedup by msg_id would protect
      // delivery, but rewinding would re-fetch everything.
      if (manifest.seq < lastSeq) {
        return Promise.resolve({ transientFailure: null });
      }

      // Candidate entries: seq > lastSeq, not already skipped as gone,
      // valid shape, deduped by msg_id within this manifest.
      var candidates = [];
      var seenInManifest = new Set();
      var entries = manifest.messages.slice().sort(function (a, b) {
        var sa = isPositiveInt(a && a.seq) ? a.seq : 0;
        var sb = isPositiveInt(b && b.seq) ? b.seq : 0;
        return sa - sb;
      });
      entries.forEach(function (entry) {
        var shapeError = validateManifestEntry(entry);
        if (shapeError) {
          reportProblem(entry && entry.msg_id, entry && entry.seq, 'manifest-entry-invalid', shapeError);
          return;
        }
        if (entry.seq <= lastSeq) return; // already processed
        if (skippedSeqs.has(entry.seq)) return; // gone (404/410) before
        if (seenInManifest.has(entry.msg_id)) return; // dup row in manifest
        seenInManifest.add(entry.msg_id);
        // Already-seen msg_id at a NEW seq: same ID, new seq. That is a
        // relay-side anomaly; the dedup rule still applies — never
        // re-deliver. Fetch it only to compare bytes (replay check below).
        candidates.push(entry);
      });

      if (candidates.length === 0) {
        // No new entries. Advance the contiguous cursor over seqs that
        // the manifest no longer lists (expired/purged gaps, RELAY-SPEC
        // §3.3): if the manifest's top seq is ahead and every seq up to
        // it is either listed or absent, the cursor may jump to the
        // manifest seq — the absent seqs are gaps, not missing messages.
        // Only jump when there is nothing left to fetch; a transient
        // failure below leaves lastSeq untouched instead.
        if (manifest.seq > lastSeq) lastSeq = manifest.seq;
        return Promise.resolve({ transientFailure: null });
      }

      // Sequential processing in seq order: fetch -> replay-tripwire ->
      // verify -> deliver. Sequential (not parallel) so delivery order is
      // exactly relay-seq order even though verification is async.
      var chain = Promise.resolve({ transientFailure: null, heldSeq: null });
      candidates.forEach(function (entry) {
        chain = chain.then(function (outcome) {
          if (outcome && outcome.transientFailure) return outcome; // abort rest
          return processEntry(entry).then(function (entryOutcome) {
            if (entryOutcome && entryOutcome.transientFailure) {
              return { transientFailure: entryOutcome.transientFailure, heldSeq: outcome.heldSeq || null };
            }
            if (entryOutcome && entryOutcome.held) {
              // Verifier missing: message held unverified, never delivered.
              // Keep the earliest held seq so the cursor below does not
              // advance past it — a later poll retries it once the
              // verifier is installed (setVerifier + pollNow).
              var held = outcome.heldSeq === null ? entryOutcome.heldSeq : Math.min(outcome.heldSeq, entryOutcome.heldSeq);
              return { transientFailure: null, heldSeq: held };
            }
            return { transientFailure: null, heldSeq: outcome.heldSeq || null };
          });
        });
      });
      return chain.then(function (outcome) {
        if (outcome && outcome.transientFailure) return outcome;
        if (outcome && outcome.heldSeq !== null && outcome.heldSeq !== undefined) {
          // Advance only up to (not past) the earliest held message.
          var heldFloor = outcome.heldSeq - 1;
          if (heldFloor > lastSeq) lastSeq = heldFloor;
          return { transientFailure: null };
        }
        // All candidates processed: advance the cursor to the manifest's
        // top seq, jumping over expired/purged gaps (see above).
        if (manifest.seq > lastSeq) lastSeq = manifest.seq;
        return { transientFailure: null };
      });
    }

    /**
     * Fetch + verify + (maybe) deliver one manifest entry.
     * Returns {transientFailure} — set only when the message file could
     * not be fetched for a transient reason (network / 5xx / timeout),
     * in which case the cursor is NOT advanced past this seq.
     * The fetch is tiered (P4): Contents API -> raw + cache-buster
     * (fetchMessageFile); the legacy Pages fetch applies only when
     * `useTieredReads` is false.
     */
    function processEntry(entry) {
      var msgId = entry.msg_id;
      var seq = entry.seq;

      return fetchMessageFile(msgId, entry).then(function (result) {
        return processFetchedEnvelope(entry, result.data, result.rawText);
      }).catch(function (err) {
        // 404/410 = expired/purged (tombstone): mark the seq skipped so
        // the cursor can advance past the gap; never retry, never deliver.
        if (err && (err.code === 'EXPIRED' || err.code === 'NOT_FOUND')) {
          skippedSeqs.add(seq);
          markSeen(msgId, seq, null);
          reportProblem(msgId, seq, err.code === 'EXPIRED' ? 'expired' : 'gone', 'message file ' + err.httpStatus + ' (expired/purged)');
          return { transientFailure: null };
        }
        // Anything else (network, 5xx, timeout, malformed JSON) is
        // transient: do NOT mark seen, do NOT advance the cursor, abort
        // the rest of this cycle so order is preserved, retry next poll
        // (with backoff) — the gap is filled then.
        return { transientFailure: err };
      });
    }

    /**
     * Routing checks + dedup + verify + deliver for one already-fetched
     * envelope. Shared by the manifest path (processEntry) and the
     * inline-log fallback (processInlineLog): the same gate decides in
     * both cases, so an inline envelope is never delivered unverified.
     * Returns {transientFailure, held, heldSeq, delivered} — delivered
     * is true only when the verifier passed and onVerified was invoked.
     */
    function processFetchedEnvelope(entry, envelope, rawText) {
      var msgId = entry.msg_id;
      var seq = entry.seq;
      var envelopeObj = envelope;
      var raw = rawText;

        // Routing-shape check before verification: the verifier owns the
        // full FILE-MAP §3 shape check, but a manifest/envelope mismatch
        // (wrong msg_id, wrong version) is a routing defect, not a
        // signature matter — report and skip without delivering.
        if (!isPlainObject(envelopeObj)) {
          markSeen(msgId, seq, fingerprintText(raw || ''));
          reportProblem(msgId, seq, 'envelope-invalid', 'message file is not a JSON object');
          return Promise.resolve({ transientFailure: null, delivered: false });
        }
        if (envelopeObj.v !== ENVELOPE_VERSION) {
          markSeen(msgId, seq, fingerprintText(raw || ''));
          reportProblem(msgId, seq, 'envelope-invalid', 'envelope v is not ecc-1');
          return Promise.resolve({ transientFailure: null, delivered: false });
        }
        if (envelopeObj.msg_id !== msgId) {
          markSeen(msgId, seq, fingerprintText(raw || ''));
          reportProblem(msgId, seq, 'envelope-invalid', 'envelope msg_id does not match manifest');
          return Promise.resolve({ transientFailure: null, delivered: false });
        }

        // Dedup by msg_id (RELAY-SPEC §3.2 / UI-SPEC §6): already seen.
        var prior = seen.get(msgId);
        var fp = fingerprintText(raw || '');
        if (prior) {
          // Same ID + same bytes = duplicate delivery; ignore silently.
          // Same ID + different bytes = replay suspect: never deliver,
          // never overwrite the first copy; report for the audit view.
          if (prior.bytesFingerprint && prior.bytesFingerprint !== fp) {
            reportProblem(msgId, seq, 'replay-suspect', 'same msg_id with different bytes');
          }
          return Promise.resolve({ transientFailure: null, delivered: false });
        }
        markSeen(msgId, seq, fp);

        // Hand the envelope to the verification path. NOTHING is
        // delivered before this resolves with ok === true.
        return resolveVerifier().then(function (verifier) {
          if (!verifier) {
            if (!verifierMissingReported) {
              verifierMissingReported = true;
              setStatus('verifier-missing');
            }
            reportProblem(msgId, seq, 'verifier-missing', 'envelope.js verification path is not loaded; message held unverified');
            // Held, not lost: it stays unmarked (seen.delete above) and
            // the cursor does not advance past it (processManifest holds
            // at heldSeq - 1), so a later poll re-processes it once the
            // verifier is installed via setVerifier() + pollNow().
            seen.delete(msgId);
            return { transientFailure: null, held: true, heldSeq: seq, delivered: false };
          }
          var ctx = { msg_id: msgId, seq: seq, sender: entry.sender || envelopeObj.sender || null, manifestEntry: entry };
          var verified;
          try {
            verified = verifier(envelopeObj, ctx);
          } catch (e) {
            verified = Promise.resolve({ ok: false, reason: 'verifier-error', detail: (e && e.message) || 'verifier threw' });
          }
          return Promise.resolve(verified).then(function (result) {
            if (result && result.ok === true) {
              if (onVerified) {
                try { onVerified(envelopeObj, result, seq); } catch (e) { /* delivery listeners must never break polling */ }
              }
              return { transientFailure: null, delivered: true };
            } else {
              var reason = (result && (result.reason || result.error)) || 'verification-failed';
              var detail = (result && (result.detail || result.message)) || null;
              reportProblem(msgId, seq, reason, detail);
              // Verification failure is per-message, not a poll failure:
              // the cursor advances past it (in processManifest) and
              // later seqs are still processed this cycle.
            }
            return { transientFailure: null, delivered: false };
          }, function (err) {
            reportProblem(msgId, seq, 'verifier-error', (err && err.message) || 'verifier rejected');
            return { transientFailure: null, delivered: false };
          });
        });
    }

    /**
     * Third read tier (P4): re-read the inline <script id="chat-log">
     * snapshot and deliver any envelope in it the poller has not seen
     * yet, in seq order, through the same verify gate as live reads.
     * The snapshot is static per page load, so in the normal case (the
     * app seeded the poller from it at bootstrap) this delivers nothing
     * and returns 0 — it only helps when the page was published with
     * messages the poller never seeded. Returns a Promise of the number
     * of newly delivered messages. Envelopes without a usable relay seq
     * are skipped (the cursor cannot order them); a held message (no
     * verifier yet) stops the scan so order is preserved.
     */
    function processInlineLog() {
      var log = readInlineLog();
      if (!log || log.length === 0) return Promise.resolve(0);
      var candidates = [];
      var seenInLog = new Set();
      log.forEach(function (envelope) {
        if (!isPlainObject(envelope)) return;
        if (typeof envelope.msg_id !== 'string' || !MSG_ID_RE.test(envelope.msg_id)) return;
        if (!isPositiveInt(envelope.seq)) return; // no relay seq: cannot order
        if (envelope.seq <= lastSeq) return; // already processed
        if (skippedSeqs.has(envelope.seq)) return;
        if (seenInLog.has(envelope.msg_id)) return;
        seenInLog.add(envelope.msg_id);
        candidates.push(envelope);
      });
      candidates.sort(function (a, b) { return a.seq - b.seq; });
      if (candidates.length === 0) return Promise.resolve(0);
      var delivered = 0;
      var chain = Promise.resolve(null);
      candidates.forEach(function (envelope) {
        chain = chain.then(function (stop) {
          if (stop) return stop;
          var entry = { msg_id: envelope.msg_id, seq: envelope.seq, sender: envelope.sender || null };
          return processFetchedEnvelope(entry, envelope, JSON.stringify(envelope)).then(function (outcome) {
            if (outcome && outcome.delivered) {
              delivered += 1;
              if (envelope.seq > lastSeq) lastSeq = envelope.seq;
            }
            if (outcome && outcome.held) return true; // stop: order preserved
            return false;
          });
        });
      });
      return chain.then(function () {
        if (delivered > 0) readSource = 'inline';
        return delivered;
      });
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    function start() {
      if (destroyed || running) return getState();
      running = true;
      consecutiveFailures = 0;
      if (doc && typeof doc.addEventListener === 'function') {
        doc.addEventListener('visibilitychange', onVisibilityChange);
      }
      if (typeof root !== 'undefined' && root.addEventListener) {
        try { root.addEventListener('online', onOnline); } catch (e) { /* ignore */ }
        try { root.addEventListener('offline', onOffline); } catch (e) { /* ignore */ }
      } else if (typeof globalThis !== 'undefined' && globalThis.addEventListener) {
        try { globalThis.addEventListener('online', onOnline); } catch (e) { /* ignore */ }
        try { globalThis.addEventListener('offline', onOffline); } catch (e) { /* ignore */ }
      }
      if (!isVisible()) {
        setStatus('hidden');
      } else {
        tick();
      }
      return getState();
    }

    function stop() {
      running = false;
      clearTimer();
      setStatus('stopped');
      return getState();
    }

    function destroy() {
      stop();
      destroyed = true;
      if (doc && typeof doc.removeEventListener === 'function') {
        doc.removeEventListener('visibilitychange', onVisibilityChange);
      }
      if (typeof root !== 'undefined' && root.removeEventListener) {
        try { root.removeEventListener('online', onOnline); } catch (e) { /* ignore */ }
        try { root.removeEventListener('offline', onOffline); } catch (e) { /* ignore */ }
      }
      return getState();
    }

    /** Force one poll cycle now (visibility return, after-send refresh, retry button). */
    function pollNow() {
      if (!running || destroyed) return Promise.resolve(getState());
      clearTimer();
      tick();
      return Promise.resolve(getState());
    }

    /**
     * Seed entries already rendered (e.g. from the inline chat-log, C15)
     * so they are never re-fetched or re-delivered. Does not verify them:
     * the caller is responsible for having verified seeded entries.
     */
    function seedSeen(entries) {
      if (!Array.isArray(entries)) return getState();
      entries.forEach(function (entry) {
        if (entry && typeof entry.msg_id === 'string' && isPositiveInt(entry.seq)) {
          markSeen(entry.msg_id, entry.seq, null);
          if (entry.seq > lastSeq) lastSeq = entry.seq;
        }
      });
      return getState();
    }

    /** Replace / install the verifier at runtime (e.g. after envelope.js loads). */
    function setVerifier(fn) {
      if (typeof fn === 'function') {
        cachedVerifier = fn;
        verifierMissingReported = false;
      }
      return getState();
    }

    return {
      start: start,
      stop: stop,
      destroy: destroy,
      pollNow: pollNow,
      seedSeen: seedSeen,
      setVerifier: setVerifier,
      getState: getState,
      // Constants, for the caller/tests (C20 config may re-export them).
      POLL_INTERVAL_MS: POLL_INTERVAL_MS,
      BACKOFF_MS: BACKOFF_MS.slice(),
      FETCH_TIMEOUT_MS: FETCH_TIMEOUT_MS,
      ENVELOPE_VERSION: ENVELOPE_VERSION,
      // P4 fresh-read endpoints, for the caller/tests.
      GITHUB_API_BASE: GITHUB_API_BASE,
      GITHUB_OWNER: GITHUB_OWNER,
      GITHUB_REPO: GITHUB_REPO,
      GITHUB_BRANCH: GITHUB_BRANCH,
      GITHUB_CHAT_DIR: GITHUB_CHAT_DIR,
      RAW_BASE_URL: RAW_BASE_URL
    };
  }

  return {
    createPoller: createPoller,
    POLL_INTERVAL_MS: POLL_INTERVAL_MS,
    BACKOFF_MS: BACKOFF_MS.slice(),
    FETCH_TIMEOUT_MS: FETCH_TIMEOUT_MS,
    ENVELOPE_VERSION: ENVELOPE_VERSION,
    GITHUB_API_BASE: GITHUB_API_BASE,
    GITHUB_OWNER: GITHUB_OWNER,
    GITHUB_REPO: GITHUB_REPO,
    GITHUB_BRANCH: GITHUB_BRANCH,
    GITHUB_CHAT_DIR: GITHUB_CHAT_DIR,
    RAW_BASE_URL: RAW_BASE_URL
  };
});
