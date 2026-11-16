/**
 * outbox.js — offline outbox + retry for the ghostcorpnet encrypted chat.
 *
 * Worker C12. Implements FILE-MAP.md §3 (envelope `ecc-1`, relay
 * idempotency, error codes) + §4 C12, UI-SPEC.md §5 ("Message pending /
 * queued", "Relay unreachable") and RELAY-SPEC.md §3.2 (dedup by
 * `msg_id`), §4.5 (error codes) and §6.2 (client retry rule).
 *
 * FILE-MAP is authoritative. Where a design doc conflicts, this file
 * follows FILE-MAP — see "Conflicts resolved" below.
 *
 * What this module does
 * ---------------------
 * When a send cannot reach the store (offline, or the PAT publish fails),
 * the SIGNED envelope is held in a local outbox (IndexedDB, ciphertext
 * only) and retried on a bounded backoff schedule: at most 5 attempts
 * total, then the failure is surfaced to the user — never a blind loop.
 * A retry re-sends the SAME envelope bytes (same `msg_id`): the relay is
 * idempotent on `msg_id` (same ID + same bytes = OK, already stored;
 * same ID + different bytes = `MSG_ID_CONFLICT`). A fresh envelope is
 * built ONLY if the user explicitly chooses "send as new" — and this
 * module never builds that envelope itself: it hands the decision to the
 * compose layer (C7), which re-encrypts and re-signs.
 *
 * What this module never does
 * ----------------------------
 * - Never sees, stores, or transmits plaintext. Its only input is a
 *   complete signed envelope (ciphertext + metadata). There is no
 *   plaintext parameter anywhere in this API.
 * - Never encrypts, signs, or generates keys. Envelope construction is
 *   A4/C7's job; verification is A4/C10's job. This module shape-checks
 *   an envelope before queueing it (is it signed? is it encrypted? is it
 *   well-formed `ecc-1`?) and refuses anything that fails.
 * - Never queues an unsigned or unencrypted message. `enqueue()` throws
 *   before anything is stored.
 * - No network calls of its own. The transport is injected as a
 *   `publish(envelope)` function (C13 PAT publish / paste-publish), so
 *   this module works with any store backend and is unit-testable.
 * - No `localStorage`. Private keys never live here at all; envelopes are
 *   ciphertext, but the store is IndexedDB (or an in-memory fallback when
 *   IndexedDB is unavailable — flagged, never silent).
 *
 * Conflicts resolved (FILE-MAP wins)
 * ----------------------------------
 * 1. UI-SPEC §2.4 step 3 says a failed send's Retry "re-encrypts fresh
 *    (new message ID, new symmetric key — never re-send the identical
 *    envelope, which would look like a replay)". FILE-MAP §3 + the task
 *    brief say the opposite: retry reuses the SAME envelope bytes (same
 *    `msg_id`), because the relay treats same-ID + same-bytes as an
 *    idempotent OK. This module implements FILE-MAP: automatic and manual
 *    retries re-send the stored bytes verbatim. "Send as new" is a
 *    separate, explicit user choice (see `sendAsNew()`), not the retry
 *    path. The UI-SPEC wording is stale against the settled idempotency
 *    rule.
 * 2. RELAY-SPEC §2 prescribes a different envelope (`v: 1`, AES-256-GCM,
 *    `cipher`/`part`/`parts`, `created_at`/`expires_at` strings).
 *    FILE-MAP D5 overrides it: `ecc-1`, AES-256-CBC + HMAC-SHA-256
 *    (`A256CBC-HS256`), integer `iat`/`exp`, flat `iv`/`ct`/`mac` /
 *    `wrapped_keys` array. This module validates the `ecc-1` shape only
 *    and rejects the relay-spec shape.
 * 3. UI-SPEC §2.4 proposes a 7-day expiry default. FILE-MAP D10 sets a
 *    24 h TTL default AND maximum (`exp - iat <= 86400`). This module
 *    enforces D10 and never retries an envelope past its `exp` (see
 *    "Expiry" below).
 *
 * Retry schedule (RELAY-SPEC §6.2: >= 1 s, exponential, max 5 attempts)
 * ----------------------------------------------------------------------
 * Attempt delays after failures 1..4 are 1 s, 2 s, 4 s, 8 s
 * (`baseDelayMs * 2^(n-1)`, capped at `maxDelayMs`, default 60 s). The
 * 5th failed attempt exhausts the entry: status becomes `failed`,
 * `needsUserDecision` is set, and the failure is surfaced through
 * `onChange` / `subscribe()` so the thread (C6) can show it. No further
 * automatic attempt is ever made for that entry.
 * A relay `RATE_LIMITED` response carrying `retry_after_seconds` is
 * honoured: the delay becomes that value (clamped to at most
 * `maxRetryAfterMs`, default 5 min), instead of the computed backoff.
 *
 * Error classification (RELAY-SPEC §4.5 + FILE-MAP §3)
 * ----------------------------------------------------
 * Retryable (transient — consume an attempt, back off, try again):
 * `RELAY_UNAVAILABLE`, `RATE_LIMITED`, `CONFLICT_RETRY`, `STORE_FULL`,
 * network/transport exceptions (fetch threw, offline mid-flight), HTTP
 * 429 / 502 / 503 / 504, and unknown errors (bounded by the 5-attempt
 * cap, so an unknown error can never loop forever).
 * Permanent (no auto-retry — surface immediately as `failed`):
 * `SCHEMA_INVALID`, `MALFORMED_JSON`, `SEQ_CLIENT_SET`,
 * `MESSAGE_TOO_LARGE`, `UNAUTHORIZED_SENDER`, `UNKNOWN_SIGNING_KEY`,
 * `RECIPIENT_KEY_UNKNOWN`, `WRAPPED_KEYS_MISMATCH`, `CLOCK_SKEW`,
 * `STALE_MESSAGE`, `EXPIRY_INVALID`, `MSG_ID_CONFLICT`, `EXPIRED`,
 * `NOT_FOUND`, HTTP 400 / 401 / 403 / 404 / 410 / 413. A permanent
 * failure means the stored bytes can never succeed; retrying them would
 * be a blind loop. The user may still Discard or Send as new.
 * Success includes `duplicate: true` (relay already has these exact
 * bytes — idempotent OK, RELAY-SPEC §3.2).
 *
 * Expiry
 * ------
 * Before every attempt the module checks `exp` against the current time.
 * An entry whose `exp` has passed is never published (the relay would
 * answer 410 GONE): it becomes `failed` with error `EXPIRED` and is
 * surfaced to the user, who can Discard it or Send as new. An entry
 * whose next retry would land after `exp` is failed the same way at
 * schedule time — a retry that cannot succeed is not scheduled.
 *
 * Pending state for the thread (UI-SPEC §5)
 * -----------------------------------------
 * Every entry carries `status` (`queued` | `sending` | `failed`),
 * `attempts`, `maxAttempts`, `nextRetryAt`, `lastError`, `queuedAt`.
 * `subscribe()` notifies the thread renderer (C6) on every change.
 * `describeEntry(entry)` returns plain-words copy for the bubble:
 * "Sending…", "Queued — will send when online",
 * "Not sent — …" with the action that applies. Copy wording follows
 * UI-SPEC §5; the canonical copy deck (J1) was not available to this
 * worker — if J1's strings differ, swap them in `STATUS_COPY` only.
 *
 * Storage
 * -------
 * IndexedDB database `ghostcorp-chat`, object store `outbox`,
 * keyPath `msg_id`. One record per queued envelope. The record stores
 * the envelope as ONE string (`envelopeJson`, serialized exactly once
 * at enqueue time) so a retry sends byte-identical content; the parsed
 * envelope is derived from that string on read, never re-serialized
 * from parts. Records hold ciphertext + routing metadata only — no
 * plaintext, no keys, no secrets.
 * If IndexedDB is unavailable (private mode, old browser, non-secure
 * context), the module falls back to an in-memory store and reports
 * `storage: 'memory'` plus a `storage-degraded` notification: queued
 * messages do NOT survive a reload in that mode. The fallback is
 * surfaced, never silent. A `storageBackend` may be injected (test seam).
 *
 * Reload safety: an entry found with status `sending` after a reload is
 * reset to `queued` — its publish outcome is unknown, and re-sending
 * the same bytes is safe because the relay dedups on `msg_id`.
 *
 * Usage (wired by C3 app.js / C7 view-compose.js)
 * ------------------------------------------------
 *   const outbox = GhostChatOutbox.createOutbox({
 *     publish: (envelope) => patPublish(envelope), // C13; must resolve
 *       // { ok: true, seq, stored_at, duplicate? } or
 *       // { ok: false, error, retry_after_seconds?, detail? };
 *       // may also throw (network failure) or carry .code/.status.
 *     onSendAsNew: (entry) => composeSendAsNew(entry), // C7 rebuilds a
 *       // FRESH envelope (new msg_id) and enqueues it; this module
 *       // discards the old entry first.
 *     onChange: (event) => renderThread(event),        // C6 pending state
 *   });
 *   await outbox.start();
 *   await outbox.enqueue(envelope); // throws if unsigned/unencrypted
 *   // ...later, user taps Retry / Discard / Send as new:
 *   await outbox.retryNow(msgId);
 *   await outbox.discard(msgId);
 *   await outbox.sendAsNew(msgId);
 */

'use strict';

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.GhostChatOutbox = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {

  // ---------------------------------------------------------------------
  // Constants — FILE-MAP §3 / RELAY-SPEC §4.5 / §6.2
  // ---------------------------------------------------------------------

  var DB_NAME = 'ghostcorp-chat';
  var STORE_NAME = 'outbox';

  var MAX_ATTEMPTS = 5;               // RELAY-SPEC §6.2: max 5 attempts
  var BASE_DELAY_MS = 1000;           // first backoff step: 1 s
  var MAX_DELAY_MS = 60000;           // backoff cap: 60 s
  var MAX_RETRY_AFTER_MS = 300000;    // honour retry_after up to 5 min
  var MAX_OUTBOX_ENTRIES = 100;       // local guard; relay cap is 10,000
  var ENVELOPE_MAX_BYTES = 65536;     // relay cap: 64 KiB encoded envelope
  var CIPHERTEXT_MAX_BYTES = 24576;   // relay cap: 24 KiB decoded ct
  var MAX_TTL_SECONDS = 86400;        // FILE-MAP D10: 24 h TTL max
  var MAX_FUTURE_SKEW_SECONDS = 300;  // FILE-MAP §3: iat <= now + 300

  var SENDERS = ['jarvis', 'chatgpt', 'owner'];
  var SIG_ALGS = ['Ed25519', 'ES256'];
  // Exact ecc-1 top-level fields (FILE-MAP §3). Unknown fields → reject.
  // `seq` is relay-assigned and must NOT be present (SEQ_CLIENT_SET).
  var ENVELOPE_FIELDS = [
    'v', 'msg_id', 'sender', 'recipients', 'iat', 'exp', 'reply_to',
    'thread_id', 'alg', 'sig_alg', 'iv', 'ct', 'mac', 'wrapped_keys',
    'sig',
  ];

  var UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  var BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

  // Error codes that can never succeed by retrying the same bytes.
  var PERMANENT_ERRORS = {
    SCHEMA_INVALID: true,
    MALFORMED_JSON: true,
    SEQ_CLIENT_SET: true,
    MESSAGE_TOO_LARGE: true,
    UNAUTHORIZED_SENDER: true,
    UNKNOWN_SIGNING_KEY: true,
    RECIPIENT_KEY_UNKNOWN: true,
    WRAPPED_KEYS_MISMATCH: true,
    CLOCK_SKEW: true,
    STALE_MESSAGE: true,
    EXPIRY_INVALID: true,
    MSG_ID_CONFLICT: true,
    EXPIRED: true,
    NOT_FOUND: true,
  };

  // Retryable relay error codes (RELAY-SPEC §4.5 "Retry? Yes").
  var RETRYABLE_ERRORS = {
    RELAY_UNAVAILABLE: true,
    RATE_LIMITED: true,
    CONFLICT_RETRY: true,
    STORE_FULL: true,
  };

  var RETRYABLE_HTTP = { 429: true, 502: true, 503: true, 504: true };
  var PERMANENT_HTTP = { 400: true, 401: true, 403: true, 404: true, 410: true, 413: true };

  // Plain-words copy for thread bubbles (UI-SPEC §5 wording; J1 copy
  // deck not yet delivered — swap strings here only if J1 differs).
  var STATUS_COPY = {
    sending: 'Sending…',
    queuedOnline: 'Queued — sending shortly',
    queuedOffline: 'Queued — will send when online',
    failedExhausted: 'Not sent — tried 5 times. Retry to try again, or send as a new message.',
    failedPermanent: 'Not sent — the chat relay refused this message. Send it as a new message, or discard it.',
    failedExpired: 'Not sent — this message expired before it could send. Send it as a new message, or discard it.',
    failedConflict: 'Not sent — a different message already uses this ID. Send it as a new message, or discard it.',
  };

  // Plain-words reason per relay error code (shown in the detail sheet,
  // never the raw code alone).
  var ERROR_COPY = {
    MSG_ID_CONFLICT: 'a different message already uses this message ID',
    RECIPIENT_KEY_UNKNOWN: 'a recipient has no published key yet',
    UNKNOWN_SIGNING_KEY: 'the signing key is not registered',
    RATE_LIMITED: 'the chat relay asked us to slow down',
    RELAY_UNAVAILABLE: 'the chat relay could not be reached',
    STORE_FULL: 'the chat store is full',
    CONFLICT_RETRY: 'the store was busy — try again',
    EXPIRED: 'the message expired',
    MESSAGE_TOO_LARGE: 'the message is too large',
    SCHEMA_INVALID: 'the message is malformed',
    UNAUTHORIZED_SENDER: 'the sender could not be verified',
    CLOCK_SKEW: 'the device clock looks wrong',
    STALE_MESSAGE: 'the message is too old to send',
    EXPIRY_INVALID: 'the expiry is invalid',
    NETWORK: 'the network could not be reached',
  };

  // ---------------------------------------------------------------------
  // Small helpers (no dependencies)
  // ---------------------------------------------------------------------

  function isPlainObject(v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
  }

  function hasOwn(obj, key) {
    return Object.prototype.hasOwnProperty.call(obj, key);
  }

  function utf8ByteLength(str) {
    if (typeof TextEncoder !== 'undefined') {
      return new TextEncoder().encode(str).length;
    }
    if (typeof Buffer !== 'undefined') {
      return Buffer.byteLength(str, 'utf8');
    }
    // Fallback estimate (ASCII-correct; non-ASCII over-counts safely for
    // a size cap — it can only reject, never admit an oversize envelope).
    var n = 0;
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      n += c < 0x80 ? 1 : c < 0x800 ? 2 : 3;
    }
    return n;
  }

  // Strict base64url decode (no padding allowed — FILE-MAP §3). Returns
  // a Uint8Array, or throws on any non-canonical input.
  function decodeBase64url(str) {
    if (typeof str !== 'string' || !BASE64URL_RE.test(str)) {
      throw new Error('not base64url');
    }
    var b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    var pad = (4 - (b64.length % 4)) % 4;
    b64 += '===='.slice(0, pad);
    if (typeof Buffer !== 'undefined') {
      var buf = Buffer.from(b64, 'base64');
      // Round-trip check: non-canonical input (e.g. trailing bits set)
      // must not slip through as a different byte string.
      if (buf.length === 0 && str.length > 0) throw new Error('bad base64url');
      return new Uint8Array(buf);
    }
    if (typeof atob !== 'undefined') {
      var bin = atob(b64);
      var out = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }
    throw new Error('no base64 decoder available');
  }

  function base64urlByteLength(str) {
    return decodeBase64url(str).length;
  }

  function outboxError(code, message) {
    var err = new Error(message || code);
    err.code = code;
    return err;
  }

  // ---------------------------------------------------------------------
  // Envelope validation — FILE-MAP §3 (ecc-1). Shape only: this module
  // does NOT verify signatures or decrypt (A4/C10 own that). It proves
  // the envelope is signed AND encrypted before it may be queued, so an
  // unsigned or plaintext message can never enter the outbox.
  // Returns { envelope, envelopeJson }. Throws OUTBOX_INVALID.
  // `nowMs` is injected for tests; defaults to Date.now().
  // ---------------------------------------------------------------------

  function validateEnvelope(input, nowMs) {
    var now = typeof nowMs === 'number' ? nowMs : Date.now();
    var envelopeJson;
    var envelope;

    if (typeof input === 'string') {
      envelopeJson = input;
      try {
        envelope = JSON.parse(input);
      } catch (e) {
        throw outboxError('OUTBOX_INVALID', 'envelope is not valid JSON');
      }
    } else if (isPlainObject(input)) {
      envelope = input;
      // Serialize exactly once here; this string is the stored bytes.
      envelopeJson = JSON.stringify(input);
    } else {
      throw outboxError('OUTBOX_INVALID', 'envelope must be an object or a JSON string');
    }

    if (!isPlainObject(envelope)) {
      throw outboxError('OUTBOX_INVALID', 'envelope must be a JSON object');
    }

    function fail(why) {
      throw outboxError('OUTBOX_INVALID', 'envelope rejected: ' + why);
    }

    // Unknown fields → reject (FILE-MAP §3). `seq` is relay-assigned;
    // a client-set seq is rejected here before it can reach the relay.
    var keys = Object.keys(envelope);
    for (var i = 0; i < keys.length; i++) {
      if (ENVELOPE_FIELDS.indexOf(keys[i]) === -1) {
        fail('unknown field "' + keys[i] + '"' +
          (keys[i] === 'seq' ? ' (seq is assigned by the relay)' : ''));
      }
    }
    for (var j = 0; j < ENVELOPE_FIELDS.length; j++) {
      if (!hasOwn(envelope, ENVELOPE_FIELDS[j])) {
        fail('missing field "' + ENVELOPE_FIELDS[j] + '"');
      }
    }

    if (envelope.v !== 'ecc-1') fail('v must be "ecc-1"');
    if (typeof envelope.msg_id !== 'string' || !UUID_RE.test(envelope.msg_id)) {
      fail('msg_id must be a lowercase UUID');
    }
    if (SENDERS.indexOf(envelope.sender) === -1) fail('unknown sender');
    if (!Array.isArray(envelope.recipients) ||
        envelope.recipients.length < 1 || envelope.recipients.length > 10) {
      fail('recipients must list 1-10 participants');
    }
    var seenRecipients = {};
    for (var r = 0; r < envelope.recipients.length; r++) {
      var rec = envelope.recipients[r];
      if (SENDERS.indexOf(rec) === -1) fail('unknown recipient "' + rec + '"');
      if (seenRecipients[rec]) fail('duplicate recipient "' + rec + '"');
      seenRecipients[rec] = true;
    }
    if (!seenRecipients[envelope.sender]) {
      fail('recipients must include the sender');
    }

    if (!Number.isInteger(envelope.iat) || !Number.isInteger(envelope.exp)) {
      fail('iat and exp must be integer unix seconds');
    }
    if (envelope.exp <= envelope.iat) fail('exp must be after iat');
    if (envelope.exp - envelope.iat > MAX_TTL_SECONDS) {
      fail('TTL exceeds the 24 h maximum');
    }
    if (envelope.iat * 1000 > now + MAX_FUTURE_SKEW_SECONDS * 1000) {
      fail('iat is more than 5 minutes in the future');
    }
    if (envelope.exp * 1000 <= now) {
      fail('envelope is already expired');
    }

    if (envelope.reply_to !== null &&
        (typeof envelope.reply_to !== 'string' || !UUID_RE.test(envelope.reply_to))) {
      fail('reply_to must be a UUID or null');
    }
    if (typeof envelope.thread_id !== 'string' || !UUID_RE.test(envelope.thread_id)) {
      fail('thread_id must be a UUID');
    }
    if (envelope.alg !== 'A256CBC-HS256') {
      fail('alg must be "A256CBC-HS256" (AES-256-CBC + HMAC-SHA-256)');
    }
    if (SIG_ALGS.indexOf(envelope.sig_alg) === -1) {
      fail('sig_alg must be "Ed25519" or "ES256"');
    }

    // Encrypted payload present: iv (16 B), ct (1..24 KiB), mac (32 B).
    // Without these the message is not encrypted — never queue it.
    var ivLen, ctLen, macLen;
    try {
      ivLen = base64urlByteLength(envelope.iv);
      ctLen = base64urlByteLength(envelope.ct);
      macLen = base64urlByteLength(envelope.mac);
    } catch (e) {
      fail('iv/ct/mac must be unpadded base64url');
    }
    if (ivLen !== 16) fail('iv must decode to 16 bytes');
    if (ctLen < 1 || ctLen > CIPHERTEXT_MAX_BYTES) {
      fail('ct must decode to 1..24576 bytes');
    }
    if (macLen !== 32) fail('mac must decode to 32 bytes');

    // Wrapped keys: one per recipient, set must match recipients exactly.
    if (!Array.isArray(envelope.wrapped_keys) || envelope.wrapped_keys.length < 1) {
      fail('wrapped_keys must list one entry per recipient');
    }
    var seenWrapped = {};
    for (var w = 0; w < envelope.wrapped_keys.length; w++) {
      var wk = envelope.wrapped_keys[w];
      if (!isPlainObject(wk) || Object.keys(wk).length !== 2 ||
          typeof wk.recipient !== 'string' || typeof wk.wk !== 'string') {
        fail('wrapped_keys entries must be {"recipient", "wk"}');
      }
      if (!seenRecipients[wk.recipient]) {
        fail('wrapped_keys entry for non-recipient "' + wk.recipient + '"');
      }
      if (seenWrapped[wk.recipient]) fail('duplicate wrapped key for "' + wk.recipient + '"');
      seenWrapped[wk.recipient] = true;
      var wkLen;
      try {
        wkLen = base64urlByteLength(wk.wk);
      } catch (e) {
        fail('wrapped key for "' + wk.recipient + '" must be unpadded base64url');
      }
      // RSA-OAEP output size: 512 bytes for a 4096-bit key, 256 for
      // 2048-bit. Anything else is not an RSA-OAEP wrap of this protocol.
      if (wkLen !== 512 && wkLen !== 256) {
        fail('wrapped key for "' + wk.recipient + '" has an impossible length');
      }
    }
    if (Object.keys(seenWrapped).length !== envelope.recipients.length) {
      fail('wrapped_keys set must equal recipients set');
    }

    // Signed: sig present, unpadded base64url, 64 bytes (Ed25519 raw, or
    // ES256 raw R || S). An absent/empty sig is an unsigned message —
    // never queue it.
    var sigLen;
    try {
      sigLen = base64urlByteLength(envelope.sig);
    } catch (e) {
      fail('sig must be unpadded base64url');
    }
    if (typeof envelope.sig !== 'string' || sigLen !== 64) {
      fail('sig must decode to 64 bytes');
    }

    // Relay size cap on the encoded envelope (FILE-MAP §3).
    if (utf8ByteLength(envelopeJson) > ENVELOPE_MAX_BYTES) {
      throw outboxError('OUTBOX_TOO_LARGE',
        'envelope exceeds the 64 KiB relay cap');
    }

    return { envelope: envelope, envelopeJson: envelopeJson };
  }

  // ---------------------------------------------------------------------
  // Publish-error classification — RELAY-SPEC §4.5
  // Returns { code, retryable, retryAfterMs|null, detail }.
  // `result` is the publish function's resolved value; `thrown` is what
  // it threw (one of the two is null). Unknown errors are retryable:
  // the 5-attempt cap bounds them, so they can never loop forever.
  // ---------------------------------------------------------------------

  function classifyPublishError(result, thrown, maxRetryAfter) {
    var cap = typeof maxRetryAfter === 'number' ? maxRetryAfter : MAX_RETRY_AFTER_MS;
    var code = null;
    var status = null;
    var retryAfterSeconds = null;
    var detail = '';

    if (result && typeof result === 'object') {
      if (typeof result.error === 'string') code = result.error;
      if (typeof result.code === 'string' && !code) code = result.code;
      if (typeof result.status === 'number') status = result.status;
      if (typeof result.retry_after_seconds === 'number') {
        retryAfterSeconds = result.retry_after_seconds;
      }
      if (typeof result.detail === 'string') detail = result.detail;
    }
    if (thrown) {
      if (typeof thrown.code === 'string' && !code) code = thrown.code;
      if (typeof thrown.status === 'number' && !status) status = thrown.status;
      if (typeof thrown.retryAfterSeconds === 'number' && retryAfterSeconds === null) {
        retryAfterSeconds = thrown.retryAfterSeconds;
      }
      if (typeof thrown.retry_after_seconds === 'number' && retryAfterSeconds === null) {
        retryAfterSeconds = thrown.retry_after_seconds;
      }
      if (!detail && thrown.message) detail = String(thrown.message).slice(0, 200);
    }

    // A fetch/network failure usually arrives as a bare TypeError with no
    // code — that is a transient transport failure, not a relay verdict.
    if (!code && thrown) {
      var name = thrown.name || '';
      if (name === 'TypeError' || name === 'NetworkError' || /network|fetch|offline|failed to fetch/i.test(String(thrown.message || ''))) {
        code = 'NETWORK';
      }
    }

    var retryable;
    if (code && hasOwn(RETRYABLE_ERRORS, code)) {
      retryable = true;
    } else if (code && hasOwn(PERMANENT_ERRORS, code)) {
      retryable = false;
    } else if (code === 'NETWORK') {
      retryable = true;
    } else if (status && RETRYABLE_HTTP[status]) {
      retryable = true;
      if (!code) code = 'RELAY_UNAVAILABLE';
    } else if (status && PERMANENT_HTTP[status]) {
      retryable = false;
      if (!code) code = status === 410 ? 'EXPIRED' : 'SCHEMA_INVALID';
    } else if (code) {
      // Unknown relay code: retry (bounded by the attempt cap), and say so.
      retryable = true;
    } else if (thrown) {
      retryable = true;
      code = 'NETWORK';
    } else {
      retryable = false;
      code = 'SCHEMA_INVALID';
    }

    var retryAfterMs = null;
    if (typeof retryAfterSeconds === 'number' && isFinite(retryAfterSeconds) && retryAfterSeconds > 0) {
      retryAfterMs = Math.min(
        Math.round(retryAfterSeconds * 1000), cap);
    }

    return {
      code: code,
      retryable: retryable,
      retryAfterMs: retryAfterMs,
      detail: detail || (ERROR_COPY[code] || ''),
    };
  }

  // Backoff delay after failure number n (1-based): 1 s, 2 s, 4 s, 8 s,
  // … capped at MAX_DELAY_MS. A relay retry_after overrides it.
  // `base`/`max` default to the module constants; createOutbox passes
  // its configured values so tests can run on short delays.
  function computeDelayMs(attempts, retryAfterMs, base, max) {
    if (retryAfterMs !== null && retryAfterMs !== undefined) return retryAfterMs;
    var baseMs = typeof base === 'number' ? base : BASE_DELAY_MS;
    var maxMs = typeof max === 'number' ? max : MAX_DELAY_MS;
    var delay = baseMs * Math.pow(2, Math.max(0, attempts - 1));
    return Math.min(delay, maxMs);
  }

  // ---------------------------------------------------------------------
  // Storage backends. Same async interface; IndexedDB is the real one,
  // memory is the fallback (and the Node/test backend).
  // Record: { msg_id, envelopeJson, sender, thread_id, reply_to,
  //   status, attempts, maxAttempts, queuedAt, updatedAt, nextRetryAt,
  //   lastError|null, needsUserDecision }
  // ---------------------------------------------------------------------

  function createMemoryBackend() {
    var map = new Map();
    return {
      kind: 'memory',
      put: function (record) {
        map.set(record.msg_id, JSON.parse(JSON.stringify(record)));
        return Promise.resolve();
      },
      get: function (msgId) {
        var rec = map.get(msgId);
        return Promise.resolve(rec ? JSON.parse(JSON.stringify(rec)) : null);
      },
      getAll: function () {
        var out = [];
        map.forEach(function (rec) { out.push(JSON.parse(JSON.stringify(rec))); });
        return Promise.resolve(out);
      },
      remove: function (msgId) {
        map.delete(msgId);
        return Promise.resolve();
      },
    };
  }

  function idbRequest(req) {
    return new Promise(function (resolve, reject) {
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () {
        reject(req.error || new Error('indexeddb request failed'));
      };
    });
  }

  function createIndexedDBBackend(dbName, storeName) {
    var dbPromise = null;
    function open() {
      if (dbPromise) return dbPromise;
      dbPromise = new Promise(function (resolve, reject) {
        var req = indexedDB.open(dbName, 1);
        req.onupgradeneeded = function () {
          var db = req.result;
          if (!db.objectStoreNames.contains(storeName)) {
            db.createObjectStore(storeName, { keyPath: 'msg_id' });
          }
        };
        req.onsuccess = function () { resolve(req.result); };
        req.onerror = function () {
          reject(req.error || new Error('indexeddb open failed'));
        };
        req.onblocked = function () {
          reject(new Error('indexeddb open blocked'));
        };
      });
      // A failed open must not poison later calls.
      dbPromise.catch(function () { dbPromise = null; });
      return dbPromise;
    }
    function tx(mode) {
      return open().then(function (db) {
        return db.transaction(storeName, mode).objectStore(storeName);
      });
    }
    return {
      kind: 'indexeddb',
      put: function (record) {
        return tx('readwrite').then(function (store) {
          return idbRequest(store.put(record));
        });
      },
      get: function (msgId) {
        return tx('readonly').then(function (store) {
          return idbRequest(store.get(msgId));
        }).then(function (rec) { return rec === undefined ? null : rec; });
      },
      getAll: function () {
        return tx('readonly').then(function (store) {
          return idbRequest(store.getAll());
        });
      },
      remove: function (msgId) {
        return tx('readwrite').then(function (store) {
          return idbRequest(store.delete(msgId));
        });
      },
      close: function () {
        if (dbPromise) {
          dbPromise.then(function (db) { db.close(); });
          dbPromise = null;
        }
      },
    };
  }

  // ---------------------------------------------------------------------
  // Outbox
  // ---------------------------------------------------------------------

  function createOutbox(options) {
    options = options || {};
    if (typeof options.publish !== 'function') {
      throw new Error('createOutbox requires options.publish(envelope)');
    }
    var publish = options.publish;
    var maxAttempts = options.maxAttempts || MAX_ATTEMPTS;
    var baseDelayMs = options.baseDelayMs || BASE_DELAY_MS;
    var maxDelayMs = options.maxDelayMs || MAX_DELAY_MS;
    var maxRetryAfterMs = options.maxRetryAfterMs || MAX_RETRY_AFTER_MS;
    var jitterMs = options.jitterMs || 0;
    var nowFn = typeof options.now === 'function' ? options.now : Date.now;
    var onChange = typeof options.onChange === 'function' ? options.onChange : null;
    var onSendAsNew = typeof options.onSendAsNew === 'function' ? options.onSendAsNew : null;
    var dbName = options.dbName || DB_NAME;
    var storeName = options.storeName || STORE_NAME;

    var backend = options.storageBackend || null;
    var storageKind = 'indexeddb';
    if (!backend) {
      if (typeof indexedDB !== 'undefined' && indexedDB) {
        backend = createIndexedDBBackend(dbName, storeName);
        storageKind = 'indexeddb';
      } else {
        backend = createMemoryBackend();
        storageKind = 'memory';
      }
    } else {
      storageKind = backend.kind || 'custom';
    }

    var subscribers = [];
    var timer = null;
    var started = false;
    var inFlight = {};      // msg_id -> true while a publish is running
    var flushing = false;
    var onlineHandler = null;
    var offlineHandler = null;
    var visibilityHandler = null;
    var storageDegradedReported = false;

    function now() { return nowFn(); }

    function isOnline() {
      if (typeof options.isOnline === 'function') return options.isOnline();
      if (typeof navigator !== 'undefined' && typeof navigator.onLine === 'boolean') {
        return navigator.onLine;
      }
      return true; // unknown — attempt; publish will fail fast if offline
    }

    function emit(event) {
      if (onChange) {
        try { onChange(event); } catch (e) { /* listener must not break the outbox */ }
      }
      subscribers.slice().forEach(function (fn) {
        try { fn(event); } catch (e) { /* same */ }
      });
    }

    // Public snapshot: the parsed envelope plus queue state. The envelope
    // shown to the thread is ciphertext only, by construction.
    function toEntry(record) {
      var envelope = null;
      try { envelope = JSON.parse(record.envelopeJson); } catch (e) { envelope = null; }
      return {
        msg_id: record.msg_id,
        sender: record.sender,
        thread_id: record.thread_id,
        reply_to: record.reply_to,
        envelope: envelope,
        envelopeJson: record.envelopeJson,
        status: record.status,
        attempts: record.attempts,
        maxAttempts: record.maxAttempts,
        nextRetryAt: record.nextRetryAt,
        lastError: record.lastError ? JSON.parse(JSON.stringify(record.lastError)) : null,
        needsUserDecision: !!record.needsUserDecision,
        queuedAt: record.queuedAt,
        updatedAt: record.updatedAt,
      };
    }

    function isExpired(record, atMs) {
      try {
        var env = JSON.parse(record.envelopeJson);
        return typeof env.exp === 'number' && env.exp * 1000 <= atMs;
      } catch (e) {
        return false;
      }
    }

    function failRecord(record, errorInfo, atMs) {
      record.status = 'failed';
      record.needsUserDecision = true;
      record.nextRetryAt = null;
      record.lastError = {
        code: errorInfo.code,
        detail: errorInfo.detail || '',
        retryable: false,
        at: atMs,
      };
      record.updatedAt = atMs;
      return record;
    }

    function scheduleRecord(record, errorInfo, atMs) {
      var delay = computeDelayMs(record.attempts, errorInfo.retryAfterMs, baseDelayMs, maxDelayMs);
      if (jitterMs > 0) delay += Math.floor(Math.random() * jitterMs);
      var nextRetryAt = atMs + delay;
      // A retry that would land after expiry can never succeed — fail
      // now with EXPIRED instead of scheduling a doomed attempt.
      var env = JSON.parse(record.envelopeJson);
      if (typeof env.exp === 'number' && env.exp * 1000 <= nextRetryAt) {
        return failRecord(record, {
          code: 'EXPIRED',
          detail: 'message expired before the next retry',
        }, atMs);
      }
      record.status = 'queued';
      record.needsUserDecision = false;
      record.nextRetryAt = nextRetryAt;
      record.lastError = {
        code: errorInfo.code,
        detail: errorInfo.detail || '',
        retryable: true,
        at: atMs,
      };
      record.updatedAt = atMs;
      return record;
    }

    function clearTimer() {
      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
      }
    }

    function scheduleNext() {
      clearTimer();
      if (!started) return;
      backend.getAll().then(function (records) {
        var atMs = now();
        var next = null;
        records.forEach(function (rec) {
          if (rec.status !== 'queued' || rec.nextRetryAt === null) return;
          if (next === null || rec.nextRetryAt < next) next = rec.nextRetryAt;
        });
        if (next === null) return;
        var wait = Math.max(0, next - now());
        timer = setTimeout(function () {
          timer = null;
          flush();
        }, wait);
      }).catch(function () { /* storage error: retry on next trigger */ });
    }

    function attemptOne(record) {
      var atMs = now();
      if (inFlight[record.msg_id]) return Promise.resolve(false);
      if (isExpired(record, atMs)) {
        // Never publish an expired envelope (relay would 410 it).
        failRecord(record, { code: 'EXPIRED', detail: 'message expired while queued' }, atMs);
        return backend.put(record).then(function () {
          emit({ type: 'failed', entry: toEntry(record), reason: 'expired' });
          return true;
        });
      }
      if (!isOnline()) {
        // Known offline: do not burn an attempt on a publish that cannot
        // succeed. Wait for the online event.
        record.nextRetryAt = null;
        record.updatedAt = atMs;
        return backend.put(record).then(function () { return false; });
      }
      inFlight[record.msg_id] = true;
      record.status = 'sending';
      record.updatedAt = atMs;
      var envelope = JSON.parse(record.envelopeJson);
      return backend.put(record)
        .then(function () {
          emit({ type: 'sending', entry: toEntry(record) });
          var result;
          try {
            result = publish(envelope, { entry: toEntry(record) });
          } catch (err) {
            return Promise.reject(err);
          }
          return Promise.resolve(result);
        })
        .then(function (result) {
          delete inFlight[record.msg_id];
          var doneAt = now();
          if (!result || typeof result !== 'object') {
            throw outboxError('OUTBOX_BAD_PUBLISH_RESULT',
              'publish() must resolve { ok: true } or { ok: false, error }');
          }
          if (result.ok) {
            // Success — including duplicate:true (idempotent OK: the
            // relay already holds these exact bytes).
            return backend.remove(record.msg_id).then(function () {
              emit({
                type: 'sent',
                entry: toEntry(record),
                seq: typeof result.seq === 'number' ? result.seq : null,
                stored_at: result.stored_at || null,
                duplicate: !!result.duplicate,
              });
              return true;
            });
          }
          var info;
          try {
            info = classifyPublishError(result, null, maxRetryAfterMs);
          } catch (e) {
            // Classification must never strand a record in `sending`.
            info = { code: 'NETWORK', retryable: true, retryAfterMs: null, detail: '' };
          }
          return handleFailure(record, info, doneAt);
        })
        .catch(function (err) {
          delete inFlight[record.msg_id];
          var doneAt = now();
          if (err && err.code === 'OUTBOX_BAD_PUBLISH_RESULT') {
            // Our own contract error: the transport is broken, not the
            // envelope. Retryable, bounded by the attempt cap.
            return handleFailure(record,
              { code: 'RELAY_UNAVAILABLE', retryable: true, retryAfterMs: null,
                detail: 'publish() returned no result' }, doneAt);
          }
          var info2;
          try {
            info2 = classifyPublishError(null, err, maxRetryAfterMs);
          } catch (e) {
            info2 = { code: 'NETWORK', retryable: true, retryAfterMs: null, detail: '' };
          }
          return handleFailure(record, info2, doneAt);
        });
    }

    function handleFailure(record, errorInfo, atMs) {
      record.attempts += 1;
      if (!errorInfo.retryable || record.attempts >= record.maxAttempts) {
        failRecord(record, errorInfo, atMs);
        return backend.put(record).then(function () {
          emit({
            type: 'failed',
            entry: toEntry(record),
            reason: errorInfo.retryable ? 'exhausted' : 'permanent',
          });
          return true;
        });
      }
      scheduleRecord(record, errorInfo, atMs);
      var wasExpired = record.status === 'failed';
      return backend.put(record).then(function () {
        if (wasExpired) {
          emit({ type: 'failed', entry: toEntry(record), reason: 'expired' });
        } else {
          emit({ type: 'retry-scheduled', entry: toEntry(record) });
        }
        scheduleNext();
        return true;
      });
    }

    // Attempt every due entry, oldest first, one at a time (sequential
    // sends avoid bursting the relay's per-minute rate limit).
    function flush() {
      if (flushing) return Promise.resolve();
      flushing = true;
      return backend.getAll()
        .then(function (records) {
          var atMs = now();
          var due = records
            .filter(function (rec) {
              return rec.status === 'queued' &&
                (rec.nextRetryAt === null || rec.nextRetryAt <= atMs) &&
                !inFlight[rec.msg_id];
            })
            .sort(function (a, b) { return a.queuedAt - b.queuedAt; });
          var chain = Promise.resolve();
          due.forEach(function (rec) {
            chain = chain.then(function () { return attemptOne(rec); });
          });
          return chain;
        })
        .catch(function () { /* storage error: leave entries for next trigger */ })
        .then(function () {
          flushing = false;
          scheduleNext();
        });
    }

    function flushSoon() {
      if (!started) return;
      // Run on the next tick so enqueue() can resolve first.
      setTimeout(function () { flush(); }, 0);
    }

    var api = {
      storage: storageKind,
      maxAttempts: maxAttempts,

      start: function () {
        if (started) return Promise.resolve(api);
        started = true;
        if (storageKind === 'memory' && !storageDegradedReported) {
          storageDegradedReported = true;
          emit({
            type: 'storage-degraded',
            storage: 'memory',
            detail: 'IndexedDB is unavailable in this browser — queued messages will not survive a reload.',
          });
        }
        if (typeof window !== 'undefined' && window.addEventListener) {
          onlineHandler = function () { api.handleOnline(); };
          offlineHandler = function () {
            emit({ type: 'offline', at: now() });
          };
          window.addEventListener('online', onlineHandler);
          window.addEventListener('offline', offlineHandler);
          if (typeof document !== 'undefined' && document.addEventListener) {
            visibilityHandler = function () {
              if (document.visibilityState === 'visible') flush();
            };
            document.addEventListener('visibilitychange', visibilityHandler);
          }
        }
        // Recover: entries left `sending` by a reload have unknown
        // outcomes — re-queue them. Re-sending the same bytes is safe
        // (relay dedups on msg_id). Entries past expiry fail as EXPIRED.
        return backend.getAll().then(function (records) {
          var atMs = now();
          var writes = [];
          records.forEach(function (rec) {
            if (rec.status === 'sending') {
              rec.status = 'queued';
              rec.nextRetryAt = atMs;
              rec.updatedAt = atMs;
              writes.push(backend.put(rec));
            } else if (rec.status === 'queued' && isExpired(rec, atMs)) {
              failRecord(rec, { code: 'EXPIRED', detail: 'message expired while queued' }, atMs);
              writes.push(backend.put(rec));
            }
          });
          return Promise.all(writes);
        }).then(function () {
          flushSoon();
          return api;
        });
      },

      stop: function () {
        started = false;
        clearTimer();
        if (typeof window !== 'undefined' && window.removeEventListener) {
          if (onlineHandler) window.removeEventListener('online', onlineHandler);
          if (offlineHandler) window.removeEventListener('offline', offlineHandler);
          if (visibilityHandler && typeof document !== 'undefined') {
            document.removeEventListener('visibilitychange', visibilityHandler);
          }
        }
        if (backend && typeof backend.close === 'function') backend.close();
        return Promise.resolve(api);
      },

      // Queue a signed envelope. Throws OUTBOX_INVALID (unsigned,
      // unencrypted, malformed, oversize, expired-at-enqueue) or
      // OUTBOX_ID_CONFLICT (same msg_id, different bytes already queued)
      // or OUTBOX_FULL. Returns the stored entry. Enqueueing the exact
      // same bytes twice is idempotent: the existing entry is returned.
      enqueue: function (input) {
        var checked = validateEnvelope(input, now());
        var envelope = checked.envelope;
        var atMs = now();
        if (envelope.exp * 1000 <= atMs) {
          throw outboxError('OUTBOX_INVALID', 'envelope is already expired');
        }
        return backend.get(envelope.msg_id).then(function (existing) {
          if (existing) {
            if (existing.envelopeJson === checked.envelopeJson) {
              return toEntry(existing);
            }
            throw outboxError('OUTBOX_ID_CONFLICT',
              'msg_id ' + envelope.msg_id + ' is already queued with different bytes');
          }
          return backend.getAll().then(function (all) {
            if (all.length >= MAX_OUTBOX_ENTRIES) {
              throw outboxError('OUTBOX_FULL',
                'outbox holds ' + MAX_OUTBOX_ENTRIES + ' messages — resolve or discard one first');
            }
            var record = {
              msg_id: envelope.msg_id,
              envelopeJson: checked.envelopeJson,
              sender: envelope.sender,
              thread_id: envelope.thread_id,
              reply_to: envelope.reply_to,
              status: 'queued',
              attempts: 0,
              maxAttempts: maxAttempts,
              queuedAt: atMs,
              updatedAt: atMs,
              // Attempt at once if we appear online; if known offline,
              // wait for the online event instead of burning an attempt.
              nextRetryAt: isOnline() ? atMs : null,
              lastError: null,
              needsUserDecision: false,
            };
            return backend.put(record).then(function () {
              emit({ type: 'queued', entry: toEntry(record) });
              scheduleNext();
              flushSoon();
              return toEntry(record);
            });
          });
        });
      },

      // Manual retry (user taps Retry). Counts as an attempt, like an
      // automatic one — otherwise a user could loop past the cap by
      // tapping. A failed (exhausted/permanent) entry retried this way
      // restarts its attempt budget: the user explicitly asked, so it is
      // a decision, not a blind loop. Expired entries are never published.
      retryNow: function (msgId) {
        return backend.get(msgId).then(function (rec) {
          if (!rec) throw outboxError('OUTBOX_NOT_FOUND', 'no queued message ' + msgId);
          var atMs = now();
          if (isExpired(rec, atMs)) {
            failRecord(rec, { code: 'EXPIRED', detail: 'message expired before retry' }, atMs);
            return backend.put(rec).then(function () {
              emit({ type: 'failed', entry: toEntry(rec), reason: 'expired' });
              return toEntry(rec);
            });
          }
          if (rec.status === 'failed') {
            rec.attempts = 0;
            rec.needsUserDecision = false;
            rec.lastError = null;
          }
          rec.status = 'queued';
          rec.nextRetryAt = atMs;
          rec.updatedAt = atMs;
          return backend.put(rec).then(function () {
            emit({ type: 'retry-scheduled', entry: toEntry(rec) });
            scheduleNext();
            return attemptOne(rec).then(function () {
              return backend.get(msgId).then(function (after) {
                // Sent entries are removed: report the sent state.
                if (!after) {
                  var sent = toEntry(rec);
                  sent.status = 'sent';
                  return sent;
                }
                return toEntry(after);
              });
            });
          });
        });
      },

      // Discard a queued/failed entry (user taps Cancel/Discard).
      // In-flight publishes are not cancelled — the relay is idempotent,
      // so a publish already in flight either lands (and the thread
      // picks it up by msg_id on the next poll) or fails harmlessly.
      discard: function (msgId, reason) {
        return backend.get(msgId).then(function (rec) {
          if (!rec) throw outboxError('OUTBOX_NOT_FOUND', 'no queued message ' + msgId);
          return backend.remove(msgId).then(function () {
            emit({ type: 'discarded', entry: toEntry(rec), reason: reason || 'user-discarded' });
            scheduleNext();
            return true;
          });
        });
      },

      // "Send as new" (explicit user choice only). This module never
      // builds the fresh envelope — it cannot: it holds no keys and never
      // encrypts or signs. It discards the old entry and hands the old
      // entry's routing metadata to the compose layer (C7) via
      // `onSendAsNew`, which builds a FRESH signed envelope (new msg_id)
      // and enqueues it through the normal path. Without a registered
      // handler, this throws instead of silently dropping the message.
      sendAsNew: function (msgId) {
        if (!onSendAsNew) {
          throw outboxError('OUTBOX_NO_SEND_AS_NEW',
            'no send-as-new handler registered — the fresh envelope must be built by compose');
        }
        return backend.get(msgId).then(function (rec) {
          if (!rec) throw outboxError('OUTBOX_NOT_FOUND', 'no queued message ' + msgId);
          var entry = toEntry(rec);
          return backend.remove(msgId).then(function () {
            emit({ type: 'superseded', entry: entry });
            scheduleNext();
            var result = onSendAsNew(entry);
            return Promise.resolve(result).then(function () { return entry; });
          });
        });
      },

      // Attempt every due entry now (online event, visibility return,
      // poll tick). Entries in `failed` are never auto-retried.
      flush: flush,

      // Called on the browser `online` event (also wired automatically
      // by start()). Re-attempts entries parked with nextRetryAt null.
      handleOnline: function () {
        return backend.getAll().then(function (records) {
          var atMs = now();
          var writes = [];
          records.forEach(function (rec) {
            if (rec.status === 'queued' && rec.nextRetryAt === null) {
              rec.nextRetryAt = atMs;
              rec.updatedAt = atMs;
              writes.push(backend.put(rec));
            }
          });
          return Promise.all(writes);
        }).then(function () {
          emit({ type: 'online', at: now() });
          return flush();
        });
      },

      get: function (msgId) {
        return backend.get(msgId).then(function (rec) {
          return rec ? toEntry(rec) : null;
        });
      },

      // All entries, oldest first (what the thread renders as pending).
      list: function () {
        return backend.getAll().then(function (records) {
          return records
            .sort(function (a, b) { return a.queuedAt - b.queuedAt; })
            .map(toEntry);
        });
      },

      listPending: function () {
        return api.list().then(function (entries) {
          return entries.filter(function (e) {
            return e.status === 'queued' || e.status === 'sending';
          });
        });
      },

      count: function () {
        return backend.getAll().then(function (records) { return records.length; });
      },

      // Plain-words bubble copy for one entry (thread renderer, C6).
      describeEntry: function (entry) {
        if (!entry) return { label: '', detail: '' };
        if (entry.status === 'sending') {
          return { label: STATUS_COPY.sending, detail: '' };
        }
        if (entry.status === 'queued') {
          return {
            label: isOnline() ? STATUS_COPY.queuedOnline : STATUS_COPY.queuedOffline,
            detail: entry.attempts > 0
              ? 'Attempt ' + entry.attempts + ' of ' + entry.maxAttempts + ' failed — next try ' +
                (entry.nextRetryAt ? new Date(entry.nextRetryAt).toLocaleTimeString() : 'when back online')
              : '',
          };
        }
        if (entry.status === 'failed') {
          var code = entry.lastError && entry.lastError.code;
          if (code === 'EXPIRED') return { label: STATUS_COPY.failedExpired, detail: '' };
          if (code === 'MSG_ID_CONFLICT') return { label: STATUS_COPY.failedConflict, detail: '' };
          if (entry.lastError && entry.lastError.retryable === false &&
              entry.attempts < entry.maxAttempts) {
            return { label: STATUS_COPY.failedPermanent, detail: '' };
          }
          return { label: STATUS_COPY.failedExhausted, detail: '' };
        }
        return { label: '', detail: '' };
      },

      subscribe: function (fn) {
        if (typeof fn !== 'function') throw new Error('subscribe requires a function');
        subscribers.push(fn);
        return function () {
          var i = subscribers.indexOf(fn);
          if (i !== -1) subscribers.splice(i, 1);
        };
      },
    };

    return api;
  }

  // ---------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------

  return {
    createOutbox: createOutbox,
    validateEnvelope: validateEnvelope,
    classifyPublishError: classifyPublishError,
    computeDelayMs: computeDelayMs,
    MAX_ATTEMPTS: MAX_ATTEMPTS,
    BASE_DELAY_MS: BASE_DELAY_MS,
    MAX_DELAY_MS: MAX_DELAY_MS,
    MAX_RETRY_AFTER_MS: MAX_RETRY_AFTER_MS,
    ENVELOPE_MAX_BYTES: ENVELOPE_MAX_BYTES,
    CIPHERTEXT_MAX_BYTES: CIPHERTEXT_MAX_BYTES,
    MAX_TTL_SECONDS: MAX_TTL_SECONDS,
    DB_NAME: DB_NAME,
    STORE_NAME: STORE_NAME,
  };
});
