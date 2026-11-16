/**
 * presence.js — typing indicators, read markers, and presence derivation
 * for the ghostcorpnet encrypted chat (ecc-1).
 *
 * Worker P5 (wave 3, STATE-OF-THE-ART-BAR-2026-11-16 § Phase 3a).
 * Normative refs:
 *   - FILE-MAP.md §3 (envelope fields, canonical JSON, TTL <= 86400,
 *     recipients include the sender, D9 default = all three participants)
 *     — FILE-MAP WINS on any conflict with a design doc.
 *   - STATE-OF-THE-ART-BAR-2026-11-16.md P5 row + P5 API block (this
 *     file's contract; P6 implements to this API verbatim).
 *   - relay/receipts.py (D8) for the receipt inner-field convention
 *     ({"text", "type", "kind", ...} — extra inner fields, never envelope
 *     fields); presence inners follow the same convention with
 *     type "presence".
 *
 * Scope (this file ONLY):
 *   - Send: build + sign + publish ephemeral typing envelopes and
 *     read-marker envelopes as STANDARD ecc-1 envelopes (same fields,
 *     same verification — §7 applies to them exactly as to messages).
 *   - Derive: typingUsers() / readState() / presence() from envelopes
 *     (or already-decrypted records) for the thread view's indicators.
 *
 * Presence envelopes are NOT chat messages. The thread view (P6) filters
 * them out of the message list by inner type "presence" and uses them for
 * indicators only. They carry no message content: inner text is always "".
 *
 * Inner plaintext formats (JSON, keys sorted, compact separators):
 *   typing: {"kind": "typing", "text": "", "thread_id": "<thread root>",
 *            "type": "presence"}                          TTL 10 s
 *   read:   {"kind": "read", "seq": <max relay seq read>, "text": "",
 *            "type": "presence"}                          TTL 24 h (86400 s)
 *
 * Envelope placement:
 *   - typing: a reply in the thread it reports on — reply_to is the
 *     thread root's msg_id and thread_id is that root. (A root envelope
 *     must have thread_id == its own msg_id, so a typing envelope can
 *     never be a root; it always names its thread.)
 *   - read: a root of its own thread when no threadId is given
 *     (reply_to null, thread_id == its own msg_id); a reply in the given
 *     thread when threadId is given.
 *
 * Throttling (per this module instance — one page load):
 *   - typing: at most one envelope per 5 s per thread. A call inside the
 *     window resolves to null (throttled) and publishes nothing.
 *   - read: at most one envelope per 30 s, and ONLY when upToSeq advances
 *     past the highest seq already sent. Otherwise resolves to null.
 * Throttle timestamps are recorded only AFTER a successful publish, so a
 * failed publish does not consume the window. The clock is wall time
 * (Date.now()) unless the caller passes nowSeconds (tests / skewed
 * clocks); throttle windows compare in seconds.
 *
 * Sending — what the caller passes (P6):
 *   sendTyping({ threadId, publish, sender, signingKey,
 *                recipientPublicKeys, recipients, buildEnvelope,
 *                nowSeconds, msgId })
 *   sendReadMarker({ upToSeq, publish, sender, signingKey,
 *                    recipientPublicKeys, recipients, buildEnvelope,
 *                    threadId, nowSeconds, msgId })
 *   - threadId / upToSeq / publish are required. publish(envelope) is the
 *     injected publisher (C7's publishEnvelope convention: it takes a
 *     complete signed envelope and returns a confirmation; the resolved
 *     value may be a msg_id string, an object carrying msg_id, or
 *     undefined — any of those resolves here to the envelope's msg_id).
 *   - sender (string) + signingKey (CryptoKey, the sender's Ed25519 or
 *     P-256 private key) + recipientPublicKeys (the A4 format: array of
 *     { recipient, publicKey }, Map, or { id: CryptoKey }) are required
 *     for the default build path. recipients defaults to all three
 *     participants (FILE-MAP D9); it must include the sender.
 *   - buildEnvelope (optional override): async (inner, ctx) => signed
 *     envelope. When supplied, this module does NOT touch crypto at all —
 *     the caller owns envelope construction (e.g. a test stub, or a
 *     caller whose builder already carries the keys). ctx is
 *     { sender, recipients, ttlSeconds, nowSeconds, replyTo, threadId,
 *       msgId }. The returned envelope MUST be a complete signed ecc-1
 *     envelope (msg_id required); this module validates its shape
 *     minimally (plain object + UUIDv4 msg_id) before publishing.
 *   Both senders resolve to the published msg_id (string), or null when
 *   throttled / when a read marker does not advance. A publish failure
 *   REJECTS (the caller distinguishes "not sent" from "throttled: null").
 *
 * Derivation — input records:
 *   typingUsers(envelopes, nowEpoch, myId[, threadId])
 *   readState(envelopes)
 *   presence(envelopes, nowEpoch)
 * Each entry may be a raw envelope, or a record carrying the envelope
 * under `.envelope` (the view-thread.js record shape), with the decrypted
 * inner JSON under `.inner` (object), `.decrypted` (object), `.plaintext`
 * (object or JSON string), or `.innerJson` (JSON string). An entry whose
 * inner cannot be found or parsed contributes nothing to the
 * typing/read derivations, but still contributes its envelope iat to
 * presence() (presence is envelope metadata, not content). Non-array
 * input yields [] / {} (defensive: a poll returning nothing must not
 * crash the indicator render).
 *   - typingUsers: sender ids with a LIVE typing envelope — inner
 *     type "presence", kind "typing", envelope exp > nowEpoch, sender !=
 *     myId (your own typing never shows to you). One entry per sender,
 *     most-recently-active first. When threadId is given, only typing
 *     envelopes for that thread count (inner thread_id must match).
 *   - readState: { senderId: maxSeq } over read markers (inner type
 *     "presence", kind "read", integer seq). No clock is involved, so
 *     expired markers still count — the caller re-polls and the store
 *     sweeper removes them at expiry.
 *   - presence: { senderId: lastActiveEpoch } from the MAXIMUM iat of
 *     any envelope per sender. Envelopes with iat more than 300 s in the
 *     future of nowEpoch are skipped (invalid per §7 step 2 — a
 *     future-dated envelope is not evidence anyone is around). "Active"
 *     is the caller's comparison: lastActive within 60 s of nowEpoch
 *     (STATE-OF-THE-ART-BAR §3 honest bound — presence here is
 *     minute-scale approximate, poll-based, never sub-second).
 *
 * Load order (browser, plain <script> tags, no build step):
 *   canonical-json.js, crypto-core.js, crypto-p256.js (ES256 only),
 *   envelope.js, then this file. Exposes window.GhostChatPresence
 *   (browser) and module.exports (Node / tests). The derivation
 *   functions work with no dependencies loaded; the send functions
 *   throw PresenceError MISSING_DEPENDENCY when the default build path
 *   is used without GhostCorpEnvelope + GhostChatCrypto.
 *
 * No real keys are generated here. No private-key material, plaintext
 * conversation content, secrets, or personal info belong in this file.
 * Keys are passed in by the caller (CryptoKey objects) and never stored
 * or logged by this module. The typing/read throttles hold only
 * timestamps and sequence numbers — no content.
 */

'use strict';

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    // Node / CommonJS (unit tests).
    var envelope = null;
    var core = null;
    try { envelope = require('./envelope.js'); } catch (e) { envelope = null; }
    try { core = require('./crypto-core.js'); } catch (e) { core = null; }
    module.exports = factory(envelope, core);
  } else {
    // Browser globals (static page, no build step).
    root.GhostChatPresence = factory(
      root.GhostCorpEnvelope || null,
      root.GhostChatCrypto || null
    );
  }
})(typeof self !== 'undefined' ? self : this, function (Envelope, Crypto) {
  'use strict';

  // ---------------------------------------------------------------------------
  // Constants — FILE-MAP §3 / STATE-OF-THE-ART-BAR P5
  // ---------------------------------------------------------------------------

  var PARTICIPANTS = ['jarvis', 'chatgpt', 'owner']; // D9 default recipients
  var TYPING_TTL_SECONDS = 10;          // P5: typing envelope TTL
  var READ_TTL_SECONDS = 86400;         // P5: read marker TTL (24 h, D10 max)
  var TYPING_THROTTLE_SECONDS = 5;      // P5: at most one typing / 5 s / thread
  var READ_THROTTLE_SECONDS = 30;       // P5: at most one read marker / 30 s
  var MAX_FUTURE_SKEW_SECONDS = 300;    // FILE-MAP D10: iat beyond now+300 rejected
  var ACTIVE_WINDOW_SECONDS = 60;       // "active" = lastActive within 60 s
  var MAX_PLAINTEXT_BYTES = 64 * 1024;  // FILE-MAP §3: max 64 KiB plaintext

  var UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

  // ---------------------------------------------------------------------------
  // Errors
  // ---------------------------------------------------------------------------

  function PresenceError(code, message) {
    var e = new Error(message);
    e.name = 'PresenceError';
    e.code = code;
    return e;
  }

  // ---------------------------------------------------------------------------
  // Small helpers (platform APIs only — no crypto re-implemented here)
  // ---------------------------------------------------------------------------

  var _encoder = (typeof TextEncoder !== 'undefined') ? new TextEncoder() : null;

  function textToBytes(text) {
    if (_encoder) return _encoder.encode(text);
    return Buffer.from(text, 'utf-8');
  }

  function isPlainObject(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
    var proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
  }

  function nowSeconds() {
    return Math.floor(Date.now() / 1000);
  }

  function isUuidV4(str) {
    return typeof str === 'string' && UUID_V4_RE.test(str);
  }

  // Deterministic inner-plaintext serialisation: keys sorted
  // lexicographically, compact separators, raw UTF-8 — the same canonical
  // shape receipts.py uses for its inner JSON (sort_keys + "," / ":").
  function innerPlaintextBytes(inner) {
    var keys = Object.keys(inner).sort();
    var sorted = {};
    for (var i = 0; i < keys.length; i++) sorted[keys[i]] = inner[keys[i]];
    var bytes = textToBytes(JSON.stringify(sorted));
    if (bytes.length > MAX_PLAINTEXT_BYTES) {
      throw PresenceError('TOO_LARGE',
        'presence inner plaintext is ' + bytes.length + ' bytes, over the 64 KiB per-message limit');
    }
    return bytes;
  }

  function requireEnvelope() {
    if (!Envelope) {
      throw PresenceError('MISSING_DEPENDENCY',
        'envelope.js (GhostCorpEnvelope) is not loaded — load app/js/envelope.js before app/js/presence.js');
    }
    return Envelope;
  }

  function requireCrypto() {
    if (!Crypto) {
      throw PresenceError('MISSING_DEPENDENCY',
        'crypto-core.js (GhostChatCrypto) is not loaded — load app/js/crypto-core.js before app/js/presence.js');
    }
    return Crypto;
  }

  // ---------------------------------------------------------------------------
  // Throttle state (module instance — one page load)
  // ---------------------------------------------------------------------------
  // lastTypingAt: { threadId: epochSeconds of last successful typing send }
  // lastReadAt: epochSeconds of last successful read-marker send (any thread)
  // lastReadSeq: highest upToSeq already sent in a read marker (0 = none)

  var lastTypingAt = {};
  var lastReadAt = null;
  var lastReadSeq = 0;

  // ---------------------------------------------------------------------------
  // Envelope construction (default path — reuses A1 + A4, duplicates nothing)
  // ---------------------------------------------------------------------------
  //
  // buildPresenceEnvelope(inner, ctx) encrypts the inner JSON with fresh
  // per-message keys (Crypto.encryptMessage: AES-256-CBC + HMAC-SHA-256
  // EtM, RSA-OAEP-SHA-256 wrap per recipient), assembles the unsigned
  // envelope (Envelope.buildUnsignedEnvelope) and signs it
  // (Envelope.signEnvelope, Ed25519 primary / ES256 via the caller's key).
  // This mirrors Envelope.buildEnvelope() step for step; the ONLY
  // difference is the inner JSON (presence fields instead of {"text"}),
  // which buildEnvelope() cannot carry — hence this file builds via the
  // same two primitives instead of duplicating any crypto.
  //
  // ctx: { sender, recipients, signingKey, recipientPublicKeys,
  //        ttlSeconds, nowSeconds, replyTo, threadId, msgId }
  async function buildPresenceEnvelope(inner, ctx) {
    var envelope = requireEnvelope();
    var core = requireCrypto();

    if (typeof ctx.sender !== 'string' || ctx.sender.length === 0) {
      throw PresenceError('BAD_SENDER', 'presence send requires opts.sender (participant id)');
    }
    if (!ctx.signingKey) {
      throw PresenceError('BAD_KEY', 'presence send requires opts.signingKey (the sender\'s signing private key)');
    }
    if (!ctx.recipientPublicKeys) {
      throw PresenceError('BAD_KEY',
        'presence send requires opts.recipientPublicKeys (array of { recipient, publicKey }, Map, or { id: CryptoKey })');
    }
    var recipients = ctx.recipients || PARTICIPANTS.slice();
    if (!Array.isArray(recipients) || recipients.length === 0) {
      throw PresenceError('BAD_RECIPIENTS', 'recipients must be a non-empty array of participant ids');
    }
    if (recipients.indexOf(ctx.sender) === -1) {
      throw PresenceError('BAD_RECIPIENTS', 'recipients must contain the sender "' + ctx.sender + '" (FILE-MAP §3)');
    }

    var plaintextBytes = innerPlaintextBytes(inner);
    var parts = await core.encryptMessage(plaintextBytes, ctx.recipientPublicKeys);
    var unsigned = envelope.buildUnsignedEnvelope({
      sender: ctx.sender,
      recipients: recipients,
      replyTo: ctx.replyTo,
      threadId: ctx.threadId,
      ttlSeconds: ctx.ttlSeconds,
      nowSeconds: ctx.nowSeconds,
      msgId: ctx.msgId,
      sigAlg: ctx.sigAlg,
      iv: parts.iv,
      ct: parts.ct,
      mac: parts.mac,
      wrappedKeys: parts.wrapped_keys
    });
    return envelope.signEnvelope(unsigned, ctx.signingKey);
  }

  // Resolve the envelope builder for a send call: the caller's injected
  // buildEnvelope(inner, ctx) wins; otherwise the default A1+A4 path.
  // Returns the complete signed envelope object.
  async function buildEnvelopeFor(inner, ctx) {
    if (typeof ctx.buildEnvelope === 'function') {
      var built = await ctx.buildEnvelope(inner, {
        sender: ctx.sender,
        recipients: ctx.recipients || PARTICIPANTS.slice(),
        ttlSeconds: ctx.ttlSeconds,
        nowSeconds: ctx.nowSeconds,
        replyTo: ctx.replyTo,
        threadId: ctx.threadId,
        msgId: ctx.msgId
      });
      if (!isPlainObject(built) || !isUuidV4(built.msg_id)) {
        throw PresenceError('BAD_ENVELOPE',
          'opts.buildEnvelope must return a complete signed ecc-1 envelope (UUIDv4 msg_id required)');
      }
      return built;
    }
    return buildPresenceEnvelope(inner, ctx);
  }

  // Validate the shared send options. Returns the resolved clock (seconds).
  function resolveSendClock(opts) {
    var t = (opts.nowSeconds === undefined) ? nowSeconds() : opts.nowSeconds;
    if (!Number.isSafeInteger(t) || t <= 0) {
      throw PresenceError('BAD_TIMESTAMP', 'nowSeconds must be a positive integer unix time');
    }
    return t;
  }

  function requirePublish(opts) {
    if (!opts || typeof opts.publish !== 'function') {
      throw PresenceError('BAD_PUBLISH', 'presence send requires opts.publish (async (envelope) => confirmation)');
    }
    return opts.publish;
  }

  // ---------------------------------------------------------------------------
  // Send — typing indicator
  // ---------------------------------------------------------------------------
  //
  // sendTyping({ threadId, publish, sender, signingKey,
  //              recipientPublicKeys, recipients, buildEnvelope,
  //              nowSeconds, msgId })
  // Publishes one typing envelope for the given thread root. Throttled to
  // at most one per 5 s per thread: a call inside the window resolves to
  // null and publishes nothing. Resolves to the published msg_id.
  async function sendTyping(opts) {
    opts = opts || {};
    var publish = requirePublish(opts);
    if (typeof opts.threadId !== 'string' || !isUuidV4(opts.threadId)) {
      throw PresenceError('BAD_THREAD_ID', 'sendTyping requires opts.threadId (the thread root msg_id, UUIDv4)');
    }
    var t = resolveSendClock(opts);

    var last = lastTypingAt[opts.threadId];
    if (last !== undefined && t - last < TYPING_THROTTLE_SECONDS) {
      return null; // throttled — inside the 5 s window for this thread
    }

    var inner = {
      text: '',
      type: 'presence',
      kind: 'typing',
      thread_id: opts.threadId
    };
    // A typing envelope is a reply in its thread: reply_to is the thread
    // root, thread_id is that root. (A root envelope must have thread_id
    // == its own msg_id, so typing can never be a root.)
    var envelope = await buildEnvelopeFor(inner, {
      sender: opts.sender,
      signingKey: opts.signingKey,
      recipientPublicKeys: opts.recipientPublicKeys,
      recipients: opts.recipients,
      buildEnvelope: opts.buildEnvelope,
      ttlSeconds: TYPING_TTL_SECONDS,
      nowSeconds: t,
      replyTo: opts.threadId,
      threadId: opts.threadId,
      msgId: opts.msgId,
      sigAlg: opts.sigAlg
    });
    await publish(envelope);
    // Record the throttle timestamp only after a successful publish, so
    // a failed publish does not consume the window.
    lastTypingAt[opts.threadId] = t;
    return envelope.msg_id;
  }

  // ---------------------------------------------------------------------------
  // Send — read marker
  // ---------------------------------------------------------------------------
  //
  // sendReadMarker({ upToSeq, publish, sender, signingKey,
  //                  recipientPublicKeys, recipients, buildEnvelope,
  //                  threadId, nowSeconds, msgId })
  // Publishes one read-marker envelope stating the sender has read up to
  // relay seq upToSeq. Throttled to at most one per 30 s, and only when
  // upToSeq advances past the highest seq already sent. Otherwise
  // resolves to null. Resolves to the published msg_id on success.
  async function sendReadMarker(opts) {
    opts = opts || {};
    var publish = requirePublish(opts);
    if (!Number.isSafeInteger(opts.upToSeq) || opts.upToSeq < 0) {
      throw PresenceError('BAD_SEQ', 'sendReadMarker requires opts.upToSeq (a non-negative integer relay seq)');
    }
    var t = resolveSendClock(opts);

    if (opts.upToSeq <= lastReadSeq) {
      return null; // no advance — nothing new to report
    }
    if (lastReadAt !== null && t - lastReadAt < READ_THROTTLE_SECONDS) {
      return null; // throttled — inside the 30 s window
    }

    var inner = {
      text: '',
      type: 'presence',
      kind: 'read',
      seq: opts.upToSeq
    };
    // A read marker is a root of its own thread unless the caller names
    // a thread (then it replies in that thread, as typing does).
    var isReply = typeof opts.threadId === 'string' && isUuidV4(opts.threadId);
    var envelope = await buildEnvelopeFor(inner, {
      sender: opts.sender,
      signingKey: opts.signingKey,
      recipientPublicKeys: opts.recipientPublicKeys,
      recipients: opts.recipients,
      buildEnvelope: opts.buildEnvelope,
      ttlSeconds: READ_TTL_SECONDS,
      nowSeconds: t,
      replyTo: isReply ? opts.threadId : null,
      threadId: isReply ? opts.threadId : undefined,
      msgId: opts.msgId,
      sigAlg: opts.sigAlg
    });
    await publish(envelope);
    // Record throttle state only after a successful publish.
    lastReadAt = t;
    lastReadSeq = opts.upToSeq;
    return envelope.msg_id;
  }

  // ---------------------------------------------------------------------------
  // Derive — record normalisation
  // ---------------------------------------------------------------------------
  //
  // An entry may be a raw envelope, or a record carrying the envelope
  // under `.envelope` (view-thread.js shape), with the decrypted inner
  // JSON under `.inner` (object), `.decrypted` (object), `.plaintext`
  // (object or JSON string), or `.innerJson` (JSON string). Returns
  // { envelope, inner } where either side may be null when absent or
  // unparseable. Never throws for a bad entry — a bad entry contributes
  // nothing (derivation is validation-like, not a build).
  function splitEntry(entry) {
    if (!isPlainObject(entry)) return { envelope: null, inner: null };
    var envelope = null;
    if (isPlainObject(entry.envelope)) {
      envelope = entry.envelope;
    } else if (typeof entry.sender === 'string' || typeof entry.msg_id === 'string') {
      envelope = entry; // the entry IS the envelope
    }
    var inner = null;
    var raw = null;
    if (isPlainObject(entry.inner)) {
      inner = entry.inner;
    } else if (isPlainObject(entry.decrypted)) {
      inner = entry.decrypted;
    } else if (isPlainObject(entry.plaintext)) {
      inner = entry.plaintext;
    } else if (typeof entry.plaintext === 'string') {
      raw = entry.plaintext;
    } else if (typeof entry.innerJson === 'string') {
      raw = entry.innerJson;
    } else if (isPlainObject(entry) && typeof entry.type === 'string' &&
               typeof entry.kind === 'string' && typeof entry.text === 'string') {
      inner = entry; // the entry IS the inner object (rare, tests)
    }
    if (inner === null && raw !== null) {
      try {
        var parsed = JSON.parse(raw);
        if (isPlainObject(parsed)) inner = parsed;
      } catch (e) {
        inner = null; // unparseable inner — contributes nothing
      }
    }
    return { envelope: envelope, inner: inner };
  }

  function isPresenceInner(inner, kind) {
    return inner !== null && inner.type === 'presence' && inner.kind === kind;
  }

  // ---------------------------------------------------------------------------
  // Derive — typingUsers(envelopes, nowEpoch, myId[, threadId])
  // ---------------------------------------------------------------------------
  //
  // Sender ids with a LIVE typing envelope: inner type "presence", kind
  // "typing", envelope exp > nowEpoch, sender != myId. One entry per
  // sender, most-recently-active (highest iat) first. When threadId is
  // given, only typing envelopes for that thread count.
  function typingUsers(envelopes, nowEpoch, myId, threadId) {
    if (!Array.isArray(envelopes)) return [];
    var t = (nowEpoch === undefined) ? nowSeconds() : nowEpoch;
    if (!Number.isSafeInteger(t) || t <= 0) return [];
    var latest = {}; // senderId -> max iat among live typing envelopes
    for (var i = 0; i < envelopes.length; i++) {
      var split = splitEntry(envelopes[i]);
      if (!isPresenceInner(split.inner, 'typing')) continue;
      if (threadId !== undefined && threadId !== null &&
          split.inner.thread_id !== undefined && split.inner.thread_id !== null &&
          split.inner.thread_id !== threadId) {
        continue;
      }
      var env = split.envelope;
      if (env === null) continue;
      if (typeof env.sender !== 'string' || env.sender.length === 0) continue;
      if (env.sender === myId) continue; // your own typing never shows to you
      if (!Number.isSafeInteger(env.exp) || env.exp <= t) continue; // expired
      var iat = Number.isSafeInteger(env.iat) ? env.iat : 0;
      if (latest[env.sender] === undefined || iat > latest[env.sender]) {
        latest[env.sender] = iat;
      }
    }
    var senders = Object.keys(latest);
    senders.sort(function (a, b) { return latest[b] - latest[a]; });
    return senders;
  }

  // ---------------------------------------------------------------------------
  // Derive — readState(envelopes)
  // ---------------------------------------------------------------------------
  //
  // { senderId: maxSeq } over read markers (inner type "presence", kind
  // "read", integer seq). Entries without a valid seq contribute nothing.
  function readState(envelopes) {
    if (!Array.isArray(envelopes)) return {};
    var state = {};
    for (var i = 0; i < envelopes.length; i++) {
      var split = splitEntry(envelopes[i]);
      if (!isPresenceInner(split.inner, 'read')) continue;
      var env = split.envelope;
      if (env === null) continue;
      if (typeof env.sender !== 'string' || env.sender.length === 0) continue;
      if (!Number.isSafeInteger(split.inner.seq) || split.inner.seq < 0) continue;
      if (state[env.sender] === undefined || split.inner.seq > state[env.sender]) {
        state[env.sender] = split.inner.seq;
      }
    }
    return state;
  }

  // ---------------------------------------------------------------------------
  // Derive — presence(envelopes, nowEpoch)
  // ---------------------------------------------------------------------------
  //
  // { senderId: lastActiveEpoch } from the MAXIMUM iat of ANY envelope per
  // sender — messages, receipts, typing and read markers alike. An
  // envelope with iat more than 300 s in the future of nowEpoch is
  // skipped (invalid per §7 step 2). "Active" is the caller's comparison:
  // lastActive within 60 s of nowEpoch. Returns the map, not a boolean,
  // so the caller can render "last seen Xm ago" as well as "online".
  function presence(envelopes, nowEpoch) {
    if (!Array.isArray(envelopes)) return {};
    var t = (nowEpoch === undefined) ? nowSeconds() : nowEpoch;
    if (!Number.isSafeInteger(t) || t <= 0) return {};
    var lastActive = {};
    for (var i = 0; i < envelopes.length; i++) {
      var split = splitEntry(envelopes[i]);
      var env = split.envelope;
      if (env === null) continue;
      if (typeof env.sender !== 'string' || env.sender.length === 0) continue;
      if (!Number.isSafeInteger(env.iat) || env.iat <= 0) continue;
      if (env.iat > t + MAX_FUTURE_SKEW_SECONDS) continue; // future-dated: not evidence
      if (lastActive[env.sender] === undefined || env.iat > lastActive[env.sender]) {
        lastActive[env.sender] = env.iat;
      }
    }
    return lastActive;
  }

  // ---------------------------------------------------------------------------
  // Public API — exactly the P5 API (P6 implements to this verbatim)
  // ---------------------------------------------------------------------------

  return {
    sendTyping: sendTyping,
    sendReadMarker: sendReadMarker,
    typingUsers: typingUsers,
    readState: readState,
    presence: presence
  };
});
