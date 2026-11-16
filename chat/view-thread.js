/**
 * view-thread.js — Chat thread rendering for the ghostcorpnet encrypted chat (ecc-1).
 *
 * Worker C6. Implements FILE-MAP §4 (C6) + §3 (envelope, verification order),
 * UI-SPEC §2.3 (chat thread) + §5 (states) + §6 (ordering, dedup), and
 * CRYPTO-DESIGN §10 (threading: reply_to / thread_id).
 *
 * What this file does:
 *   - Renders messages in relay-seq order (oldest at top, newest at bottom).
 *   - Header per message: sender display name, time (from `iat`, local time),
 *     and one verification badge per message.
 *   - Reply threading: `reply_to` renders as a quote of the parent message's
 *     text when the parent is available AND decrypted; `thread_id` groups
 *     messages (exposed via data-thread-id and groupThreads()).
 *   - Per-message verification badge from app/badges.js (C10), computed
 *     locally at render time — never trusted from a relay verdict. A local
 *     fail-closed fallback is used only when badges.js is absent or its
 *     function throws/returns nothing usable.
 *   - Undecryptable messages render as "? Undecryptable" with no plaintext
 *     guessed. Expired messages render dimmed with "⚠ Expired" (body still
 *     shown — it was valid when sent). Tampered / replay-suspected messages
 *     NEVER render as normal messages: their bodies stay hidden.
 *   - Tap a message (or its ⓘ button) for a detail sheet: msg_id, seq,
 *     sig_alg, expiry, plus sender, sent time, thread_id, reply_to.
 *
 * What this file does NOT do (other workers' scope):
 *   - It does not verify signatures, decrypt, or fetch anything itself.
 *     Callers (app.js / poll.js, via envelope.js + crypto-core.js) supply
 *     already-verified/decrypted records; this file only *renders* them and
 *     asks badges.js to compute the badge at render time. It never trusts a
 *     badge/verdict string carried on the envelope or supplied by the relay.
 *   - It does not send, poll, or store anything. No network, no storage.
 *   - It holds no keys and no plaintext of its own: message text arrives
 *     only as caller-supplied records, is rendered via textContent (never
 *     innerHTML), and is never written anywhere by this file.
 *
 * P6 — thread/compose polish (STATE-OF-THE-ART-BAR-2026-11-16, P6;
 * implements to the P5 API in that doc verbatim):
 *   - Typing indicator: "X is typing…" rendered from
 *     window.GhostChatPresence.typingUsers(envelopes, nowEpoch, myId)
 *     (own typing hidden). A local fallback derives the same list from
 *     the presence records when presence.js has not loaded yet.
 *   - Read ticks + "read by X": per own message, delivery states
 *     sending → sent → delivered → read, from
 *     window.GhostChatPresence.readState(envelopes) plus the RECEIVED
 *     receipts (relay/receipts.py D8: inner {"type": "receipt",
 *     "kind": "RECEIVED", "ref_msg_id": "<msg_id>"}).
 *   - Optimistic render: createThreadRenderer().addOptimistic(pending)
 *     shows an own send immediately (synchronous render, "sending"
 *     state). updateOptimistic() attaches the real msg_id/envelope when
 *     compose emits the built envelope; confirmOptimistic() /
 *     failOptimistic() upgrade it on publish confirm / failure. When the
 *     relay-accepted store copy arrives with the same msg_id it replaces
 *     the optimistic bubble in place — never a duplicate (dedupe by
 *     msg_id; optimistic records never enter the replay seen-map).
 *   - Presence envelopes (inner {"type": "presence", ...}) are filtered
 *     out of the message list — indicators only, never rendered as
 *     messages. RECEIVED receipts are likewise consumed for delivery
 *     state and not rendered as bubbles (JOIN-OK / PINNED receipts keep
 *     their existing rendering). All filtered records stay available via
 *     getPresenceRecords() / getReceipts() and in the render result.
 *   - Read markers: when a render shows newly-read messages, the
 *     renderer calls window.GhostChatPresence.sendReadMarker({upToSeq,
 *     publish, sender, signingKey, recipientPublicKeys, recipients})
 *     with the highest rendered relay seq (throttled inside
 *     presence.js; 1 per 30 s, only when the watermark advances). The
 *     bare {upToSeq, publish} shape carries no key material, so the
 *     renderer resolves sender + signing key + recipient keys from its
 *     options (currentUserId, signingKey / getSigningKey, participants
 *     / recipientPublicKeys) — or a buildEnvelope(inner, ctx) override
 *     via opts.presenceBuildEnvelope — and skips the send when any of
 *     it is missing, rather than calling presence.js in a shape that
 *     throws. publish is likewise required by presence.js (BAD_PUBLISH
 *     without it). See resolvePresenceSendOpts().
 *     DOC VS FILE (recorded, not "fixed"): the bar doc's P5 API block
 *     shows sendTyping({threadId, publish}) / sendReadMarker({upToSeq,
 *     publish}) with no key material; the landed presence.js REQUIRES
 *     sender + signingKey + recipientPublicKeys (or a buildEnvelope
 *     override), REQUIRES publish, and REQUIRES sendTyping's threadId
 *     to be a UUIDv4. This file follows the doc's call shapes and
 *     extends them with exactly those fields, per the 2026-11-16
 *     design note. readState() also returns a bare {senderId: maxSeq}
 *     map (the doc does not specify its shape); the normalizer here
 *     accepts that plus wrapped variants.
 *     OPTIONS the caller (app.js) must pass for presence SENDS to
 *     actually publish (rendering/derivation need none of these):
 *     currentUserId (sender), signingKey or getSigningKey() (the
 *     keys-store contract), participants with encPublicKey/enc_pub_pem
 *     or recipientPublicKeys, and publishPresence / publishEnvelope /
 *     publish. presenceBuildEnvelope replaces the key resolution.
 *     threadId (UUIDv4) threads the marker; sendReadMarkers: false
 *     disables markers entirely.
 *   - Presence.js is written in parallel (P5) to the same bar doc. Every
 *     call into it is defensive: missing module, a throw, or an
 *     unusable return falls back to local derivation from the same
 *     records, and never breaks rendering. If a P5 function name in the
 *     doc and the landed file disagree, the DOC wins (see the report).
 *
 * Input record shape (one per message; see normalizeMessage):
 *   {
 *     seq: number | null,          // relay-assigned seq (FILE-MAP §3 manifest);
 *                                  // null = pending, not yet accepted
 *     envelope: { ...ecc-1 envelope... },   // or pass the envelope itself
 *     text: string | null,         // decrypted plaintext `text` (§6.4), or
 *                                  // null when undecryptable / not decrypted
 *     pending: boolean,            // own message, sent but not yet accepted
 *     system: boolean,             // system event row (key published, joined…)
 *     verification: {              // local verification outcome, if known
 *       signatureValid: boolean | null, // true only if the signature verified
 *       keyVerified: boolean | null,    // sender key verified out-of-band (§2.2)
 *       replaySuspected: boolean,       // same msg_id seen with other bytes
 *       decryptError: string | null,    // e.g. 'no-wrapped-key' — class only,
 *                                        // never a stack trace, never plaintext
 *       verifiedAt: number | null       // unix seconds of the local check
 *     }
 *   }
 *   Callers may also pass the envelope directly with `seq`, `text` and
 *   `verification` attached as sibling fields; normalizeMessage() accepts both.
 *
 * Badge contract — app/badges.js (C10), as landed:
 *   window.GhostChatBadges.badgeFor(envelope, context) -> Promise<result>
 * where `envelope` is the RAW ecc-1 envelope (not this file's normalized
 * record — badgeFor validates its shape itself, strips the relay-added
 * `seq`, and re-runs every §7 check locally), and `context` is:
 *   { me, keyDirectory, seenIds, ownerVerified, reverify, now,
 *     privateKey | unwrapKey }
 *   - me: the local participant id (this file passes options.currentUserId).
 *   - keyDirectory: participants.json entries (array / {participants} /
 *     Map). Only status "pinned" entries verify anything.
 *   - seenIds: seen-ledger state (Set / Array / {has(id)}). This file
 *     ALWAYS passes reverify: true when rendering, because rendering is
 *     re-verification of already-accepted messages — C10's contract says
 *     otherwise every accepted message would report Replay. Replay
 *     detection at render time is this file's own dedup (same msg_id +
 *     different bytes), which short-circuits to the replay badge before
 *     badgeFor is ever called.
 *   - ownerVerified: ids the owner marked verified out-of-band (§2.2).
 *   - privateKey (RSA-OAEP CryptoKey) or unwrapKey (async fn): needed
 *     for C10's steps 6–8. If the caller supplies neither (keyless
 *     visitor, UI-SPEC §4.2 Mode A), badgeFor honestly reports
 *     "? Undecryptable" for messages whose signature passes — app.js must
 *     pass its key through options for the normal owner view.
 * Result: { badge, status, reason, detail, sender, msgId,
 *   senderOwnerVerified, checks }, status one of 'signed' | 'expired' |
 *   'replay' | 'tampered' | 'undecryptable' | 'unverified' (sender
 *   unpinned / unknown / revoked / sig_alg mismatch — C10's sixth badge,
 *   the FILE-MAP C10 list plus the brief's "? Unverified").
 *   `senderOwnerVerified === false` alongside a Signed badge is what
 *   drives UI-SPEC §2.3's second, smaller "⚠ Unverified key" tag.
 * If badges.js is absent, returns nothing usable, or throws (e.g.
 * WebCrypto unavailable — C10 throws rather than fabricating a badge),
 * this file falls back to computeFallbackBadge() — a deterministic local
 * mapping from the supplied verification fields + expiry. The fallback
 * is fail-closed: a message is shown as a normal message ONLY when
 * signatureValid === true and the badge is Signed or Expired.
 *
 * Security rules enforced here, regardless of what the caller passes:
 *   1. A body is shown ONLY when signatureValid === true AND the badge is
 *      Signed or Expired (or the message is the sender's own pending bubble
 *      or a system row). Supplied `text` is otherwise never rendered.
 *   2. Tampered bodies are never revealed, not even on tap.
 *   3. Replay-suspected bodies are hidden by default; tap reveals them with
 *      a red border (UI-SPEC §2.3) — and only after the explicit tap.
 *   4. Undecryptable messages show a placeholder; no plaintext is guessed,
 *      reconstructed, or shown from any other field (ct / mac / wrapped_keys
 *      are never rendered as text).
 *   5. All message text is inserted via textContent / DOM nodes only.
 *      URLs become <a> links only for http(s) schemes (rel="noopener",
 *      target="_blank"); anything else renders as plain text.
 *
 * Runs as a plain <script> (window.GhostChatThread) or under Node/CommonJS
 * (module.exports) for tests. No dependencies, no build step, no framework.
 */

'use strict';

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.GhostChatThread = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {

  // ---------------------------------------------------------------------------
  // Constants — FILE-MAP §3 / UI-SPEC §2.3 badge labels (verbatim)
  // ---------------------------------------------------------------------------

  var BADGE_LABELS = {
    signed: '✓ Signed',
    expired: '⚠ Expired',
    replay: '⛔ Replay suspected',
    tampered: '⛔ Tampered',
    undecryptable: '? Undecryptable',
    unverified: '? Unverified',
    decrypting: '… Decrypting',
    pending: '… Sending',
    unknown: '? Undecryptable'
  };

  // Badge statuses whose body may be shown (UI-SPEC §2.3). Everything else
  // hides the body. 'expired' shows the body WITH an expiry note.
  var BODY_VISIBLE_STATUSES = { signed: true, expired: true };

  var MAX_QUOTE_CHARS = 120;   // reply-quote truncation (UI-SPEC §2.5 uses ~60
                                // for audit rows; thread quotes show a little more)
  var MAX_PLAINTEXT_RENDER = 64 * 1024; // FILE-MAP §3: 64 KiB plaintext cap

  var PARTICIPANT_IDS = ['jarvis', 'chatgpt', 'owner'];

  // P6 — presence / delivery (STATE-OF-THE-ART-BAR-2026-11-16, P5/P6).
  // Typing envelopes carry TTL 10 s (bar doc P5); a typing indicator is
  // shown only while the envelope is that fresh.
  var TYPING_TTL_SECONDS = 10;
  // Delivery states for own messages, in upgrade order.
  var DELIVERY_STATES = ['sending', 'sent', 'delivered', 'read'];
  var DELIVERY_LABELS = {
    sending: 'Sending…',
    sent: '✓ Sent',
    delivered: '✓✓ Delivered',
    read: '✓✓ Read',
    failed: 'Not sent',
    queued: 'Queued — will send when online'
  };

  // ---------------------------------------------------------------------------
  // Small helpers
  // ---------------------------------------------------------------------------

  function isObject(v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
  }

  function nowSeconds(nowFn) {
    if (typeof nowFn === 'function') {
      var v = nowFn();
      if (typeof v === 'number' && isFinite(v)) return Math.floor(v);
    }
    return Math.floor(Date.now() / 1000);
  }

  function isValidUnixSeconds(n) {
    return typeof n === 'number' && isFinite(n) && n > 0 &&
      n < 4102444800; // sanity: before 2100-01-01
  }

  // Time from `iat` (FILE-MAP §3: unix epoch seconds, UTC). Displayed in the
  // viewer's local time, HH:MM (UI-SPEC §2.3). Full date appears in details.
  function formatTime(unixSeconds) {
    if (!isValidUnixSeconds(unixSeconds)) return '—';
    var d = new Date(unixSeconds * 1000);
    var hh = d.getHours();
    var mm = d.getMinutes();
    return (hh < 10 ? '0' : '') + hh + ':' + (mm < 10 ? '0' : '') + mm;
  }

  function formatDateTime(unixSeconds) {
    if (!isValidUnixSeconds(unixSeconds)) return '—';
    var d = new Date(unixSeconds * 1000);
    var y = d.getFullYear();
    var mo = d.getMonth() + 1;
    var day = d.getDate();
    return y + '-' + (mo < 10 ? '0' : '') + mo + '-' +
      (day < 10 ? '0' : '') + day + ' ' + formatTime(unixSeconds);
  }

  function truncateText(text, maxChars) {
    if (typeof text !== 'string') return '';
    if (text.length <= maxChars) return text;
    return text.slice(0, maxChars) + '…';
  }

  // ---------------------------------------------------------------------------
  // Normalizing caller records
  // ---------------------------------------------------------------------------
  //
  // Accepts either { envelope, seq, text, verification, ... } or a bare
  // envelope with seq/text/verification attached. Never trusts a badge or
  // `verified` flag carried on the envelope/relay payload: any such field is
  // ignored here (badges are computed locally at render time).

  var ENVELOPE_FIELDS = ['v', 'msg_id', 'sender', 'recipients', 'iat', 'exp',
    'reply_to', 'thread_id', 'alg', 'sig_alg', 'iv', 'ct', 'mac',
    'wrapped_keys', 'sig'];

  function looksLikeEnvelope(v) {
    return isObject(v) && typeof v.msg_id === 'string' &&
      typeof v.sender === 'string';
  }

  // P6 — a record is an own not-yet-accepted bubble when any of these
  // hold: the explicit `pending` flag, the compose pending shape
  // (status 'pending' / 'encrypting', view-compose.js newPendingRecord),
  // or the `optimistic` marker compose stamps on its pending records.
  function isPendingRecord(raw) {
    if (raw.pending === true) return true;
    if (raw.optimistic === true) return true;
    return raw.status === 'pending' || raw.status === 'encrypting';
  }

  function normalizeMessage(raw) {
    if (!isObject(raw)) return null;
    var envelope = null;
    var seq = null;
    var text = null;
    var verification = {};
    var pending = false;
    var system = false;
    var status = null;

    if (isObject(raw.envelope) && looksLikeEnvelope(raw.envelope)) {
      envelope = raw.envelope;
      seq = (typeof raw.seq === 'number') ? raw.seq : null;
      text = (typeof raw.text === 'string') ? raw.text : null;
      if (isObject(raw.verification)) verification = raw.verification;
      pending = isPendingRecord(raw);
      system = raw.system === true || raw.type === 'system';
      status = (typeof raw.status === 'string') ? raw.status : null;
      // A bare `seq` on the envelope itself (relay adds seq to the stored
      // envelope, FILE-MAP §3) counts when no sibling seq was given.
      if (seq === null && typeof envelope.seq === 'number') seq = envelope.seq;
    } else if (looksLikeEnvelope(raw)) {
      envelope = raw;
      seq = (typeof raw.seq === 'number') ? raw.seq : null;
      text = (typeof raw.text === 'string') ? raw.text : null;
      if (isObject(raw.verification)) verification = raw.verification;
      pending = isPendingRecord(raw);
      system = raw.system === true || raw.type === 'system';
      status = (typeof raw.status === 'string') ? raw.status : null;
    } else {
      return null;
    }

    // System rows carry display text in `text` (not an encrypted payload).
    if (system && typeof raw.text === 'string') text = raw.text;

    return {
      seq: seq,
      envelope: envelope,
      msg_id: envelope.msg_id,
      sender: envelope.sender,
      iat: envelope.iat,
      exp: envelope.exp,
      sig_alg: envelope.sig_alg,
      reply_to: (typeof envelope.reply_to === 'string') ? envelope.reply_to : null,
      thread_id: (typeof envelope.thread_id === 'string')
        ? envelope.thread_id : envelope.msg_id,
      recipients: Array.isArray(envelope.recipients) ? envelope.recipients : [],
      text: text,
      verification: verification,
      pending: pending,
      system: system,
      status: status,
      // P6 — the decrypted inner-plaintext object, when the caller
      // supplied it (or it can be recovered from `text`). Presence /
      // receipt detection reads this; normal messages have no `type`.
      inner: extractInner(raw, envelope, text),
      // P6 — optimistic bookkeeping (view-compose.js pending shape).
      optimistic: raw.optimistic === true,
      pendingId: (typeof raw.id === 'string') ? raw.id : null,
      // P6 — set by the stateful renderer on publish confirmation
      // (confirmOptimistic): the delivery line upgrades to 'sent' while
      // the badge stays '… Sending' until the store copy arrives.
      confirmedSent: raw.confirmedSent === true,
      deliveryOverride: (typeof raw.deliveryOverride === 'string')
        ? raw.deliveryOverride : null,
      // Raw envelope size, for the detail sheet (UI-SPEC §2.3).
      envelopeSize: envelopeSizeBytes(envelope)
    };
  }

  function envelopeSizeBytes(envelope) {
    try {
      var s = JSON.stringify(envelope);
      if (typeof TextEncoder !== 'undefined') {
        return new TextEncoder().encode(s).length;
      }
      if (typeof Buffer !== 'undefined') return Buffer.byteLength(s, 'utf8');
      return s.length;
    } catch (e) {
      return null;
    }
  }

  // ---------------------------------------------------------------------------
  // Ordering + dedup — UI-SPEC §6
  // ---------------------------------------------------------------------------
  //
  // Order is relay sequence (FILE-MAP §3 manifest `seq`), NOT sender clock:
  // sender clocks can skew. Pending messages (seq null) sort after all
  // sequenced messages, in `iat` order. Ties break on iat, then msg_id, so
  // the order is total and deterministic.

  function compareMessages(a, b) {
    var aSeq = (typeof a.seq === 'number') ? a.seq : Infinity;
    var bSeq = (typeof b.seq === 'number') ? b.seq : Infinity;
    if (aSeq !== bSeq) return aSeq - bSeq;
    var aIat = (typeof a.iat === 'number') ? a.iat : 0;
    var bIat = (typeof b.iat === 'number') ? b.iat : 0;
    if (aIat !== bIat) return aIat - bIat;
    if (a.msg_id < b.msg_id) return -1;
    if (a.msg_id > b.msg_id) return 1;
    return 0;
  }

  function sortMessages(messages) {
    var copy = messages.slice();
    copy.sort(compareMessages);
    return copy;
  }

  // Dedup by msg_id (UI-SPEC §6). Same ID + same bytes = ignore silently.
  // Same ID + different bytes = replay: the later copy is kept but flagged
  // replaySuspected, so it renders as ⛔ Replay suspected, never merged.
  // `seen` is a Map msg_id -> fingerprint string, shared across renders by
  // the stateful renderer (createThreadRenderer) so a replay arriving in a
  // later poll is still caught. A message already in `seen` with the SAME
  // fingerprint is a re-render of a known message, not a new delivery, so
  // it is kept (once per call); only a second copy WITHIN one call is dropped.
  function envelopeFingerprint(record) {
    var e = record.envelope;
    return [e.ct || '', e.sig || '', e.iv || '', e.mac || ''].join('|');
  }

  function dedupMessages(normalized, seen) {
    var out = [];
    var batch = {}; // msg_ids already emitted by this call
    for (var i = 0; i < normalized.length; i++) {
      var rec = normalized[i];
      var fp = envelopeFingerprint(rec);
      if (!seen.has(rec.msg_id)) {
        seen.set(rec.msg_id, fp);
        batch[rec.msg_id] = true;
        out.push(rec);
      } else if (seen.get(rec.msg_id) !== fp) {
        // Same ID, different bytes: replay suspect — keep, flag, never merge.
        var flagged = Object.assign({}, rec, {
          verification: Object.assign({}, rec.verification, { replaySuspected: true })
        });
        flagged.isReplayDuplicate = true;
        out.push(flagged);
      } else if (batch[rec.msg_id]) {
        // Identical re-delivery inside this one call: ignore silently (UI-SPEC §6).
        continue;
      } else {
        // Re-render of a message seen in an earlier call: keep it.
        batch[rec.msg_id] = true;
        out.push(rec);
      }
    }
    return out;
  }

  // ---------------------------------------------------------------------------
  // Thread grouping — CRYPTO-DESIGN §10
  // ---------------------------------------------------------------------------
  //
  // thread_id = msg_id of the thread root; a root has reply_to null and
  // thread_id equal to its own msg_id. A reply copies the root's thread_id
  // from its parent. Grouping never reorders: the thread still renders in
  // relay-seq order; grouping is for callers (audit view, "jump to thread")
  // and is exposed on each bubble as data-thread-id.

  function groupThreads(normalized) {
    var groups = {};
    var order = [];
    for (var i = 0; i < normalized.length; i++) {
      var rec = normalized[i];
      var tid = rec.thread_id || rec.msg_id;
      if (!groups[tid]) {
        groups[tid] = [];
        order.push(tid);
      }
      groups[tid].push(rec);
    }
    var result = [];
    for (var j = 0; j < order.length; j++) {
      result.push({ thread_id: order[j], messages: groups[order[j]] });
    }
    return result;
  }

  function isThreadRoot(record) {
    return record.reply_to === null && record.thread_id === record.msg_id;
  }

  // ---------------------------------------------------------------------------
  // P6 — presence envelopes, typing, read state, delivery states
  // ---------------------------------------------------------------------------
  //
  // Presence envelopes and receipts are standard ecc-1 envelopes; only
  // their decrypted INNER plaintext marks them (bar doc P5):
  //   presence: {"text": "", "type": "presence",
  //              "kind": "typing" | "read", "thread_id": ..., "seq": N}
  //   receipt:  {"text": "...", "type": "receipt", "kind": "RECEIVED",
  //              "ref_msg_id": "<msg_id>"}          (relay/receipts.py D8)
  // A read marker's `seq` is a watermark: the sender has read everything
  // up to relay seq N. A RECEIVED receipt confirms one message (ref_msg_id).
  //
  // The caller (app.js / poll.js) supplies already-decrypted records, so
  // the inner object can arrive in several places; extractInner checks
  // them all and never guesses: a record is presence/receipt ONLY when
  // a parsed inner object carries type 'presence' / 'receipt'. Ordinary
  // message text that happens to be JSON (e.g. a user pasting
  // {"text": "hi"}) has no `type` field and is never misclassified.

  function tryParseInnerJson(s) {
    if (typeof s !== 'string') return null;
    var t = s.replace(/^\s+/, '');
    if (t.charAt(0) !== '{') return null;
    try {
      var parsed = JSON.parse(s);
      return isObject(parsed) ? parsed : null;
    } catch (e) {
      return null;
    }
  }

  // Recover the decrypted inner-plaintext object for a record, or null.
  // `raw` is the caller's record as passed in, `envelope` its ecc-1
  // envelope, `text` the decrypted inner `text` string (or null).
  function extractInner(raw, envelope, text) {
    var candidates = [];
    if (isObject(raw.inner)) candidates.push(raw.inner);
    if (isObject(raw.innerJson)) candidates.push(raw.innerJson);
    if (typeof raw.innerJson === 'string') candidates.push(tryParseInnerJson(raw.innerJson));
    if (typeof raw.innerPlaintext === 'string') candidates.push(tryParseInnerJson(raw.innerPlaintext));
    if (envelope && isObject(envelope.inner)) candidates.push(envelope.inner);
    if (envelope && isObject(envelope._inner)) candidates.push(envelope._inner);
    // A caller that kept only the inner `type`/`kind` as flat fields.
    if (typeof raw.innerType === 'string') {
      candidates.push({
        type: raw.innerType,
        kind: (typeof raw.innerKind === 'string') ? raw.innerKind : null,
        seq: (typeof raw.innerSeq === 'number') ? raw.innerSeq : null,
        ref_msg_id: (typeof raw.refMsgId === 'string') ? raw.refMsgId : null,
        thread_id: (typeof raw.threadId === 'string') ? raw.threadId : null
      });
    }
    if (typeof raw.type === 'string' &&
        (raw.type === 'presence' || raw.type === 'receipt')) {
      candidates.push({
        type: raw.type,
        kind: (typeof raw.kind === 'string') ? raw.kind : null,
        seq: (typeof raw.seq === 'number') ? raw.seq : null,
        ref_msg_id: (typeof raw.ref_msg_id === 'string') ? raw.ref_msg_id :
          (typeof raw.refMsgId === 'string' ? raw.refMsgId : null),
        thread_id: (typeof raw.thread_id === 'string') ? raw.thread_id : null
      });
    }
    // Last resort: `text` itself is the raw inner JSON string (callers
    // that hand the decrypted inner JSON through unchanged).
    candidates.push(tryParseInnerJson(text));
    for (var i = 0; i < candidates.length; i++) {
      var c = candidates[i];
      if (c && typeof c.type === 'string') return c;
    }
    // An inner object without `type` is a normal message inner
    // ({"text": ...}) — return it so callers can see it, but it is
    // never presence/receipt.
    for (var j = 0; j < candidates.length; j++) {
      if (candidates[j]) return candidates[j];
    }
    return null;
  }

  function isPresenceRecord(record) {
    return !!(record && isObject(record.inner) && record.inner.type === 'presence');
  }

  function isReceiptRecord(record, kind) {
    if (!record || !isObject(record.inner) || record.inner.type !== 'receipt') return false;
    if (typeof kind === 'string') return record.inner.kind === kind;
    return true;
  }

  // Split normalized records into chat messages (rendered), presence
  // envelopes (indicators only) and RECEIVED receipts (delivery state
  // only). JOIN-OK / PINNED receipts stay in the chat list — they are
  // join/key events the user may want to see; their existing rendering
  // (system rows / bubbles, as the caller supplies them) is unchanged.
  function partitionRecords(normalized) {
    var chat = [];
    var presenceRecords = [];
    var receipts = [];
    for (var i = 0; i < normalized.length; i++) {
      var rec = normalized[i];
      if (isPresenceRecord(rec)) {
        presenceRecords.push(rec);
      } else if (isReceiptRecord(rec, 'RECEIVED')) {
        receipts.push(rec);
      } else {
        chat.push(rec);
      }
    }
    return { chat: chat, presenceRecords: presenceRecords, receipts: receipts };
  }

  // Locate window.GhostChatPresence (P5), if it has loaded. Probes the
  // documented function names; a module missing a function simply does
  // not offer it, and the local fallback below is used instead.
  function getPresenceModule() {
    var g = null;
    if (typeof globalThis !== 'undefined') g = globalThis;
    else if (typeof self !== 'undefined') g = self;
    else if (typeof window !== 'undefined') g = window;
    if (g && g.GhostChatPresence) return g.GhostChatPresence;
    if (typeof root !== 'undefined' && root && root.GhostChatPresence) {
      return root.GhostChatPresence;
    }
    return null;
  }

  function resolvePublishFn(opts) {
    if (!opts) return null;
    if (typeof opts.publishPresence === 'function') return opts.publishPresence;
    if (typeof opts.publishEnvelope === 'function') return opts.publishEnvelope;
    if (typeof opts.publish === 'function') return opts.publish;
    return null;
  }

  var UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

  function isUuidV4(s) {
    return typeof s === 'string' && UUID_V4_RE.test(s);
  }

  function getCryptoCore() {
    if (typeof globalThis !== 'undefined' && globalThis.GhostChatCrypto) {
      return globalThis.GhostChatCrypto;
    }
    return null;
  }

  function findParticipantEntry(list, id) {
    for (var i = 0; i < list.length; i++) {
      if (list[i] && list[i].id === id) return list[i];
    }
    return null;
  }

  // Resolve [{recipient, publicKey}] for the presence default build path,
  // from opts.recipientPublicKeys (direct — tests / callers that already
  // hold the keys) or opts.participants / opts.keyDirectory (key-directory
  // entries carrying encPublicKey, or enc_pub_pem imported via
  // GhostChatCrypto when it has loaded; the import is cached on the
  // entry, as view-compose.js does). Returns null when no usable keys
  // resolve — the caller then skips the send instead of calling
  // presence.js without key material.
  async function resolveThreadRecipientKeys(opts) {
    if (Array.isArray(opts.recipientPublicKeys) &&
        opts.recipientPublicKeys.length > 0) {
      return opts.recipientPublicKeys;
    }
    var participants = opts.participants || opts.keyDirectory || null;
    if (!participants) return null;
    var core = getCryptoCore();
    var out = [];
    for (var i = 0; i < PARTICIPANT_IDS.length; i++) {
      var id = PARTICIPANT_IDS[i];
      var entry = null;
      if (Array.isArray(participants)) {
        entry = findParticipantEntry(participants, id);
      } else if (isObject(participants[id])) {
        entry = participants[id];
      } else if (isObject(participants) && participants.id === id) {
        entry = participants;
      }
      if (!entry) continue;
      var pub = entry.encPublicKey || entry.enc_public_key || null;
      if (!pub && typeof entry.enc_pub_pem === 'string' && entry.enc_pub_pem &&
          core && typeof core.importEncryptionPublicKey === 'function') {
        try {
          pub = await core.importEncryptionPublicKey(entry.enc_pub_pem);
          entry.encPublicKey = pub; // cache on the entry for later sends
        } catch (e) {
          pub = null;
        }
      }
      if (pub) out.push({ recipient: id, publicKey: pub });
    }
    return out.length > 0 ? out : null;
  }

  // P6 — resolve everything the presence.js send functions need that
  // the bare {upToSeq, publish} / {threadId, publish} shapes do not
  // carry: sender + signingKey + recipientPublicKeys (the default build
  // path), or a buildEnvelope(inner, ctx) override. publish is REQUIRED
  // by presence.js (it throws BAD_PUBLISH without one). Sender comes
  // from opts.currentUserId; the signing key from opts.signingKey or
  // opts.getSigningKey() (the keys-store contract, same as compose);
  // recipient keys from opts.recipientPublicKeys or the participants.
  // Returns the options object to spread into the send call, or null
  // when a send cannot be built — the caller skips silently, never a
  // call that throws.
  async function resolvePresenceSendOpts(opts) {
    if (!opts) return null;
    var publish = resolvePublishFn(opts);
    if (!publish) return null;
    var sender = (typeof opts.currentUserId === 'string' && opts.currentUserId)
      ? opts.currentUserId : null;
    if (!sender) return null;
    if (typeof opts.presenceBuildEnvelope === 'function') {
      return { sender: sender, publish: publish, buildEnvelope: opts.presenceBuildEnvelope };
    }
    var signingKey = null;
    var sigAlg = null;
    if (opts.signingKey) {
      signingKey = opts.signingKey;
      sigAlg = (typeof opts.sigAlg === 'string') ? opts.sigAlg : 'Ed25519';
    } else if (typeof opts.getSigningKey === 'function') {
      try {
        var got = await opts.getSigningKey();
        if (got && got.privateKey) {
          signingKey = got.privateKey;
          sigAlg = got.sigAlg || 'Ed25519';
        }
      } catch (e) {
        return null;
      }
    }
    if (!signingKey) return null;
    var recipientPublicKeys = null;
    try {
      recipientPublicKeys = await resolveThreadRecipientKeys(opts);
    } catch (e) {
      return null;
    }
    if (!recipientPublicKeys || recipientPublicKeys.length === 0) return null;
    var resolved = {
      sender: sender,
      signingKey: signingKey,
      recipientPublicKeys: recipientPublicKeys,
      publish: publish
    };
    if (sigAlg) resolved.sigAlg = sigAlg;
    if (Array.isArray(opts.recipients) && opts.recipients.length > 0) {
      resolved.recipients = opts.recipients;
    }
    return resolved;
  }

  function displayNameFor(id, participants) {
    if (participants && isObject(participants[id])) {
      var p = participants[id];
      if (typeof p.display_name === 'string' && p.display_name) return p.display_name;
      if (typeof p.displayName === 'string' && p.displayName) return p.displayName;
      if (typeof p.name === 'string' && p.name) return p.name;
    }
    if (id === 'owner') return 'Owner';
    if (id === 'jarvis') return 'Jarvis';
    if (id === 'chatgpt') return 'ChatGPT';
    return String(id);
  }

  // Normalize whatever typingUsers() returns to an array of sender ids.
  // Accepted: ['chatgpt'], [{sender: 'chatgpt'}], [{id: 'chatgpt'}],
  // {users: [...]}, {typing: [...]}. Anything else -> null (fallback).
  function normalizeTypingUsersResult(result) {
    var list = null;
    if (Array.isArray(result)) list = result;
    else if (isObject(result) && Array.isArray(result.users)) list = result.users;
    else if (isObject(result) && Array.isArray(result.typing)) list = result.typing;
    else if (isObject(result) && Array.isArray(result.typingUsers)) list = result.typingUsers;
    else return null;
    var ids = [];
    for (var i = 0; i < list.length; i++) {
      var item = list[i];
      var id = null;
      if (typeof item === 'string') id = item;
      else if (isObject(item)) {
        id = (typeof item.sender === 'string') ? item.sender :
          (typeof item.id === 'string') ? item.id :
          (typeof item.user === 'string') ? item.user : null;
      }
      if (typeof id === 'string' && id && ids.indexOf(id) === -1) ids.push(id);
    }
    return ids;
  }

  // Local fallback for typingUsers(): a typing presence envelope is live
  // while its sender clock is within the 10 s TTL (bar doc P5). Own
  // typing is always hidden, here and in the module path.
  function deriveTypingUsersLocal(presenceRecords, now, myId) {
    var ids = [];
    var freshest = {};
    for (var i = 0; i < presenceRecords.length; i++) {
      var rec = presenceRecords[i];
      if (!rec.inner || rec.inner.kind !== 'typing') continue;
      if (rec.sender === myId) continue;
      if (typeof rec.iat !== 'number') continue;
      if (now - rec.iat > TYPING_TTL_SECONDS || rec.iat > now + 300) continue;
      if (freshest[rec.sender] === undefined || rec.iat > freshest[rec.sender]) {
        freshest[rec.sender] = rec.iat;
      }
    }
    Object.keys(freshest).sort(function (a, b) {
      return freshest[b] - freshest[a]; // most recently typing first
    }).forEach(function (id) { ids.push(id); });
    return ids;
  }

  // Typing users, via the P5 API verbatim — typingUsers(envelopes,
  // nowEpoch, myId) — with the local fallback when presence.js has not
  // loaded, throws, or returns nothing usable. `envelopes` here are the
  // normalized presence records this file holds (each carries its raw
  // envelope plus the parsed inner object); the module receives them
  // exactly as the thread view sees them.
  function deriveTypingUsers(presenceRecords, now, myId) {
    var mod = getPresenceModule();
    if (mod && typeof mod.typingUsers === 'function') {
      try {
        var result = mod.typingUsers(presenceRecords, now, myId);
        var ids = normalizeTypingUsersResult(result);
        if (ids !== null) {
          return ids.filter(function (id) { return id !== myId; });
        }
      } catch (e) {
        // Fall through to the local derivation — never break rendering.
      }
    }
    return deriveTypingUsersLocal(presenceRecords, now, myId);
  }

  // Normalize whatever readState() returns to
  //   { maxReadSeq: {senderId: seq}, readByMsg: {msgId: [senderId]} }
  // Accepted shapes:
  //   {maxReadSeq: {jarvis: 12}} | {bySender: {...}} | {readUpTo: {...}}
  //   {readBy: {msgId: [...]}} | {byMsgId: {msgId: {read: [...]}}}
  //   [{sender, seq}] | [{sender, upToSeq}] | {jarvis: 12, ...} (bare map)
  // Anything else -> null (fallback).
  function normalizeReadStateResult(result) {
    if (!result) return null;
    var maxReadSeq = {};
    var readByMsg = {};
    var sawAnything = false;
    function noteRead(sender, seq) {
      if (typeof sender !== 'string' || typeof seq !== 'number') return;
      sawAnything = true;
      if (maxReadSeq[sender] === undefined || seq > maxReadSeq[sender]) {
        maxReadSeq[sender] = seq;
      }
    }
    function noteReadByMsg(msgId, senders) {
      if (typeof msgId !== 'string' || !Array.isArray(senders)) return;
      sawAnything = true;
      var list = readByMsg[msgId] || (readByMsg[msgId] = []);
      senders.forEach(function (s) {
        if (typeof s === 'string' && list.indexOf(s) === -1) list.push(s);
      });
    }
    if (Array.isArray(result)) {
      result.forEach(function (item) {
        if (!isObject(item)) return;
        var sender = item.sender || item.id || item.user;
        var seq = item.seq;
        if (typeof seq !== 'number') seq = item.upToSeq;
        if (typeof seq !== 'number') seq = item.maxSeq;
        noteRead(sender, seq);
        if (typeof item.msg_id === 'string' && Array.isArray(item.readBy)) {
          noteReadByMsg(item.msg_id, item.readBy);
        }
      });
    } else if (isObject(result)) {
      var map = result.maxReadSeq || result.bySender || result.readUpTo ||
        result.maxSeqBySender || null;
      if (isObject(map)) {
        Object.keys(map).forEach(function (sender) { noteRead(sender, map[sender]); });
      }
      var byMsg = result.readBy || result.byMsgId || result.readByMsg || null;
      if (isObject(byMsg)) {
        Object.keys(byMsg).forEach(function (msgId) {
          var v = byMsg[msgId];
          if (Array.isArray(v)) noteReadByMsg(msgId, v);
          else if (isObject(v) && Array.isArray(v.read)) noteReadByMsg(msgId, v.read);
        });
      }
      // Bare map {senderId: seq} with no wrapper key.
      if (!map && !byMsg) {
        Object.keys(result).forEach(function (k) {
          if (typeof result[k] === 'number') noteRead(k, result[k]);
        });
      }
    }
    if (!sawAnything) return null;
    return { maxReadSeq: maxReadSeq, readByMsg: readByMsg };
  }

  // Local fallback for readState(): read markers are watermarks — the
  // max `seq` each sender has read — plus RECEIVED receipts, which mark
  // individual messages delivered to their sender.
  function deriveReadStateLocal(presenceRecords, receipts) {
    var maxReadSeq = {};
    var readByMsg = {};
    var deliveredByMsg = {};
    for (var i = 0; i < presenceRecords.length; i++) {
      var rec = presenceRecords[i];
      if (!rec.inner || rec.inner.kind !== 'read') continue;
      var seq = (typeof rec.inner.seq === 'number') ? rec.inner.seq : null;
      if (seq === null && typeof rec.seq === 'number') seq = rec.seq;
      if (seq === null) continue;
      if (maxReadSeq[rec.sender] === undefined || seq > maxReadSeq[rec.sender]) {
        maxReadSeq[rec.sender] = seq;
      }
    }
    for (var j = 0; j < receipts.length; j++) {
      var r = receipts[j];
      var ref = (r.inner && typeof r.inner.ref_msg_id === 'string')
        ? r.inner.ref_msg_id : null;
      if (!ref && typeof r.reply_to === 'string') ref = r.reply_to;
      if (!ref) continue;
      var list = deliveredByMsg[ref] || (deliveredByMsg[ref] = []);
      if (list.indexOf(r.sender) === -1) list.push(r.sender);
    }
    return { maxReadSeq: maxReadSeq, readByMsg: readByMsg, deliveredByMsg: deliveredByMsg };
  }

  // Read state, via the P5 API verbatim — readState(envelopes) — with
  // the local fallback. RECEIVED receipts are folded in by this file
  // (the P5 signature takes presence envelopes only); a receipt from a
  // sender marks that one message delivered to them.
  function deriveReadState(presenceRecords, receipts) {
    var mod = getPresenceModule();
    var fromModule = null;
    if (mod && typeof mod.readState === 'function') {
      try {
        fromModule = normalizeReadStateResult(mod.readState(presenceRecords));
      } catch (e) {
        fromModule = null;
      }
    }
    var local = deriveReadStateLocal(presenceRecords, receipts || []);
    if (!fromModule) return local;
    // Merge: module watermarks win per sender; receipts add delivery.
    var merged = {
      maxReadSeq: Object.assign({}, local.maxReadSeq, fromModule.maxReadSeq),
      readByMsg: Object.assign({}, local.readByMsg, fromModule.readByMsg),
      deliveredByMsg: local.deliveredByMsg
    };
    return merged;
  }

  // Delivery state for ONE own message. Precedence: read > delivered >
  // sent > sending. `readInfo` is a deriveReadState() result. A read
  // marker watermark covers a message when its relay seq is <= the
  // sender's max-read seq; a message with no seq yet is never read or
  // delivered. Own markers/receipts never count (readBy/deliveredTo
  // exclude myId). Optimistic records carry deliveryOverride
  // ('sent' | 'failed' | 'queued') set by the renderer on publish
  // confirm / failure, which wins over the seq-based states below it.
  function deliveryStateFor(record, readInfo, myId) {
    var empty = { state: 'sending', readBy: [], deliveredTo: [] };
    if (!record) return empty;
    if (record.deliveryOverride === 'failed' ||
        record.status === 'failed') {
      return { state: 'failed', readBy: [], deliveredTo: [] };
    }
    if (record.deliveryOverride === 'queued' ||
        record.status === 'queued') {
      return { state: 'queued', readBy: [], deliveredTo: [] };
    }
    var readBy = [];
    var deliveredTo = [];
    if (readInfo) {
      if (typeof record.seq === 'number' && readInfo.maxReadSeq) {
        Object.keys(readInfo.maxReadSeq).forEach(function (sender) {
          if (sender === myId) return;
          if (record.seq <= readInfo.maxReadSeq[sender] &&
              readBy.indexOf(sender) === -1) readBy.push(sender);
        });
      }
      if (readInfo.readByMsg && readInfo.readByMsg[record.msg_id]) {
        readInfo.readByMsg[record.msg_id].forEach(function (sender) {
          if (sender !== myId && readBy.indexOf(sender) === -1) readBy.push(sender);
        });
      }
      if (readInfo.deliveredByMsg && readInfo.deliveredByMsg[record.msg_id]) {
        readInfo.deliveredByMsg[record.msg_id].forEach(function (sender) {
          if (sender !== myId && deliveredTo.indexOf(sender) === -1) deliveredTo.push(sender);
        });
      }
    }
    if (readBy.length > 0) return { state: 'read', readBy: readBy, deliveredTo: deliveredTo };
    if (deliveredTo.length > 0) return { state: 'delivered', readBy: readBy, deliveredTo: deliveredTo };
    if (record.deliveryOverride === 'sent' || record.confirmedSent === true) {
      return { state: 'sent', readBy: readBy, deliveredTo: deliveredTo };
    }
    if (typeof record.seq === 'number') {
      return { state: 'sent', readBy: readBy, deliveredTo: deliveredTo };
    }
    return empty;
  }

  function formatTypingLine(userIds, participants) {
    var names = userIds.map(function (id) { return displayNameFor(id, participants); });
    if (names.length === 0) return '';
    if (names.length === 1) return names[0] + ' is typing…';
    if (names.length === 2) return names[0] + ' and ' + names[1] + ' are typing…';
    var last = names.pop();
    return names.join(', ') + ' and ' + last + ' are typing…';
  }

  // "✓✓ Read by Jarvis" / "✓✓ Delivered" / "✓ Sent" / "Sending…" —
  // plain words, no jargon (copy-deck style). `delivery` is a
  // deliveryStateFor() result; names come from the participants map.
  function formatDeliveryLine(delivery, participants) {
    if (!delivery) return '';
    switch (delivery.state) {
      case 'read': {
        var names = delivery.readBy.map(function (id) {
          return displayNameFor(id, participants);
        });
        return '✓✓ Read by ' + names.join(', ');
      }
      case 'delivered': return '✓✓ Delivered';
      case 'sent': return '✓ Sent';
      case 'failed': return 'Not sent';
      case 'queued': return 'Queued — will send when online';
      default: return 'Sending…';
    }
  }

  // Send a read marker for the highest relay seq rendered in this view,
  // via the P5 API verbatim — sendReadMarker({upToSeq, publish, sender,
  // signingKey, recipientPublicKeys, recipients, buildEnvelope,
  // threadId}). The bare {upToSeq, publish} shape carries no key
  // material, so presence.js cannot build the envelope without the
  // sender + signing key + recipient keys (or a buildEnvelope override)
  // resolved here by resolvePresenceSendOpts(); publish is likewise
  // required by presence.js (BAD_PUBLISH without it). threadId is
  // passed only when opts.threadId is a valid UUIDv4 (a marker without
  // one is a root of its own thread). Only when the watermark advances
  // past the per-container last-sent seq (presence.js also throttles
  // internally, 1 per 30 s, and only on advance). Fire-and-forget from
  // render: returns a Promise<boolean> that never rejects; the
  // container watermark advances only on a successful publish (a
  // msg_id returned) — a throttle-null or a failed publish leaves it,
  // so a later render can retry the same seq. Never breaks rendering.
  function maybeSendReadMarker(maxSeq, opts, container) {
    if (!opts || opts.sendReadMarkers === false) return Promise.resolve(false);
    if (typeof maxSeq !== 'number' || maxSeq <= 0) return Promise.resolve(false);
    var last = 0;
    try {
      if (container && typeof container.__ghostChatLastReadSeq === 'number') {
        last = container.__ghostChatLastReadSeq;
      }
    } catch (e) { /* a stub container without property storage */ }
    if (maxSeq <= last) return Promise.resolve(false);
    var mod = getPresenceModule();
    if (!mod || typeof mod.sendReadMarker !== 'function') return Promise.resolve(false);
    if (!resolvePublishFn(opts)) return Promise.resolve(false);
    var threadId = (typeof opts.threadId === 'string' && isUuidV4(opts.threadId))
      ? opts.threadId : null;
    return resolvePresenceSendOpts(opts).then(function (sendOpts) {
      if (!sendOpts) return false;
      var arg = { upToSeq: maxSeq, publish: sendOpts.publish, sender: sendOpts.sender };
      if (sendOpts.buildEnvelope) {
        arg.buildEnvelope = sendOpts.buildEnvelope;
      } else {
        arg.signingKey = sendOpts.signingKey;
        arg.recipientPublicKeys = sendOpts.recipientPublicKeys;
        if (sendOpts.sigAlg) arg.sigAlg = sendOpts.sigAlg;
        if (sendOpts.recipients) arg.recipients = sendOpts.recipients;
      }
      if (threadId) arg.threadId = threadId;
      return mod.sendReadMarker(arg).then(function (msgId) {
        if (typeof msgId === 'string' && msgId) {
          try {
            if (container) container.__ghostChatLastReadSeq = maxSeq;
          } catch (e) { /* ignore */ }
          return true;
        }
        return false; // throttled / no advance — presence.js owns that state
      });
    }).catch(function () { return false; });
  }

  // ---------------------------------------------------------------------------
  // Badges — app/badges.js (C10), computed locally at render time
  // ---------------------------------------------------------------------------
  //
  // Normalized badge shape used everywhere in this file:
  //   { status, label, unverifiedKey, note, showBody, revealable }
  // `showBody` / `revealable` are derived here from the status, never taken
  // from an untrusted source: only Signed / Expired show a body; only Replay
  // is tap-to-reveal; Tampered is never revealable.

  function normalizeBadge(raw, record) {
    var status = null;
    var label = null;
    var unverifiedKey = false;
    var note = null;

    if (typeof raw === 'string') {
      label = raw;
      status = statusFromLabel(raw);
    } else if (isObject(raw)) {
      if (typeof raw.status === 'string') status = raw.status;
      else if (typeof raw.kind === 'string') status = raw.kind;
      else if (typeof raw.type === 'string') status = raw.type;
      else if (typeof raw.badge === 'string') status = statusFromLabel(raw.badge);
      if (typeof raw.label === 'string') label = raw.label;
      else if (typeof raw.text === 'string') label = raw.text;
      else if (typeof raw.badge === 'string') label = raw.badge;
      // C10's result shape: { badge, status, senderOwnerVerified, detail }.
      // senderOwnerVerified === false alongside Signed drives the second
      // "⚠ Unverified key" tag (UI-SPEC §2.3); it is not a badge itself.
      if (raw.senderOwnerVerified === false) unverifiedKey = true;
      if (raw.unverifiedKey === true || raw.unverified_key === true ||
          raw.keyUnverified === true) unverifiedKey = true;
      if (typeof raw.detail === 'string') note = raw.detail;
      else if (typeof raw.note === 'string') note = raw.note;
    }

    if (!status || !BADGE_LABELS[status]) {
      // Unrecognised badges.js output: fail closed, do not guess a status.
      return null;
    }
    if (!label) label = BADGE_LABELS[status];
    return finishBadge(status, label, unverifiedKey, note, record);
  }

  function statusFromLabel(label) {
    var l = String(label || '').toLowerCase();
    if (l.indexOf('tamper') !== -1) return 'tampered';
    if (l.indexOf('replay') !== -1) return 'replay';
    if (l.indexOf('expir') !== -1) return 'expired';
    if (l.indexOf('unverified') !== -1) return 'unverified';
    if (l.indexOf('undecryptable') !== -1 || l.indexOf('undecrypt') !== -1) return 'undecryptable';
    if (l.indexOf('decrypting') !== -1) return 'decrypting';
    if (l.indexOf('signed') !== -1) return 'signed';
    if (l.indexOf('sending') !== -1 || l.indexOf('pending') !== -1) return 'pending';
    return null;
  }

  function finishBadge(status, label, unverifiedKey, note, record) {
    var badge = {
      status: status,
      label: label,
      unverifiedKey: !!unverifiedKey,
      note: note || null,
      showBody: !!BODY_VISIBLE_STATUSES[status],
      revealable: status === 'replay'
    };
    // An "unverified sender key" tag rides ALONGSIDE ✓ Signed (UI-SPEC §2.3),
    // never instead of it — and only when the signature itself verified.
    if (status === 'signed' && record && record.verification &&
        record.verification.keyVerified === false) {
      badge.unverifiedKey = true;
    }
    return badge;
  }

  // Fail-closed local fallback. Used ONLY when badges.js is absent, throws,
  // or returns nothing usable. It maps the caller-supplied verification
  // outcome + expiry — never any relay verdict — onto the same badge set.
  // Precedence: the renderer's own replay verdict on this copy first
  // (dedup: same msg_id + different bytes), then FILE-MAP §3 / CRYPTO §7
  // order as C10 implements it — expiry (step 2) BEFORE the signature
  // (step 5), then decryptability. Anything unchecked is undecryptable,
  // never signed. The body gate in buildMessageBubble additionally
  // requires signatureValid === true, so an Expired badge on a message
  // whose signature failed still never shows its body.
  function computeFallbackBadge(record, now) {
    var v = record.verification || {};
    if (record.pending) {
      return finishBadge('pending', BADGE_LABELS.pending, false, null, record);
    }
    if (record.status === 'decrypting') {
      return finishBadge('decrypting', BADGE_LABELS.decrypting, false, null, record);
    }
    if (v.replaySuspected === true || record.isReplayDuplicate === true) {
      return finishBadge('replay', BADGE_LABELS.replay, false, null, record);
    }
    // §7 step 2 — expiry / future / TTL, before the signature.
    if (isValidUnixSeconds(record.exp) && record.exp <= now) {
      return finishBadge('expired', BADGE_LABELS.expired, false,
        'This message expired at ' + formatDateTime(record.exp) +
        '. It was valid when sent.', record);
    }
    if (isValidUnixSeconds(record.iat) && record.iat > now + 300) {
      return finishBadge('tampered', BADGE_LABELS.tampered, false, null, record);
    }
    if (isValidUnixSeconds(record.iat) && isValidUnixSeconds(record.exp) &&
        (record.exp <= record.iat || record.exp - record.iat > 86400)) {
      return finishBadge('tampered', BADGE_LABELS.tampered, false, null, record);
    }
    if (v.signatureValid === false) {
      return finishBadge('tampered', BADGE_LABELS.tampered, false, null, record);
    }
    if (typeof record.text !== 'string' || record.text.length === 0) {
      // No plaintext to show: either never decrypted, wrong recipient set,
      // or a decrypt failure. Never guess at a body.
      return finishBadge('undecryptable', BADGE_LABELS.undecryptable, false, null, record);
    }
    if (v.signatureValid !== true) {
      // Plaintext supplied but the signature was never verified (or the
      // caller did not say). Fail closed: do not show it as a normal message.
      return finishBadge('undecryptable', BADGE_LABELS.undecryptable, false, null, record);
    }
    return finishBadge('signed', BADGE_LABELS.signed, false, null, record);
  }

  // Locate the badges.js implementation (C10), if it has loaded. Probes the
  // documented function names in order; badgeFor (the landed C10 export)
  // wins, older/alternate names are accepted for forward-compat.
  function findBadgesImpl() {
    var g = (typeof root !== 'undefined') ? root : null;
    // `root` here is the UMD global (window/self); also check globalThis.
    var candidates = [];
    if (g && g.GhostChatBadges) candidates.push(g.GhostChatBadges);
    if (typeof globalThis !== 'undefined' && globalThis.GhostChatBadges) {
      candidates.push(globalThis.GhostChatBadges);
    }
    for (var i = 0; i < candidates.length; i++) {
      var mod = candidates[i];
      var names = ['badgeFor', 'computeBadge', 'getBadge', 'compute',
        'getVerificationBadge'];
      for (var j = 0; j < names.length; j++) {
        if (typeof mod[names[j]] === 'function') return mod[names[j]];
      }
      // A badges module that IS itself a function.
      if (typeof mod === 'function') return mod;
    }
    return null;
  }

  // Build the badgeFor context (C10 caller contract) from the render
  // options. The caller (app.js) supplies keyDirectory + its key material;
  // without them badgeFor can only report Undecryptable for signed-passing
  // messages (Mode A keyless view) — that is C10's honest answer, not a bug.
  function buildBadgeContext(opts, seen, now) {
    return {
      now: now,
      me: (typeof opts.currentUserId === 'string') ? opts.currentUserId : 'owner',
      keyDirectory: opts.keyDirectory || null,
      seenIds: seen || null,
      ownerVerified: opts.ownerVerified || null,
      // Rendering is re-verification of already-accepted messages: skip
      // C10's replay step here (its contract: reverify skips step 4).
      // Replay on a duplicate copy is settled by this file's dedup first.
      reverify: true,
      privateKey: opts.privateKey || null,
      unwrapKey: opts.unwrapKey || null
    };
  }

  // Resolve the badge for one record. Returns a badge object, or a Promise
  // of one when badges.js is async (badgeFor always is). Callers that need
  // a plain value use resolveBadgeSync(); renderThreadAsync() awaits the
  // async path. Short-circuits (pending / decrypting / replay) never call
  // badgeFor: those states are settled by the renderer, not by re-running
  // WebCrypto on an envelope that is not yet accepted or already flagged.
  function resolveBadge(record, context) {
    var now = context.now;
    if (record.pending) {
      return finishBadge('pending', BADGE_LABELS.pending, false, null, record);
    }
    if (record.status === 'decrypting') {
      return finishBadge('decrypting', BADGE_LABELS.decrypting, false, null, record);
    }
    if (record.verification && record.verification.replaySuspected === true ||
        record.isReplayDuplicate === true) {
      return finishBadge('replay', BADGE_LABELS.replay, false, null, record);
    }
    // Pre-resolved by renderThreadAsync (which awaited badgeFor for every
    // message before the first paint): use it verbatim so the first paint
    // never flashes the fallback badge.
    if (context.preResolvedBadges && context.preResolvedBadges.has(record.msg_id)) {
      var pre = context.preResolvedBadges.get(record.msg_id);
      if (pre) return pre;
    }
    var impl = findBadgesImpl();
    if (!impl) return computeFallbackBadge(record, now);
    var raw;
    try {
      // C10 takes the RAW envelope as its first argument — never this
      // file's normalized record (its shape check would reject it).
      raw = impl(record.envelope, context.badgeContext ||
        buildBadgeContext(context.opts || {}, context.seenIds, now));
    } catch (e) {
      // badgeFor throws rather than fabricating a badge (e.g. WebCrypto
      // unavailable). Fall back to the caller-supplied verification
      // outcome — which stays fail-closed: without signatureValid === true
      // the fallback never reports Signed.
      return computeFallbackBadge(record, now);
    }
    if (raw && typeof raw.then === 'function') {
      return raw.then(function (resolved) {
        var b = normalizeBadge(resolved, record);
        return b || computeFallbackBadge(record, now);
      }, function () {
        return computeFallbackBadge(record, now);
      });
    }
    var badge = normalizeBadge(raw, record);
    return badge || computeFallbackBadge(record, now);
  }

  function resolveBadgeSync(record, context) {
    var result = resolveBadge(record, context);
    if (result && typeof result.then === 'function') {
      // Async badges.js: the caller renders with the fail-closed fallback
      // now; renderThread() patches the badge element when it settles.
      return { badge: computeFallbackBadge(record, context.now), pending: result };
    }
    return { badge: result, pending: null };
  }

  // ---------------------------------------------------------------------------
  // DOM rendering
  // ---------------------------------------------------------------------------

  function el(doc, tag, className, text) {
    var node = doc.createElement(tag);
    if (className) node.className = className;
    if (typeof text === 'string') node.textContent = text;
    return node;
  }

  function getDocument(container) {
    if (container && container.ownerDocument) return container.ownerDocument;
    if (typeof document !== 'undefined') return document;
    throw new Error('view-thread: no document available (pass a container element)');
  }

  function senderDisplayName(record, participants) {
    if (participants && isObject(participants[record.sender])) {
      var p = participants[record.sender];
      if (typeof p.display_name === 'string' && p.display_name) return p.display_name;
      if (typeof p.displayName === 'string' && p.displayName) return p.displayName;
      if (typeof p.name === 'string' && p.name) return p.name;
    }
    return record.sender; // unknown sender: show the id, never invent a name
  }

  // Render plaintext as DOM nodes: plain text with line breaks preserved,
  // http(s) URLs as tappable links, nothing fetched (UI-SPEC §2.3 — no link
  // previews). All text goes through textContent; only http/https hrefs are
  // ever created, so javascript: / data: URLs render as inert text.
  function renderTextWithLinks(doc, text) {
    var frag = doc.createDocumentFragment();
    var urlRe = /(https?:\/\/[^\s<>"')\]]+)/g;
    var last = 0;
    var m;
    var remaining = String(text);
    // Split on newlines first so <br> nodes preserve line breaks exactly.
    var lines = remaining.split('\n');
    for (var li = 0; li < lines.length; li++) {
      if (li > 0) frag.appendChild(doc.createElement('br'));
      var line = lines[li];
      last = 0;
      urlRe.lastIndex = 0;
      while ((m = urlRe.exec(line)) !== null) {
        if (m.index > last) {
          frag.appendChild(doc.createTextNode(line.slice(last, m.index)));
        }
        var a = doc.createElement('a');
        a.textContent = m[0];
        a.setAttribute('href', m[0]);
        a.setAttribute('target', '_blank');
        a.setAttribute('rel', 'noopener noreferrer');
        frag.appendChild(a);
        last = m.index + m[0].length;
      }
      if (last < line.length) frag.appendChild(doc.createTextNode(line.slice(last)));
    }
    return frag;
  }

  function replyQuoteText(parentRecord) {
    if (!parentRecord) return null; // history gap — parent not in this view
    if (typeof parentRecord.text !== 'string' || parentRecord.text.length === 0) {
      return null; // parent undecryptable / failed: quote nothing, guess nothing
    }
    var v = parentRecord.verification || {};
    if (v.signatureValid !== true && !parentRecord.pending) return null;
    return truncateText(parentRecord.text, MAX_QUOTE_CHARS);
  }

  // One bubble's detail payload (tap → detail sheet). Metadata only; never
  // includes plaintext, ciphertext, wrapped keys, or signatures.
  function getMessageDetails(record, participants) {
    return {
      msg_id: record.msg_id,
      seq: (typeof record.seq === 'number') ? record.seq : null,
      seqLabel: (typeof record.seq === 'number')
        ? String(record.seq) : 'pending — not yet accepted by the relay',
      sender: record.sender,
      senderDisplayName: senderDisplayName(record, participants),
      sentAt: isValidUnixSeconds(record.iat) ? formatDateTime(record.iat) : '—',
      iat: record.iat,
      expiry: isValidUnixSeconds(record.exp) ? formatDateTime(record.exp) : '—',
      exp: record.exp,
      sig_alg: (typeof record.sig_alg === 'string') ? record.sig_alg : '—',
      alg: (record.envelope && typeof record.envelope.alg === 'string')
        ? record.envelope.alg : '—',
      thread_id: record.thread_id,
      reply_to: record.reply_to,
      recipients: record.recipients.slice(),
      envelopeSize: record.envelopeSize,
      signatureValid: (record.verification && typeof record.verification.signatureValid === 'boolean')
        ? record.verification.signatureValid : null,
      keyVerified: (record.verification && typeof record.verification.keyVerified === 'boolean')
        ? record.verification.keyVerified : null,
      replaySuspected: !!(record.verification && record.verification.replaySuspected) ||
        !!record.isReplayDuplicate,
      // P6 — delivery state, when computed at render time for an own
      // message (null for others' messages / unrendered records).
      deliveryState: (record.delivery && record.delivery.state) || null,
      readBy: (record.delivery && record.delivery.readBy)
        ? record.delivery.readBy.slice() : [],
      deliveredTo: (record.delivery && record.delivery.deliveredTo)
        ? record.delivery.deliveredTo.slice() : []
    };
  }

  function buildDetailSheet(doc, record, participants, onClose) {
    var details = getMessageDetails(record, participants);
    var overlay = el(doc, 'div', 'chat-detail-overlay');
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-label', 'Message details');
    var sheet = el(doc, 'div', 'chat-detail-sheet');
    var head = el(doc, 'div', 'chat-detail-head');
    head.appendChild(el(doc, 'h2', 'chat-detail-title', 'Message details'));
    var closeBtn = el(doc, 'button', 'chat-detail-close', '✕');
    closeBtn.setAttribute('type', 'button');
    closeBtn.setAttribute('aria-label', 'Close message details');
    closeBtn.addEventListener('click', function () { onClose(overlay); });
    head.appendChild(closeBtn);
    sheet.appendChild(head);

    var rows = [
      ['Message ID', details.msg_id],
      ['Relay sequence', details.seqLabel],
      ['Sender', details.senderDisplayName + ' (' + details.sender + ')'],
      ['Sent (sender clock)', details.sentAt],
      ['Expiry', details.expiry],
      ['Signature algorithm', details.sig_alg],
      ['Content algorithm', details.alg],
      ['Thread', details.thread_id],
      ['Reply to', details.reply_to || '— (thread root)'],
      ['Recipients', details.recipients.length ? details.recipients.join(', ') : '—'],
      ['Envelope size', (typeof details.envelopeSize === 'number')
        ? details.envelopeSize + ' bytes' : '—'],
      ['Signature valid', details.signatureValid === null ? 'not checked'
        : (details.signatureValid ? 'yes' : 'no')],
      ['Sender key verified', details.keyVerified === null ? 'not checked'
        : (details.keyVerified ? 'yes' : 'no')],
      ['Replay suspected', details.replaySuspected ? 'yes' : 'no']
    ];
    var dl = doc.createElement('dl');
    dl.className = 'chat-detail-list';
    for (var i = 0; i < rows.length; i++) {
      var dt = doc.createElement('dt');
      dt.textContent = rows[i][0];
      var dd = doc.createElement('dd');
      dd.textContent = rows[i][1];
      dl.appendChild(dt);
      dl.appendChild(dd);
    }
    sheet.appendChild(dl);
    var note = el(doc, 'p', 'chat-detail-note',
      'Metadata only — no plaintext, ciphertext, or key material is shown here.');
    sheet.appendChild(note);
    overlay.appendChild(sheet);
    overlay.addEventListener('click', function (ev) {
      if (ev.target === overlay) onClose(overlay);
    });
    return overlay;
  }

  function openDetails(doc, container, record, options) {
    closeDetails(container);
    var overlay = buildDetailSheet(doc, record, options.participants || {},
      function (node) {
        if (node.parentNode) node.parentNode.removeChild(node);
      });
    // Detail sheet is a bottom sheet (UI-SPEC §7): append at the thread root
    // so it overlays the list without disturbing scroll position.
    container.appendChild(overlay);
    var closeBtn = overlay.querySelector
      ? overlay.querySelector('.chat-detail-close') : null;
    if (closeBtn && closeBtn.focus) closeBtn.focus();
    if (typeof options.onDetailsOpen === 'function') {
      options.onDetailsOpen(getMessageDetails(record, options.participants || {}), record);
    }
    return overlay;
  }

  function closeDetails(container) {
    if (!container || !container.querySelectorAll) return;
    var open = container.querySelectorAll('.chat-detail-overlay');
    for (var i = 0; i < open.length; i++) {
      if (open[i].parentNode) open[i].parentNode.removeChild(open[i]);
    }
  }

  // Apply a resolved badge to an already-built bubble: badge label, tone
  // class, expired dimming, and body visibility. Re-applied when an async
  // badges.js promise settles, so the bubble never stays on a stale badge.
  function applyBadgeToBubble(bubble, badge, record, doc) {
    var badgeEl = bubble.querySelector
      ? bubble.querySelector('.chat-badge') : null;
    if (badgeEl) {
      badgeEl.textContent = badge.label;
      badgeEl.className = 'chat-badge chat-badge-' + badge.status;
      badgeEl.setAttribute('data-badge-status', badge.status);
    }
    bubble.setAttribute('data-badge', badge.status);
    bubble.classList.remove('chat-msg-expired', 'chat-msg-tampered',
      'chat-msg-replay', 'chat-msg-undecryptable', 'chat-msg-unverified');
    if (badge.status === 'expired') bubble.classList.add('chat-msg-expired');
    if (badge.status === 'tampered') bubble.classList.add('chat-msg-tampered');
    if (badge.status === 'replay') bubble.classList.add('chat-msg-replay');
    if (badge.status === 'undecryptable') bubble.classList.add('chat-msg-undecryptable');
    if (badge.status === 'unverified') bubble.classList.add('chat-msg-unverified');

    var bodyEl = bubble.querySelector
      ? bubble.querySelector('.chat-body') : null;
    var placeholderEl = bubble.querySelector
      ? bubble.querySelector('.chat-placeholder') : null;
    if (bodyEl && placeholderEl) {
      // Body visibility is decided by the badge + the fail-closed gate in
      // buildMessageBubble(); this re-application only swaps which of the
      // two nodes is shown, never invents a body.
      var showBody = bodyEl.getAttribute('data-body-allowed') === 'true' &&
        badge.showBody;
      bodyEl.style.display = showBody ? '' : 'none';
      placeholderEl.style.display = showBody ? 'none' : '';
      if (badge.status === 'expired' && showBody) {
        var noteEl = bubble.querySelector('.chat-expiry-note');
        if (noteEl) noteEl.style.display = '';
      }
    }

    // Unverified-key second tag (UI-SPEC §2.3): alongside ✓ Signed only.
    var unverifiedEl = bubble.querySelector
      ? bubble.querySelector('.chat-badge-unverified') : null;
    if (unverifiedEl) {
      unverifiedEl.style.display =
        (badge.status === 'signed' && badge.unverifiedKey) ? '' : 'none';
    }
  }

  function placeholderCopyFor(badge) {
    switch (badge.status) {
      case 'tampered':
        return 'Signature failed — this message may have been changed. Do not act on it.';
      case 'replay':
        return 'Possible replay — same message ID seen before. Tap to reveal after checking.';
      case 'undecryptable':
        return 'Couldn\'t decrypt — this message wasn\'t encrypted for your key, or your key changed. Check the key directory.';
      case 'unverified':
        return 'The sender\'s key hasn\'t been confirmed yet, so this message can\'t be checked. Do not act on it.';
      case 'decrypting':
        return 'Decrypting…';
      case 'pending':
        return 'Sending…';
      default:
        return 'This message can\'t be shown.';
    }
  }

  function buildSystemRow(doc, record, options) {
    var row = el(doc, 'div', 'chat-system-row');
    row.setAttribute('data-msg-id', record.msg_id);
    var text = (typeof record.text === 'string' && record.text)
      ? record.text : 'System event';
    row.textContent = text; // system rows carry no badge (UI-SPEC §2.3)
    row.setAttribute('role', 'note');
    return row;
  }

  function buildMessageBubble(doc, record, byId, options, context) {
    var isOwn = options.currentUserId &&
      record.sender === options.currentUserId;
    var bubble = el(doc, 'article', 'chat-msg' + (isOwn ? ' chat-msg-own' : ''));
    bubble.setAttribute('data-msg-id', record.msg_id);
    bubble.setAttribute('data-thread-id', record.thread_id || record.msg_id);
    bubble.setAttribute('data-seq',
      (typeof record.seq === 'number') ? String(record.seq) : 'pending');
    bubble.setAttribute('tabindex', '0');
    bubble.setAttribute('role', 'button');
    bubble.setAttribute('aria-label',
      senderDisplayName(record, options.participants || {}) + ', ' +
      formatTime(record.iat) + ', tap for details');

    // Resolve the badge locally at render time (badges.js first, fail-closed
    // fallback when it is absent). The body gate below uses the SAME badge.
    var resolved = resolveBadgeSync(record, context);
    var badge = resolved.badge;

    // --- header: sender · time · badge -------------------------------
    var header = el(doc, 'div', 'chat-header');
    header.appendChild(el(doc, 'span', 'chat-sender',
      senderDisplayName(record, options.participants || {})));
    var timeBtn = el(doc, 'button', 'chat-time', formatTime(record.iat));
    timeBtn.setAttribute('type', 'button');
    timeBtn.setAttribute('aria-label', 'Message details: sent ' +
      formatDateTime(record.iat));
    timeBtn.addEventListener('click', function (ev) {
      ev.stopPropagation();
      openDetails(doc, options.container, record, options);
    });
    header.appendChild(timeBtn);
    var badgeEl = el(doc, 'span', 'chat-badge chat-badge-' + badge.status, badge.label);
    badgeEl.setAttribute('data-badge-status', badge.status);
    header.appendChild(badgeEl);
    if (badge.status === 'signed') {
      var unverifiedEl = el(doc, 'span', 'chat-badge-unverified',
        '⚠ Unverified key');
      unverifiedEl.style.display = badge.unverifiedKey ? '' : 'none';
      header.appendChild(unverifiedEl);
    }
    var infoBtn = el(doc, 'button', 'chat-info', 'ⓘ');
    infoBtn.setAttribute('type', 'button');
    infoBtn.setAttribute('aria-label', 'Message details');
    infoBtn.addEventListener('click', function (ev) {
      ev.stopPropagation();
      openDetails(doc, options.container, record, options);
    });
    header.appendChild(infoBtn);
    bubble.appendChild(header);

    // --- reply quote (CRYPTO-DESIGN §10) -----------------------------
    if (record.reply_to) {
      var parent = byId[record.reply_to] || null;
      var quote = el(doc, 'div', 'chat-quote');
      var quoteText = replyQuoteText(parent);
      if (quoteText !== null) {
        var quoteName = parent
          ? senderDisplayName(parent, options.participants || {}) : '';
        quote.appendChild(el(doc, 'span', 'chat-quote-sender',
          quoteName ? quoteName + ': ' : ''));
        quote.appendChild(doc.createTextNode(quoteText));
      } else if (parent) {
        quote.textContent = 'Reply to a message that can\'t be shown here.';
      } else {
        // History gap (CRYPTO-DESIGN §10 reply_to_missing): the message is
        // still accepted; the quote simply cannot be resolved.
        quote.textContent = 'Reply to a message not in this view.';
      }
      quote.setAttribute('data-reply-to', record.reply_to);
      bubble.appendChild(quote);
    }

    // --- body vs placeholder (the fail-closed gate) -------------------
    // Show the body ONLY if: the badge allows it AND the signature verified
    // (or this is the sender's own pending bubble / a system row, handled
    // by the caller). Every other case renders the placeholder.
    var bodyAllowed = false;
    if (record.pending && isOwn) {
      bodyAllowed = true; // own typed text, not yet relay-accepted; labelled Sending…
    } else if (badge.showBody &&
        record.verification && record.verification.signatureValid === true &&
        typeof record.text === 'string' &&
        record.text.length <= MAX_PLAINTEXT_RENDER) {
      bodyAllowed = true;
    }
    if (record.pending && isOwn) badge = resolved.badge; // keep '… Sending'

    var bodyEl = el(doc, 'div', 'chat-body');
    bodyEl.setAttribute('data-body-allowed', bodyAllowed ? 'true' : 'false');
    if (bodyAllowed) {
      bodyEl.appendChild(renderTextWithLinks(doc, record.text));
    }
    bodyEl.style.display = bodyAllowed ? '' : 'none';
    bubble.appendChild(bodyEl);

    var placeholderEl = el(doc, 'div', 'chat-placeholder',
      placeholderCopyFor(badge));
    placeholderEl.style.display = bodyAllowed ? 'none' : '';
    if (badge.status === 'replay') {
      // Tap-to-reveal (UI-SPEC §2.3): only replay, never tampered. The
      // reveal shows the body with a red border — only when a body was
      // actually supplied AND the signature verified; otherwise the tap
      // only marks the row as inspected, it never invents content.
      placeholderEl.setAttribute('role', 'button');
      placeholderEl.setAttribute('tabindex', '0');
      placeholderEl.addEventListener('click', function (ev) {
        ev.stopPropagation();
        var canReveal = typeof record.text === 'string' &&
          record.text.length > 0 &&
          record.verification && record.verification.signatureValid === true;
        if (!canReveal) return;
        if (bodyEl.style.display === 'none') {
          bodyEl.style.display = '';
          placeholderEl.style.display = 'none';
          bubble.classList.add('chat-msg-replay-revealed');
        }
      });
    }
    if (badge.status === 'undecryptable' &&
        typeof options.onRetryDecrypt === 'function') {
      var retryBtn = el(doc, 'button', 'chat-retry', 'Retry decrypt');
      retryBtn.setAttribute('type', 'button');
      retryBtn.addEventListener('click', function (ev) {
        ev.stopPropagation();
        options.onRetryDecrypt(record);
      });
      placeholderEl.appendChild(doc.createTextNode(' '));
      placeholderEl.appendChild(retryBtn);
    }
    bubble.appendChild(placeholderEl);

    // Expired note (UI-SPEC §2.3): body shown, with the expiry line above it.
    if (badge.status === 'expired') {
      var noteEl = el(doc, 'div', 'chat-expiry-note',
        badge.note || ('This message expired at ' +
          formatDateTime(record.exp) + '. It was valid when sent.'));
      noteEl.style.display = bodyAllowed ? '' : 'none';
      // Keep the note visually above the body: move it before the body node.
      bubble.insertBefore(noteEl, bodyEl);
    }

    if (record.pending) {
      bubble.classList.add('chat-msg-pending');
      bubble.appendChild(el(doc, 'div', 'chat-pending-label', 'Sending…'));
    }
    // P6 — delivery line under own messages ("✓ Sent", "✓✓ Delivered",
    // "✓✓ Read by Jarvis"). Skipped while still 'sending' — the
    // 'Sending…' pending label above already says that.
    if (isOwn && context.deliveryById && context.deliveryById[record.msg_id]) {
      var delivery = context.deliveryById[record.msg_id];
      if (delivery.state !== 'sending') {
        var deliveryEl = el(doc, 'div', 'chat-delivery',
          formatDeliveryLine(delivery, options.participants || {}));
        deliveryEl.setAttribute('data-delivery-state', delivery.state);
        if (delivery.readBy && delivery.readBy.length > 0) {
          deliveryEl.setAttribute('data-read-by', delivery.readBy.join(','));
        }
        if (delivery.deliveredTo && delivery.deliveredTo.length > 0) {
          deliveryEl.setAttribute('data-delivered-to', delivery.deliveredTo.join(','));
        }
        bubble.appendChild(deliveryEl);
      }
    }
    if (badge.status === 'expired') bubble.classList.add('chat-msg-expired');
    if (badge.status === 'tampered') bubble.classList.add('chat-msg-tampered');
    if (badge.status === 'replay') bubble.classList.add('chat-msg-replay');
    if (badge.status === 'undecryptable') bubble.classList.add('chat-msg-undecryptable');
    if (badge.status === 'unverified') bubble.classList.add('chat-msg-unverified');
    bubble.setAttribute('data-badge', badge.status);
    // P6 — delivery state on the bubble itself (own messages only).
    if (isOwn && context.deliveryById && context.deliveryById[record.msg_id]) {
      bubble.setAttribute('data-delivery-state',
        context.deliveryById[record.msg_id].state);
    }

    // Tap the bubble (anywhere except the time / ⓘ / retry controls, which
    // stop propagation above) opens the detail sheet.
    bubble.addEventListener('click', function () {
      openDetails(doc, options.container, record, options);
    });
    bubble.addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter' || ev.key === ' ') {
        ev.preventDefault();
        openDetails(doc, options.container, record, options);
      }
      if (ev.key === 'Escape') closeDetails(options.container);
    });

    // Async badges.js: patch the badge (and body visibility) when it settles.
    if (resolved.pending) {
      resolved.pending.then(function (asyncBadge) {
        if (!bubble.parentNode) return; // bubble removed before it settled
        applyBadgeToBubble(bubble, asyncBadge, record, doc);
      });
    }

    return bubble;
  }

  // ---------------------------------------------------------------------------
  // Public render entry points
  // ---------------------------------------------------------------------------

  function renderMessages(container, rawMessages, options, seen) {
    if (!container) throw new Error('view-thread: renderThread needs a container element');
    var opts = options || {};
    opts.container = container;
    var doc = getDocument(container);
    var now = nowSeconds(opts.nowFn || opts.now);
    var myId = (typeof opts.currentUserId === 'string') ? opts.currentUserId : null;
    var seenMap = seen || new Map();
    var context = {
      now: now,
      seenIds: seenMap,
      participants: opts.participants || {},
      opts: opts,
      preResolvedBadges: opts._badgesById || null,
      badgeContext: buildBadgeContext(opts, seenMap, now),
      deliveryById: {}
    };

    var normalized = [];
    var inputs = Array.isArray(rawMessages) ? rawMessages : [];
    for (var i = 0; i < inputs.length; i++) {
      var rec = normalizeMessage(inputs[i]);
      if (rec) normalized.push(rec);
    }
    // P6 — optimistic/store reconciliation (dedupe by msg_id): when the
    // relay-accepted store copy of an optimistic message is in this same
    // batch, drop the optimistic twin BEFORE dedup, so it is never
    // flagged as a replay and never renders twice.
    var storeIds = {};
    for (var si = 0; si < normalized.length; si++) {
      if (!normalized[si].optimistic) storeIds[normalized[si].msg_id] = true;
    }
    normalized = normalized.filter(function (r) {
      return !r.optimistic || !storeIds[r.msg_id];
    });
    normalized = dedupMessages(normalized, seenMap);
    // P6 — optimistic records never enter the replay seen-map: a later
    // store copy with the same msg_id must arrive as first-seen, not as
    // a different-bytes replay.
    for (var oi = 0; oi < normalized.length; oi++) {
      if (normalized[oi].optimistic) seenMap.delete(normalized[oi].msg_id);
    }
    normalized = sortMessages(normalized);

    // P6 — presence envelopes and RECEIVED receipts leave the message
    // list here; they are indicators / delivery state only.
    var parts = partitionRecords(normalized);
    var chat = parts.chat;

    // P6 — typing + read state, via the P5 API (local fallback when
    // presence.js has not loaded). An explicit opts.typingUsers /
    // opts.readState lets the caller pass already-derived values.
    var typingIds = null;
    if (opts.typingUsers !== undefined && opts.typingUsers !== null) {
      typingIds = normalizeTypingUsersResult(opts.typingUsers);
    }
    if (typingIds === null) {
      typingIds = deriveTypingUsers(parts.presenceRecords, now, myId);
    }
    var readInfo = null;
    if (opts.readState !== undefined && opts.readState !== null &&
        isObject(opts.readState) && isObject(opts.readState.maxReadSeq)) {
      readInfo = opts.readState;
    } else {
      readInfo = deriveReadState(parts.presenceRecords, parts.receipts);
    }

    // P6 — delivery state per own message (sending → sent → delivered
    // → read), stashed on the record for the bubble + detail sheet.
    var deliveryStates = {};
    for (var di = 0; di < chat.length; di++) {
      var recD = chat[di];
      if (myId && recD.sender === myId) {
        recD.delivery = deliveryStateFor(recD, readInfo, myId);
        deliveryStates[recD.msg_id] = recD.delivery;
        context.deliveryById[recD.msg_id] = recD.delivery;
      } else {
        recD.delivery = null;
      }
    }

    var byId = {};
    for (var j = 0; j < chat.length; j++) byId[chat[j].msg_id] = chat[j];

    // Clear previous render (detail overlays included) and rebuild in seq order.
    while (container.firstChild) container.removeChild(container.firstChild);

    var list = el(doc, 'div', 'chat-list');
    list.setAttribute('role', 'log');
    list.setAttribute('aria-label', 'Chat messages, oldest first');
    if (chat.length === 0) {
      var empty = el(doc, 'div', 'chat-empty',
        'No messages yet. Say hello — your first message is encrypted before it leaves this browser.');
      empty.setAttribute('role', 'status');
      list.appendChild(empty);
    }
    for (var k = 0; k < chat.length; k++) {
      var recK = chat[k];
      if (recK.system) {
        list.appendChild(buildSystemRow(doc, recK, opts));
      } else {
        list.appendChild(buildMessageBubble(doc, recK, byId, opts, context));
      }
    }
    // P6 — typing indicator, last in the list, own typing hidden.
    if (typingIds.length > 0) {
      var typingEl = el(doc, 'div', 'chat-typing',
        formatTypingLine(typingIds, opts.participants || {}));
      typingEl.setAttribute('role', 'status');
      typingEl.setAttribute('aria-live', 'polite');
      typingEl.setAttribute('data-typing-users', typingIds.join(','));
      list.appendChild(typingEl);
    }
    container.appendChild(list);

    // P6 — read marker: the highest relay seq rendered in this view.
    var maxSeq = null;
    for (var mi = 0; mi < chat.length; mi++) {
      if (typeof chat[mi].seq === 'number' &&
          (maxSeq === null || chat[mi].seq > maxSeq)) {
        maxSeq = chat[mi].seq;
      }
    }
    if (maxSeq !== null) maybeSendReadMarker(maxSeq, opts, container);

    return {
      count: chat.length,
      messages: chat,
      threads: groupThreads(chat),
      presenceRecords: parts.presenceRecords,
      receipts: parts.receipts,
      typingUsers: typingIds,
      readState: readInfo,
      deliveryStates: deliveryStates
    };
  }

  // Synchronous render. Uses badges.js synchronously when it answers
  // synchronously; an async badges.js is patched in place when it settles
  // (fail-closed fallback badge shown meanwhile).
  function renderThread(container, rawMessages, options) {
    return renderMessages(container, rawMessages, options, new Map());
  }

  // Async render: awaits badges.js when it returns a Promise, so every
  // badge in the first paint is the badges.js verdict, not the fallback.
  // (The fallback still applies if badges.js is absent or throws.)
  function renderThreadAsync(container, rawMessages, options) {
    var opts = options || {};
    var now = nowSeconds(opts.nowFn || opts.now);
    var normalized = [];
    var inputs = Array.isArray(rawMessages) ? rawMessages : [];
    for (var i = 0; i < inputs.length; i++) {
      var rec = normalizeMessage(inputs[i]);
      if (rec) normalized.push(rec);
    }
    normalized = dedupMessages(normalized, new Map());
    normalized = sortMessages(normalized);
    var seenMap = new Map();
    var context = { now: now, seenIds: seenMap, participants: opts.participants || {}, opts: opts, preResolvedBadges: null, badgeContext: buildBadgeContext(opts, seenMap, now) };
    var badgePromises = normalized.map(function (rec) {
      if (rec.system) return Promise.resolve(null);
      var r = resolveBadge(rec, context);
      return (r && typeof r.then === 'function') ? r : Promise.resolve(r);
    });
    return Promise.all(badgePromises).then(function (badgeResults) {
      // Hand the awaited badges to the render so the first paint already
      // carries the badges.js verdicts (no fallback flash, no patch race).
      var byId = new Map();
      for (var i = 0; i < normalized.length; i++) {
        if (badgeResults[i]) byId.set(normalized[i].msg_id, badgeResults[i]);
      }
      var renderOpts = Object.assign({}, options, { _badgesById: byId });
      return renderMessages(container, rawMessages, renderOpts, new Map());
    });
  }

  // Stateful renderer: keeps the seen-ID map across polls so replays that
  // arrive in a later poll are still caught, and offers incremental adds.
  // app.js / poll.js (C3/C9) own the container; this owns only render state.
  function createThreadRenderer(container, options) {
    var opts = options || {};
    var seen = new Map();
    var current = []; // normalized chat records (presence/receipts kept apart)
    var currentById = {};
    var optimistic = []; // P6 — live optimistic records (never in `seen`)
    var presenceRecords = []; // P6 — last render's presence envelopes
    var receiptRecords = []; // P6 — last render's RECEIVED receipts
    var lastTypingUsers = []; // P6 — last render's typing derivation
    var lastReadState = null; // P6 — last render's read-state derivation
    var optimisticCounter = 0;

    // P6 — build a renderable record for an own send that has not
    // reached the store yet, from a view-compose.js pending record
    // ({id, msgId, text, envelope, status, sender, ...}). With an
    // envelope, normalizeMessage() does the work; without one (compose's
    // first 'encrypting' emit, before crypto runs) a synthetic record
    // keyed by the local pending id stands in — re-keyed by
    // updateOptimistic() when the envelope is built, replaced by the
    // store copy when it arrives. Never published, never in `seen`.
    function normalizeOptimistic(pending) {
      if (!isObject(pending)) return null;
      if (isObject(pending.envelope) &&
          typeof pending.envelope.msg_id === 'string') {
        var rec = normalizeMessage(pending);
        if (!rec) return null;
        rec.optimistic = true;
        rec.pending = true;
        if (typeof pending.id === 'string') rec.pendingId = pending.id;
        return rec;
      }
      var id = (typeof pending.id === 'string') ? pending.id :
        ('local-' + (++optimisticCounter) + '-' + Date.now());
      var sender = (typeof pending.sender === 'string') ? pending.sender :
        ((typeof opts.currentUserId === 'string') ? opts.currentUserId : 'owner');
      var iat = (typeof pending.iat === 'number') ? pending.iat :
        nowSeconds(opts.nowFn || opts.now);
      var synthetic = {
        v: 'ecc-1', msg_id: 'pending:' + id, sender: sender, recipients: [],
        iat: iat, exp: iat + 86400, reply_to: null,
        thread_id: (typeof pending.threadId === 'string')
          ? pending.threadId : ('pending:' + id),
        alg: 'A256CBC-HS256', sig_alg: 'Ed25519', iv: '', ct: '', mac: '',
        wrapped_keys: [], sig: ''
      };
      return {
        seq: null, envelope: synthetic, msg_id: synthetic.msg_id,
        sender: sender, iat: iat, exp: synthetic.exp, sig_alg: 'Ed25519',
        reply_to: (typeof pending.replyTo === 'string') ? pending.replyTo : null,
        thread_id: synthetic.thread_id,
        recipients: Array.isArray(pending.recipients)
          ? pending.recipients.slice() : [],
        text: (typeof pending.text === 'string') ? pending.text : null,
        verification: {}, pending: true, system: false,
        status: (typeof pending.status === 'string') ? pending.status : 'pending',
        inner: null, optimistic: true, pendingId: id, id: id,
        confirmedSent: false, deliveryOverride: null, envelopeSize: null
      };
    }

    function findOptimistic(idOrMsgId) {
      for (var i = 0; i < optimistic.length; i++) {
        var o = optimistic[i];
        if (o.pendingId === idOrMsgId || o.msg_id === idOrMsgId) return o;
      }
      return null;
    }

    // Attach a compose pending record's built envelope / msg_id / status
    // to a live optimistic record (same pending id, second onPending
    // emit). Mutates the live record; the next render re-normalizes it.
    function applyOptimisticUpdate(rec, src) {
      if (!isObject(src)) return rec;
      if (isObject(src.envelope) && typeof src.envelope.msg_id === 'string') {
        rec.envelope = src.envelope;
        rec.msg_id = src.envelope.msg_id;
      } else if (typeof src.msgId === 'string' && src.msgId) {
        rec.msg_id = src.msgId;
      }
      if (typeof src.status === 'string') rec.status = src.status;
      if (typeof src.text === 'string') rec.text = src.text;
      if (typeof src.threadId === 'string') rec.thread_id = src.threadId;
      if (typeof src.replyTo === 'string' || src.replyTo === null) {
        rec.reply_to = src.replyTo;
      }
      if (typeof src.seq === 'number') rec.seq = src.seq;
      return rec;
    }

    function renderAll() {
      var result = renderMessages(container, current.concat(optimistic), opts, seen);
      // The store copy supersedes its optimistic twin: drop the
      // optimistic entry once a non-optimistic record with the same
      // msg_id has rendered (dedupe by msg_id, never a duplicate).
      var storeIds = {};
      for (var s = 0; s < result.messages.length; s++) {
        if (!result.messages[s].optimistic) storeIds[result.messages[s].msg_id] = true;
      }
      optimistic = optimistic.filter(function (o) {
        return !(typeof o.msg_id === 'string' && storeIds[o.msg_id]);
      });
      // Optimistic records live only in `optimistic`, never in `current`.
      current = result.messages.filter(function (r) { return !r.optimistic; });
      presenceRecords = result.presenceRecords || [];
      receiptRecords = result.receipts || [];
      lastTypingUsers = result.typingUsers || [];
      lastReadState = result.readState || null;
      currentById = {};
      var all = current.concat(optimistic);
      for (var i = 0; i < all.length; i++) currentById[all[i].msg_id] = all[i];
      return result;
    }

    return {
      container: container,
      // Replace the whole list (e.g. initial load, "Load older messages").
      // Optimistic bubbles survive: they are re-merged at render time
      // and pruned only once their store copy arrives.
      setMessages: function (rawMessages) {
        seen = new Map();
        current = [];
        var inputs = Array.isArray(rawMessages) ? rawMessages : [];
        for (var i = 0; i < inputs.length; i++) {
          var rec = normalizeMessage(inputs[i]);
          if (rec) current.push(rec);
        }
        return renderAll();
      },
      // Add newly polled messages; dedup + replay detection apply against
      // everything seen so far, then re-render in relay-seq order.
      addMessages: function (rawMessages) {
        var inputs = Array.isArray(rawMessages) ? rawMessages : [];
        for (var i = 0; i < inputs.length; i++) {
          var rec = normalizeMessage(inputs[i]);
          if (rec) current.push(rec);
        }
        return renderAll();
      },
      // P6 — optimistic render. Shows an own send immediately (the
      // render is synchronous, so the bubble appears in under 100 ms of
      // the call — compose emits onPending before crypto runs). Called
      // with the compose pending record on every onPending emit: the
      // first call adds the bubble (no envelope yet), later calls with
      // the same pending id attach the built envelope / msg_id instead
      // of adding a second bubble. Returns the render result.
      addOptimistic: function (pending) {
        return this.addOrUpdateOptimistic(pending);
      },
      addOrUpdateOptimistic: function (pending) {
        if (!isObject(pending)) return renderAll();
        var existing = null;
        if (typeof pending.id === 'string') existing = findOptimistic(pending.id);
        if (!existing && typeof pending.msgId === 'string') {
          existing = findOptimistic(pending.msgId);
        }
        if (!existing && isObject(pending.envelope) &&
            typeof pending.envelope.msg_id === 'string') {
          existing = findOptimistic(pending.envelope.msg_id);
        }
        if (existing) {
          applyOptimisticUpdate(existing, pending);
          return renderAll();
        }
        var rec = normalizeOptimistic(pending);
        if (rec) optimistic.push(rec);
        return renderAll();
      },
      // P6 — attach the built envelope / msg_id to an optimistic bubble
      // (compose's second onPending emit). `update` is the compose
      // pending record or a partial {msgId, envelope, status, ...}.
      updateOptimistic: function (pendingIdOrMsgId, update) {
        var rec = findOptimistic(pendingIdOrMsgId);
        if (!rec) return null;
        applyOptimisticUpdate(rec, update);
        renderAll();
        return rec;
      },
      // P6 — publish confirmed (compose onSent): the delivery line
      // upgrades to 'sent' ("✓ Sent"). The bubble stays '… Sending'
      // until the store copy arrives and replaces it.
      confirmOptimistic: function (pendingIdOrMsgId, confirmation) {
        var rec = findOptimistic(pendingIdOrMsgId);
        if (!rec) return null;
        rec.deliveryOverride = 'sent';
        rec.confirmedSent = true;
        if (confirmation && typeof confirmation.seq === 'number') {
          rec.seq = confirmation.seq;
        }
        renderAll();
        return rec;
      },
      // P6 — publish failed (compose onFailed): the bubble shows
      // "Not sent" and stays until retried (retry re-uses the same
      // pending id via addOrUpdateOptimistic) or discarded.
      failOptimistic: function (pendingIdOrMsgId, error) {
        var rec = findOptimistic(pendingIdOrMsgId);
        if (!rec) return null;
        rec.deliveryOverride = 'failed';
        rec.status = 'failed';
        if (error !== undefined && error !== null) {
          rec.error = (error && error.message) ? error.message : String(error);
        }
        renderAll();
        return rec;
      },
      // P6 — drop an optimistic bubble (e.g. the user discarded it in
      // compose). The store copy, if it later arrives, still renders.
      removeOptimistic: function (pendingIdOrMsgId) {
        var rec = findOptimistic(pendingIdOrMsgId);
        if (!rec) return false;
        optimistic = optimistic.filter(function (o) { return o !== rec; });
        renderAll();
        return true;
      },
      getOptimistic: function () { return optimistic.slice(); },
      getPresenceRecords: function () { return presenceRecords.slice(); },
      getReceipts: function () { return receiptRecords.slice(); },
      getTypingUsers: function () { return lastTypingUsers.slice(); },
      getReadState: function () { return lastReadState; },
      // P6 — re-derive typing / read state from the current records and
      // re-render (e.g. after a typing envelope arrives without a poll).
      refreshPresence: function () { return renderAll(); },
      getMessages: function () {
        return sortMessages(current.concat(optimistic));
      },
      getMessageById: function (msgId) { return currentById[msgId] || null; },
      getThreads: function () { return groupThreads(this.getMessages()); },
      getDetails: function (msgId) {
        var rec = currentById[msgId];
        return rec ? getMessageDetails(rec, opts.participants || {}) : null;
      },
      verifyAll: function () {
        // Re-render, which recomputes every badge locally at render time
        // (UI-SPEC §2.3 "Verify all"). Returns the fresh badge counts.
        var result = renderAll();
        var counts = { signed: 0, expired: 0, replay: 0, tampered: 0, undecryptable: 0, unverified: 0, decrypting: 0, pending: 0 };
        var now = nowSeconds(opts.nowFn || opts.now);
        for (var i = 0; i < result.messages.length; i++) {
          var b = computeFallbackBadge(result.messages[i], now);
          // Prefer the live badges.js verdict when it answers synchronously.
          var live = resolveBadgeSync(result.messages[i], { now: now, seenIds: seen, participants: opts.participants || {}, opts: opts, badgeContext: buildBadgeContext(opts, seen, now) });
          var status = live.badge ? live.badge.status : b.status;
          if (counts[status] !== undefined) counts[status]++;
        }
        return { counts: counts, total: result.messages.length };
      },
      closeDetails: function () { closeDetails(container); },
      clear: function () {
        seen = new Map();
        current = [];
        currentById = {};
        optimistic = [];
        presenceRecords = [];
        receiptRecords = [];
        lastTypingUsers = [];
        lastReadState = null;
        while (container.firstChild) container.removeChild(container.firstChild);
      }
    };
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  return {
    renderThread: renderThread,
    renderThreadAsync: renderThreadAsync,
    createThreadRenderer: createThreadRenderer,
    // Exposed for tests / the audit view (C8) / app.js (C3):
    normalizeMessage: normalizeMessage,
    sortMessages: sortMessages,
    dedupMessages: dedupMessages,
    groupThreads: groupThreads,
    isThreadRoot: isThreadRoot,
    computeFallbackBadge: computeFallbackBadge,
    resolveBadge: resolveBadge,
    getMessageDetails: getMessageDetails,
    // P6 — presence / delivery helpers (exposed for tests / app.js):
    extractInner: extractInner,
    isPresenceRecord: isPresenceRecord,
    isReceiptRecord: isReceiptRecord,
    partitionRecords: partitionRecords,
    deriveTypingUsers: deriveTypingUsers,
    deriveReadState: deriveReadState,
    deliveryStateFor: deliveryStateFor,
    formatTypingLine: formatTypingLine,
    formatDeliveryLine: formatDeliveryLine,
    formatTime: formatTime,
    formatDateTime: formatDateTime,
    BADGE_LABELS: BADGE_LABELS
  };
});
