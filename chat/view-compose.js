/**
 * view-compose.js — compose / send view for the ghostcorpnet encrypted chat (ecc-1).
 *
 * Worker C7. Normative refs (FILE-MAP.md is authoritative; it wins on conflict):
 *   - FILE-MAP.md §3 (envelope `ecc-1`, canonical JSON, verification order),
 *     D9 (recipients default = all three participants), D10 (TTL default AND
 *     maximum 24 h), D15 (channel authorizes nothing), §4 C7.
 *   - design/CRYPTO-DESIGN.md §6 (envelope), §7 (verification order),
 *     §11 (limits: TTL <= 86400, plaintext <= 64 KiB, recipients 1-10),
 *     §10 (threading: reply_to / thread_id).
 *   - design/UI-SPEC.md §2.4 (compose/send), §5 (pending / queued / failed
 *     states), §6 (ordering / dedup by msg_id).
 *
 * What this file does:
 *   - Textarea, 4,000-character limit (UI-SPEC §2.4 step 4 proposal; the
 *     64 KiB plaintext cap of FILE-MAP §3 / CRYPTO-DESIGN §11 is also enforced).
 *   - Explicit per-recipient lock line shown BEFORE send, e.g.
 *     "Locked for: Jarvis, ChatGPT, you" (default all three, FILE-MAP D9).
 *     A 1:1 option exists only behind an explicit warning + acknowledgement
 *     that Jarvis cannot re-share 1:1 history if Jarvis is not a recipient.
 *   - Expiry picker, default 24 h, maximum 24 h (FILE-MAP D10).
 *   - Reply-to support: sets reply_to + thread_id (CRYPTO-DESIGN §10).
 *   - On send: builds the envelope (envelope.js A4 when present, otherwise
 *     the internal builder below using crypto-core.js A1 + canonical-json.js
 *     A3), shows a pending state, publishes via the owner's GitHub PAT
 *     (pat.js C13) or queues to the outbox (outbox.js C12) when offline /
 *     when publishing fails, then marks sent on confirmation.
 *   - On failure: fresh-envelope retry — new msg_id, new per-message keys,
 *     new IV — never resends the same envelope bytes with a new signature.
 *   - Never sends unsigned or unencrypted content: send is blocked unless
 *     a signing key is available, the envelope validates locally, and (when
 *     the sender's public signing key is supplied) the local signature
 *     verifies before publish.
 *   - P6 typing signal (STATE-OF-THE-ART-BAR-2026-11-16, P6): on compose
 *     input, calls window.GhostChatPresence.sendTyping({threadId,
 *     publish, sender, signingKey, recipientPublicKeys, recipients})
 *     — presence.js throttles internally (1 per 5 s). The bare
 *     {threadId, publish} shape carries no key material, so the signal
 *     resolves the sender + signing key + recipient keys here (or a
 *     buildEnvelope override via opts.presenceBuildEnvelope) and skips
 *     silently when any of it is missing; threadId must be a UUIDv4, so
 *     typing only signals inside an existing thread (reply target or
 *     opts.threadId). The call is defensive: with presence.js not yet
 *     loaded it is a silent no-op and never breaks typing or sending.
 *     The thread view (C6) renders the "X is typing…" indicator from
 *     the same module.
 *   - P6 optimistic render: send() emits onPending twice — first with
 *     status 'encrypting' (no envelope yet, so the thread view can show
 *     the bubble in under 100 ms, before crypto runs) and again with
 *     status 'pending' once the envelope is built (same pending id, now
 *     with msgId + envelope, so the thread view upgrades the same bubble
 *     instead of adding a second one). onSent / onFailed let the thread
 *     view upgrade the bubble to sent / failed. The pending record
 *     carries sender + iat + optimistic: true for exactly that wiring.
 *
 * What this file does NOT do (other workers own these):
 *   - Envelope build/parse/validate .......... A4 app/js/envelope.js
 *   - Crypto primitives ....................... A1 app/js/crypto-core.js
 *   - Canonical JSON .......................... A3 app/js/canonical-json.js
 *   - ES256 fallback primitives ............... A2 app/js/crypto-p256.js
 *     (P2: self-registers its ES256 handlers on GhostChatCrypto via
 *     registerSigAlg() when the file loads, so crypto-core's signBytes
 *     dispatches on sig_alg with no caller wiring; this file never
 *     signs directly.)
 *   - Presence (typing envelopes + read markers) .. P5 app/js/presence.js
 *     (window.GhostChatPresence; this file only calls its sendTyping()
 *     on input — the thread view renders the indicators).
 *   - GitHub PAT storage / use ................ C13 app/pat.js
 *   - Offline outbox storage / retry .......... C12 app/outbox.js
 *   - Private-key storage ..................... C17 app/keys-store.js
 *     (this file receives the signing key through `getSigningKey()` and
 *     never reads IndexedDB, localStorage, or any key store itself.)
 *   - Thread rendering / badges ............... C6 app/view-thread.js,
 *     C10 app/badges.js (pending/sent events are emitted via callbacks so
 *     the thread view can render the bubble; this file also shows its own
 *     compact pending/failed list under the compose box.)
 *
 * Dependency contracts (what this file expects from sibling modules):
 *   - window.GhostChatCrypto (A1): encryptMessage(plaintextBytes,
 *     [{recipient, publicKey}]) -> {iv, ct, mac, wrapped_keys} (base64url);
 *     signBytes(canonicalBytes, privateKey, sigAlg) -> base64url sig;
 *     verifySignature(canonicalBytes, sig, publicKey, sigAlg) -> boolean;
 *     textToBytes(text); MAX_PLAINTEXT_BYTES (64 KiB).
 *   - window.GhostCorpCanonicalJSON (A3): canonicalSignedBytes(envelope)
 *     -> Uint8Array of the canonical JSON of the envelope WITHOUT `sig`
 *     (and WITHOUT `seq`).
 *   - window.GhostChatEnvelope (A4, when it lands): buildEnvelope(input)
 *     where input is {text, sender, recipients, replyTo, threadId,
 *     ttlSeconds, signingKey, sigAlg, recipientPublicKeys} and the return
 *     is a Promise of a complete signed envelope; and/or
 *     validateEnvelope(envelope) -> {ok, errors[]}. If A4 is absent or its
 *     build throws, this file falls back to its internal builder below,
 *     which uses A1 + A3 directly and produces byte-identical envelopes
 *     for the same inputs (same canonical bytes, same crypto calls).
 *   - window.GhostChatPAT (C13, when it lands): publishEnvelope(envelope)
 *     -> Promise of a confirmation (any truthy value; {seq, url,
 *     receivedAt} honoured when present). Aliases tried, in order:
 *     publishEnvelope, publishMessage, publish, postEnvelope.
 *   - window.GhostChatOutbox (C12, when it lands): enqueue(envelope) ->
 *     Promise (or sync) acknowledgement; aliases tried: enqueue, queue,
 *     add, save. The outbox stores ENVELOPES (ciphertext) only — plaintext
 *     is kept in memory here, only until a fresh-envelope retry rebuilds
 *     from it or the pending item is discarded.
 *   All sibling lookups are defensive: a missing module is a clear error
 *   ("cannot send yet: ..."), never a silent plaintext send.
 *
 * Security rules enforced here:
 *   - Plaintext lives only in page memory (the textarea + pending items).
 *     It is never written to localStorage / IndexedDB / the outbox / the
 *     network except inside a signed, encrypted envelope.
 *   - No private-key material, secrets, or personal info in this file.
 *   - No forward secrecy in ecc-1 (FILE-MAP D14) — never claimed.
 *   - DOM is built with createElement / textContent only; user text is
 *     never inserted via innerHTML (no markup injection through a message).
 *
 * FILE-MAP conflicts found (FILE-MAP wins; implemented to FILE-MAP):
 *   1. UI-SPEC §2.4 step 5 proposes expiry options 1 h / 24 h / 7 d / 30 d /
 *      never, default 7 days. FILE-MAP D10 + CRYPTO-DESIGN §11 cap TTL at
 *      24 h (default AND maximum). Implemented: 1 h / 6 h / 24 h only,
 *      default 24 h; any requested TTL above 86400 s is clamped to 86400.
 *   2. UI-SPEC §2.4 assumes a relay POST /messages as the send path.
 *      FILE-MAP D1/D3 settle transport as the public git store published
 *      via the owner's GitHub PAT (pat.js). Implemented: PAT publish first;
 *      a caller-supplied deps.publishEnvelope may wire a different
 *      publisher (e.g. the relay probe, D14) without changing this file.
 *   3. UI-SPEC §2.4 step 4 calls the 4,000-char limit "NOT VERIFIED / OPEN
 *      DEPENDENCY" on a relay size limit. FILE-MAP §3 + CRYPTO-DESIGN §11
 *      bound plaintext at 64 KiB, which the 4,000-char UI limit sits well
 *      inside. Implemented: 4,000 chars (UI) AND 64 KiB plaintext (hard).
 *
 * Runs in a secure context (HTTPS / localhost) where WebCrypto exists, and
 * as a CommonJS module under Node >= 18 (globalThis.crypto.subtle) for tests.
 * No external resources, no network calls of its own (publish/outbox calls
 * are made only through the injected / sibling-module functions above).
 */

'use strict';

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.GhostChatCompose = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {

  // ---------------------------------------------------------------------------
  // Constants — FILE-MAP §3 / CRYPTO-DESIGN §6, §11; UI-SPEC §2.4
  // ---------------------------------------------------------------------------

  var ENVELOPE_VERSION = 'ecc-1';
  var ALG = 'A256CBC-HS256';
  var SIG_ALG_ED25519 = 'Ed25519';
  var SIG_ALG_ES256 = 'ES256';

  /** UI-SPEC §2.4 step 4 (proposal): 4,000 characters per message. */
  var MAX_CHARS = 4000;
  /** FILE-MAP §3 / CRYPTO-DESIGN §11: max 64 KiB plaintext per message. */
  var MAX_PLAINTEXT_BYTES = 64 * 1024;
  /** FILE-MAP D10 / CRYPTO-DESIGN §11: TTL default AND maximum 24 h. */
  var MAX_TTL_SECONDS = 86400;
  var DEFAULT_TTL_SECONDS = 86400;
  /** Clock-skew tolerance (FILE-MAP §3 verification order step 2). */
  var FUTURE_TOLERANCE_SECONDS = 300;

  /** Expiry picker options. 7 d / 30 d / "never" are NOT offered: D10 caps TTL at 24 h. */
  var TTL_OPTIONS = [
    { seconds: 3600, label: '1 hour' },
    { seconds: 21600, label: '6 hours' },
    { seconds: 86400, label: '24 hours' }
  ];

  var ALL_PARTICIPANTS = ['jarvis', 'chatgpt', 'owner'];
  var PARTICIPANT_LABELS = { jarvis: 'Jarvis', chatgpt: 'ChatGPT', owner: 'you' };
  var PARTICIPANT_DISPLAY = { jarvis: 'Jarvis', chatgpt: 'ChatGPT', owner: 'Owner' };

  var ENVELOPE_FIELDS = [
    'v', 'msg_id', 'sender', 'recipients', 'iat', 'exp', 'reply_to',
    'thread_id', 'alg', 'sig_alg', 'iv', 'ct', 'mac', 'wrapped_keys', 'sig'
  ];

  // ---------------------------------------------------------------------------
  // Errors
  // ---------------------------------------------------------------------------

  function ComposeError(code, message) {
    var e = new Error(message);
    e.name = 'ComposeError';
    e.code = code;
    return e;
  }

  // ---------------------------------------------------------------------------
  // Small helpers
  // ---------------------------------------------------------------------------

  function nowSeconds() {
    return Math.floor(Date.now() / 1000);
  }

  /** UUIDv4, lowercase (FILE-MAP §3: msg_id). Uses a cryptographic RNG. */
  function uuidv4() {
    var bytes = new Uint8Array(16);
    var c = (typeof crypto !== 'undefined') ? crypto : null;
    if (c && c.getRandomValues) {
      c.getRandomValues(bytes);
    } else if (typeof require === 'function') {
      // Node fallback (tests only — browsers always have crypto.getRandomValues).
      var nodeCrypto = require('node:crypto');
      var buf = nodeCrypto.randomBytes(16);
      bytes = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    } else {
      throw ComposeError('NO_RNG', 'no cryptographic RNG available for msg_id');
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10
    var hex = '';
    for (var i = 0; i < 16; i++) hex += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    return hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' + hex.slice(12, 16) +
      '-' + hex.slice(16, 20) + '-' + hex.slice(20);
  }

  var UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

  /** P6 — presence.js requires threadId to be a UUIDv4 (BAD_THREAD_ID otherwise). */
  function isUuidV4(s) {
    return typeof s === 'string' && UUID_V4_RE.test(s);
  }

  function clampTtl(ttlSeconds) {
    var ttl = Number(ttlSeconds);
    if (!Number.isFinite(ttl) || ttl <= 0) return DEFAULT_TTL_SECONDS;
    return Math.min(Math.floor(ttl), MAX_TTL_SECONDS);
  }

  function charCount(text) {
    // Code points, not UTF-16 units: what the user perceives as characters.
    return Array.from(text).length;
  }

  function truncatePreview(text, maxLen) {
    var t = String(text == null ? '' : text).replace(/\s+/g, ' ').trim();
    if (t.length <= maxLen) return t;
    return t.slice(0, maxLen - 1) + '…';
  }

  function displayNameOf(id) {
    return PARTICIPANT_DISPLAY[id] || id;
  }

  function lockLabelOf(id) {
    return PARTICIPANT_LABELS[id] || id;
  }

  /**
   * Reply threading (CRYPTO-DESIGN §10). A root message has reply_to null
   * and thread_id equal to its own msg_id. A reply has reply_to = the parent
   * msg_id and thread_id = the root's msg_id (copied from the parent; a
   * parent with no thread_id is itself the root).
   */
  function computeReplyContext(parent) {
    if (!parent || !parent.msg_id) return { reply_to: null, thread_id: null };
    return {
      reply_to: parent.msg_id,
      thread_id: parent.thread_id || parent.msg_id
    };
  }

  // ---------------------------------------------------------------------------
  // Sibling-module resolution (defensive — see header contracts)
  // ---------------------------------------------------------------------------

  function getGlobal(name) {
    if (typeof globalThis !== 'undefined' && globalThis[name]) return globalThis[name];
    if (typeof window !== 'undefined' && window[name]) return window[name];
    if (typeof self !== 'undefined' && self[name]) return self[name];
    return null;
  }

  function getCryptoCore(injected) {
    return injected || getGlobal('GhostChatCrypto') || null;
  }

  function getCanonicalJson(injected) {
    return injected || getGlobal('GhostCorpCanonicalJSON') || null;
  }

  function getEnvelopeModule(injected) {
    return injected || getGlobal('GhostChatEnvelope') || null;
  }

  // P6 — presence module (P5 app/js/presence.js). Defensive lookup: the
  // module loads in parallel with this file's P6 work, so its absence
  // is a silent no-op here, never a send/typing failure.
  function getPresenceModule(injected) {
    return injected || getGlobal('GhostChatPresence') || null;
  }

  // Minimal canonical-JSON fallback, used ONLY if A3 has not loaded.
  // Sorts keys lexicographically (UTF-8 byte order == code-point order for
  // the ASCII envelope keys) with "," / ":" separators and no whitespace —
  // the same form A3 produces for envelope objects (all envelope keys and
  // string values here are ASCII except message-adjacent strings, which
  // JSON.stringify leaves raw, matching Python ensure_ascii=False).
  // Envelopes built through this fallback are still verified by
  // validateEnvelope() before publish, and the caller should load A3.
  function fallbackCanonicalSignedBytes(envelope) {
    var copy = {};
    Object.keys(envelope).forEach(function (k) {
      if (k !== 'sig' && k !== 'seq') copy[k] = envelope[k];
    });
    var text = canonicalStringify(copy);
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(text);
    return Buffer.from(text, 'utf-8');
  }

  function canonicalStringify(value) {
    if (value === null) return 'null';
    if (typeof value === 'number') {
      if (!Number.isInteger(value)) throw new Error('canonical fallback: non-integer number');
      return String(value);
    }
    if (typeof value === 'boolean') return value ? 'true' : 'false';
    if (typeof value === 'string') return JSON.stringify(value);
    if (Array.isArray(value)) {
      return '[' + value.map(canonicalStringify).join(',') + ']';
    }
    if (typeof value === 'object') {
      var keys = Object.keys(value).sort();
      return '{' + keys.map(function (k) {
        return JSON.stringify(k) + ':' + canonicalStringify(value[k]);
      }).join(',') + '}';
    }
    throw new Error('canonical fallback: unsupported value of type ' + typeof value);
  }

  // ---------------------------------------------------------------------------
  // Envelope building
  // ---------------------------------------------------------------------------

  /**
   * Validate user text before any crypto runs. Returns { text } with the
   * text exactly as typed (no trimming of the message body — only the
   * emptiness check trims). Throws ComposeError on any violation.
   */
  function validateText(text) {
    if (typeof text !== 'string') {
      throw ComposeError('BAD_TEXT', 'message text must be a string');
    }
    if (text.trim().length === 0) {
      throw ComposeError('EMPTY_MESSAGE', 'Write a message before sending.');
    }
    if (charCount(text) > MAX_CHARS) {
      throw ComposeError('TOO_LONG',
        'Too long — split into two messages. (' + charCount(text) + ' / ' + MAX_CHARS + ' characters)');
    }
    return text;
  }

  /**
   * Resolve the recipient list for a send.
   *   requested: array of participant ids, or null/undefined for the D9 default.
   *   keyed:     array of participant ids that have a published encryption
   *              public key available for wrapping (from participants[]).
   * Returns { recipients, missing } — recipients are the ids actually
   * wrapped for (sender always included when keyed); missing are requested
   * ids with no key, who will NOT be able to read this message. The caller
   * surfaces `missing` in the lock line / inline note (UI-SPEC §2.4: the
   * app never silently drops a recipient).
   */
  function resolveRecipients(requested, keyed, senderId) {
    var want = (Array.isArray(requested) && requested.length > 0)
      ? requested.slice() : ALL_PARTICIPANTS.slice();
    if (want.indexOf(senderId) === -1) want.push(senderId);
    // De-duplicate, preserving order.
    var seen = {};
    var deduped = [];
    want.forEach(function (id) {
      if (!seen[id]) { seen[id] = true; deduped.push(id); }
    });
    if (deduped.length < 1 || deduped.length > 10) {
      throw ComposeError('BAD_RECIPIENTS', 'recipients must be 1–10 participants');
    }
    var recipients = [];
    var missing = [];
    deduped.forEach(function (id) {
      if (keyed.indexOf(id) !== -1) recipients.push(id);
      else missing.push(id);
    });
    if (recipients.indexOf(senderId) === -1) {
      throw ComposeError('NO_SENDER_KEY',
        'Your own encryption key is not available, so this message cannot be wrapped for you. Finish key setup first.');
    }
    if (recipients.length === 0) {
      throw ComposeError('NO_RECIPIENT_KEYS', 'No recipient has a published encryption key yet.');
    }
    return { recipients: recipients, missing: missing };
  }

  /**
   * Internal envelope builder (A1 + A3). Builds a complete, signed ecc-1
   * envelope for one message. Every call generates fresh per-message keys,
   * a fresh IV, a fresh msg_id, and a fresh signature — a retry therefore
   * never reuses envelope bytes.
   *
   * input:
   *   text, sender, recipients (resolved ids), replyTo, threadId,
   *   ttlSeconds, signingKey (CryptoKey), sigAlg ('Ed25519' | 'ES256'),
   *   recipientPublicKeys: [{recipient, publicKey}],
   *   crypto (optional injected GhostChatCrypto), canonicalJson (optional).
   */
  async function buildEnvelopeInternal(input) {
    var cryptoCore = getCryptoCore(input.crypto);
    if (!cryptoCore) {
      throw ComposeError('NO_CRYPTO', 'crypto-core.js (GhostChatCrypto) is not loaded — cannot encrypt or sign.');
    }
    var canonicalJson = getCanonicalJson(input.canonicalJson);
    var text = validateText(input.text);
    if (!input.signingKey) {
      throw ComposeError('NO_SIGNING_KEY', 'No signing key — finish key setup before sending. Nothing was sent.');
    }
    var sigAlg = input.sigAlg || SIG_ALG_ED25519;
    if (sigAlg !== SIG_ALG_ED25519 && sigAlg !== SIG_ALG_ES256) {
      throw ComposeError('BAD_SIG_ALG', 'unknown sig_alg "' + sigAlg + '"');
    }
    if (!input.sender || ALL_PARTICIPANTS.indexOf(input.sender) === -1) {
      throw ComposeError('BAD_SENDER', 'sender must be jarvis, chatgpt, or owner');
    }
    var recipients = input.recipients;
    if (!Array.isArray(recipients) || recipients.length < 1 || recipients.length > 10) {
      throw ComposeError('BAD_RECIPIENTS', 'recipients must be 1–10 participants');
    }
    if (recipients.indexOf(input.sender) === -1) {
      throw ComposeError('BAD_RECIPIENTS', 'recipients must include the sender');
    }

    var iat = nowSeconds();
    var ttl = clampTtl(input.ttlSeconds);
    var msgId = uuidv4();
    var replyCtx = input.replyTo
      ? { reply_to: input.replyTo, thread_id: input.threadId || input.replyTo }
      : { reply_to: null, thread_id: msgId };

    // Inner plaintext: UTF-8 JSON {"text": "..."} (FILE-MAP §3).
    var inner = JSON.stringify({ text: text });
    var plaintextBytes = cryptoCore.textToBytes(inner);
    if (plaintextBytes.length > MAX_PLAINTEXT_BYTES) {
      throw ComposeError('TOO_LARGE', 'message exceeds the 64 KiB plaintext limit');
    }

    // Symmetric layer (CRYPTO-DESIGN §3): fresh ENC_KEY / MAC_KEY / IV per
    // message, RSA-OAEP-wrapped per recipient. crypto-core enforces EtM.
    var cryptoFields = await cryptoCore.encryptMessage(plaintextBytes, input.recipientPublicKeys || []);

    var unsigned = {
      v: ENVELOPE_VERSION,
      msg_id: msgId,
      sender: input.sender,
      recipients: recipients.slice(),
      iat: iat,
      exp: iat + ttl,
      reply_to: replyCtx.reply_to,
      thread_id: replyCtx.thread_id,
      alg: ALG,
      sig_alg: sigAlg,
      iv: cryptoFields.iv,
      ct: cryptoFields.ct,
      mac: cryptoFields.mac,
      wrapped_keys: cryptoFields.wrapped_keys
    };

    // Sign the canonical JSON of the envelope WITHOUT sig (FILE-MAP §3).
    var canonicalBytes = canonicalJson && canonicalJson.canonicalSignedBytes
      ? canonicalJson.canonicalSignedBytes(unsigned)
      : fallbackCanonicalSignedBytes(unsigned);
    var sig;
    try {
      sig = await cryptoCore.signBytes(canonicalBytes, input.signingKey, sigAlg);
    } catch (e) {
      // P2: crypto-p256.js self-registers its ES256 handlers on
      // GhostChatCrypto when the file loads, so "no ES256 handler" can
      // now only mean crypto-p256.js is not loaded at all, or it loaded
      // BEFORE crypto-core.js (its on-load registration then found no
      // core — retry via GhostChatP256.registerWithCore() after both
      // scripts load). Anything else is a genuine signing failure.
      throw ComposeError('SIGN_FAILED',
        'Signing failed' + (sigAlg === SIG_ALG_ES256 ? ' (no ES256 handler on GhostChatCrypto — crypto-p256.js is not loaded, or it loaded before crypto-core.js; retry GhostChatP256.registerWithCore() after both scripts load)' : '') +
        ': ' + (e && e.message ? e.message : String(e)));
    }

    var envelope = Object.assign({}, unsigned, { sig: sig });
    var check = validateEnvelope(envelope);
    if (!check.ok) {
      throw ComposeError('ENVELOPE_INVALID', 'built envelope failed local validation: ' + check.errors.join('; '));
    }
    return envelope;
  }

  /**
   * Build an envelope, preferring A4 (envelope.js) when it is present and
   * usable, falling back to the internal builder above. Either path yields
   * the same envelope shape; the fallback is what the Node test harness
   * exercises while A4 is still landing in parallel.
   */
  async function buildEnvelope(input) {
    var envelopeModule = getEnvelopeModule(input.envelopeModule);
    if (envelopeModule && typeof envelopeModule.buildEnvelope === 'function') {
      try {
        var built = await envelopeModule.buildEnvelope({
          text: input.text,
          sender: input.sender,
          recipients: input.recipients,
          replyTo: input.replyTo,
          threadId: input.threadId,
          ttlSeconds: input.ttlSeconds,
          signingKey: input.signingKey,
          sigAlg: input.sigAlg,
          recipientPublicKeys: input.recipientPublicKeys
        });
        var check = validateEnvelope(built);
        if (!check.ok) {
          throw ComposeError('ENVELOPE_INVALID', 'envelope.js returned an invalid envelope: ' + check.errors.join('; '));
        }
        return built;
      } catch (e) {
        if (e && e.code && String(e.code).indexOf('ENVELOPE') === 0) throw e;
        // A4 present but unusable for this call (e.g. API-shape drift while
        // it lands) — fall through to the internal builder rather than
        // failing the send; the internal builder is the same crypto.
        // The failure is recorded on the returned envelope's build path by
        // the caller if it needs it; send still never goes out unsigned.
      }
    }
    return buildEnvelopeInternal(input);
  }

  /**
   * Local envelope shape validation (FILE-MAP §3 / CRYPTO-DESIGN §7 steps
   * 1–2). No network, no ledger, no signature check here — the signature is
   * verified by verifyOwnSignature() when the sender's public key is known.
   * Returns { ok, errors[] }.
   */
  function validateEnvelope(envelope) {
    var errors = [];
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
      return { ok: false, errors: ['envelope must be a JSON object'] };
    }
    ENVELOPE_FIELDS.forEach(function (f) {
      if (!(f in envelope)) errors.push('missing field: ' + f);
    });
    Object.keys(envelope).forEach(function (f) {
      if (ENVELOPE_FIELDS.indexOf(f) === -1 && f !== 'seq') {
        errors.push('unknown field: ' + f);
      }
    });
    if (errors.length > 0) return { ok: false, errors: errors };
    if (envelope.v !== ENVELOPE_VERSION) errors.push('v must be "ecc-1"');
    if (typeof envelope.msg_id !== 'string' ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(envelope.msg_id)) {
      errors.push('msg_id must be a lowercase UUIDv4');
    }
    if (ALL_PARTICIPANTS.indexOf(envelope.sender) === -1) errors.push('sender must be jarvis, chatgpt, or owner');
    if (!Array.isArray(envelope.recipients) || envelope.recipients.length < 1 || envelope.recipients.length > 10) {
      errors.push('recipients must be 1–10 entries');
    } else {
      var seen = {};
      envelope.recipients.forEach(function (r) {
        if (typeof r !== 'string') errors.push('recipient must be a string');
        if (seen[r]) errors.push('duplicate recipient: ' + r);
        seen[r] = true;
      });
      if (envelope.recipients.indexOf(envelope.sender) === -1) {
        errors.push('recipients must include the sender');
      }
    }
    if (!Number.isInteger(envelope.iat) || !Number.isInteger(envelope.exp)) {
      errors.push('iat and exp must be integer unix seconds');
    } else {
      var now = nowSeconds();
      if (envelope.exp <= envelope.iat) errors.push('exp must be > iat');
      if (envelope.exp - envelope.iat > MAX_TTL_SECONDS) errors.push('TTL exceeds the 24 h maximum');
      if (envelope.exp <= now) errors.push('envelope is already expired');
      if (envelope.iat > now + FUTURE_TOLERANCE_SECONDS) errors.push('iat is more than 300 s in the future');
    }
    if (!(envelope.reply_to === null || typeof envelope.reply_to === 'string')) {
      errors.push('reply_to must be a string or null');
    }
    if (typeof envelope.thread_id !== 'string' || envelope.thread_id.length === 0) {
      errors.push('thread_id must be a non-empty string');
    }
    if (envelope.reply_to === null && envelope.thread_id !== envelope.msg_id) {
      errors.push('a root message must have thread_id equal to its own msg_id');
    }
    if (envelope.alg !== ALG) errors.push('alg must be "A256CBC-HS256"');
    if (envelope.sig_alg !== SIG_ALG_ED25519 && envelope.sig_alg !== SIG_ALG_ES256) {
      errors.push('sig_alg must be "Ed25519" or "ES256"');
    }
    ['iv', 'ct', 'mac', 'sig'].forEach(function (f) {
      if (typeof envelope[f] !== 'string' || envelope[f].length === 0) errors.push(f + ' must be a non-empty base64url string');
      else if (envelope[f].indexOf('=') !== -1 || !/^[A-Za-z0-9_-]+$/.test(envelope[f])) {
        errors.push(f + ' must be base64url without padding');
      }
    });
    if (!Array.isArray(envelope.wrapped_keys) || envelope.wrapped_keys.length < 1) {
      errors.push('wrapped_keys must be a non-empty array');
    } else {
      envelope.wrapped_keys.forEach(function (wk) {
        if (!wk || typeof wk.recipient !== 'string' || typeof wk.wk !== 'string') {
          errors.push('each wrapped_keys entry needs {recipient, wk}');
        }
      });
      var wkRecipients = envelope.wrapped_keys.map(function (wk) { return wk && wk.recipient; });
      envelope.recipients.forEach(function (r) {
        if (wkRecipients.indexOf(r) === -1) errors.push('missing wrapped_keys entry for recipient: ' + r);
      });
    }
    return { ok: errors.length === 0, errors: errors };
  }

  /**
   * Verify our own freshly built envelope's signature against the sender's
   * public signing key, before publish (defence in depth — a signing bug
   * must fail here, never on the relay). Skipped when no public key is
   * supplied. Returns true/false; throws only on malformed inputs.
   */
  async function verifyOwnSignature(envelope, senderSigPublicKey, crypto, canonicalJson) {
    if (!senderSigPublicKey) return true;
    var cryptoCore = getCryptoCore(crypto);
    var canon = getCanonicalJson(canonicalJson);
    if (!cryptoCore) throw ComposeError('NO_CRYPTO', 'crypto-core.js is not loaded');
    var bytes = canon && canon.canonicalSignedBytes
      ? canon.canonicalSignedBytes(envelope)
      : fallbackCanonicalSignedBytes(envelope);
    return cryptoCore.verifySignature(bytes, envelope.sig, senderSigPublicKey, envelope.sig_alg);
  }

  // ---------------------------------------------------------------------------
  // Publish / outbox adapters (C13 pat.js / C12 outbox.js)
  // ---------------------------------------------------------------------------

  function pickFunction(obj, names) {
    if (!obj) return null;
    for (var i = 0; i < names.length; i++) {
      if (typeof obj[names[i]] === 'function') {
        return { fn: obj[names[i]], name: names[i], owner: obj };
      }
    }
    return null;
  }

  function resolvePublisher(deps) {
    if (deps && typeof deps.publishEnvelope === 'function') {
      return { fn: deps.publishEnvelope, name: 'deps.publishEnvelope', owner: deps };
    }
    var pat = getGlobal('GhostChatPAT');
    var picked = pickFunction(pat, ['publishEnvelope', 'publishMessage', 'publish', 'postEnvelope']);
    if (picked) return picked;
    return null;
  }

  function resolveOutbox(deps) {
    if (deps && deps.outbox) {
      var d = pickFunction(deps.outbox, ['enqueue', 'queue', 'add', 'save']);
      if (d) return d;
      if (typeof deps.outbox === 'function') return { fn: deps.outbox, name: 'deps.outbox', owner: deps };
    }
    var outbox = getGlobal('GhostChatOutbox');
    var picked = pickFunction(outbox, ['enqueue', 'queue', 'add', 'save']);
    if (picked) return picked;
    return null;
  }

  function isOffline() {
    if (typeof navigator !== 'undefined' && typeof navigator.onLine === 'boolean') {
      return !navigator.onLine;
    }
    return false;
  }

  function isNetworkError(e) {
    if (!e) return false;
    var msg = String((e && e.message) || e);
    return /network|offline|failed to fetch|econn|enotfound|timed out|timeout/i.test(msg);
  }

  // ---------------------------------------------------------------------------
  // Compose view (headless core — no DOM required)
  // ---------------------------------------------------------------------------

  /**
   * createComposeView(options) — the send engine. Works without a DOM, so
   * app.js (C3) can drive it and tests can exercise it in Node.
   *
   * options:
   *   senderId: 'owner' (default) | 'jarvis' | 'chatgpt'
   *   participants: [{id, display_name, encPublicKey (CryptoKey),
   *     enc_pub_pem (string, imported when encPublicKey is absent),
   *     sigPublicKey (CryptoKey, optional — enables pre-publish
   *     self-verification), status ('pinned'|'unpinned'|'revoked')}]
   *   getSigningKey: async () => ({privateKey, sigAlg}) — supplied by the
   *     caller (keys-store.js C17 owns storage). Or pass signingKey + sigAlg
   *     directly for tests.
   *   signingKey, sigAlg: direct key (tests / non-browser hosts only).
   *   publishEnvelope: async (envelope) => confirmation (overrides pat.js).
   *   outbox: {enqueue,...} (overrides outbox.js).
   *   crypto, canonicalJson, envelopeModule: injected sibling modules
   *     (tests; the browser resolves them from window globals).
   *   presence: injected GhostChatPresence module (tests; the browser
   *     resolves it from window.GhostChatPresence). sendTyping() is
   *     called with {threadId, publish, sender, signingKey,
   *     recipientPublicKeys, recipients} per the P5 API + design note.
   *   presenceBuildEnvelope: optional (inner, ctx) => signed envelope
   *     override for the typing signal (presence.js buildEnvelope
   *     contract); when supplied, no signing/recipient keys are
   *     resolved for the signal.
   *   publishPresence, publishEnvelope, publish: publish function handed
   *     to presence.js sendTyping() calls (first defined wins; the
   *     compose publisher from resolvePublisher is the last resort).
   *   threadId: the thread this compose box belongs to (typing signal);
   *     defaults to the reply target's thread_id, else null. Must be a
   *     UUIDv4 — presence.js rejects anything else, so a fresh root
   *     compose with no thread yet sends no typing signal.
   *   defaultTtlSeconds (default 86400, clamped to 86400), maxChars (4000).
   *   keepRecipientsAfterSend (default false — resets to the D9 group).
   *   onPending(pending), onSent(pending, confirmation),
   *     onQueued(pending, reason), onFailed(pending, error),
   *     onStateChange(state) — state is the view's public snapshot.
   *   onLockLine(text) — lock-line text for hosts without a DOM.
   */
  function createComposeView(options) {
    var opts = options || {};
    var senderId = opts.senderId || 'owner';
    var participants = Array.isArray(opts.participants) ? opts.participants.slice() : [];
    var maxChars = opts.maxChars || MAX_CHARS;
    var defaultTtl = clampTtl(opts.defaultTtlSeconds || DEFAULT_TTL_SECONDS);
    var keepRecipients = !!opts.keepRecipientsAfterSend;

    var state = {
      text: '',
      recipientsRequested: null, // null = D9 default (all three)
      oneToOne: false,
      oneToOneRecipient: null,
      oneToOneAcknowledged: false,
      ttlSeconds: defaultTtl,
      replyTarget: null, // {msg_id, thread_id, sender, text?}
      sending: false,
      lastError: null,
      pending: [] // [{id, msgId, text, recipients, ttlSeconds, replyTo, threadId, envelope, status, error, confirmation, createdAt}]
    };

    function emit(name) {
      var fn = opts['on' + name.charAt(0).toUpperCase() + name.slice(1)];
      if (typeof fn !== 'function') return;
      try {
        if (name === 'stateChange') fn(snapshot());
        else if (name === 'sent') fn.apply(null, Array.prototype.slice.call(arguments, 1));
        else fn.apply(null, Array.prototype.slice.call(arguments, 1));
      } catch (e) { /* callbacks must never break the send path */ }
    }

    function snapshot() {
      return {
        text: state.text,
        recipientsRequested: state.recipientsRequested ? state.recipientsRequested.slice() : null,
        recipientsEffective: effectiveRecipients().recipients,
        oneToOne: state.oneToOne,
        oneToOneRecipient: state.oneToOneRecipient,
        oneToOneAcknowledged: state.oneToOneAcknowledged,
        ttlSeconds: state.ttlSeconds,
        replyTarget: state.replyTarget ? Object.assign({}, state.replyTarget) : null,
        sending: state.sending,
        lastError: state.lastError,
        pending: state.pending.map(function (p) {
          return { id: p.id, msgId: p.msgId, status: p.status, error: p.error || null };
        }),
        lockLine: lockLineText()
      };
    }

    // P6 — typing signal (STATE-OF-THE-ART-BAR-2026-11-16, P6).
    // Calls window.GhostChatPresence.sendTyping({threadId, publish,
    // sender, signingKey, recipientPublicKeys, recipients,
    // buildEnvelope}) exactly as the P5 API + design note specify.
    // presence.js throttles internally (1 per 5 s), so calling on every
    // input is the documented usage. The bare {threadId, publish} shape
    // carries no key material, so the envelope cannot be built without
    // the sender + signing key + recipient keys (resolved here from
    // getSigningKey() / opts.signingKey and the participants, exactly as
    // buildFreshEnvelope() resolves them) — or a buildEnvelope(inner,
    // ctx) override via opts.presenceBuildEnvelope. publish is likewise
    // required by presence.js (BAD_PUBLISH without one), and threadId
    // must be a UUIDv4 (BAD_THREAD_ID otherwise): typing only signals
    // inside an existing thread (the reply target's thread_id, or
    // opts.threadId) — a fresh root compose with no thread yet sends no
    // signal. Fire-and-forget from setText: async, never awaited, never
    // rejects, never blocks typing or sending. Returns a Promise that
    // resolves true when the signal was handed to presence.js.
    var cachedSigningKey = null; // {privateKey, sigAlg} once resolved (a Promise while in flight)

    async function getCachedSigningKey() {
      if (cachedSigningKey) return cachedSigningKey;
      var p;
      try {
        p = Promise.resolve(getSigningKey());
      } catch (e) {
        return null; // no signing key available (yet)
      }
      cachedSigningKey = p.then(function (got) {
        if (got && got.privateKey) {
          cachedSigningKey = got;
          return got;
        }
        cachedSigningKey = null;
        return null;
      }, function () {
        cachedSigningKey = null;
        return null;
      });
      return cachedSigningKey;
    }

    // Recipient keys for the typing envelope, wrapped for exactly the
    // recipients actually keyed (mirrors buildFreshEnvelope(): the
    // recipients list passed to presence.js is the wrapped set, so the
    // envelope's wrapped_keys always cover its recipients).
    async function resolveTypingRecipientKeys() {
      var resolved = effectiveRecipients();
      var keys = [];
      for (var i = 0; i < resolved.recipients.length; i++) {
        var entry = participantById(resolved.recipients[i]);
        var pub = await importPemIfNeeded(entry);
        if (pub) keys.push({ recipient: resolved.recipients[i], publicKey: pub });
      }
      if (keys.map(function (k) { return k.recipient; }).indexOf(senderId) === -1) {
        return { keys: [], recipients: [] };
      }
      return {
        keys: keys,
        recipients: keys.map(function (k) { return k.recipient; })
      };
    }

    async function sendTypingSignal(presenceModule) {
      var mod = getPresenceModule(presenceModule || opts.presence);
      if (!mod || typeof mod.sendTyping !== 'function') return false;
      var threadId = null;
      if (state.replyTarget && typeof state.replyTarget.thread_id === 'string' &&
          isUuidV4(state.replyTarget.thread_id)) {
        threadId = state.replyTarget.thread_id;
      } else if (typeof opts.threadId === 'string' && isUuidV4(opts.threadId)) {
        threadId = opts.threadId;
      }
      if (!threadId) return false;
      var publish = null;
      if (typeof opts.publishPresence === 'function') publish = opts.publishPresence;
      else if (typeof opts.publishEnvelope === 'function') publish = opts.publishEnvelope;
      else if (typeof opts.publish === 'function') publish = opts.publish;
      else {
        var publisher = resolvePublisher(opts);
        if (publisher) {
          publish = function (envelope) {
            return publisher.fn.call(publisher.owner, envelope);
          };
        }
      }
      if (!publish) return false;
      try {
        var arg = { threadId: threadId, publish: publish, sender: senderId };
        if (typeof opts.presenceBuildEnvelope === 'function') {
          arg.buildEnvelope = opts.presenceBuildEnvelope;
        } else {
          var signing = await getCachedSigningKey();
          if (!signing || !signing.privateKey) return false;
          var resolvedKeys = await resolveTypingRecipientKeys();
          if (!resolvedKeys.keys || resolvedKeys.keys.length === 0) return false;
          arg.signingKey = signing.privateKey;
          if (signing.sigAlg) arg.sigAlg = signing.sigAlg;
          arg.recipientPublicKeys = resolvedKeys.keys;
          arg.recipients = resolvedKeys.recipients;
        }
        await mod.sendTyping(arg);
        return true;
      } catch (e) {
        return false;
      }
    }

    function participantById(id) {
      for (var i = 0; i < participants.length; i++) {
        if (participants[i].id === id) return participants[i];
      }
      return null;
    }

    function senderEntry() {
      return participantById(senderId);
    }

    async function importPemIfNeeded(entry) {
      if (!entry) return null;
      if (entry.encPublicKey) return entry.encPublicKey;
      if (typeof entry.enc_pub_pem === 'string' && entry.enc_pub_pem.length > 0) {
        var cryptoCore = getCryptoCore(opts.crypto);
        if (!cryptoCore) return null;
        var key = await cryptoCore.importEncryptionPublicKey(entry.enc_pub_pem);
        entry.encPublicKey = key; // cache on the entry for later sends
        return key;
      }
      return null;
    }

    /** Recipients actually wrappable right now + ids missing a key. */
    function effectiveRecipients() {
      var requested;
      if (state.oneToOne && state.oneToOneRecipient) {
        requested = [state.oneToOneRecipient, senderId];
      } else if (Array.isArray(state.recipientsRequested) && state.recipientsRequested.length > 0) {
        requested = state.recipientsRequested.slice();
      } else {
        requested = ALL_PARTICIPANTS.slice();
      }
      var keyed = participants.filter(function (p) {
        return p.encPublicKey || (typeof p.enc_pub_pem === 'string' && p.enc_pub_pem.length > 0);
      }).map(function (p) { return p.id; });
      // The sender counts as keyed if a key is expected to be importable;
      // resolveRecipients() still enforces the sender actually being wrapped.
      var resolved = resolveRecipients(requested, keyed, senderId);
      return resolved;
    }

    /**
     * The lock line, shown BEFORE send (UI-SPEC §2.4). Exact form:
     *   "🔒 Locked for: Jarvis ✓ · ChatGPT ✓ · you ✓"
     * A participant with no published key shows "✗ no key" and is named in
     * the note; the send still proceeds for the others (UI-SPEC §2.4).
     */
    function lockLineText() {
      var resolved;
      try {
        resolved = effectiveRecipients();
      } catch (e) {
        return '🔒 Locked for: — (' + (e && e.message ? e.message : 'no recipients available') + ')';
      }
      var parts = resolved.recipients.map(function (id) {
        return lockLabelOf(id) + ' ✓';
      });
      var text = '🔒 Locked for: ' + parts.join(' · ');
      if (resolved.missing.length > 0) {
        var missingNames = resolved.missing.map(displayNameOf).join(', ');
        text += ' — ' + missingNames + ' ✗ no key (' +
          (resolved.missing.length === 1 ? 'they' : 'they') +
          ' won’t be able to read this)';
      }
      return text;
    }

    function oneToOneWarningText() {
      if (!state.oneToOne || !state.oneToOneRecipient) return null;
      if (state.oneToOneRecipient === senderId) return null;
      if (state.oneToOneRecipient === 'jarvis' || senderId === 'jarvis') {
        return '1:1 with Jarvis — only you and Jarvis can read this. ChatGPT won’t see it.';
      }
      // Jarvis is not a recipient: he holds no copy, so he cannot re-share
      // this history if the owner loses their key and backup (FILE-MAP D9).
      return 'Warning: this 1:1 message is locked for only you and ' +
        displayNameOf(state.oneToOneRecipient) +
        '. Jarvis will NOT have a copy, so he cannot re-share this history if you lose your key and backup. ' +
        'Group messages (all three) stay re-shareable. Tick the box to send 1:1 anyway.';
    }

    function canSendReason() {
      if (state.sending) return 'Sending…';
      try {
        validateText(state.text);
      } catch (e) {
        return e.message;
      }
      if (charCount(state.text) > maxChars) return 'Too long — split into two messages.';
      if (state.oneToOne) {
        if (!state.oneToOneRecipient || state.oneToOneRecipient === senderId) {
          return 'Choose who this 1:1 message is for.';
        }
        if (!state.oneToOneAcknowledged) {
          return 'Tick the 1:1 warning box to send to one person only.';
        }
      }
      try {
        effectiveRecipients();
      } catch (e) {
        return e.message;
      }
      return null; // can send
    }

    async function getSigningKey() {
      if (opts.signingKey) return { privateKey: opts.signingKey, sigAlg: opts.sigAlg || SIG_ALG_ED25519 };
      if (typeof opts.getSigningKey === 'function') {
        var got = await opts.getSigningKey();
        if (!got || !got.privateKey) {
          throw ComposeError('NO_SIGNING_KEY', 'No signing key — finish key setup before sending. Nothing was sent.');
        }
        return { privateKey: got.privateKey, sigAlg: got.sigAlg || SIG_ALG_ED25519 };
      }
      throw ComposeError('NO_SIGNING_KEY', 'No signing key — finish key setup before sending. Nothing was sent.');
    }

    async function buildFreshEnvelope(pending) {
      var signing = await getSigningKey();
      var resolved = effectiveRecipients();
      // (Re-)import PEM public keys for wrapping; a recipient whose key
      // cannot be imported drops out of this attempt and is reported.
      var recipientPublicKeys = [];
      var missingNow = [];
      for (var i = 0; i < resolved.recipients.length; i++) {
        var entry = participantById(resolved.recipients[i]);
        var pub = await importPemIfNeeded(entry);
        if (pub) recipientPublicKeys.push({ recipient: resolved.recipients[i], publicKey: pub });
        else missingNow.push(resolved.recipients[i]);
      }
      if (missingNow.indexOf(senderId) !== -1) {
        throw ComposeError('NO_SENDER_KEY', 'Your own encryption key is not available. Nothing was sent.');
      }
      var actualRecipients = recipientPublicKeys.map(function (r) { return r.recipient; });
      var envelope = await buildEnvelope({
        text: pending.text,
        sender: senderId,
        recipients: actualRecipients,
        replyTo: pending.replyTo,
        threadId: pending.threadId,
        ttlSeconds: pending.ttlSeconds,
        signingKey: signing.privateKey,
        sigAlg: signing.sigAlg,
        recipientPublicKeys: recipientPublicKeys,
        crypto: opts.crypto,
        canonicalJson: opts.canonicalJson,
        envelopeModule: opts.envelopeModule
      });
      // Pre-publish self-verification when the sender's public signing key
      // is known: a signing bug fails here, never on the relay/store.
      var sender = senderEntry();
      if (sender && sender.sigPublicKey) {
        var ok = await verifyOwnSignature(envelope, sender.sigPublicKey, opts.crypto, opts.canonicalJson);
        if (!ok) {
          throw ComposeError('SIGN_FAILED', 'The fresh envelope failed its own signature check. Nothing was sent.');
        }
      }
      pending.recipients = actualRecipients;
      pending.missingRecipients = resolved.missing.concat(
        missingNow.filter(function (id) { return resolved.missing.indexOf(id) === -1; }));
      return envelope;
    }

    function newPendingRecord() {
      var replyCtx = computeReplyContext(state.replyTarget);
      var createdAt = Date.now();
      return {
        id: uuidv4(), // local pending id (not the envelope msg_id)
        msgId: null,
        text: state.text,
        // P6 — the thread view's optimistic bubble needs these: sender
        // (own-bubble check), iat (ordering), optimistic (marks this
        // record as a not-yet-accepted send, never a store message).
        sender: senderId,
        iat: Math.floor(createdAt / 1000),
        optimistic: true,
        recipients: effectiveRecipients().recipients,
        ttlSeconds: state.ttlSeconds,
        replyTo: replyCtx.reply_to,
        threadId: replyCtx.thread_id, // null for a root message: set from the envelope msg_id at build time
        envelope: null,
        status: 'encrypting',
        error: null,
        confirmation: null,
        createdAt: createdAt
      };
    }

    async function publishOrQueue(pending) {
      var publisher = resolvePublisher(opts);
      if (isOffline()) {
        return { queued: true, reason: 'offline' };
      }
      if (!publisher) {
        return { queued: true, reason: 'no-publisher' };
      }
      try {
        var confirmation = await publisher.fn.call(publisher.owner, pending.envelope);
        return { queued: false, confirmation: confirmation || true };
      } catch (e) {
        if (isNetworkError(e)) return { queued: true, reason: 'network-error' };
        throw e;
      }
    }

    async function queuePending(pending, reason) {
      pending.status = 'queued';
      pending.error = reason === 'offline'
        ? 'You’re offline — queued. It will send when you’re back online.'
        : reason === 'no-publisher'
          ? 'No publish path is ready yet (pat.js not loaded) — queued in the outbox.'
          : 'Send failed (' + reason + ') — queued in the outbox.';
      var outbox = resolveOutbox(opts);
      if (outbox) {
        try {
          await outbox.fn.call(outbox.owner, pending.envelope);
        } catch (e) {
          // The outbox itself failed: keep the pending item in memory with
          // its plaintext so a manual retry is still possible; do not drop it.
          pending.error += ' (Outbox also failed: ' + (e && e.message ? e.message : String(e)) + ')';
        }
      } else {
        pending.error += ' (No outbox module loaded — kept in memory only. Retry before closing this page.)';
      }
      emit('queued', pending, reason);
      emit('stateChange');
      return pending;
    }

    /**
     * Send the current compose text. Flow (UI-SPEC §2.4):
     *   validate -> build fresh signed+encrypted envelope -> pending ->
     *   publish via PAT (or queue to the outbox if offline) -> sent on
     *   confirmation. Plaintext is cleared from the compose box only after
     *   the envelope is built; a failed send keeps the pending item (with
     *   its in-memory plaintext) for a fresh-envelope retry.
     */
    async function send() {
      var blocked = canSendReason();
      if (blocked) {
        var err = ComposeError('SEND_BLOCKED', blocked);
        state.lastError = blocked;
        emit('stateChange');
        throw err;
      }
      var pending = newPendingRecord();
      pending.status = 'encrypting';
      state.pending.push(pending);
      state.sending = true;
      state.lastError = null;
      emit('pending', pending);
      emit('stateChange');
      try {
        var envelope = await buildFreshEnvelope(pending);
        pending.envelope = envelope;
        pending.msgId = envelope.msg_id;
        if (!pending.threadId) pending.threadId = envelope.thread_id;
        pending.status = 'pending';
        emit('pending', pending);
        emit('stateChange');

        var result = await publishOrQueue(pending);
        if (result.queued) {
          state.sending = false;
          // Clear the compose box: the message now lives as a queued
          // envelope + an in-memory pending item (retryable), not as text.
          clearComposeAfterSend();
          await queuePending(pending, result.reason);
          return pending;
        }

        pending.status = 'sent';
        pending.confirmation = result.confirmation;
        pending.error = null;
        state.sending = false;
        clearComposeAfterSend();
        emit('sent', pending, result.confirmation);
        emit('stateChange');
        return pending;
      } catch (e) {
        state.sending = false;
        pending.status = 'failed';
        pending.error = (e && e.message) || String(e);
        state.lastError = pending.error;
        emit('failed', pending, e);
        emit('stateChange');
        throw e;
      }
    }

    function clearComposeAfterSend() {
      state.text = '';
      state.replyTarget = null;
      if (!keepRecipients) {
        state.oneToOne = false;
        state.oneToOneRecipient = null;
        state.oneToOneAcknowledged = false;
        state.recipientsRequested = null;
      }
      if (typeof opts.onLockLine === 'function') {
        try { opts.onLockLine(lockLineText()); } catch (e) { /* ignore */ }
      }
    }

    /**
     * Fresh-envelope retry (UI-SPEC §2.4 step 3). Rebuilds from the stored
     * in-memory plaintext with a NEW msg_id, NEW per-message keys, NEW IV
     * and NEW signature. Never resends the same envelope bytes, and never
     * re-signs the old bytes — the old envelope is discarded.
     */
    async function retry(pendingId) {
      var pending = findPending(pendingId);
      if (!pending) throw ComposeError('NOT_FOUND', 'no pending message with that id');
      if (pending.status === 'sent') return pending;
      if (!pending.text) throw ComposeError('NO_TEXT', 'nothing left to retry — the message text is gone');
      pending.status = 'encrypting';
      pending.error = null;
      pending.envelope = null; // discard the old envelope bytes entirely
      pending.msgId = null;
      state.sending = true;
      emit('pending', pending);
      emit('stateChange');
      try {
        var envelope = await buildFreshEnvelope(pending);
        pending.envelope = envelope;
        pending.msgId = envelope.msg_id;
        if (!pending.threadId) pending.threadId = envelope.thread_id;
        pending.status = 'pending';
        emit('pending', pending);
        var result = await publishOrQueue(pending);
        if (result.queued) {
          state.sending = false;
          await queuePending(pending, result.reason);
          return pending;
        }
        pending.status = 'sent';
        pending.confirmation = result.confirmation;
        state.sending = false;
        emit('sent', pending, result.confirmation);
        emit('stateChange');
        return pending;
      } catch (e) {
        state.sending = false;
        pending.status = 'failed';
        pending.error = (e && e.message) || String(e);
        state.lastError = pending.error;
        emit('failed', pending, e);
        emit('stateChange');
        throw e;
      }
    }

    /** Discard a pending / queued / failed item after the caller's confirm. */
    function discard(pendingId) {
      var idx = -1;
      for (var i = 0; i < state.pending.length; i++) {
        if (state.pending[i].id === pendingId) { idx = i; break; }
      }
      if (idx === -1) throw ComposeError('NOT_FOUND', 'no pending message with that id');
      var removed = state.pending.splice(idx, 1)[0];
      // Drop the in-memory plaintext with the item.
      removed.text = '';
      removed.envelope = null;
      emit('stateChange');
      return removed;
    }

    function findPending(pendingId) {
      for (var i = 0; i < state.pending.length; i++) {
        if (state.pending[i].id === pendingId) return state.pending[i];
      }
      return null;
    }

    /**
     * Flush queued items (called on reconnect by app.js / poll.js, or by
     * the user tapping Retry). Each queued item is re-published with its
     * EXISTING envelope: it was already signed+encrypted and has never been
     * accepted (queueing means publish never confirmed), so re-posting the
     * same envelope is a resume, not a replay — the relay/store dedups by
     * msg_id (FILE-MAP §3: same ID + same bytes = OK). A queued item that
     * the publisher REJECTS (not a network error) goes to fresh-envelope
     * retry via retry(), never to a silent re-send of the same bytes.
     */
    async function flushOutbox() {
      var results = [];
      var queued = state.pending.filter(function (p) { return p.status === 'queued'; });
      for (var i = 0; i < queued.length; i++) {
        var pending = queued[i];
        try {
          var publisher = resolvePublisher(opts);
          if (!publisher) { results.push({ id: pending.id, status: 'queued', reason: 'no-publisher' }); continue; }
          if (!pending.envelope) { results.push({ id: pending.id, status: 'failed', reason: 'no-envelope' }); continue; }
          var confirmation = await publisher.fn.call(publisher.owner, pending.envelope);
          pending.status = 'sent';
          pending.confirmation = confirmation || true;
          pending.error = null;
          emit('sent', pending, pending.confirmation);
          results.push({ id: pending.id, status: 'sent' });
        } catch (e) {
          if (isNetworkError(e) || isOffline()) {
            results.push({ id: pending.id, status: 'queued', reason: 'network-error' });
          } else {
            pending.status = 'failed';
            pending.error = (e && e.message) || String(e);
            emit('failed', pending, e);
            results.push({ id: pending.id, status: 'failed', reason: pending.error });
          }
        }
      }
      emit('stateChange');
      return results;
    }

    // -- setters (DOM + headless callers use the same ones) -----------------

    function setText(text) {
      state.text = typeof text === 'string' ? text : '';
      state.lastError = null;
      // P6 — typing signal on compose input (presence.js throttles
      // internally). Only for non-empty text: an emptied box is not
      // typing, and the signal is cheap to skip.
      if (state.text.length > 0) sendTypingSignal();
      if (typeof opts.onLockLine === 'function') {
        try { opts.onLockLine(lockLineText()); } catch (e) { /* ignore */ }
      }
      emit('stateChange');
      return state.text;
    }

    function setTtlSeconds(seconds) {
      state.ttlSeconds = clampTtl(seconds);
      emit('stateChange');
      return state.ttlSeconds;
    }

    function setRecipients(ids) {
      if (ids == null) {
        state.recipientsRequested = null;
        state.oneToOne = false;
        state.oneToOneRecipient = null;
        state.oneToOneAcknowledged = false;
      } else {
        state.recipientsRequested = ids.slice();
        state.oneToOne = false;
        state.oneToOneRecipient = null;
        state.oneToOneAcknowledged = false;
      }
      emit('stateChange');
      return effectiveRecipients();
    }

    function setOneToOne(recipientId, acknowledged) {
      if (!recipientId) {
        state.oneToOne = false;
        state.oneToOneRecipient = null;
        state.oneToOneAcknowledged = false;
      } else {
        state.oneToOne = true;
        state.oneToOneRecipient = recipientId;
        state.oneToOneAcknowledged = !!acknowledged;
      }
      emit('stateChange');
      return { oneToOne: state.oneToOne, recipient: state.oneToOneRecipient, warning: oneToOneWarningText() };
    }

    function acknowledgeOneToOne(acknowledged) {
      state.oneToOneAcknowledged = !!acknowledged;
      emit('stateChange');
      return state.oneToOneAcknowledged;
    }

    function setReplyTarget(message) {
      if (!message || !message.msg_id) {
        state.replyTarget = null;
      } else {
        state.replyTarget = {
          msg_id: message.msg_id,
          thread_id: message.thread_id || message.msg_id,
          sender: message.sender || null,
          text: message.text || null
        };
      }
      emit('stateChange');
      return state.replyTarget;
    }

    function clearReplyTarget() {
      state.replyTarget = null;
      emit('stateChange');
    }

    function setParticipants(next) {
      participants = Array.isArray(next) ? next.slice() : [];
      emit('stateChange');
    }

    return {
      // state
      getState: snapshot,
      lockLineText: lockLineText,
      oneToOneWarningText: oneToOneWarningText,
      canSendReason: canSendReason,
      // editing
      setText: setText,
      setTtlSeconds: setTtlSeconds,
      setRecipients: setRecipients,
      setOneToOne: setOneToOne,
      acknowledgeOneToOne: acknowledgeOneToOne,
      setReplyTarget: setReplyTarget,
      clearReplyTarget: clearReplyTarget,
      setParticipants: setParticipants,
      // sending
      send: send,
      retry: retry,
      discard: discard,
      flushOutbox: flushOutbox,
      findPending: findPending,
      // P6 — typing signal (also fired automatically by setText on
      // non-empty input). Async: returns a Promise<boolean>, never
      // rejects. Exposed so app.js / tests can trigger it.
      sendTyping: sendTypingSignal,
      // crypto (exposed for tests / app.js)
      buildEnvelope: buildEnvelope,
      validateEnvelope: validateEnvelope,
      computeReplyContext: computeReplyContext,
      senderId: senderId
    };
  }

  // ---------------------------------------------------------------------------
  // DOM view — mountCompose(container, options)
  // ---------------------------------------------------------------------------

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (typeof text === 'string') node.textContent = text;
    return node;
  }

  /**
   * mountCompose(container, options) — builds the compose DOM inside
   * `container` and wires it to createComposeView(options). Returns the
   * view object plus { root, elements } for app.js / tests.
   * Container may be an Element or a CSS selector string.
   */
  function mountCompose(container, options) {
    if (typeof document === 'undefined') {
      throw ComposeError('NO_DOM', 'mountCompose needs a DOM — use createComposeView() headlessly in Node.');
    }
    var root = typeof container === 'string' ? document.querySelector(container) : container;
    if (!root) throw ComposeError('NO_CONTAINER', 'compose container not found');
    var opts = options || {};
    var view = createComposeView(opts);
    var maxChars = opts.maxChars || MAX_CHARS;

    var isCoarsePointer = false;
    try {
      isCoarsePointer = typeof window !== 'undefined' && window.matchMedia &&
        window.matchMedia('(pointer: coarse)').matches;
    } catch (e) { isCoarsePointer = false; }

    // -- reply banner (hidden unless replying) -------------------------------
    var replyBanner = el('div', 'compose-reply');
    replyBanner.style.display = 'none';
    var replyLabel = el('span', 'compose-reply-label');
    var replyCancel = el('button', 'compose-reply-cancel', '✕');
    replyCancel.type = 'button';
    replyCancel.setAttribute('aria-label', 'Cancel reply');
    replyCancel.addEventListener('click', function () {
      view.clearReplyTarget();
      refresh();
    });
    replyBanner.appendChild(replyLabel);
    replyBanner.appendChild(replyCancel);

    // -- textarea + counter ---------------------------------------------------
    var textarea = document.createElement('textarea');
    textarea.className = 'compose-input';
    textarea.setAttribute('aria-label', 'Message');
    textarea.setAttribute('placeholder', 'Write a message… (encrypted before it leaves this browser)');
    textarea.setAttribute('rows', '3');
    textarea.setAttribute('maxlength', String(maxChars));
    textarea.addEventListener('input', function () {
      view.setText(textarea.value);
      refresh();
    });
    textarea.addEventListener('keydown', function (ev) {
      // UI-SPEC §2.4 step 7: desktop Enter sends, Shift+Enter newline;
      // mobile Enter inserts a newline, Send is the button only.
      if (ev.key === 'Enter' && !ev.shiftKey && !isCoarsePointer) {
        ev.preventDefault();
        onSendClick();
      }
    });

    var counter = el('div', 'compose-counter', '0 / ' + maxChars);

    // -- lock line (BEFORE send — always visible) ------------------------------
    var lockLine = el('div', 'compose-lockline', view.lockLineText());
    lockLine.setAttribute('aria-live', 'polite');

    // -- 1:1 controls -----------------------------------------------------------
    var oneToOneWrap = el('div', 'compose-onetoone');
    var oneToOneToggle = el('button', 'compose-onetoone-toggle', 'Send to one person only');
    oneToOneToggle.type = 'button';
    oneToOneToggle.setAttribute('aria-expanded', 'false');
    var oneToOnePanel = el('div', 'compose-onetoone-panel');
    oneToOnePanel.style.display = 'none';
    var oneToOneSelect = document.createElement('select');
    oneToOneSelect.className = 'compose-onetoone-select';
    oneToOneSelect.setAttribute('aria-label', 'Send to one person only');
    ALL_PARTICIPANTS.forEach(function (id) {
      if (id === view.senderId) return;
      var opt = document.createElement('option');
      opt.value = id;
      opt.textContent = displayNameOf(id);
      oneToOneSelect.appendChild(opt);
    });
    var oneToOneWarning = el('div', 'compose-onetoone-warning');
    oneToOneWarning.style.display = 'none';
    var oneToOneAckLabel = el('label', 'compose-onetoone-ack-label');
    var oneToOneAck = document.createElement('input');
    oneToOneAck.type = 'checkbox';
    oneToOneAck.className = 'compose-onetoone-ack';
    oneToOneAckLabel.appendChild(oneToOneAck);
    oneToOneAckLabel.appendChild(document.createTextNode(' I understand — send 1:1 anyway.'));
    oneToOneAckLabel.style.display = 'none';
    oneToOnePanel.appendChild(oneToOneSelect);
    oneToOnePanel.appendChild(oneToOneWarning);
    oneToOnePanel.appendChild(oneToOneAckLabel);
    oneToOneToggle.addEventListener('click', function () {
      var open = oneToOnePanel.style.display === 'none';
      oneToOnePanel.style.display = open ? '' : 'none';
      oneToOneToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
      if (open) {
        view.setOneToOne(oneToOneSelect.value, oneToOneAck.checked);
      } else {
        view.setOneToOne(null);
        oneToOneAck.checked = false;
      }
      refresh();
    });
    oneToOneSelect.addEventListener('change', function () {
      view.setOneToOne(oneToOneSelect.value, oneToOneAck.checked);
      refresh();
    });
    oneToOneAck.addEventListener('change', function () {
      view.acknowledgeOneToOne(oneToOneAck.checked);
      refresh();
    });
    oneToOneWrap.appendChild(oneToOneToggle);
    oneToOneWrap.appendChild(oneToOnePanel);

    // -- expiry picker (default 24 h, max 24 h — FILE-MAP D10) -----------------
    var expiryWrap = el('div', 'compose-expiry');
    var expiryLabel = el('label', 'compose-expiry-label', 'Expires: ');
    expiryLabel.setAttribute('for', 'compose-expiry-select');
    var expirySelect = document.createElement('select');
    expirySelect.id = 'compose-expiry-select';
    expirySelect.className = 'compose-expiry-select';
    expirySelect.setAttribute('aria-label', 'Message expiry');
    TTL_OPTIONS.forEach(function (opt) {
      var option = document.createElement('option');
      option.value = String(opt.seconds);
      option.textContent = opt.label;
      if (opt.seconds === DEFAULT_TTL_SECONDS) option.selected = true;
      expirySelect.appendChild(option);
    });
    expirySelect.addEventListener('change', function () {
      view.setTtlSeconds(parseInt(expirySelect.value, 10));
      refresh();
    });
    var expiryNote = el('span', 'compose-expiry-note', 'Messages expire after at most 24 hours.');
    expiryWrap.appendChild(expiryLabel);
    expiryWrap.appendChild(expirySelect);
    expiryWrap.appendChild(expiryNote);

    // -- send button + status ----------------------------------------------------
    var sendButton = el('button', 'compose-send', 'Send');
    sendButton.type = 'button';
    var statusLine = el('div', 'compose-status');
    statusLine.setAttribute('aria-live', 'polite');

    // -- pending / queued / failed list -------------------------------------------
    var pendingList = el('div', 'compose-pending-list');

    function onSendClick() {
      if (sendButton.disabled) return;
      statusLine.textContent = 'Encrypting…';
      sendButton.disabled = true;
      view.send().then(function (pending) {
        if (pending.status === 'queued') {
          statusLine.textContent = pending.error || 'Queued — will send when online.';
        } else {
          statusLine.textContent = 'Sent.';
        }
        refresh();
      }).catch(function (e) {
        statusLine.textContent = (e && e.message) || 'Send failed.';
        refresh();
      });
    }
    sendButton.addEventListener('click', onSendClick);

    function renderPendingList() {
      while (pendingList.firstChild) pendingList.removeChild(pendingList.firstChild);
      var snap = view.getState();
      snap.pending.forEach(function (p) {
        if (p.status === 'sent') return;
        var row = el('div', 'compose-pending compose-pending-' + p.status);
        var label = el('span', 'compose-pending-label',
          (p.status === 'pending' ? 'Sending…' :
           p.status === 'queued' ? 'Queued — will send when online' :
           p.status === 'failed' ? 'Not sent' : p.status) +
          (p.error ? ' — ' + p.error : ''));
        row.appendChild(label);
        if (p.status === 'failed' || p.status === 'queued') {
          var retryBtn = el('button', 'compose-pending-retry', 'Retry');
          retryBtn.type = 'button';
          retryBtn.addEventListener('click', function () {
            retryBtn.disabled = true;
            view.retry(p.id).then(function () {
              statusLine.textContent = 'Sent.';
              refresh();
            }).catch(function (e) {
              statusLine.textContent = (e && e.message) || 'Retry failed.';
              refresh();
            });
          });
          row.appendChild(retryBtn);
        }
        if (p.status === 'failed' || p.status === 'queued') {
          var discardBtn = el('button', 'compose-pending-discard', 'Discard');
          discardBtn.type = 'button';
          discardBtn.addEventListener('click', function () {
            if (typeof window !== 'undefined' && window.confirm) {
              if (!window.confirm('Discard this unsent message?')) return;
            }
            view.discard(p.id);
            refresh();
          });
          row.appendChild(discardBtn);
        }
        pendingList.appendChild(row);
      });
    }

    function refresh() {
      var snap = view.getState();
      lockLine.textContent = snap.lockLine;
      counter.textContent = charCount(textarea.value) + ' / ' + maxChars;
      counter.classList.toggle('compose-counter-over', charCount(textarea.value) > maxChars);
      // Reply banner.
      if (snap.replyTarget) {
        replyBanner.style.display = '';
        var who = snap.replyTarget.sender ? displayNameOf(snap.replyTarget.sender) : 'a message';
        var preview = snap.replyTarget.text ? truncatePreview(snap.replyTarget.text, 60) : snap.replyTarget.msg_id;
        replyLabel.textContent = 'Replying to ' + who + ': ' + preview;
      } else {
        replyBanner.style.display = 'none';
        replyLabel.textContent = '';
      }
      // 1:1 warning.
      var warning = view.oneToOneWarningText();
      if (snap.oneToOne && warning) {
        oneToOneWarning.style.display = '';
        oneToOneWarning.textContent = warning;
        oneToOneAckLabel.style.display = '';
      } else {
        oneToOneWarning.style.display = 'none';
        oneToOneWarning.textContent = '';
        oneToOneAckLabel.style.display = 'none';
      }
      // Send availability.
      var reason = view.canSendReason();
      sendButton.disabled = !!reason || snap.sending;
      sendButton.textContent = snap.sending ? 'Encrypting…' : 'Send';
      sendButton.title = reason || 'Send (encrypted for the recipients above)';
      if (!snap.sending && reason && statusLine.textContent === 'Encrypting…') {
        statusLine.textContent = '';
      }
      renderPendingList();
    }

    root.appendChild(replyBanner);
    root.appendChild(textarea);
    root.appendChild(counter);
    root.appendChild(lockLine);
    root.appendChild(oneToOneWrap);
    root.appendChild(expiryWrap);
    root.appendChild(sendButton);
    root.appendChild(statusLine);
    root.appendChild(pendingList);
    refresh();

    return {
      view: view,
      root: root,
      elements: {
        replyBanner: replyBanner,
        textarea: textarea,
        counter: counter,
        lockLine: lockLine,
        oneToOneToggle: oneToOneToggle,
        oneToOnePanel: oneToOnePanel,
        oneToOneSelect: oneToOneSelect,
        oneToOneWarning: oneToOneWarning,
        oneToOneAck: oneToOneAck,
        expirySelect: expirySelect,
        sendButton: sendButton,
        statusLine: statusLine,
        pendingList: pendingList
      },
      refresh: refresh
    };
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  return {
    MAX_CHARS: MAX_CHARS,
    MAX_PLAINTEXT_BYTES: MAX_PLAINTEXT_BYTES,
    MAX_TTL_SECONDS: MAX_TTL_SECONDS,
    DEFAULT_TTL_SECONDS: DEFAULT_TTL_SECONDS,
    TTL_OPTIONS: TTL_OPTIONS,
    ALL_PARTICIPANTS: ALL_PARTICIPANTS,
    ENVELOPE_VERSION: ENVELOPE_VERSION,
    ALG: ALG,
    createComposeView: createComposeView,
    mountCompose: mountCompose,
    buildEnvelope: buildEnvelope,
    buildEnvelopeInternal: buildEnvelopeInternal,
    validateEnvelope: validateEnvelope,
    verifyOwnSignature: verifyOwnSignature,
    computeReplyContext: computeReplyContext,
    uuidv4: uuidv4,
    ComposeError: ComposeError
  };
});
