/**
 * envelope.js — ecc-1 envelope build / parse / validate (client-side).
 *
 * Worker A4. Normative refs:
 *   - FILE-MAP.md §3 (envelope fields, canonical JSON, verification order
 *     steps 1-2 + step 5, store/manifest `seq` rule) — FILE-MAP WINS on any
 *     conflict with a design doc.
 *   - design/CRYPTO-DESIGN.md §6 (envelope format, canonical form,
 *     encoding, inner plaintext) and §7 (verification order).
 *   - design/CRYPTO-TEST-VECTORS.md §1.4 (run-2 canonical payload, the
 *     byte-exact reference for the signed bytes).
 *
 * Scope (this file ONLY):
 *   - Build: assemble a complete signed ecc-1 envelope from a plaintext
 *     message + the sender's signing key + recipients' RSA-OAEP public
 *     keys. Fresh per-message keys / IV come from crypto-core.js.
 *   - Canonical sign input: the envelope WITHOUT `sig` AND WITHOUT `seq`
 *     (`seq` is relay-assigned AFTER signing — FILE-MAP §3 "Store /
 *     manifest" — so it is never part of the signed bytes).
 *   - Parse: strict JSON parse, `seq` separated from the envelope.
 *   - Validate: shape (all required fields, right types, v == "ecc-1",
 *     known alg / sig_alg, no unknown fields, exp > iat, TTL <= 86400,
 *     recipients contain sender, strict base64url, decoded lengths),
 *     timing (exp > now, iat <= now + 300), optional participant /
 *     pinned-sig_alg membership, signature verification (§7 step 5).
 *   - Decrypt: thin orchestration over crypto-core.js decryptMessage()
 *     (unwrap -> HMAC verify -> decrypt, EtM order); the crypto itself
 *     lives in crypto-core.js, not here.
 *
 * Out of scope (other workers — this file does NOT re-implement them):
 *   - Canonical JSON .............. A3 app/js/canonical-json.js
 *   - AES-CBC+HMAC, RSA-OAEP wrap, Ed25519, base64url codec ... A1
 *     app/js/crypto-core.js
 *   - ES256 (ECDSA P-256) sign/verify ......... A2 app/js/crypto-p256.js
 *   - Seen-ledger / replay check (§7 steps 4 + 8) ... A12 / relay (the
 *     caller checks the ledger; this module never touches it).
 *   - Pinning / participants.json lookup ....... B-workers (the caller
 *     passes the pinned public key + pinned sig_alg in).
 *
 * Load order (browser, plain <script> tags, no build step):
 *   canonical-json.js, crypto-core.js, crypto-p256.js (ES256 only), then
 *   this file. Exposes window.GhostCorpEnvelope (browser) and
 *   module.exports (Node / tests). If a dependency is absent, the
 *   functions that need it throw EnvelopeError MISSING_DEPENDENCY —
 *   fail closed, never silently proceed unsigned/unverified.
 *
 * No real keys are generated here. No private-key material, plaintext
 * conversation content, secrets, or personal info belong in this file.
 * Keys are passed in by the caller (CryptoKey objects) and never stored
 * or logged by this module.
 */

(function (root, factory) {
  'use strict';
  if (typeof module === 'object' && module.exports) {
    // Node / CommonJS (unit tests). crypto-p256.js is optional: it is
    // only needed when an ES256 envelope is signed or verified.
    var canon = require('./canonical-json.js');
    var core = require('./crypto-core.js');
    var p256 = null;
    try { p256 = require('./crypto-p256.js'); } catch (e) { p256 = null; }
    module.exports = factory(canon, core, p256);
  } else {
    // Browser globals (static page, no build step).
    root.GhostCorpEnvelope = factory(
      root.GhostCorpCanonicalJSON || null,
      root.GhostChatCrypto || null,
      root.GhostCorpP256 || null
    );
  }
})(typeof self !== 'undefined' ? self : this, function (CanonicalJSON, Crypto, P256) {
  'use strict';

  // ---------------------------------------------------------------------------
  // Constants — FILE-MAP §3 / CRYPTO-DESIGN §6.1, §11
  // ---------------------------------------------------------------------------

  var ENVELOPE_VERSION = 'ecc-1';
  var ALG = 'A256CBC-HS256';
  var SIG_ALG_ED25519 = 'Ed25519';
  var SIG_ALG_ES256 = 'ES256';
  var SIG_ALGS = [SIG_ALG_ED25519, SIG_ALG_ES256];

  // The three ecc-1 participants (FILE-MAP §3, D9). Shape validation does
  // NOT enforce membership in this set — see validateEnvelopeParticipants()
  // and the note below — but production callers MUST pass it (or the
  // participants.json roster) so unknown senders are rejected (§7 step 3).
  var KNOWN_PARTICIPANTS = ['jarvis', 'chatgpt', 'owner'];

  var MAX_TTL_SECONDS = 86400;        // 24 h TTL, default AND maximum (D10)
  var DEFAULT_TTL_SECONDS = 86400;
  var MAX_FUTURE_SKEW_SECONDS = 300;  // iat beyond now + 300 -> reject (D10)
  var MAX_PLAINTEXT_BYTES = 64 * 1024; // FILE-MAP §3: max 64 KiB plaintext
  var MAX_RECIPIENTS = 10;            // FILE-MAP §3: recipients 1-10
  var MIN_RECIPIENTS = 1;

  var IV_BYTES = 16;                  // AES-CBC IV
  var MAC_BYTES = 32;                 // HMAC-SHA-256 output
  var SIG_BYTES = 64;                 // Ed25519 raw, or ES256 raw R || S
  // RSA-OAEP wrap output sizes for the key sizes ecc-1 admits (§5:
  // RSA-2048 minimum, RSA-4096 recommended; 3072 admitted defensively).
  var WRAPPED_KEY_BYTES = [256, 384, 512];

  // All envelope fields, per FILE-MAP §3 / CRYPTO-DESIGN §6.1. `seq` is NOT
  // an envelope field: it is relay-assigned after signing and carried
  // alongside the envelope in the store (FILE-MAP §3 "Store / manifest").
  // parseEnvelope() separates it; canonicalSignInput() excludes it.
  var ENVELOPE_FIELDS = [
    'v', 'msg_id', 'sender', 'recipients', 'iat', 'exp', 'reply_to',
    'thread_id', 'alg', 'sig_alg', 'iv', 'ct', 'mac', 'wrapped_keys', 'sig'
  ];
  var REQUIRED_FIELDS = ENVELOPE_FIELDS.slice(); // all 15 required (§6.1)

  var UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  var B64URL_RE = /^[A-Za-z0-9_-]*$/;

  // ---------------------------------------------------------------------------
  // Errors
  // ---------------------------------------------------------------------------

  function EnvelopeError(code, message) {
    var e = new Error(message);
    e.name = 'EnvelopeError';
    e.code = code;
    return e;
  }

  // ---------------------------------------------------------------------------
  // Small helpers (platform APIs only — no crypto re-implemented here)
  // ---------------------------------------------------------------------------

  var _encoder = (typeof TextEncoder !== 'undefined') ? new TextEncoder() : null;
  var _decoder = (typeof TextDecoder !== 'undefined')
    ? new TextDecoder('utf-8', { fatal: true }) : null;

  function textToBytes(text) {
    if (_encoder) return _encoder.encode(text);
    return Buffer.from(text, 'utf-8');
  }

  function bytesToText(bytes) {
    if (_decoder) return _decoder.decode(bytes);
    return Buffer.from(bytes).toString('utf-8');
  }

  function isPlainObject(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
    var proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
  }

  function nowSeconds() {
    return Math.floor(Date.now() / 1000);
  }

  function requireCrypto() {
    if (!Crypto) {
      throw EnvelopeError('MISSING_DEPENDENCY',
        'crypto-core.js (GhostChatCrypto) is not loaded — load app/js/crypto-core.js before app/js/envelope.js');
    }
    return Crypto;
  }

  function requireCanonicalJSON() {
    if (!CanonicalJSON) {
      throw EnvelopeError('MISSING_DEPENDENCY',
        'canonical-json.js (GhostCorpCanonicalJSON) is not loaded — load app/js/canonical-json.js before app/js/envelope.js');
    }
    return CanonicalJSON;
  }

  function requireP256() {
    if (!P256) {
      throw EnvelopeError('ES256_UNAVAILABLE',
        'crypto-p256.js (GhostCorpP256) is not loaded — ES256 envelopes cannot be signed or verified without it');
    }
    return P256;
  }

  // New random UUIDv4 (lowercase), via the platform CSPRNG.
  // crypto.getRandomValues is available in secure contexts and in Node.
  function newMsgId() {
    var c = (typeof crypto !== 'undefined') ? crypto : null;
    if (!c || !c.getRandomValues) {
      throw EnvelopeError('MISSING_DEPENDENCY', 'crypto.getRandomValues is unavailable');
    }
    var b = new Uint8Array(16);
    c.getRandomValues(b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 10
    var hex = '';
    for (var i = 0; i < 16; i++) hex += (b[i] < 16 ? '0' : '') + b[i].toString(16);
    return hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' + hex.slice(12, 16) +
      '-' + hex.slice(16, 20) + '-' + hex.slice(20, 32);
  }

  // Strict base64url syntax check (FILE-MAP §3 / CRYPTO-DESIGN §6.3):
  // alphabet only, no padding, length % 4 != 1. This is validation, not a
  // codec — actual decoding always goes through Crypto.base64urlToBytes,
  // which additionally rejects non-canonical trailing bits.
  function isValidBase64Url(str) {
    return typeof str === 'string' &&
      str.indexOf('=') === -1 &&
      B64URL_RE.test(str) &&
      (str.length % 4) !== 1;
  }

  // Strict decode via crypto-core.js (throws its CryptoError BAD_ENCODING
  // on any non-canonical input). Wrapped here so callers get EnvelopeError.
  function decodeBase64UrlStrict(str, field) {
    var core = requireCrypto();
    try {
      return core.base64urlToBytes(str);
    } catch (e) {
      throw EnvelopeError('BAD_BASE64URL',
        'field "' + field + '" is not canonical base64url (no padding): ' + e.message);
    }
  }

  function encodeBase64Url(bytes) {
    return requireCrypto().bytesToBase64url(bytes);
  }

  function isUuidV4(str) {
    return typeof str === 'string' && UUID_V4_RE.test(str);
  }

  // ---------------------------------------------------------------------------
  // Inner plaintext — FILE-MAP §3 / CRYPTO-DESIGN §6.4
  // Plaintext after decrypt is UTF-8 JSON {"text": "<message text>"}.
  // ---------------------------------------------------------------------------

  function encodePlaintext(text) {
    if (typeof text !== 'string') {
      throw EnvelopeError('BAD_PLAINTEXT', 'message text must be a string');
    }
    var bytes = textToBytes(JSON.stringify({ text: text }));
    if (bytes.length > MAX_PLAINTEXT_BYTES) {
      throw EnvelopeError('TOO_LARGE',
        'plaintext is ' + bytes.length + ' bytes, over the 64 KiB per-message limit');
    }
    return bytes;
  }

  function decodePlaintext(bytes) {
    if (!(bytes instanceof Uint8Array)) {
      throw EnvelopeError('BAD_PLAINTEXT', 'plaintext must be bytes');
    }
    if (bytes.length > MAX_PLAINTEXT_BYTES) {
      throw EnvelopeError('TOO_LARGE',
        'decrypted plaintext is ' + bytes.length + ' bytes, over the 64 KiB per-message limit');
    }
    var str;
    try {
      str = bytesToText(bytes);
    } catch (e) {
      throw EnvelopeError('BAD_PLAINTEXT', 'decrypted plaintext is not valid UTF-8');
    }
    var obj;
    try {
      obj = JSON.parse(str);
    } catch (e) {
      throw EnvelopeError('BAD_PLAINTEXT', 'decrypted plaintext is not valid JSON');
    }
    if (!isPlainObject(obj) || typeof obj.text !== 'string') {
      throw EnvelopeError('BAD_PLAINTEXT',
        'decrypted plaintext must be JSON {"text": "<string>"}');
    }
    return obj.text;
  }

  // ---------------------------------------------------------------------------
  // Canonical sign input — FILE-MAP §3 "Canonical JSON (what is signed)",
  // CRYPTO-DESIGN §6.2. The signed bytes are the canonical JSON of the
  // envelope WITHOUT `sig` AND WITHOUT `seq`.
  // ---------------------------------------------------------------------------

  function canonicalSignInput(envelope) {
    var cj = requireCanonicalJSON();
    // canonicalSignedBytes() (A3) omits exactly 'sig' and 'seq', so an
    // envelope that still carries a relay-assigned seq signs identically
    // to the envelope as the sender signed it.
    return cj.canonicalSignedBytes(envelope);
  }

  function canonicalSignInputString(envelope) {
    var cj = requireCanonicalJSON();
    return cj.canonicalSignedJSON(envelope);
  }

  // ---------------------------------------------------------------------------
  // Build — unsigned envelope (pure field assembly, no keys, no signing)
  // ---------------------------------------------------------------------------
  //
  // params:
  //   sender            string, participant id
  //   recipients        string[], includes sender, 1-10, no duplicates
  //   replyTo           string (parent msg_id, UUIDv4) | null (default null)
  //   threadId          string | null. Root (replyTo null): defaults to the
  //                     new msg_id. Reply: the caller MUST pass the thread
  //                     root's msg_id, copied from the parent (§10).
  //   ttlSeconds        integer, 1..86400 (default 86400)
  //   nowSeconds        integer unix seconds (default: current time)
  //   msgId             string UUIDv4 override (tests only; default: fresh)
  //   sigAlg            'Ed25519' | 'ES256' (default 'Ed25519')
  //   iv, ct, mac       base64url strings (as produced by
  //                     Crypto.encryptMessage) or Uint8Array
  //   wrappedKeys       [{ recipient, wk }] with wk base64url string or
  //                     Uint8Array, one entry per recipient
  //
  // Returns the unsigned envelope object (no `sig` field). Throws
  // EnvelopeError on any invalid input — an envelope is never built half-valid.
  function buildUnsignedEnvelope(params) {
    params = params || {};
    var core = requireCrypto();

    if (typeof params.sender !== 'string' || params.sender.length === 0) {
      throw EnvelopeError('BAD_SENDER', 'sender must be a non-empty string');
    }
    if (!Array.isArray(params.recipients) ||
        params.recipients.length < MIN_RECIPIENTS ||
        params.recipients.length > MAX_RECIPIENTS) {
      throw EnvelopeError('BAD_RECIPIENTS',
        'recipients must be an array of ' + MIN_RECIPIENTS + '-' + MAX_RECIPIENTS + ' participant ids');
    }
    var seen = {};
    for (var i = 0; i < params.recipients.length; i++) {
      var r = params.recipients[i];
      if (typeof r !== 'string' || r.length === 0) {
        throw EnvelopeError('BAD_RECIPIENTS', 'each recipient must be a non-empty string');
      }
      if (seen[r]) throw EnvelopeError('BAD_RECIPIENTS', 'duplicate recipient "' + r + '"');
      seen[r] = true;
    }
    if (!seen[params.sender]) {
      throw EnvelopeError('BAD_RECIPIENTS', 'recipients must contain the sender "' + params.sender + '"');
    }

    var sigAlg = params.sigAlg || SIG_ALG_ED25519;
    if (SIG_ALGS.indexOf(sigAlg) === -1) {
      throw EnvelopeError('UNKNOWN_SIG_ALG', 'unknown sig_alg "' + sigAlg + '" (expected Ed25519 or ES256)');
    }

    var msgId = params.msgId || newMsgId();
    if (!isUuidV4(msgId)) {
      throw EnvelopeError('BAD_MSG_ID', 'msg_id must be a lowercase UUIDv4');
    }

    var replyTo = (params.replyTo === undefined) ? null : params.replyTo;
    if (replyTo !== null && !isUuidV4(replyTo)) {
      throw EnvelopeError('BAD_REPLY_TO', 'reply_to must be null or a UUIDv4 msg_id');
    }
    var threadId = params.threadId;
    if (replyTo === null) {
      // Root message: thread_id is its own msg_id (§10).
      if (threadId !== undefined && threadId !== null && threadId !== msgId) {
        throw EnvelopeError('BAD_THREAD_ID',
          'root message thread_id must equal its own msg_id');
      }
      threadId = msgId;
    } else if (typeof threadId !== 'string' || threadId.length === 0) {
      throw EnvelopeError('BAD_THREAD_ID',
        'a reply must carry thread_id copied from its parent (the thread root msg_id)');
    }

    var now = (params.nowSeconds === undefined) ? nowSeconds() : params.nowSeconds;
    if (!Number.isSafeInteger(now) || now <= 0) {
      throw EnvelopeError('BAD_TIMESTAMP', 'nowSeconds must be a positive integer unix time');
    }
    var ttl = (params.ttlSeconds === undefined) ? DEFAULT_TTL_SECONDS : params.ttlSeconds;
    if (!Number.isSafeInteger(ttl) || ttl < 1 || ttl > MAX_TTL_SECONDS) {
      throw EnvelopeError('BAD_TTL', 'ttlSeconds must be an integer in 1..' + MAX_TTL_SECONDS);
    }

    // Crypto fields: accept base64url strings or raw bytes; validate the
    // decoded lengths here so a malformed part can never be signed.
    function fieldBytes(value, field, expectedLength, multipleOf) {
      var bytes;
      if (typeof value === 'string') {
        if (!isValidBase64Url(value)) {
          throw EnvelopeError('BAD_BASE64URL', 'field "' + field + '" is not canonical base64url (no padding)');
        }
        bytes = decodeBase64UrlStrict(value, field);
      } else if (value instanceof Uint8Array) {
        bytes = value;
      } else {
        throw EnvelopeError('BAD_TYPE', 'field "' + field + '" must be a base64url string or Uint8Array');
      }
      if (expectedLength !== undefined && bytes.length !== expectedLength) {
        throw EnvelopeError('BAD_LENGTH',
          'field "' + field + '" must decode to ' + expectedLength + ' bytes, got ' + bytes.length);
      }
      if (multipleOf !== undefined &&
          (bytes.length === 0 || bytes.length % multipleOf !== 0)) {
        throw EnvelopeError('BAD_LENGTH',
          'field "' + field + '" must decode to a non-empty multiple of ' + multipleOf + ' bytes');
      }
      return bytes;
    }

    var iv = fieldBytes(params.iv, 'iv', IV_BYTES);
    var ct = fieldBytes(params.ct, 'ct', undefined, 16);
    var mac = fieldBytes(params.mac, 'mac', MAC_BYTES);

    if (!Array.isArray(params.wrappedKeys)) {
      throw EnvelopeError('BAD_WRAPPED_KEYS', 'wrappedKeys must be an array');
    }
    var wkSeen = {};
    var wrappedKeys = [];
    for (var j = 0; j < params.wrappedKeys.length; j++) {
      var entry = params.wrappedKeys[j];
      if (!isPlainObject(entry) || typeof entry.recipient !== 'string' ||
          entry.recipient.length === 0) {
        throw EnvelopeError('BAD_WRAPPED_KEYS',
          'each wrapped_keys entry must be {"recipient", "wk"}');
      }
      if (Object.keys(entry).length !== 2 || !('wk' in entry)) {
        throw EnvelopeError('BAD_WRAPPED_KEYS',
          'wrapped_keys entries carry exactly {"recipient", "wk"} — no extra fields');
      }
      if (wkSeen[entry.recipient]) {
        throw EnvelopeError('BAD_WRAPPED_KEYS', 'duplicate wrapped_keys entry for "' + entry.recipient + '"');
      }
      wkSeen[entry.recipient] = true;
      var wkBytes = fieldBytes(entry.wk, 'wrapped_keys[].wk');
      if (WRAPPED_KEY_BYTES.indexOf(wkBytes.length) === -1) {
        throw EnvelopeError('BAD_LENGTH',
          'wrapped key for "' + entry.recipient + '" must decode to 256, 384 or 512 bytes ' +
          '(RSA-2048/3072/4096 OAEP output), got ' + wkBytes.length);
      }
      wrappedKeys.push({
        recipient: entry.recipient,
        wk: (typeof entry.wk === 'string') ? entry.wk : core.bytesToBase64url(wkBytes)
      });
    }
    for (var k = 0; k < params.recipients.length; k++) {
      if (!wkSeen[params.recipients[k]]) {
        throw EnvelopeError('BAD_WRAPPED_KEYS',
          'missing wrapped_keys entry for recipient "' + params.recipients[k] + '"');
      }
    }
    if (wrappedKeys.length !== params.recipients.length) {
      throw EnvelopeError('BAD_WRAPPED_KEYS',
        'wrapped_keys must carry exactly one entry per recipient (no extras)');
    }

    return {
      v: ENVELOPE_VERSION,
      msg_id: msgId,
      sender: params.sender,
      recipients: params.recipients.slice(),
      iat: now,
      exp: now + ttl,
      reply_to: replyTo,
      thread_id: threadId,
      alg: ALG,
      sig_alg: sigAlg,
      iv: (typeof params.iv === 'string') ? params.iv : core.bytesToBase64url(iv),
      ct: (typeof params.ct === 'string') ? params.ct : core.bytesToBase64url(ct),
      mac: (typeof params.mac === 'string') ? params.mac : core.bytesToBase64url(mac),
      wrapped_keys: wrappedKeys
    };
  }

  // ---------------------------------------------------------------------------
  // Sign — attach `sig` to an unsigned envelope
  // ---------------------------------------------------------------------------
  //
  // signFn is NOT needed by callers: signEnvelope() signs with the given
  // CryptoKey via crypto-core.js (Ed25519) or crypto-p256.js (ES256).
  // The signature covers the canonical JSON WITHOUT `sig` and WITHOUT `seq`.
  async function signEnvelope(unsignedEnvelope, signingKey, sigAlg) {
    if (!isPlainObject(unsignedEnvelope)) {
      throw EnvelopeError('BAD_ENVELOPE', 'signEnvelope requires an envelope object');
    }
    if ('sig' in unsignedEnvelope) {
      throw EnvelopeError('BAD_ENVELOPE', 'envelope already carries a sig — refusing to double-sign');
    }
    if (!signingKey) {
      throw EnvelopeError('BAD_KEY', 'signEnvelope requires the sender signing private key');
    }
    var alg = sigAlg || unsignedEnvelope.sig_alg || SIG_ALG_ED25519;
    if (SIG_ALGS.indexOf(alg) === -1) {
      throw EnvelopeError('UNKNOWN_SIG_ALG', 'unknown sig_alg "' + alg + '"');
    }
    if (unsignedEnvelope.sig_alg && unsignedEnvelope.sig_alg !== alg) {
      throw EnvelopeError('UNKNOWN_SIG_ALG',
        'sig_alg argument "' + alg + '" does not match envelope sig_alg "' + unsignedEnvelope.sig_alg + '"');
    }
    var canonicalBytes = canonicalSignInput(unsignedEnvelope);
    var sigB64u;
    if (alg === SIG_ALG_ES256) {
      var p256 = requireP256();
      var raw = await p256.sign(canonicalBytes, signingKey, SIG_ALG_ES256);
      if (!(raw instanceof Uint8Array) || raw.length !== SIG_BYTES) {
        throw EnvelopeError('SIGN_FAILED', 'ES256 signature must be 64 raw bytes (R || S)');
      }
      sigB64u = encodeBase64Url(raw);
    } else {
      var core = requireCrypto();
      sigB64u = await core.signBytes(canonicalBytes, signingKey, SIG_ALG_ED25519);
    }
    var signed = {};
    var keys = Object.keys(unsignedEnvelope);
    for (var i = 0; i < keys.length; i++) signed[keys[i]] = unsignedEnvelope[keys[i]];
    signed.sig = sigB64u;
    return signed;
  }

  // ---------------------------------------------------------------------------
  // Build — full signed envelope from plaintext (the normal send path)
  // ---------------------------------------------------------------------------
  //
  // params: buildUnsignedEnvelope's params, plus:
  //   text                 string — the message (inner {"text": ...})
  //   signingKey           CryptoKey — sender's Ed25519 (or P-256) private key
  //   recipientPublicKeys  [{ recipient, publicKey }] | Map | { id: CryptoKey }
  //                       — RSA-OAEP public keys, one per recipient.
  //                       (Encrypts via Crypto.encryptMessage: fresh
  //                       ENC_KEY/MAC_KEY/IV per message, EtM HMAC,
  //                       RSA-OAEP-SHA-256 wrap per recipient.)
  //
  // Returns the complete signed envelope object. Never returns an unsigned
  // or half-built envelope.
  async function buildEnvelope(params) {
    params = params || {};
    if (typeof params.text !== 'string') {
      throw EnvelopeError('BAD_PLAINTEXT', 'buildEnvelope requires params.text (string)');
    }
    if (!params.signingKey) {
      throw EnvelopeError('BAD_KEY', 'buildEnvelope requires params.signingKey');
    }
    var sigAlg = params.sigAlg || SIG_ALG_ED25519;
    if (SIG_ALGS.indexOf(sigAlg) === -1) {
      throw EnvelopeError('UNKNOWN_SIG_ALG', 'unknown sig_alg "' + sigAlg + '"');
    }
    if (!Array.isArray(params.recipients) || params.recipients.length === 0) {
      throw EnvelopeError('BAD_RECIPIENTS', 'buildEnvelope requires params.recipients');
    }
    var core = requireCrypto();

    // Normalise recipientPublicKeys to [{ recipient, publicKey }] and
    // require exactly the recipients set — no missing wraps, no extras.
    var pubList = [];
    var supplied = params.recipientPublicKeys;
    if (Array.isArray(supplied)) {
      pubList = supplied;
    } else if (supplied && typeof supplied === 'object') {
      if (typeof supplied.get === 'function') {
        // Map
        supplied.forEach(function (publicKey, recipient) {
          pubList.push({ recipient: recipient, publicKey: publicKey });
        });
      } else {
        Object.keys(supplied).forEach(function (recipient) {
          pubList.push({ recipient: recipient, publicKey: supplied[recipient] });
        });
      }
    } else {
      throw EnvelopeError('BAD_KEY',
        'buildEnvelope requires params.recipientPublicKeys (array, Map, or { id: CryptoKey })');
    }
    var pubSeen = {};
    pubList.forEach(function (entry) {
      if (!entry || typeof entry.recipient !== 'string' || !entry.publicKey) {
        throw EnvelopeError('BAD_KEY', 'each recipientPublicKeys entry needs { recipient, publicKey }');
      }
      pubSeen[entry.recipient] = true;
    });
    params.recipients.forEach(function (r) {
      if (!pubSeen[r]) {
        throw EnvelopeError('BAD_KEY', 'no recipient public key supplied for "' + r + '"');
      }
    });
    pubList.forEach(function (entry) {
      if (params.recipients.indexOf(entry.recipient) === -1) {
        throw EnvelopeError('BAD_KEY',
          'recipient public key supplied for "' + entry.recipient + '", who is not a recipient');
      }
    });

    var plaintextBytes = encodePlaintext(params.text);
    var parts = await core.encryptMessage(plaintextBytes, pubList);
    var unsigned = buildUnsignedEnvelope({
      sender: params.sender,
      recipients: params.recipients,
      replyTo: params.replyTo,
      threadId: params.threadId,
      ttlSeconds: params.ttlSeconds,
      nowSeconds: params.nowSeconds,
      msgId: params.msgId,
      sigAlg: sigAlg,
      iv: parts.iv,
      ct: parts.ct,
      mac: parts.mac,
      wrappedKeys: parts.wrapped_keys
    });
    return signEnvelope(unsigned, params.signingKey, sigAlg);
  }

  // ---------------------------------------------------------------------------
  // Parse — JSON text / object -> { envelope, seq }
  // ---------------------------------------------------------------------------
  //
  // Accepts a JSON string (store file / inline log / pasted envelope) or an
  // already-parsed object. Returns { envelope, seq } where `envelope` is the
  // signed envelope WITHOUT `seq` and `seq` is the relay-assigned sequence
  // number or null when absent. `seq`, when present, must be a non-negative
  // safe integer. Throws EnvelopeError on malformed input — parse never
  // returns a half-envelope.
  function parseEnvelope(input) {
    var obj;
    if (typeof input === 'string') {
      try {
        obj = JSON.parse(input);
      } catch (e) {
        throw EnvelopeError('PARSE_ERROR', 'envelope is not valid JSON: ' + e.message);
      }
    } else if (isPlainObject(input)) {
      obj = input;
    } else {
      throw EnvelopeError('PARSE_ERROR', 'envelope must be a JSON string or a plain object');
    }
    if (Array.isArray(obj) || obj === null || typeof obj !== 'object') {
      throw EnvelopeError('PARSE_ERROR', 'envelope must be a JSON object');
    }
    var seq = null;
    if ('seq' in obj) {
      if (!Number.isSafeInteger(obj.seq) || obj.seq < 0) {
        throw EnvelopeError('BAD_SEQ', 'seq, when present, must be a non-negative integer');
      }
      seq = obj.seq;
    }
    // Copy (top level + the two arrays) so later mutation by the caller
    // cannot rewrite the parsed envelope, and strip `seq` from it.
    var envelope = {};
    var keys = Object.keys(obj);
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i];
      if (k === 'seq') continue;
      var v = obj[k];
      if (Array.isArray(v)) {
        envelope[k] = v.map(function (item) {
          return (isPlainObject(item)) ? Object.assign({}, item) : item;
        });
      } else {
        envelope[k] = v;
      }
    }
    return { envelope: envelope, seq: seq };
  }

  // Serialise an envelope for storage (store file / paste / relay). Plain
  // JSON.stringify — field order in storage is irrelevant; only the
  // canonical form matters for signing, and that is produced by
  // canonical-json.js, never by this function.
  function serializeEnvelope(envelope) {
    if (!isPlainObject(envelope)) {
      throw EnvelopeError('BAD_ENVELOPE', 'serializeEnvelope requires an envelope object');
    }
    return JSON.stringify(envelope);
  }

  // ---------------------------------------------------------------------------
  // Validate — shape (CRYPTO-DESIGN §7 step 1)
  // ---------------------------------------------------------------------------
  //
  // Returns an array of 'CODE: message' strings; [] means the shape is
  // valid. Never throws for a bad envelope (a bad envelope is a REJECT,
  // not an exception) — except MISSING_DEPENDENCY, which is a local
  // configuration failure, not an envelope defect.
  //
  // Checks (FILE-MAP §3, CRYPTO-DESIGN §6.1):
  //   all 15 required fields present, right types; no unknown fields
  //   (other than the relay's `seq`, which is allowed and ignored here);
  //   v == "ecc-1"; alg / sig_alg known; msg_id UUIDv4 lowercase;
  //   recipients 1-10, unique, containing sender; exp > iat;
  //   exp - iat <= 86400; reply_to null or UUIDv4; thread_id non-empty,
  //   and == msg_id for a root message; strict base64url everywhere with
  //   the decoded lengths (iv 16, mac 32, sig 64, ct non-empty multiple
  //   of 16, wk 256/384/512); wrapped_keys exactly one entry per
  //   recipient, entries shaped exactly {"recipient", "wk"}.
  //
  // Deliberately NOT checked here (see validateEnvelopeParticipants and
  // the caller): whether sender/recipients are among the three known
  // participants, and whether sig_alg matches the sender's PINNED
  // sig_alg. The published test vectors use placeholder ids
  // ("test-sender" / "test-recipient") and a placeholder thread_id, so
  // enforcing the production roster inside shape validation would reject
  // the vectors. Production callers MUST pass `participants` (and
  // `pinnedSigAlg`) to validateEnvelope().
  function validateEnvelopeShape(envelope, opts) {
    opts = opts || {};
    var requireSig = (opts.requireSig === undefined) ? true : !!opts.requireSig;
    var errors = [];
    function fail(code, message) { errors.push(code + ': ' + message); }

    if (!isPlainObject(envelope)) {
      fail('BAD_ENVELOPE', 'envelope must be a plain object');
      return errors;
    }

    // Unknown fields (fail closed — an envelope with fields the receiver
    // does not understand may be a newer version smuggled into an old v).
    var allowed = {};
    ENVELOPE_FIELDS.forEach(function (f) { allowed[f] = true; });
    allowed.seq = true; // relay-assigned, carried alongside, never signed
    Object.keys(envelope).forEach(function (k) {
      if (!allowed[k]) fail('UNKNOWN_FIELD', 'unknown envelope field "' + k + '"');
    });

    // Required fields.
    REQUIRED_FIELDS.forEach(function (f) {
      if (f === 'sig' && !requireSig) return;
      if (!(f in envelope)) fail('MISSING_FIELD', 'missing required field "' + f + '"');
    });
    if (errors.length > 0) return errors; // cannot check types of absent fields

    if (envelope.v !== ENVELOPE_VERSION) {
      fail('BAD_VERSION', 'v must be "' + ENVELOPE_VERSION + '", got ' + JSON.stringify(envelope.v));
    }
    if (!isUuidV4(envelope.msg_id)) {
      fail('BAD_MSG_ID', 'msg_id must be a lowercase UUIDv4');
    }
    if (typeof envelope.sender !== 'string' || envelope.sender.length === 0) {
      fail('BAD_SENDER', 'sender must be a non-empty string');
    }
    if (!Array.isArray(envelope.recipients)) {
      fail('BAD_RECIPIENTS', 'recipients must be an array');
    } else {
      if (envelope.recipients.length < MIN_RECIPIENTS ||
          envelope.recipients.length > MAX_RECIPIENTS) {
        fail('BAD_RECIPIENTS',
          'recipients must have ' + MIN_RECIPIENTS + '-' + MAX_RECIPIENTS + ' entries, got ' +
          envelope.recipients.length);
      }
      var rSeen = {};
      var rBad = false;
      envelope.recipients.forEach(function (r) {
        if (typeof r !== 'string' || r.length === 0) {
          fail('BAD_RECIPIENTS', 'each recipient must be a non-empty string');
          rBad = true;
        } else if (rSeen[r]) {
          fail('BAD_RECIPIENTS', 'duplicate recipient "' + r + '"');
          rBad = true;
        }
        rSeen[r] = true;
      });
      if (!rBad && envelope.recipients.indexOf(envelope.sender) === -1) {
        fail('BAD_RECIPIENTS', 'recipients must contain the sender "' + envelope.sender + '"');
      }
    }
    if (!Number.isSafeInteger(envelope.iat) || envelope.iat <= 0) {
      fail('BAD_TIMESTAMP', 'iat must be a positive integer unix time');
    }
    if (!Number.isSafeInteger(envelope.exp) || envelope.exp <= 0) {
      fail('BAD_TIMESTAMP', 'exp must be a positive integer unix time');
    }
    if (Number.isSafeInteger(envelope.iat) && Number.isSafeInteger(envelope.exp)) {
      if (envelope.exp <= envelope.iat) {
        fail('BAD_EXPIRY', 'exp must be greater than iat');
      } else if (envelope.exp - envelope.iat > MAX_TTL_SECONDS) {
        fail('BAD_TTL', 'exp - iat must be <= ' + MAX_TTL_SECONDS + ' seconds (24 h maximum)');
      }
    }
    if (envelope.reply_to !== null && !isUuidV4(envelope.reply_to)) {
      fail('BAD_REPLY_TO', 'reply_to must be null or a UUIDv4 msg_id');
    }
    if (typeof envelope.thread_id !== 'string' || envelope.thread_id.length === 0) {
      fail('BAD_THREAD_ID', 'thread_id must be a non-empty string');
    } else if (envelope.reply_to === null && isUuidV4(envelope.msg_id) &&
               envelope.thread_id !== envelope.msg_id) {
      fail('BAD_THREAD_ID', 'root message thread_id must equal its own msg_id');
    }
    if (envelope.alg !== ALG) {
      fail('UNKNOWN_ALG', 'alg must be "' + ALG + '", got ' + JSON.stringify(envelope.alg));
    }
    if (SIG_ALGS.indexOf(envelope.sig_alg) === -1) {
      fail('UNKNOWN_SIG_ALG',
        'sig_alg must be "Ed25519" or "ES256", got ' + JSON.stringify(envelope.sig_alg));
    }

    // Binary fields: strict base64url syntax first, then decoded lengths.
    // Decoding goes through crypto-core.js (strict: rejects padding,
    // out-of-alphabet chars, and non-canonical trailing bits).
    var core;
    try {
      core = requireCrypto();
    } catch (e) {
      fail('MISSING_DEPENDENCY', e.message);
      return errors;
    }
    function checkB64Field(field, expectedLength, multipleOf) {
      var value = envelope[field];
      if (typeof value !== 'string' || value.length === 0) {
        fail('BAD_TYPE', 'field "' + field + '" must be a non-empty base64url string');
        return;
      }
      if (!isValidBase64Url(value)) {
        fail('BAD_BASE64URL',
          'field "' + field + '" is not canonical base64url (no padding, alphabet A-Za-z0-9-_)');
        return;
      }
      var bytes;
      try {
        bytes = core.base64urlToBytes(value);
      } catch (e2) {
        fail('BAD_BASE64URL', 'field "' + field + '" is not canonical base64url: ' + e2.message);
        return;
      }
      if (expectedLength !== undefined && bytes.length !== expectedLength) {
        fail('BAD_LENGTH',
          'field "' + field + '" must decode to ' + expectedLength + ' bytes, got ' + bytes.length);
      }
      if (multipleOf !== undefined && (bytes.length === 0 || bytes.length % multipleOf !== 0)) {
        fail('BAD_LENGTH',
          'field "' + field + '" must decode to a non-empty multiple of ' + multipleOf + ' bytes');
      }
    }
    checkB64Field('iv', IV_BYTES);
    checkB64Field('ct', undefined, 16);
    checkB64Field('mac', MAC_BYTES);
    if (requireSig) checkB64Field('sig', SIG_BYTES);

    if (!Array.isArray(envelope.wrapped_keys)) {
      fail('BAD_WRAPPED_KEYS', 'wrapped_keys must be an array');
    } else {
      var wSeen = {};
      envelope.wrapped_keys.forEach(function (entry, idx) {
        if (!isPlainObject(entry)) {
          fail('BAD_WRAPPED_KEYS', 'wrapped_keys[' + idx + '] must be an object');
          return;
        }
        var eKeys = Object.keys(entry);
        if (eKeys.length !== 2 || !('recipient' in entry) || !('wk' in entry)) {
          fail('BAD_WRAPPED_KEYS',
            'wrapped_keys[' + idx + '] must carry exactly {"recipient", "wk"}');
          return;
        }
        if (typeof entry.recipient !== 'string' || entry.recipient.length === 0) {
          fail('BAD_WRAPPED_KEYS', 'wrapped_keys[' + idx + '].recipient must be a non-empty string');
          return;
        }
        if (wSeen[entry.recipient]) {
          fail('BAD_WRAPPED_KEYS', 'duplicate wrapped_keys entry for "' + entry.recipient + '"');
          return;
        }
        wSeen[entry.recipient] = true;
        if (typeof entry.wk !== 'string' || !isValidBase64Url(entry.wk)) {
          fail('BAD_BASE64URL',
            'wrapped_keys[' + idx + '].wk is not canonical base64url (no padding)');
          return;
        }
        var wkBytes;
        try {
          wkBytes = core.base64urlToBytes(entry.wk);
        } catch (e3) {
          fail('BAD_BASE64URL', 'wrapped_keys[' + idx + '].wk is not canonical base64url: ' + e3.message);
          return;
        }
        if (WRAPPED_KEY_BYTES.indexOf(wkBytes.length) === -1) {
          fail('BAD_LENGTH',
            'wrapped key for "' + entry.recipient + '" must decode to 256, 384 or 512 bytes ' +
            '(RSA-2048/3072/4096 OAEP output), got ' + wkBytes.length);
        }
      });
      if (Array.isArray(envelope.recipients)) {
        envelope.recipients.forEach(function (r) {
          if (typeof r === 'string' && !wSeen[r]) {
            fail('BAD_WRAPPED_KEYS', 'missing wrapped_keys entry for recipient "' + r + '"');
          }
        });
        Object.keys(wSeen).forEach(function (r) {
          if (envelope.recipients.indexOf(r) === -1) {
            fail('BAD_WRAPPED_KEYS',
              'wrapped_keys entry for "' + r + '", who is not a recipient');
          }
        });
      }
    }
    return errors;
  }

  // ---------------------------------------------------------------------------
  // Validate — timing (CRYPTO-DESIGN §7 step 2)
  // ---------------------------------------------------------------------------
  //
  // Returns 'CODE: message' errors, [] when the envelope is live.
  //   exp > now, iat <= now + 300. (exp > iat and TTL <= 86400 are shape
  // checks, above.) `now` defaults to the current time; pass an explicit
  // unix time in tests.
  function validateEnvelopeTiming(envelope, now) {
    var errors = [];
    function fail(code, message) { errors.push(code + ': ' + message); }
    if (!isPlainObject(envelope)) {
      fail('BAD_ENVELOPE', 'envelope must be a plain object');
      return errors;
    }
    var t = (now === undefined) ? nowSeconds() : now;
    if (!Number.isSafeInteger(t) || t <= 0) {
      fail('BAD_TIMESTAMP', 'reference time must be a positive integer unix time');
      return errors;
    }
    if (Number.isSafeInteger(envelope.exp) && envelope.exp <= t) {
      fail('EXPIRED', 'envelope expired at exp=' + envelope.exp + ' (now=' + t + ')');
    }
    if (Number.isSafeInteger(envelope.iat) && envelope.iat > t + MAX_FUTURE_SKEW_SECONDS) {
      fail('FUTURE_IAT',
        'iat=' + envelope.iat + ' is more than ' + MAX_FUTURE_SKEW_SECONDS +
        ' s in the future (now=' + t + ')');
    }
    return errors;
  }

  // ---------------------------------------------------------------------------
  // Validate — participants + pinned sig_alg (CRYPTO-DESIGN §7 step 3)
  // ---------------------------------------------------------------------------
  //
  // Returns errors, [] when the sender/recipients are all on the roster and
  // the envelope sig_alg matches the pinned one (when a pinned value is
  // supplied). `participants` defaults to the three ecc-1 ids; pass the
  // participants.json roster (or a test roster) to override. Passing
  // participants: null SKIPS the membership check — only for vector /
  // fixture checks, never in production.
  function validateEnvelopeParticipants(envelope, participants, pinnedSigAlg) {
    var errors = [];
    function fail(code, message) { errors.push(code + ': ' + message); }
    if (!isPlainObject(envelope)) {
      fail('BAD_ENVELOPE', 'envelope must be a plain object');
      return errors;
    }
    if (participants !== null && participants !== undefined) {
      var roster = Array.isArray(participants) ? participants : KNOWN_PARTICIPANTS;
      if (roster.indexOf(envelope.sender) === -1) {
        fail('UNKNOWN_SENDER', 'sender "' + envelope.sender + '" is not a known participant');
      }
      if (Array.isArray(envelope.recipients)) {
        envelope.recipients.forEach(function (r) {
          if (roster.indexOf(r) === -1) {
            fail('UNKNOWN_RECIPIENT', 'recipient "' + r + '" is not a known participant');
          }
        });
      }
    }
    if (pinnedSigAlg !== null && pinnedSigAlg !== undefined &&
        envelope.sig_alg !== pinnedSigAlg) {
      fail('SIG_ALG_MISMATCH',
        'envelope sig_alg "' + envelope.sig_alg + '" does not match the sender\'s pinned ' +
        'sig_alg "' + pinnedSigAlg + '" — refusing (no silent downgrade)');
    }
    return errors;
  }

  // ---------------------------------------------------------------------------
  // Validate — combined (§7 steps 1-3, minus the ledger step 4)
  // ---------------------------------------------------------------------------
  //
  // opts:
  //   nowSeconds     integer unix time (default: current time)
  //   participants   array of known ids (default: the three ecc-1 ids).
  //                  Pass null to skip membership (vectors/fixtures only).
  //   pinnedSigAlg   'Ed25519' | 'ES256' | null — when supplied, the
  //                  envelope sig_alg must match it (no silent downgrade).
  //   requireSig     bool (default true)
  //
  // Returns { ok: boolean, errors: string[] }. The seen-ledger check
  // (§7 step 4) is NOT done here — the caller (relay / A12 ledger) owns
  // it, and re-checks atomically at step 8.
  function validateEnvelope(envelope, opts) {
    opts = opts || {};
    var errors = [];
    errors = errors.concat(validateEnvelopeShape(envelope, opts));
    // Timing is only meaningful on a well-shaped envelope; still run it
    // when the shape errors are unrelated to iat/exp so callers see the
    // full picture, but skip it if iat/exp themselves are malformed.
    if (Number.isSafeInteger(envelope && envelope.iat) &&
        Number.isSafeInteger(envelope && envelope.exp)) {
      errors = errors.concat(validateEnvelopeTiming(envelope, opts.nowSeconds));
    }
    var participants = (opts.participants === undefined)
      ? KNOWN_PARTICIPANTS : opts.participants;
    errors = errors.concat(
      validateEnvelopeParticipants(envelope, participants, opts.pinnedSigAlg || null));
    return { ok: errors.length === 0, errors: errors };
  }

  // ---------------------------------------------------------------------------
  // Verify — signature (§7 step 5)
  // ---------------------------------------------------------------------------
  //
  // verifyEnvelopeSignature(envelope, publicKey, opts) verifies the
  // envelope's `sig` against `publicKey` (a CryptoKey) over the canonical
  // JSON WITHOUT `sig` and WITHOUT `seq`. Dispatches on the envelope's
  // sig_alg: Ed25519 via crypto-core.js, ES256 via crypto-p256.js.
  //
  // opts.pinnedSigAlg — when supplied, a mismatch is a REJECT before any
  // crypto runs (no silent downgrade, §4.4).
  //
  // Returns Promise<{ ok: boolean, errors: string[] }>. A bad signature is
  // { ok: false } — never a throw. Throws EnvelopeError only for a
  // structurally unusable envelope or a missing dependency (ES256 without
  // crypto-p256.js loaded).
  async function verifyEnvelopeSignature(envelope, publicKey, opts) {
    opts = opts || {};
    var errors = [];
    function fail(code, message) { errors.push(code + ': ' + message); }
    var shapeErrors = validateEnvelopeShape(envelope);
    if (shapeErrors.length > 0) {
      return { ok: false, errors: shapeErrors };
    }
    if (opts.pinnedSigAlg && envelope.sig_alg !== opts.pinnedSigAlg) {
      fail('SIG_ALG_MISMATCH',
        'envelope sig_alg "' + envelope.sig_alg + '" does not match the sender\'s pinned ' +
        'sig_alg "' + opts.pinnedSigAlg + '" — refusing (no silent downgrade)');
      return { ok: false, errors: errors };
    }
    if (!publicKey) {
      fail('BAD_KEY', 'verifyEnvelopeSignature requires the sender\'s pinned public key');
      return { ok: false, errors: errors };
    }
    var canonicalBytes;
    try {
      canonicalBytes = canonicalSignInput(envelope);
    } catch (e) {
      fail('BAD_ENVELOPE', 'canonical sign input could not be produced: ' + e.message);
      return { ok: false, errors: errors };
    }
    var verified = false;
    try {
      if (envelope.sig_alg === SIG_ALG_ES256) {
        var p256 = requireP256();
        var sigBytes = decodeBase64UrlStrict(envelope.sig, 'sig');
        if (sigBytes.length !== SIG_BYTES) {
          fail('BAD_SIGNATURE', 'sig must decode to 64 bytes, got ' + sigBytes.length);
          return { ok: false, errors: errors };
        }
        verified = await p256.verify(canonicalBytes, sigBytes, publicKey, SIG_ALG_ES256);
      } else {
        var core = requireCrypto();
        verified = await core.verifySignature(
          canonicalBytes, envelope.sig, publicKey, SIG_ALG_ED25519);
      }
    } catch (e) {
      if (e && e.name === 'EnvelopeError') throw e; // missing dependency: fail loudly
      fail('BAD_SIGNATURE', 'signature verification failed: ' + (e && e.message ? e.message : e));
      return { ok: false, errors: errors };
    }
    if (!verified) fail('BAD_SIGNATURE', 'signature does not verify against the pinned public key');
    return { ok: verified, errors: errors };
  }

  // verifyEnvelope() — §7 steps 1, 2, 3 (partial: roster + pinned
  // sig_alg) and 5, in order; first failure short-circuits. Ledger (step 4)
  // and decrypt (steps 6-8) are the caller's — see validateEnvelope() and
  // decryptEnvelope(). Returns Promise<{ ok, errors, signatureValid }>,
  // where signatureValid is true/false, or null when no publicKey was
  // supplied (shape+timing only — the caller must still verify the
  // signature before trusting the message).
  async function verifyEnvelope(envelope, opts) {
    opts = opts || {};
    var result = validateEnvelope(envelope, opts);
    if (!result.ok) {
      return { ok: false, errors: result.errors, signatureValid: null };
    }
    if (!opts.publicKey) {
      return { ok: true, errors: [], signatureValid: null };
    }
    var sig = await verifyEnvelopeSignature(envelope, opts.publicKey, opts);
    return { ok: sig.ok, errors: sig.errors, signatureValid: sig.ok };
  }

  // ---------------------------------------------------------------------------
  // Decrypt — §7 steps 6-8 (orchestration; crypto lives in crypto-core.js)
  // ---------------------------------------------------------------------------
  //
  // decryptEnvelope(envelope, privateKey, recipientId) unwraps this
  // recipient's wrapped key, verifies the HMAC (constant-time, BEFORE
  // decrypting — EtM order), decrypts, and parses the inner plaintext.
  // Returns Promise<{ text: string }>. Throws CryptoError / EnvelopeError
  // on any failure (NO_WRAPPED_KEY, UNWRAP_FAILED, MAC_MISMATCH,
  // DECRYPT_FAILED, BAD_PLAINTEXT) — a failure rejects the message and
  // produces NO plaintext. Shape is validated first so malformed
  // envelopes never reach the private key (§7: signature-verified
  // messages only should reach keys — callers MUST verifyEnvelope() with
  // the pinned key before calling this).
  async function decryptEnvelope(envelope, privateKey, recipientId) {
    var shapeErrors = validateEnvelopeShape(envelope);
    if (shapeErrors.length > 0) {
      throw EnvelopeError('BAD_ENVELOPE',
        'cannot decrypt a malformed envelope: ' + shapeErrors.join('; '));
    }
    if (typeof recipientId !== 'string' || recipientId.length === 0) {
      throw EnvelopeError('BAD_TYPE', 'decryptEnvelope requires the recipient id');
    }
    if (!privateKey) {
      throw EnvelopeError('BAD_KEY', 'decryptEnvelope requires the recipient private key');
    }
    var core = requireCrypto();
    var plaintextBytes = await core.decryptMessage(
      { iv: envelope.iv, ct: envelope.ct, mac: envelope.mac, wrapped_keys: envelope.wrapped_keys },
      recipientId,
      privateKey
    );
    return { text: decodePlaintext(plaintextBytes) };
  }

  // ---------------------------------------------------------------------------
  // Dependency / readiness diagnostic (for C1 bootstrap + tests)
  // ---------------------------------------------------------------------------

  function isReady() {
    return {
      canonicalJSON: !!CanonicalJSON,
      cryptoCore: !!Crypto,
      p256: !!P256,
      ed25519: !!Crypto,
      es256: !!P256
    };
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  return {
    // Constants
    ENVELOPE_VERSION: ENVELOPE_VERSION,
    ALG: ALG,
    SIG_ALG_ED25519: SIG_ALG_ED25519,
    SIG_ALG_ES256: SIG_ALG_ES256,
    SIG_ALGS: SIG_ALGS,
    KNOWN_PARTICIPANTS: KNOWN_PARTICIPANTS,
    MAX_TTL_SECONDS: MAX_TTL_SECONDS,
    DEFAULT_TTL_SECONDS: DEFAULT_TTL_SECONDS,
    MAX_FUTURE_SKEW_SECONDS: MAX_FUTURE_SKEW_SECONDS,
    MAX_PLAINTEXT_BYTES: MAX_PLAINTEXT_BYTES,
    MAX_RECIPIENTS: MAX_RECIPIENTS,
    IV_BYTES: IV_BYTES,
    MAC_BYTES: MAC_BYTES,
    SIG_BYTES: SIG_BYTES,
    ENVELOPE_FIELDS: ENVELOPE_FIELDS,
    REQUIRED_FIELDS: REQUIRED_FIELDS,

    // Errors / misc helpers
    EnvelopeError: EnvelopeError,
    isReady: isReady,
    newMsgId: newMsgId,
    isUuidV4: isUuidV4,
    isValidBase64Url: isValidBase64Url,
    decodeBase64UrlStrict: decodeBase64UrlStrict,

    // Inner plaintext (§6.4)
    encodePlaintext: encodePlaintext,
    decodePlaintext: decodePlaintext,

    // Canonical sign input (§6.2) — envelope WITHOUT sig AND WITHOUT seq
    canonicalSignInput: canonicalSignInput,
    canonicalSignInputString: canonicalSignInputString,

    // Build
    buildUnsignedEnvelope: buildUnsignedEnvelope,
    signEnvelope: signEnvelope,
    buildEnvelope: buildEnvelope,

    // Parse / serialise
    parseEnvelope: parseEnvelope,
    serializeEnvelope: serializeEnvelope,

    // Validate (§7 steps 1-3)
    validateEnvelopeShape: validateEnvelopeShape,
    validateEnvelopeTiming: validateEnvelopeTiming,
    validateEnvelopeParticipants: validateEnvelopeParticipants,
    validateEnvelope: validateEnvelope,

    // Verify + decrypt (§7 steps 5-8)
    verifyEnvelopeSignature: verifyEnvelopeSignature,
    verifyEnvelope: verifyEnvelope,
    decryptEnvelope: decryptEnvelope
  };
});
