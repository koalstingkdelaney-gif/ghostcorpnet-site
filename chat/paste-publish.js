/**
 * paste-publish.js — paste-envelope publish (worker C14, wave 2).
 *
 * The path by which ChatGPT's replies reach the store. ChatGPT has NO direct
 * write path (FILE-MAP D3): it encrypts + signs in its sandbox and hands the
 * envelope to the owner, who pastes it into the app. This module validates
 * the pasted envelope and, only if every check passes, publishes it with the
 * owner's GitHub PAT to `chat/messages/<msg_id>.json` + a manifest update.
 * If any check fails it rejects with a plain-words reason and publishes
 * NOTHING.
 *
 * Normative refs (FILE-MAP.md is authoritative; it wins over design docs):
 *   - FILE-MAP §3 envelope (`ecc-1`), canonical JSON, verification order,
 *     store / manifest layout, relay caps and error codes.
 *   - FILE-MAP D2/D3 store layout + writers (owner via PAT; ChatGPT none).
 *   - FILE-MAP D5 `ecc-1` (AES-256-CBC + HMAC-SHA-256 EtM, Ed25519 primary,
 *     ES256 fallback) — overrides the relay spec's AES-256-GCM and the
 *     CHATGPT-JOIN §4/§5 v1 envelope (`id`/`from`/`to`/`created`/`expires`
 *     strings, GCM `enc_key`/`nonce`/`ciphertext`/`tag`).
 *   - FILE-MAP D9/D10/D17: default recipients all three; 24 h TTL max;
 *     no message accepted from a sender whose keys are not `pinned`.
 *   - CRYPTO-DESIGN.md §7 verification order (steps 1–3 + 5; steps 6–8 —
 *     unwrap / HMAC / decrypt — are the RECIPIENT's job, not this module's:
 *     paste-publish never decrypts and never sees plaintext).
 *   - RELAY-SPEC §7(b) `post` flow: read manifest (note `sha` + next seq),
 *     write the message file, CAS-update the manifest, retry up to 5 times,
 *     re-stamping `seq` on retry (safe: `seq` is never part of the signed
 *     bytes). Idempotent: same ID + same bytes = OK; same ID + different
 *     bytes = MSG_ID_CONFLICT.
 *
 * Paste forms accepted (CHATGPT-JOIN §5b: "the app MUST provide a
 * paste-a-ciphertext compose box"):
 *   (a) Raw envelope JSON — one object, compact or pretty-printed, with or
 *       without ```json fences and with or without label lines around it.
 *   (b) A 3-line BEGIN/END-wrapped block: a label line, one base64url blob
 *       holding the envelope JSON, and an END line (the blob may wrap over
 *       several lines). The blob is decoded to UTF-8 JSON, then handled as (a).
 *   NOT accepted, rejected with a plain-words reason, publishing nothing:
 *   - the old v2 bridge 3-line block (header / base64 ciphertext / base64
 *     signature). It is not an `ecc-1` envelope: it carries no `msg_id`,
 *     `recipients`, `iat`/`exp` or wrapped keys, and its signature covers
 *     different bytes, so it cannot be verified as a chat message.
 *     (FILE-MAP D5 / CRYPTO-DESIGN §2.2: a v2 drop signature cannot be
 *     transplanted into a chat message — by design.)
 *   - anything that looks like a plain typed message. The pasted block is
 *     ciphertext, never plaintext — this module has no plaintext input path
 *     at all, and never asks for or accepts a plaintext message from ChatGPT
 *     (CHATGPT-JOIN §6 F12).
 *
 * What this module does NOT do:
 *   - No decryption, no plaintext handling, no key generation, no private
 *     keys anywhere. It only verifies a signature against a PINNED public
 *     key from the key directory.
 *   - No seen-ledger check against a local file (the browser has none).
 *     The store-level equivalent runs at publish time: if a message file
 *     with the same `msg_id` already exists, same envelope bytes = idempotent
 *     OK, different bytes = MSG_ID_CONFLICT (FILE-MAP §3).
 *   - No token storage. The PAT comes from the caller (see wiring below);
 *     it is used only as a Bearer header and never logged or stored here.
 *
 * Wiring (app integration — the app owns the page, this module owns logic):
 *   Load order: app/config.js, app/js/canonical-json.js (A3),
 *   app/js/crypto-core.js (A1), app/js/crypto-p256.js (A2), then this file.
 *   A3/A1/A2 are used when present; every one of them has a self-contained
 *   fallback below, so the module also works standalone / under Node tests.
 *     const result = await GhostChatPastePublish.publishPasted(pastedText, {
 *       getToken: () => GhostChatPat.getToken(),   // C13, async or sync
 *       // …or: pat: "<token>", …or: publisher: <custom {getFile,putFile}>
 *     });
 *     if (result.ok) show("Published as message #" + result.seq);
 *     else show(result.reason);                    // plain words, no jargon
 *   Expected C13 contract (not yet landed at time of writing — C14 defines
 *   its side here): `window.GhostChatPat.getToken()` returns a Promise (or
 *   a string) resolving to the owner's fine-grained PAT (contents write on
 *   the site repo only). If no PAT source is supplied and none is found on
 *   `window.GhostChatPat`, publish fails with NO_ACCESS_TOKEN and nothing
 *   is written.
 *   Repo/paths default from `window.CONFIG` (C20) when present, else
 *   owner `koalstingkdelaney-gif`, repo `ghostcorpnet-site`, store dir
 *   `chat/` (CONFIG.siteRepoOwner/siteRepoName, verified from the live
 *   clone in config.js). Override via options.github / options.storeDir.
 *
 * No keys, no plaintext conversation content, no secrets, no personal info
 * belong in this file. Test fixtures use throwaway keys only.
 */

(function (global) {
  'use strict';

  // ---------------------------------------------------------------------------
  // Constants — FILE-MAP §3 / CRYPTO-DESIGN §6, §11
  // ---------------------------------------------------------------------------

  var ENVELOPE_VERSION = 'ecc-1';
  var ALG = 'A256CBC-HS256';
  var SIG_ALG_ED25519 = 'Ed25519';
  var SIG_ALG_ES256 = 'ES256';
  var KNOWN_PARTICIPANTS = ['jarvis', 'chatgpt', 'owner'];

  var MAX_TTL_SECONDS = 86400;        // D10: 24 h default AND maximum
  var MAX_FUTURE_SKEW_SECONDS = 300;  // v2 rule, FILE-MAP §3 step 2
  var MAX_ENVELOPE_BYTES = 65536;     // relay cap, FILE-MAP §3
  var MAX_CIPHERTEXT_BYTES = 24576;   // relay cap, FILE-MAP §3
  var IV_BYTES = 16;
  var MAC_BYTES = 32;
  var SIG_BYTES = 64;                 // Ed25519 raw, or ES256 raw R||S
  var UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

  // Envelope fields, exactly FILE-MAP §3 / CRYPTO-DESIGN §6.1. Unknown
  // fields → reject; missing fields → reject.
  var ENVELOPE_FIELDS = [
    'v', 'msg_id', 'sender', 'recipients', 'iat', 'exp', 'reply_to',
    'thread_id', 'alg', 'sig_alg', 'iv', 'ct', 'mac', 'wrapped_keys', 'sig'
  ];

  var MAX_MANIFEST_CAS_ATTEMPTS = 5;  // RELAY-SPEC §7(b) post step 4

  var DEFAULT_GITHUB = {
    owner: 'koalstingkdelaney-gif',
    repo: 'ghostcorpnet-site',
    apiBase: 'https://api.github.com',
    storeDir: 'chat'
  };

  // ---------------------------------------------------------------------------
  // Errors — every rejection carries a machine code AND a plain-words reason.
  // The UI shows `reason` verbatim (no jargon). Nothing is published on any
  // rejection; the caller checks `result.ok`.
  // ---------------------------------------------------------------------------

  var REASONS = {
    EMPTY_PASTE: 'Nothing was pasted. Paste the whole locked message block ChatGPT gave you.',
    NOT_AN_ENVELOPE: 'That doesn\u2019t look like a locked message. Paste the whole block ChatGPT printed \u2014 the app never accepts a plain typed message from ChatGPT.',
    OLD_BRIDGE_FORMAT: 'That block is the old bridge format (three lines), not a chat message. Ask ChatGPT to send the chat envelope instead \u2014 the app can\u2019t check the old format, so nothing was published.',
    BAD_SHAPE: 'The message block is missing pieces or has pieces in the wrong shape, so it can\u2019t be checked. Nothing was published \u2014 ask ChatGPT to send it again.',
    UNKNOWN_VERSION: 'This message uses a chat version this app doesn\u2019t know yet. Nothing was published.',
    UNKNOWN_ALG: 'This message uses an encryption method this app doesn\u2019t know. Nothing was published.',
    UNKNOWN_SIG_ALG: 'This message uses a signing method this app doesn\u2019t know. Nothing was published.',
    EXPIRED: 'This message has expired. Ask ChatGPT to send a fresh one \u2014 nothing was published.',
    NOT_YET_VALID: 'This message says it was created in the future. Check the clock, or ask ChatGPT to send it again.',
    TTL_TOO_LONG: 'This message claims to last longer than 24 hours. The chat only allows 24 hours, so nothing was published.',
    SENDER_UNKNOWN: 'The sender isn\u2019t in the chat\u2019s key list, so the message can\u2019t be checked. Nothing was published.',
    SENDER_NOT_PINNED: 'ChatGPT\u2019s keys aren\u2019t confirmed yet. The owner needs to confirm ChatGPT\u2019s key fingerprints first \u2014 until then no message from ChatGPT can be accepted, and nothing was published.',
    SIG_ALG_MISMATCH: 'The message was signed with a different method than the one on file for this sender. Nothing was published.',
    KEY_MISMATCH: 'The key on file for this sender doesn\u2019t match its recorded fingerprint, so it can\u2019t be trusted. Nothing was published.',
    BAD_SIGNATURE: 'The signature doesn\u2019t match. The message may have been changed after signing, or copied wrong. Nothing was published \u2014 ask ChatGPT to send it again.',
    MSG_ID_CONFLICT: 'A different message with this same ID is already in the chat. Nothing was changed.',
    KEY_DIRECTORY_UNAVAILABLE: 'Couldn\u2019t load the chat\u2019s key list. Check you\u2019re online and try again.',
    NO_ACCESS_TOKEN: 'No GitHub access token is saved in this browser yet. Add it first (owner only), then paste again. Nothing was published.',
    PUBLISH_FAILED: 'GitHub wouldn\u2019t take the message. Nothing was published \u2014 try again.',
    MANIFEST_CONFLICT_RETRY: 'Too many people published at the same moment and the chat list kept changing. The message itself was saved, but the list update needs another try \u2014 paste again and it will finish without duplicating.',
    STORE_UNEXPECTED: 'The chat store came back in a shape the app doesn\u2019t recognise. Nothing was published.'
  };

  function fail(code, detail) {
    var err = new Error(REASONS[code] || code);
    err.name = 'PastePublishError';
    err.code = code;
    err.reason = REASONS[code] || code;
    if (detail) err.detail = detail;
    return err;
  }

  function rejection(err) {
    return {
      ok: false,
      code: err && err.code ? err.code : 'PUBLISH_FAILED',
      reason: (err && err.reason) || REASONS.PUBLISH_FAILED,
      detail: err && err.detail ? String(err.detail) : undefined
    };
  }

  // ---------------------------------------------------------------------------
  // Small helpers (self-contained; no dependency on sibling modules)
  // ---------------------------------------------------------------------------

  function isPlainObject(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
    var proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
  }

  function nowSeconds(nowFn) {
    if (typeof nowFn === 'function') return nowFn();
    return Math.floor(Date.now() / 1000);
  }

  function utf8Bytes(text) {
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(text);
    return Buffer.from(text, 'utf-8');
  }

  function utf8Text(bytes) {
    if (typeof TextDecoder !== 'undefined') {
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    }
    return Buffer.from(bytes).toString('utf-8');
  }

  // --- base64url (RFC 4648 §5), strict: no padding, canonical only --------
  // FILE-MAP §3 / CRYPTO-DESIGN §6.3: decoders reject non-canonical input.

  var B64U_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  var B64U_RE = /^[A-Za-z0-9_-]*$/;

  function bytesToBase64url(bytes) {
    var out = '';
    var i;
    for (i = 0; i + 3 <= bytes.length; i += 3) {
      var n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
      out += B64U_ALPHABET[(n >> 18) & 63] + B64U_ALPHABET[(n >> 12) & 63] +
             B64U_ALPHABET[(n >> 6) & 63] + B64U_ALPHABET[n & 63];
    }
    var rem = bytes.length - i;
    if (rem === 1) {
      var n1 = bytes[i] << 16;
      out += B64U_ALPHABET[(n1 >> 18) & 63] + B64U_ALPHABET[(n1 >> 12) & 63];
    } else if (rem === 2) {
      var n2 = (bytes[i] << 16) | (bytes[i + 1] << 8);
      out += B64U_ALPHABET[(n2 >> 18) & 63] + B64U_ALPHABET[(n2 >> 12) & 63] +
             B64U_ALPHABET[(n2 >> 6) & 63];
    }
    return out;
  }

  function base64urlToBytes(str) {
    if (typeof str !== 'string') throw fail('BAD_SHAPE', 'base64url field is not a string');
    if (str.indexOf('=') !== -1) throw fail('BAD_SHAPE', 'base64url field contains padding');
    if (!B64U_RE.test(str)) throw fail('BAD_SHAPE', 'base64url field has characters outside the alphabet');
    if (str.length % 4 === 1) throw fail('BAD_SHAPE', 'base64url field has an impossible length');
    var b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4 !== 0) b64 += '=';
    var bin;
    if (typeof atob === 'function') bin = atob(b64);
    else bin = Buffer.from(b64, 'base64').toString('binary');
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i) & 0xff;
    if (bytesToBase64url(out) !== str) throw fail('BAD_SHAPE', 'base64url field is not canonically encoded');
    return out;
  }

  // --- standard base64 (PEM bodies, GitHub Contents API payloads) ----------

  function base64ToBytes(b64) {
    var clean = String(b64).replace(/\s+/g, '');
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) {
      throw fail('BAD_SHAPE', 'base64 input has characters outside the alphabet');
    }
    var bin;
    if (typeof atob === 'function') bin = atob(clean);
    else bin = Buffer.from(clean, 'base64').toString('binary');
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i) & 0xff;
    return out;
  }

  function bytesToBase64(bytes) {
    if (typeof btoa === 'function') {
      var bin = '';
      for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      return btoa(bin);
    }
    return Buffer.from(bytes).toString('base64');
  }

  function pemToDer(pem) {
    if (typeof pem !== 'string') throw fail('KEY_MISMATCH', 'public key is not a PEM string');
    var beginMarker = '-----BEGIN PUBLIC KEY-----';
    var endMarker = '-----END PUBLIC KEY-----';
    var begin = pem.indexOf(beginMarker);
    var end = pem.indexOf(endMarker);
    if (begin === -1 || end === -1 || end <= begin) {
      throw fail('KEY_MISMATCH', 'public key is not a PUBLIC KEY PEM block');
    }
    return base64ToBytes(pem.slice(begin + beginMarker.length, end));
  }

  function bytesToHex(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) out += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    return out;
  }

  function subtle() {
    var c = (typeof crypto !== 'undefined') ? crypto : (typeof global !== 'undefined' ? global.crypto : null);
    if (!c || !c.subtle) throw fail('PUBLISH_FAILED', 'WebCrypto is unavailable (needs HTTPS or localhost)');
    return c.subtle;
  }

  async function sha256Hex(bytes) {
    var digest = await subtle().digest('SHA-256', bytes);
    return bytesToHex(new Uint8Array(digest));
  }

  function sleep(ms) {
    return new Promise(function (resolve) { setTimeout(resolve, ms); });
  }

  // ---------------------------------------------------------------------------
  // Canonical JSON (fallback when A3 is absent — same JCS subset, byte-
  // identical to Python json.dumps(sort_keys=True, separators=(",", ":"),
  // ensure_ascii=False). A3 (GhostCorpCanonicalJSON) is preferred when loaded.
  // ---------------------------------------------------------------------------

  function compareUTF8(a, b) {
    var ab = utf8Bytes(a);
    var bb = utf8Bytes(b);
    var n = Math.min(ab.length, bb.length);
    for (var i = 0; i < n; i++) if (ab[i] !== bb[i]) return ab[i] - bb[i];
    return ab.length - bb.length;
  }

  function canonicalStringify(value) {
    if (value === null) return 'null';
    switch (typeof value) {
      case 'boolean': return value ? 'true' : 'false';
      case 'number':
        if (!Number.isInteger(value) || !Number.isSafeInteger(value)) {
          throw fail('BAD_SHAPE', 'canonical JSON supports integers only');
        }
        return JSON.stringify(value);
      case 'string': return JSON.stringify(value);
      case 'object': {
        if (Array.isArray(value)) {
          var parts = new Array(value.length);
          for (var i = 0; i < value.length; i++) {
            if (!(i in value)) throw fail('BAD_SHAPE', 'sparse array in envelope');
            parts[i] = canonicalStringify(value[i]);
          }
          return '[' + parts.join(',') + ']';
        }
        if (!isPlainObject(value)) throw fail('BAD_SHAPE', 'non-plain object in envelope');
        var keys = Object.keys(value).sort(compareUTF8);
        var out = new Array(keys.length);
        for (var j = 0; j < keys.length; j++) {
          out[j] = JSON.stringify(keys[j]) + ':' + canonicalStringify(value[keys[j]]);
        }
        return '{' + out.join(',') + '}';
      }
      default:
        throw fail('BAD_SHAPE', 'unsupported value in envelope');
    }
  }

  // Canonical bytes of an envelope as signed: WITHOUT `sig` and WITHOUT
  // `seq` (FILE-MAP §3 — `seq` is relay-assigned after signing).
  function canonicalSignedBytes(envelope) {
    var canon = global.GhostCorpCanonicalJSON;
    if (canon && typeof canon.canonicalSignedBytes === 'function') {
      return canon.canonicalSignedBytes(envelope);
    }
    var copy = {};
    var keys = Object.keys(envelope);
    for (var i = 0; i < keys.length; i++) {
      if (keys[i] !== 'sig' && keys[i] !== 'seq') copy[keys[i]] = envelope[keys[i]];
    }
    return utf8Bytes(canonicalStringify(copy));
  }

  function canonicalString(value) {
    var canon = global.GhostCorpCanonicalJSON;
    if (canon && typeof canon.canonicalJSON === 'function') return canon.canonicalJSON(value);
    return canonicalStringify(value);
  }

  // ---------------------------------------------------------------------------
  // Step 0 — extract an envelope object from pasted text.
  // Accepts (a) raw envelope JSON, (b) a BEGIN/END-wrapped base64url blob
  // holding the envelope JSON. Rejects the v2 3-line bridge block and
  // anything that looks like a plain message. Never returns plaintext.
  // ---------------------------------------------------------------------------

  var B64_STDISH_RE = /^[A-Za-z0-9+/]+={0,2}$/;
  var LABEL_LINE_RE = /^(ecc-1|chatgpt|envelope|encrypted chat|message|chat message|-----BEGIN|-----END)[\s:.-]/i;

  function isProbablyBase64Blob(line) {
    return line.length >= 20 && B64_STDISH_RE.test(line) && line.length % 4 === 0;
  }

  function parsePastedBlock(text) {
    if (typeof text !== 'string' || text.trim().length === 0) {
      throw fail('EMPTY_PASTE');
    }
    var cleaned = text.trim();

    // Strip ``` fences (```json … ``` or ``` … ```).
    cleaned = cleaned.replace(/^```[A-Za-z0-9_-]*\s*\n?/, '').replace(/\n?```\s*$/, '').trim();
    if (cleaned.length === 0) throw fail('EMPTY_PASTE');

    var lines = cleaned.split(/\r?\n/).map(function (l) { return l.trim(); })
      .filter(function (l) { return l.length > 0; });

    // Old v2 bridge 3-line block: header / base64 ciphertext / base64 sig.
    // It is NOT an ecc-1 envelope and its signature covers different bytes,
    // so it cannot be verified as a chat message (CRYPTO-DESIGN §2.2).
    if (lines.length === 3 && lines[0].charAt(0) !== '{' &&
        isProbablyBase64Blob(lines[1]) && isProbablyBase64Blob(lines[2])) {
      throw fail('OLD_BRIDGE_FORMAT');
    }

    // Drop BEGIN/END wrapper lines and label lines; keep everything else.
    var kept = lines.filter(function (l) {
      if (/^-----BEGIN /.test(l) || /^-----END /.test(l)) return false;
      if (LABEL_LINE_RE.test(l) && l.charAt(0) !== '{') return false;
      return true;
    });
    if (kept.length === 0) throw fail('NOT_AN_ENVELOPE');
    var joined = kept.join('\n');

    // (a) Direct JSON.
    try {
      var parsed = JSON.parse(joined);
      if (isPlainObject(parsed)) return parsed;
      throw fail('NOT_AN_ENVELOPE');
    } catch (e) {
      if (e && e.code) throw e; // a fail() from the plain-object check
    }

    // (b) One base64url blob (possibly line-wrapped) holding envelope JSON.
    // A blob that decodes but is not envelope JSON is simply not an
    // envelope — fall through to NOT_AN_ENVELOPE below, never a shape error.
    var blob = kept.join('').replace(/\s+/g, '');
    if (B64U_RE.test(blob) && blob.length % 4 !== 1 && blob.length > 0) {
      try {
        var decoded = utf8Text(base64urlToBytes(blob));
        var fromBlob = JSON.parse(decoded);
        if (isPlainObject(fromBlob)) return fromBlob;
      } catch (e) {
        // Not a base64url-encoded envelope — fall through.
      }
    }

    throw fail('NOT_AN_ENVELOPE');
  }

  // ---------------------------------------------------------------------------
  // Step 1 — parse / shape (FILE-MAP §3, CRYPTO-DESIGN §7 step 1).
  // Throws PastePublishError on the first failure. No side effects.
  // ---------------------------------------------------------------------------

  function validateShape(envelope, opts) {
    opts = opts || {};
    if (!isPlainObject(envelope)) throw fail('NOT_AN_ENVELOPE');

    var keys = Object.keys(envelope);
    for (var i = 0; i < keys.length; i++) {
      if (ENVELOPE_FIELDS.indexOf(keys[i]) === -1) {
        throw fail('BAD_SHAPE', 'unknown field "' + keys[i] + '"');
      }
    }
    for (var j = 0; j < ENVELOPE_FIELDS.length; j++) {
      if (!Object.prototype.hasOwnProperty.call(envelope, ENVELOPE_FIELDS[j])) {
        throw fail('BAD_SHAPE', 'missing field "' + ENVELOPE_FIELDS[j] + '"');
      }
    }

    if (envelope.v !== ENVELOPE_VERSION) throw fail('UNKNOWN_VERSION', 'v=' + String(envelope.v));
    if (envelope.alg !== ALG) throw fail('UNKNOWN_ALG', 'alg=' + String(envelope.alg));
    if (envelope.sig_alg !== SIG_ALG_ED25519 && envelope.sig_alg !== SIG_ALG_ES256) {
      throw fail('UNKNOWN_SIG_ALG', 'sig_alg=' + String(envelope.sig_alg));
    }

    if (typeof envelope.msg_id !== 'string' || !UUID_V4_RE.test(envelope.msg_id)) {
      throw fail('BAD_SHAPE', 'msg_id is not a lowercase UUIDv4');
    }
    if (typeof envelope.sender !== 'string' || KNOWN_PARTICIPANTS.indexOf(envelope.sender) === -1) {
      throw fail('BAD_SHAPE', 'sender is not a known participant');
    }
    if (!Array.isArray(envelope.recipients) || envelope.recipients.length < 1 ||
        envelope.recipients.length > 10) {
      throw fail('BAD_SHAPE', 'recipients must list 1-10 participants');
    }
    var seenRecips = {};
    for (var r = 0; r < envelope.recipients.length; r++) {
      var recip = envelope.recipients[r];
      if (typeof recip !== 'string' || KNOWN_PARTICIPANTS.indexOf(recip) === -1) {
        throw fail('BAD_SHAPE', 'recipients holds an unknown participant');
      }
      if (seenRecips[recip]) throw fail('BAD_SHAPE', 'recipients holds a duplicate');
      seenRecips[recip] = true;
    }
    if (!seenRecips[envelope.sender]) {
      throw fail('BAD_SHAPE', 'recipients must include the sender');
    }

    if (!Number.isSafeInteger(envelope.iat) || !Number.isSafeInteger(envelope.exp)) {
      throw fail('BAD_SHAPE', 'iat/exp must be integer epoch seconds');
    }
    if (envelope.reply_to !== null &&
        (typeof envelope.reply_to !== 'string' || !UUID_V4_RE.test(envelope.reply_to))) {
      throw fail('BAD_SHAPE', 'reply_to must be null or a UUIDv4');
    }
    if (typeof envelope.thread_id !== 'string' || !UUID_V4_RE.test(envelope.thread_id)) {
      throw fail('BAD_SHAPE', 'thread_id is not a UUIDv4');
    }
    // CRYPTO-DESIGN §10: a root message has reply_to null and thread_id
    // equal to its own msg_id.
    if (envelope.reply_to === null && envelope.thread_id !== envelope.msg_id) {
      throw fail('BAD_SHAPE', 'a first message must carry thread_id equal to its own msg_id');
    }

    // Binary fields: strict base64url, canonical, right decoded lengths.
    var iv = base64urlToBytes(envelope.iv);
    if (iv.length !== IV_BYTES) throw fail('BAD_SHAPE', 'iv must decode to 16 bytes');
    var mac = base64urlToBytes(envelope.mac);
    if (mac.length !== MAC_BYTES) throw fail('BAD_SHAPE', 'mac must decode to 32 bytes');
    var ct = base64urlToBytes(envelope.ct);
    if (ct.length === 0 || ct.length % 16 !== 0) {
      throw fail('BAD_SHAPE', 'ct must decode to a non-empty multiple of 16 bytes');
    }
    if (ct.length > MAX_CIPHERTEXT_BYTES) throw fail('BAD_SHAPE', 'ciphertext exceeds the 24 KiB cap');
    var sig = base64urlToBytes(envelope.sig);
    if (sig.length !== SIG_BYTES) throw fail('BAD_SHAPE', 'sig must decode to 64 bytes');

    if (!Array.isArray(envelope.wrapped_keys) || envelope.wrapped_keys.length === 0) {
      throw fail('BAD_SHAPE', 'wrapped_keys must list one entry per recipient');
    }
    var seenWk = {};
    for (var w = 0; w < envelope.wrapped_keys.length; w++) {
      var entry = envelope.wrapped_keys[w];
      if (!isPlainObject(entry)) throw fail('BAD_SHAPE', 'wrapped_keys entry is not an object');
      var wkKeys = Object.keys(entry);
      if (wkKeys.length !== 2 || wkKeys.indexOf('recipient') === -1 || wkKeys.indexOf('wk') === -1) {
        throw fail('BAD_SHAPE', 'wrapped_keys entry must hold exactly {recipient, wk}');
      }
      if (typeof entry.recipient !== 'string' || !seenRecips[entry.recipient]) {
        throw fail('BAD_SHAPE', 'wrapped_keys entry is not for a listed recipient');
      }
      if (seenWk[entry.recipient]) throw fail('BAD_SHAPE', 'wrapped_keys holds a duplicate recipient');
      seenWk[entry.recipient] = true;
      var wk = base64urlToBytes(entry.wk);
      // RSA-OAEP wrap of 64 bytes: 256 bytes (RSA-2048) or 512 (RSA-4096) —
      // the two key sizes CRYPTO-DESIGN §5 allows.
      if (wk.length !== 256 && wk.length !== 512) {
        throw fail('BAD_SHAPE', 'wrapped key has an unexpected length');
      }
    }
    if (Object.keys(seenWk).length !== envelope.recipients.length) {
      throw fail('BAD_SHAPE', 'wrapped_keys must cover every recipient exactly once');
    }

    // Relay cap: whole envelope ≤ 64 KiB (FILE-MAP §3).
    if (utf8Bytes(JSON.stringify(envelope)).length > MAX_ENVELOPE_BYTES) {
      throw fail('BAD_SHAPE', 'envelope exceeds the 64 KiB cap');
    }
    return envelope;
  }

  // ---------------------------------------------------------------------------
  // Step 2 — expiry / future (FILE-MAP §3, CRYPTO-DESIGN §7 step 2).
  // ---------------------------------------------------------------------------

  function validateTimes(envelope, opts) {
    opts = opts || {};
    var now = nowSeconds(opts.now);
    if (envelope.exp <= now) throw fail('EXPIRED');
    if (envelope.iat > now + MAX_FUTURE_SKEW_SECONDS) throw fail('NOT_YET_VALID');
    if (envelope.exp <= envelope.iat) throw fail('BAD_SHAPE', 'exp must be after iat');
    if (envelope.exp - envelope.iat > MAX_TTL_SECONDS) throw fail('TTL_TOO_LONG');
  }

  // ---------------------------------------------------------------------------
  // Step 3 — sender pinned (FILE-MAP D17, CRYPTO-DESIGN §7 step 3).
  // Both the encryption AND the signing key must be `pinned`; the envelope's
  // sig_alg must match the pinned sig_alg (no silent downgrade, D6/§4.4).
  // Fingerprints are recomputed from the published PEMs and must match the
  // recorded fingerprints — a mismatch means the entry can't be trusted.
  // ---------------------------------------------------------------------------

  function normalizeKeyDirectory(directory) {
    if (Array.isArray(directory)) return directory;
    if (isPlainObject(directory) && Array.isArray(directory.participants)) {
      return directory.participants;
    }
    throw fail('KEY_DIRECTORY_UNAVAILABLE', 'key directory has an unexpected shape');
  }

  async function checkSenderPinned(envelope, directory) {
    var entries = normalizeKeyDirectory(directory);
    var entry = null;
    for (var i = 0; i < entries.length; i++) {
      if (entries[i] && entries[i].id === envelope.sender) { entry = entries[i]; break; }
    }
    if (!entry) throw fail('SENDER_UNKNOWN');
    if (entry.status !== 'pinned') throw fail('SENDER_NOT_PINNED');
    if (typeof entry.sig_pub_pem !== 'string' || typeof entry.sig_fingerprint !== 'string') {
      throw fail('SENDER_NOT_PINNED');
    }
    if (typeof entry.enc_pub_pem !== 'string' || typeof entry.enc_fingerprint !== 'string') {
      throw fail('SENDER_NOT_PINNED');
    }
    if (entry.sig_alg !== envelope.sig_alg) throw fail('SIG_ALG_MISMATCH');
    // Fingerprint = SHA-256 hex of DER SPKI (CRYPTO-DESIGN §2.1/§9).
    var sigDer = pemToDer(entry.sig_pub_pem);
    if ((await sha256Hex(sigDer)) !== entry.sig_fingerprint.toLowerCase()) {
      throw fail('KEY_MISMATCH', 'signing key fingerprint mismatch');
    }
    var encDer = pemToDer(entry.enc_pub_pem);
    if ((await sha256Hex(encDer)) !== entry.enc_fingerprint.toLowerCase()) {
      throw fail('KEY_MISMATCH', 'encryption key fingerprint mismatch');
    }
    return entry;
  }

  // ---------------------------------------------------------------------------
  // Step 5 — signature verifies against the pinned public key, over the
  // canonical JSON of the envelope WITHOUT sig (and WITHOUT seq).
  // Ed25519 signs the bytes directly; ES256 signs SHA-256 of the bytes
  // (WebCrypto ECDSA hashes internally). Uses A1/A2 when loaded, else
  // native WebCrypto. A bad signature returns false — it is a REJECT,
  // never an exception (CRYPTO-DESIGN §7 step 5).
  // ---------------------------------------------------------------------------

  async function importVerifyKey(pem, sigAlg) {
    var der = pemToDer(pem);
    if (sigAlg === SIG_ALG_ES256) {
      return subtle().importKey('spki', der, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
    }
    return subtle().importKey('spki', der, { name: 'Ed25519' }, true, ['verify']);
  }

  async function verifySignatureBytes(canonicalBytes, sigBase64url, publicKey, sigAlg) {
    // A2 (GhostCorpP256) verifies both schemes with raw R||S wire format.
    var p256 = global.GhostCorpP256;
    if (p256 && typeof p256.verify === 'function') {
      try {
        var sigBytes = base64urlToBytes(sigBase64url);
        return await p256.verify(canonicalBytes, sigBytes, publicKey, sigAlg);
      } catch (e) {
        return false;
      }
    }
    // A1 (GhostChatCrypto) dispatches on sig_alg via its registry.
    var core = global.GhostChatCrypto;
    if (core && typeof core.verifySignature === 'function') {
      try {
        return await core.verifySignature(canonicalBytes, sigBase64url, publicKey, sigAlg);
      } catch (e) {
        return false;
      }
    }
    // Native WebCrypto fallback.
    try {
      var rawSig = base64urlToBytes(sigBase64url);
      if (rawSig.length !== SIG_BYTES) return false;
      if (sigAlg === SIG_ALG_ES256) {
        return await subtle().verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, rawSig, canonicalBytes);
      }
      return await subtle().verify({ name: 'Ed25519' }, publicKey, rawSig, canonicalBytes);
    } catch (e) {
      return false;
    }
  }

  // Verify an envelope's signature against a PEM public key. Exported so
  // tests can check it against the published vectors without a key directory.
  async function verifyEnvelopeSignature(envelope, sigPubPem, sigAlg) {
    var alg = sigAlg || envelope.sig_alg;
    var canonicalBytes = canonicalSignedBytes(envelope);
    var publicKey = await importVerifyKey(sigPubPem, alg);
    return verifySignatureBytes(canonicalBytes, envelope.sig, publicKey, alg);
  }

  // Full client-side verification: shape → expiry/future → sender pinned →
  // signature (FILE-MAP §3 order, steps 1–3 + 5). Returns the envelope and
  // its pinned key-directory entry. Throws PastePublishError on failure.
  // `keyDirectory` may be the parsed participants array/object, or a URL
  // string to fetch it from (options.keyDirectoryUrl / CONFIG).
  async function verifyEnvelope(envelope, keyDirectory, opts) {
    opts = opts || {};
    validateShape(envelope, opts);
    validateTimes(envelope, opts);
    var directory = keyDirectory;
    if (typeof directory === 'string' || directory === undefined || directory === null) {
      directory = await getKeyDirectory(opts);
    }
    var entry = await checkSenderPinned(envelope, directory);
    var ok = await verifyEnvelopeSignature(envelope, entry.sig_pub_pem, envelope.sig_alg);
    if (!ok) throw fail('BAD_SIGNATURE');
    return { envelope: envelope, senderEntry: entry, verified: true };
  }

  // ---------------------------------------------------------------------------
  // Key directory fetch. Default URL from CONFIG.keyDirectoryUrl (C20),
  // else the store-relative path. `options.participants` skips the fetch
  // (tests / offline use). Never fetches with credentials; the directory
  // holds public keys only.
  // ---------------------------------------------------------------------------

  function defaultKeyDirectoryUrl(opts) {
    if (opts && typeof opts.keyDirectoryUrl === 'string') return opts.keyDirectoryUrl;
    if (global.CONFIG && typeof global.CONFIG.keyDirectoryUrl === 'string') {
      return global.CONFIG.keyDirectoryUrl;
    }
    return 'chat/keys/participants.json';
  }

  async function getKeyDirectory(opts) {
    opts = opts || {};
    if (opts.participants !== undefined) return opts.participants;
    if (opts.keyDirectory !== undefined) return opts.keyDirectory;
    var fetchImpl = opts.fetch || global.fetch;
    if (typeof fetchImpl !== 'function') throw fail('KEY_DIRECTORY_UNAVAILABLE', 'no fetch available');
    var url = defaultKeyDirectoryUrl(opts);
    var res;
    try {
      res = await fetchImpl(url, { method: 'GET', headers: { Accept: 'application/json' } });
    } catch (e) {
      throw fail('KEY_DIRECTORY_UNAVAILABLE', String(e && e.message ? e.message : e));
    }
    if (!res || !res.ok) throw fail('KEY_DIRECTORY_UNAVAILABLE', 'HTTP ' + (res ? res.status : 'no response'));
    var data;
    try {
      data = await res.json();
    } catch (e) {
      throw fail('KEY_DIRECTORY_UNAVAILABLE', 'key directory is not valid JSON');
    }
    return data;
  }

  // ---------------------------------------------------------------------------
  // Publish — GitHub Contents API (FILE-MAP D2/D3, RELAY-SPEC §7(b) post).
  //
  //   chat/messages/<msg_id>.json  — the envelope exactly as signed, plus
  //       `seq` added by the relay (receivers verify over the envelope
  //       minus `sig` AND minus `seq` — FILE-MAP §3).
  //   chat/manifest.json           — FILE-MAP shape:
  //       {"v": "ecc-1", "seq": <latest>, "messages": [{"msg_id", "seq",
  //        "sender", "iat", "exp", "url": "messages/<msg_id>.json"}]}
  //
  // Flow: read manifest (note sha + next seq) → write message file →
  // CAS-update manifest with that sha → on 409/sha mismatch re-read and
  // retry (up to 5), re-stamping `seq` each time. Same ID + same envelope
  // bytes = idempotent OK; same ID + different bytes = MSG_ID_CONFLICT.
  // A message file that lands while the manifest CAS keeps failing is still
  // durable and fetchable; the next successful publish repairs the manifest
  // (RELAY-SPEC §7(b) step 5).
  // ---------------------------------------------------------------------------

  function githubConfig(opts) {
    var cfg = global.CONFIG || {};
    var gh = (opts && opts.github) || {};
    return {
      owner: gh.owner || cfg.siteRepoOwner || DEFAULT_GITHUB.owner,
      repo: gh.repo || cfg.siteRepoName || DEFAULT_GITHUB.repo,
      apiBase: gh.apiBase || cfg.githubApiBaseUrl || DEFAULT_GITHUB.apiBase,
      storeDir: gh.storeDir || opts.storeDir || 'chat'
    };
  }

  async function resolveToken(opts) {
    if (opts && typeof opts.pat === 'string' && opts.pat.length > 0) return opts.pat;
    if (opts && typeof opts.getToken === 'function') {
      var token = await opts.getToken();
      if (typeof token === 'string' && token.length > 0) return token;
    }
    var patModule = global.GhostChatPat;
    if (patModule && typeof patModule.getToken === 'function') {
      var t = await patModule.getToken();
      if (typeof t === 'string' && t.length > 0) return t;
    }
    if (patModule && typeof patModule.getPat === 'function') {
      var t2 = await patModule.getPat();
      if (typeof t2 === 'string' && t2.length > 0) return t2;
    }
    if (patModule && typeof patModule.token === 'string' && patModule.token.length > 0) {
      return patModule.token;
    }
    return null;
  }

  // Default publisher: GitHub Contents API. `opts.fetch` injectable (tests).
  // Returns { getFile(path) -> {sha, text} | null, putFile(path, text,
  // message, sha?) -> {sha} } where path is store-relative, e.g.
  // "messages/<msg_id>.json" or "manifest.json".
  function githubPublisher(opts, token) {
    var gh = githubConfig(opts);
    var fetchImpl = (opts && opts.fetch) || global.fetch;
    if (typeof fetchImpl !== 'function') throw fail('PUBLISH_FAILED', 'no fetch available');
    var base = gh.apiBase.replace(/\/$/, '') + '/repos/' +
      encodeURIComponent(gh.owner) + '/' + encodeURIComponent(gh.repo) +
      '/contents/' + gh.storeDir.replace(/^\/|\/$/g, '');

    function headers(extra) {
      var h = { Accept: 'application/vnd.github+json' };
      if (token) h.Authorization = 'Bearer ' + token;
      if (extra) for (var k in extra) h[k] = extra[k];
      return h;
    }

    async function getFile(path) {
      var res;
      try {
        res = await fetchImpl(base + '/' + path, { method: 'GET', headers: headers() });
      } catch (e) {
        throw fail('PUBLISH_FAILED', 'network error reading ' + path + ': ' + (e && e.message ? e.message : e));
      }
      if (res.status === 404) return null;
      if (!res.ok) {
        throw fail('PUBLISH_FAILED', 'reading ' + path + ' failed: HTTP ' + res.status);
      }
      var data = await res.json();
      if (!data || typeof data.content !== 'string' || typeof data.sha !== 'string') {
        throw fail('STORE_UNEXPECTED', 'unexpected Contents API response for ' + path);
      }
      return { sha: data.sha, text: utf8Text(base64ToBytes(data.content)) };
    }

    async function putFile(path, text, message, sha) {
      var body = { message: message, content: bytesToBase64(utf8Bytes(text)) };
      if (sha) body.sha = sha;
      var res;
      try {
        res = await fetchImpl(base + '/' + path, {
          method: 'PUT',
          headers: headers({ 'Content-Type': 'application/json' }),
          body: JSON.stringify(body)
        });
      } catch (e) {
        throw fail('PUBLISH_FAILED', 'network error writing ' + path + ': ' + (e && e.message ? e.message : e));
      }
      if (res.status === 409 || res.status === 422) {
        var conflict = fail('PUBLISH_FAILED', 'Contents API refused ' + path + ': HTTP ' + res.status);
        conflict.httpStatus = res.status;
        conflict.isCasConflict = true;
        throw conflict;
      }
      if (!res.ok) {
        if (res.status === 401 || res.status === 403) {
          throw fail('NO_ACCESS_TOKEN', 'GitHub refused the token: HTTP ' + res.status);
        }
        throw fail('PUBLISH_FAILED', 'writing ' + path + ' failed: HTTP ' + res.status);
      }
      var data = await res.json();
      return { sha: data && data.content && data.content.sha ? data.content.sha : null };
    }

    return { getFile: getFile, putFile: putFile };
  }

  function nextSeqFromManifest(manifest) {
    var max = 0;
    if (manifest && typeof manifest.seq === 'number') max = manifest.seq;
    if (manifest && Array.isArray(manifest.messages)) {
      for (var i = 0; i < manifest.messages.length; i++) {
        var s = manifest.messages[i] && manifest.messages[i].seq;
        if (typeof s === 'number' && s > max) max = s;
      }
    }
    return max + 1;
  }

  function sameEnvelopeBytes(storedText, envelope) {
    try {
      var stored = JSON.parse(storedText);
      if (!isPlainObject(stored)) return false;
      delete stored.seq;
      return canonicalString(stored) === canonicalString(envelope);
    } catch (e) {
      return false;
    }
  }

  // Publish an already-verified envelope. Returns
  // { ok, msg_id, seq, messageUrl, manifestSeq, duplicate }.
  // Throws PastePublishError on failure; publishes nothing on validation
  // failure (callers should verify first — publishEnvelope re-checks the
  // store-level idempotency but NOT the signature; use publishPasted for
  // the full flow).
  async function publishEnvelope(envelope, opts) {
    opts = opts || {};
    var token = await resolveToken(opts);
    if (!token) throw fail('NO_ACCESS_TOKEN');
    var publisher = opts.publisher || githubPublisher(opts, token);
    if (!publisher || typeof publisher.getFile !== 'function' ||
        typeof publisher.putFile !== 'function') {
      throw fail('PUBLISH_FAILED', 'publisher must provide getFile/putFile');
    }

    var msgPath = 'messages/' + envelope.msg_id + '.json';
    var manifestPath = 'manifest.json';
    var gh = githubConfig(opts);
    var messageUrl = 'https://github.com/' + gh.owner + '/' + gh.repo +
      '/blob/main/' + gh.storeDir + '/' + msgPath;

    // If the message file already exists, decide idempotent-OK vs conflict
    // BEFORE writing anything (FILE-MAP §3).
    var existing = await publisher.getFile(msgPath);
    if (existing) {
      if (sameEnvelopeBytes(existing.text, envelope)) {
        var dupManifest = await readManifest(publisher, manifestPath);
        var alreadyListed = dupManifest.data && Array.isArray(dupManifest.data.messages) &&
          dupManifest.data.messages.some(function (m) { return m && m.msg_id === envelope.msg_id; });
        var dupSeq = null;
        if (alreadyListed) {
          for (var d = 0; d < dupManifest.data.messages.length; d++) {
            if (dupManifest.data.messages[d].msg_id === envelope.msg_id) {
              dupSeq = dupManifest.data.messages[d].seq;
            }
          }
          return { ok: true, msg_id: envelope.msg_id, seq: dupSeq, messageUrl: messageUrl, manifestSeq: dupManifest.data.seq, duplicate: true };
        }
        // Stored but missing from the manifest: fall through and repair
        // the manifest below (re-stamping is safe — seq is not signed).
      } else {
        throw fail('MSG_ID_CONFLICT');
      }
    }

    var lastError = null;
    for (var attempt = 1; attempt <= MAX_MANIFEST_CAS_ATTEMPTS; attempt++) {
      var manifest = await readManifest(publisher, manifestPath);
      var seq = nextSeqFromManifest(manifest.data);
      var stored = {};
      var envKeys = Object.keys(envelope);
      for (var k = 0; k < envKeys.length; k++) stored[envKeys[k]] = envelope[envKeys[k]];
      stored.seq = seq;
      var storedText = JSON.stringify(stored, null, 2) + '\n';

      try {
        // Write (or re-stamp) the message file first — it is durable from
        // here even if the manifest CAS below keeps failing.
        await publisher.putFile(msgPath, storedText,
          'Add chat message ' + envelope.msg_id + ' from ' + envelope.sender,
          existing ? existing.sha : undefined);

        var next = manifest.data || { v: ENVELOPE_VERSION, seq: 0, messages: [] };
        if (!Array.isArray(next.messages)) next.messages = [];
        var found = false;
        for (var m = 0; m < next.messages.length; m++) {
          if (next.messages[m] && next.messages[m].msg_id === envelope.msg_id) {
            next.messages[m] = {
              msg_id: envelope.msg_id, seq: seq, sender: envelope.sender,
              iat: envelope.iat, exp: envelope.exp,
              url: 'messages/' + envelope.msg_id + '.json'
            };
            found = true;
          }
        }
        if (!found) {
          next.messages.push({
            msg_id: envelope.msg_id, seq: seq, sender: envelope.sender,
            iat: envelope.iat, exp: envelope.exp,
            url: 'messages/' + envelope.msg_id + '.json'
          });
        }
        next.messages.sort(function (a, b) { return a.seq - b.seq; });
        next.v = ENVELOPE_VERSION;
        next.seq = seq;
        await publisher.putFile(manifestPath, JSON.stringify(next, null, 2) + '\n',
          'Add chat message ' + envelope.msg_id + ' to manifest',
          manifest.sha || undefined);
        return { ok: true, msg_id: envelope.msg_id, seq: seq, messageUrl: messageUrl, manifestSeq: seq, duplicate: false };
      } catch (e) {
        if (e && e.isCasConflict && attempt < MAX_MANIFEST_CAS_ATTEMPTS) {
          lastError = e;
          // Another writer moved the manifest first: re-read, take the new
          // next seq, re-stamp the message file, retry (RELAY-SPEC §7(b)).
          existing = await publisher.getFile(msgPath);
          await sleep(400 * attempt);
          continue;
        }
        throw e;
      }
    }
    throw fail('MANIFEST_CONFLICT_RETRY', lastError ? lastError.detail : undefined);
  }

  async function readManifest(publisher, manifestPath) {
    var raw = await publisher.getFile(manifestPath);
    if (!raw) return { data: null, sha: null };
    var data;
    try {
      data = JSON.parse(raw.text);
    } catch (e) {
      throw fail('STORE_UNEXPECTED', 'manifest.json is not valid JSON');
    }
    if (!isPlainObject(data)) throw fail('STORE_UNEXPECTED', 'manifest.json is not an object');
    // FILE-MAP §3 manifest shape is authoritative (v "ecc-1"); the
    // RELAY-SPEC v-1 shape is superseded and is not accepted here.
    if (data.v !== ENVELOPE_VERSION) {
      throw fail('STORE_UNEXPECTED', 'manifest version is not ecc-1');
    }
    return { data: data, sha: raw.sha };
  }

  // ---------------------------------------------------------------------------
  // Full flow: paste → parse → shape → expiry/future → sender pinned →
  // signature → publish. Any failure returns { ok:false, code, reason }
  // and publishes NOTHING. Success returns { ok:true, msg_id, seq,
  // messageUrl, manifestSeq, duplicate }.
  // ---------------------------------------------------------------------------

  async function publishPasted(text, opts) {
    opts = opts || {};
    try {
      var envelope = parsePastedBlock(text);
      await verifyEnvelope(envelope, opts.participants !== undefined ? opts.participants : undefined, opts);
      return await publishEnvelope(envelope, opts);
    } catch (e) {
      if (e && e.name === 'PastePublishError') return rejection(e);
      return rejection(fail('PUBLISH_FAILED', String(e && e.message ? e.message : e)));
    }
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  var api = {
    parsePastedBlock: parsePastedBlock,
    validateShape: validateShape,
    validateTimes: validateTimes,
    checkSenderPinned: checkSenderPinned,
    verifyEnvelopeSignature: verifyEnvelopeSignature,
    verifyEnvelope: verifyEnvelope,
    getKeyDirectory: getKeyDirectory,
    publishEnvelope: publishEnvelope,
    publishPasted: publishPasted,
    // Exposed for tests / app diagnostics (not for UI display).
    canonicalSignedBytes: canonicalSignedBytes,
    ENVELOPE_VERSION: ENVELOPE_VERSION,
    MAX_TTL_SECONDS: MAX_TTL_SECONDS,
    REASONS: REASONS
  };

  global.GhostChatPastePublish = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
