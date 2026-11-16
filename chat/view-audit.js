// view-audit.js — owner audit view for the ghostcorpnet encrypted chat (ecc-1).
//
// Worker C8 (FILE-MAP §4). Static SPA, no build step, no framework, no
// external resources. Loaded as a plain <script> (see app/index.html);
// also usable as a CommonJS module in Node for unit tests.
//
// Normative refs (FILE-MAP.md is authoritative; design docs are reference):
//   - FILE-MAP §3  envelope fields ("ecc-1"), verification order, key
//     directory schema, manifest / tombstones layout, 24 h TTL (D10),
//     default recipients all three (D9), no forward secrecy (D14).
//   - FILE-MAP D5  crypto is AES-256-CBC + HMAC-SHA-256 (EtM), Ed25519
//     primary / ES256 fallback. NOT AES-GCM.
//   - FILE-MAP D13 Jarvis encryption fingerprint (public, pinned):
//     ceabe1c77c4c15710dc6e06992bad6c70c8ba1d8c0adaf17a2f3b1042a620ee5
//   - FILE-MAP D17 no message is accepted from an unpinned sender.
//   - UI-SPEC §2.5 (audit view) and OWNER-JOIN §6 (audit via Jarvis)
//     — see "Conflicts resolved" below.
//   - C10 app/badges.js — badge computation (this module consumes badge
//     results; it does not trust a relay-supplied verdict).
//   - C5 app/view-keys.js — key directory view (this module re-checks
//     the same directory, independently, by recomputing fingerprints).
//
// What this view shows:
//   1. Key directory integrity — every fingerprint recomputed from the
//      published PEM and compared with the pinned value.
//   2. Message counts — total, per sender, signed, expired,
//      replay-suspected, tampered, undecryptable, unknown.
//   3. Store ciphertext-only confirmation — the store / page holds no
//      plaintext outside decrypted messages in memory.
//   4. An "Ask Jarvis" path — a button that copies a short audit
//      request the owner pastes to Jarvis in Muse chat. Jarvis re-reads
//      history from his own decryptable copy; the app never pastes
//      scrambled text or key material.
//
// What this view NEVER does:
//   - Display raw ciphertext dumps (no ct / iv / mac / wk / sig values).
//   - Display key material (no PEM, no private key, no full public key).
//     Fingerprints are shown only as an 8-character check-code
//     (OWNER-JOIN §1) — a fingerprint is a hash of a public key, not
//     key material, and even it is truncated here.
//   - Decrypt for anyone else, send as anyone else, edit/delete
//     messages, or reveal anyone's private key (UI-SPEC §2.5).
//   - Put plaintext, secrets, or personal info in any file, log, or
//     copied text. The Ask-Jarvis request contains only counts,
//     truncated message IDs (first 8 chars), and 8-char check-codes.
//
// Conflicts resolved in favour of FILE-MAP (flagged in the build report):
//   C8-1 UI-SPEC §2.5 "Copy envelope (ciphertext)" — NOT implemented.
//     Copying a raw envelope is a ciphertext dump by another name, and
//     the C8 brief forbids the audit view from displaying (or handing
//     out) raw ciphertext. The Ask-Jarvis request replaces it: counts +
//     truncated IDs only. If Jarvis needs an envelope, he fetches it
//     himself from the store he already reads.
//   C8-2 UI-SPEC §2.4/§2.5 expiry "7 days" / "30 days" — NOT used.
//     FILE-MAP D10: 24 h TTL default AND maximum (exp - iat <= 86400).
//     Expired here means exp <= now under that rule.
//   C8-3 UI-SPEC §7 / §9 AES-GCM envelope layout — NOT used. FILE-MAP
//     D5 overrides with ecc-1 (AES-256-CBC + HMAC, iat/exp integers).
//   C8-4 UI-SPEC §2.5 key-change log ("GET /keys/history") — shown
//     only when the caller supplies a log; the relay/store has no such
//     endpoint in FILE-MAP §3, so the view states "Key history not
//     available" rather than inventing one. Current keys are always shown.
//   C8-5 OWNER-JOIN §5/§7 "1:1 messages out of scope" vs FILE-MAP D9:
//     D9 wins — every message is wrapped for all three by default, so
//     Jarvis holds a readable copy of every group message and can
//     re-share history for a lost owner key. 1:1 is an explicit opt-in
//     with a warning; the audit view flags any message NOT wrapped for
//     all three (see classifyMessage / recipientsNote).
//
// Dependencies (all injected / optional globals — this file never
// fetches, never generates keys, never stores anything):
//   - GhostChatCrypto (A1 app/js/crypto-core.js) — only its
//     fingerprintPublicKey(pem) is used, for the key-integrity check.
//     verifyKeyDirectory() also accepts an injected { fingerprint }
//     function (used by tests), so the pure counting / request code
//     works with no crypto at all.
//   - GhostChatBadges (C10 app/badges.js) — optional; when present,
//     classifyMessage() can delegate badge labels to it. When absent,
//     the local classification below is used. Either way the badge is
//     computed locally at render time, never trusted from the relay.
//   - CONFIG (C20 app/config.js) — optional; only roomId / TTL values
//     are read, with FILE-MAP defaults below when it is absent.
//
// Inputs this module expects from app.js (C3) / poll.js (C9):
//   messages: array of per-message audit records, one per envelope in
//     the loaded set. Each record is:
//       {
//         msg_id: string (UUIDv4), sender: "jarvis"|"chatgpt"|"owner",
//         iat: integer, exp: integer, thread_id?: string,
//         recipients?: string[],            // envelope recipients
//         seq?: integer,                    // relay sequence, if known
//         status?: string,                  // C10 badge key, if computed
//         badge?: string,                   // C10 badge label, if computed
//         signatureValid?: boolean,         // step 5 result, if verified
//         macValid?: boolean,               // step 7 result, if verified
//         decryptable?: boolean,            // could this browser decrypt it
//         decryptedText?: string,           // IN MEMORY ONLY, if decrypted
//         duplicateOf?: string,             // msg_id of an earlier copy
//         duplicateDiffers?: boolean,       // same ID, different content
//         envelope?: object                 // raw envelope, if the caller
//                                            // wants the store check run;
//                                            // never rendered or copied
//       }
//     Records WITHOUT decryptedText are normal: the snippet column then
//     shows "— not encrypted for you —" (UI-SPEC §2.5). Records without
//     any verification fields classify as "unknown" — the view says so
//     instead of guessing.
//   keyDirectory: the parsed keys/participants.json array (public keys
//     + fingerprints only — never private keys).
//   storeSnapshot (optional): { envelopes, manifest, participants }
//     for the ciphertext-only check; see checkCiphertextOnly().
//
// No real keys, no plaintext conversation, no secrets, and no personal
// info belong in this file. The only key-like literal is Jarvis's
// PUBLIC fingerprint (FILE-MAP D13), which is meant to be public.

(function (root, factory) {
  'use strict';
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.GhostChatAuditView = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ---------------------------------------------------------------------------
  // Constants — FILE-MAP §3 / D9 / D10 / D13
  // ---------------------------------------------------------------------------

  var ENVELOPE_VERSION = 'ecc-1';
  var MAX_TTL_SECONDS = 86400;          // D10: 24 h default AND maximum
  var MAX_FUTURE_SKEW_SECONDS = 300;    // FILE-MAP §3 verification step 2
  var PARTICIPANTS = ['jarvis', 'chatgpt', 'owner'];
  var DEFAULT_RECIPIENTS = ['jarvis', 'chatgpt', 'owner']; // D9

  // Jarvis encryption fingerprint (SHA-256 of DER SPKI). Public value,
  // FILE-MAP D13. The blocking check in setup (C4) and here: if the key
  // directory's Jarvis enc fingerprint is not exactly this, it is a
  // MISMATCH — do not send, tell Jarvis.
  var JARVIS_ENC_FINGERPRINT =
    'ceabe1c77c4c15710dc6e06992bad6c70c8ba1d8c0adaf17a2f3b1042a620ee5';

  // Envelope fields, exactly FILE-MAP §3 (plus relay-added `seq`, which is
  // never part of the signed bytes). Anything else in an envelope is a
  // store-check violation (unknown fields -> reject, §7 step 1).
  var ENVELOPE_FIELDS = [
    'v', 'msg_id', 'sender', 'recipients', 'iat', 'exp', 'reply_to',
    'thread_id', 'alg', 'sig_alg', 'iv', 'ct', 'mac', 'wrapped_keys', 'sig'
  ];
  var ENVELOPE_FIELDS_WITH_SEQ = ENVELOPE_FIELDS.concat(['seq']);

  var MANIFEST_FIELDS = ['v', 'seq', 'messages'];
  var MANIFEST_MESSAGE_FIELDS = ['msg_id', 'seq', 'sender', 'iat', 'exp', 'url'];

  // Base64url, no padding — FILE-MAP §3. Decoders reject anything else.
  var B64U_RE = /^[A-Za-z0-9_-]+$/;

  // Badge keys (C10). One per message, computed locally at render time.
  var STATUS_SIGNED = 'signed';
  var STATUS_EXPIRED = 'expired';
  var STATUS_REPLAY = 'replay_suspected';
  var STATUS_TAMPERED = 'tampered';
  var STATUS_UNDECRYPTABLE = 'undecryptable';
  var STATUS_DECRYPTING = 'decrypting';
  var STATUS_UNKNOWN = 'unknown';
  var ALL_STATUSES = [
    STATUS_SIGNED, STATUS_EXPIRED, STATUS_REPLAY, STATUS_TAMPERED,
    STATUS_UNDECRYPTABLE, STATUS_DECRYPTING, STATUS_UNKNOWN
  ];

  // Badge labels (C10 / UI-SPEC §2.3) — text + icon, never colour alone.
  var BADGE_LABELS = {
    signed: '✓ Signed',
    expired: '⚠ Expired',
    replay_suspected: '⛔ Replay suspected',
    tampered: '⛔ Tampered',
    undecryptable: '? Undecryptable',
    decrypting: '… Decrypting',
    unknown: '? Not checked yet'
  };

  // Plain-words copy (J1 copy deck where it exists; otherwise plain words,
  // no jargon — C19). Keep these strings verbatim in the render below.
  var COPY = {
    title: 'Audit — check this chat',
    intro: 'This page checks the locked chat. It never shows scrambled text or key material.',
    ciphertextOnlyTitle: 'Ciphertext only',
    ciphertextOnlyOk: 'The store holds scrambled messages only. This page holds no plain text outside messages it has unlocked in memory right now.',
    ciphertextOnlyBad: 'Problem found in the store check. Tell Jarvis — do not send anything until he confirms.',
    plaintextNote: 'Decrypted messages live in this page’s memory only. They are never saved to disk, never sent anywhere except as a new locked message, and they disappear when you close the tab.',
    askJarvisTitle: 'Ask Jarvis to check it',
    askJarvisNote: 'Copy this short request and paste it to Jarvis in Muse chat. Jarvis re-reads the history from his own copy of the chat. This request contains no scrambled text and no key material — only counts and short message IDs.',
    askJarvisCopied: 'Copied. Paste it to Jarvis in Muse chat.',
    askJarvisCopyFailed: 'Copy did not work — select the text and copy it by hand.',
    keyHistoryUnavailable: 'Key history not available from the store — only the current keys are shown.',
    noKey: 'No key published yet — they can’t receive locked messages until they finish setup.',
    notEncryptedForYou: '— not locked for you —',
    reviewProblems: 'Review problems',
    showAll: 'Show all',
    reverify: 'Re-check now',
    reverifyDone: 'Re-checked',
    loadedRange: 'Showing the loaded messages — load more in the chat view to audit older ones.',
    noMessages: 'No messages loaded yet.',
    noProblems: 'No problems in the loaded messages.',
    recipientsWarning: 'Not locked for all three — Jarvis may not be able to re-share this one if a key is lost.'
  };

  // ---------------------------------------------------------------------------
  // Small helpers (pure, no DOM, no crypto)
  // ---------------------------------------------------------------------------

  function isPlainObject(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
    var proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
  }

  function isInteger(value) {
    return typeof value === 'number' && Number.isFinite(value) &&
      Math.floor(value) === value;
  }

  // Short check-code for a fingerprint: first 8 hex chars (OWNER-JOIN §1).
  // A fingerprint is a hash of a public key, not key material — and even
  // so, the audit view shows only this short form, never the full 64.
  function fingerprintShort(fingerprint) {
    if (typeof fingerprint !== 'string' || fingerprint.length < 8) return '—';
    return fingerprint.slice(0, 8);
  }

  function truncateMsgId(msgId) {
    if (typeof msgId !== 'string' || msgId.length === 0) return '—';
    return msgId.length <= 8 ? msgId : msgId.slice(0, 8) + '…';
  }

  function formatTime(epochSeconds) {
    if (!isInteger(epochSeconds)) return '—';
    var d = new Date(epochSeconds * 1000);
    if (isNaN(d.getTime())) return '—';
    return d.toLocaleString();
  }

  function nowSeconds() {
    return Math.floor(Date.now() / 1000);
  }

  function normaliseStatus(raw) {
    if (typeof raw !== 'string') return null;
    var s = raw.trim().toLowerCase().replace(/[\s-]+/g, '_');
    // Accept C10 badge labels as well as keys: "✓ Signed" -> "signed",
    // "⛔ Replay suspected" -> "replay_suspected", "replay" -> replay.
    s = s.replace(/^[^a-z]+/, '').replace(/[^a-z]+$/, '');
    if (s === 'replay' || s === 'replay_suspected') return STATUS_REPLAY;
    if (ALL_STATUSES.indexOf(s) !== -1) return s;
    return null;
  }

  // ---------------------------------------------------------------------------
  // 1. Message classification — local, at render/audit time (C10 rule:
  //    never trust a relay-supplied verdict). Precedence, most serious
  //    first: replay > tampered > expired > undecryptable > signed.
  //    Expiry is FILE-MAP §3 step 2 (exp > now); a signature failure
  //    outranks expiry because a tampered message must never be shown
  //    as merely expired. "Unknown" means no verification data was
  //    supplied — the view says so, it never guesses "signed".
  // ---------------------------------------------------------------------------

  function classifyMessage(record, nowSec) {
    var now = isInteger(nowSec) ? nowSec : nowSeconds();
    var rec = isPlainObject(record) ? record : {};
    var result = {
      msg_id: typeof rec.msg_id === 'string' ? rec.msg_id : null,
      sender: PARTICIPANTS.indexOf(rec.sender) !== -1 ? rec.sender : 'unknown',
      status: STATUS_UNKNOWN,
      badge: BADGE_LABELS[STATUS_UNKNOWN],
      reason: 'No verification result was supplied for this message yet.',
      expired: false,
      recipientsNote: null
    };

    // D9: a message not wrapped for all three cannot be re-shared by
    // Jarvis after a lost owner key. Flag it; it does not change the badge.
    if (Array.isArray(rec.recipients)) {
      var missing = DEFAULT_RECIPIENTS.filter(function (p) {
        return rec.recipients.indexOf(p) === -1;
      });
      if (missing.length > 0) {
        result.recipientsNote = COPY.recipientsWarning +
          ' (not locked for: ' + missing.join(', ') + ')';
      }
    }

    if (isInteger(rec.exp) && rec.exp <= now) result.expired = true;

    // Replay: same ID seen before with different content, or an explicit
    // replay flag from the ledger/dedup check (C9 poll dedup, FILE-MAP §8).
    if (rec.duplicateDiffers === true ||
        (typeof rec.duplicateOf === 'string' && rec.duplicateOf.length > 0 &&
          rec.duplicateDiffers !== false && rec.status !== STATUS_SIGNED)) {
      result.status = STATUS_REPLAY;
      result.badge = BADGE_LABELS[STATUS_REPLAY];
      result.reason = 'This message ID was seen before with different content.';
      return result;
    }
    // A caller-supplied replay verdict (ledger / C10) also counts.
    var supplied = normaliseStatus(rec.status) || normaliseStatus(rec.badge);
    if (supplied === STATUS_REPLAY) {
      result.status = STATUS_REPLAY;
      result.badge = BADGE_LABELS[STATUS_REPLAY];
      result.reason = 'This message ID was seen before.';
      return result;
    }

    // Tampered: signature or HMAC failed (FILE-MAP §7 steps 5 and 7).
    // A MAC mismatch rejects without decrypting — never show the body.
    if (rec.signatureValid === false || rec.macValid === false) {
      result.status = STATUS_TAMPERED;
      result.badge = BADGE_LABELS[STATUS_TAMPERED];
      result.reason = rec.signatureValid === false
        ? 'Signature does not verify — this message may have been changed after it was sent.'
        : 'Message check failed — the scrambled text does not match its check value.';
      return result;
    }
    if (supplied === STATUS_TAMPERED) {
      result.status = STATUS_TAMPERED;
      result.badge = BADGE_LABELS[STATUS_TAMPERED];
      result.reason = 'Signature or message check failed.';
      return result;
    }

    // Expired: signature valid (or not yet checked) but exp has passed.
    // Body may still be shown with the expiry note (UI-SPEC §2.3).
    if (result.expired) {
      result.status = STATUS_EXPIRED;
      result.badge = BADGE_LABELS[STATUS_EXPIRED];
      result.reason = 'This message expired at ' + formatTime(rec.exp) +
        '. It was valid when sent.';
      return result;
    }
    if (supplied === STATUS_EXPIRED) {
      result.status = STATUS_EXPIRED;
      result.badge = BADGE_LABELS[STATUS_EXPIRED];
      result.reason = 'This message has expired.';
      return result;
    }

    // Undecryptable: well-formed envelope, but none of my keys unlock it
    // (wrong recipient set, rotated key, corrupt envelope).
    if (rec.decryptable === false) {
      result.status = STATUS_UNDECRYPTABLE;
      result.badge = BADGE_LABELS[STATUS_UNDECRYPTABLE];
      result.reason = 'Couldn’t unlock — this message wasn’t locked for your key, or your key changed.';
      return result;
    }
    if (supplied === STATUS_UNDECRYPTABLE) {
      result.status = STATUS_UNDECRYPTABLE;
      result.badge = BADGE_LABELS[STATUS_UNDECRYPTABLE];
      result.reason = 'Couldn’t unlock this message with the keys in this browser.';
      return result;
    }

    if (supplied === STATUS_DECRYPTING) {
      result.status = STATUS_DECRYPTING;
      result.badge = BADGE_LABELS[STATUS_DECRYPTING];
      result.reason = 'Unlocking in progress.';
      return result;
    }

    // Signed: signature verified, not expired, decryptable (or at least
    // not known-undecryptable). Only a positive verification earns this.
    if (rec.signatureValid === true || supplied === STATUS_SIGNED) {
      result.status = STATUS_SIGNED;
      result.badge = BADGE_LABELS[STATUS_SIGNED];
      result.reason = 'Signature verifies against the sender’s published key; not expired.';
      return result;
    }

    // Nothing verified yet — say so plainly.
    return result;
  }

  // ---------------------------------------------------------------------------
  // 2. Message counts — total, per sender, per badge (UI-SPEC §2.5
  //    summary strip + the C8 brief). Duplicate IDs are counted once in
  //    `total` (they are the same message seen twice) but listed under
  //    `duplicateIds` and counted as replay-suspected when their content
  //    differs. Identical re-deliveries are dedup only, not problems.
  // ---------------------------------------------------------------------------

  function computeMessageCounts(messages, nowSec) {
    var now = isInteger(nowSec) ? nowSec : nowSeconds();
    var list = Array.isArray(messages) ? messages : [];
    var byStatus = {};
    ALL_STATUSES.forEach(function (s) { byStatus[s] = 0; });
    var perSender = { jarvis: 0, chatgpt: 0, owner: 0, unknown: 0 };
    var seenIds = {};
    var duplicateIds = [];
    var problemIds = [];
    var earliest = null;
    var latest = null;

    list.forEach(function (rec) {
      var c = classifyMessage(rec, now);
      byStatus[c.status] += 1;
      perSender[c.sender] += 1;
      if (c.status === STATUS_REPLAY || c.status === STATUS_TAMPERED ||
          c.status === STATUS_UNDECRYPTABLE) {
        if (c.msg_id) problemIds.push(c.msg_id);
      }
      if (typeof rec.msg_id === 'string' && rec.msg_id.length > 0) {
        if (seenIds[rec.msg_id]) {
          if (duplicateIds.indexOf(rec.msg_id) === -1) duplicateIds.push(rec.msg_id);
        } else {
          seenIds[rec.msg_id] = true;
        }
      }
      if (isInteger(rec.iat)) {
        if (earliest === null || rec.iat < earliest) earliest = rec.iat;
        if (latest === null || rec.iat > latest) latest = rec.iat;
      }
    });

    var uniqueTotal = Object.keys(seenIds).length;
    var problemCount = byStatus[STATUS_REPLAY] + byStatus[STATUS_TAMPERED] +
      byStatus[STATUS_UNDECRYPTABLE];

    return {
      total: list.length,
      uniqueTotal: uniqueTotal,
      loadedCount: list.length,
      perSender: perSender,
      byStatus: byStatus,
      // C8 brief names, kept as top-level fields for the Ask-Jarvis text:
      signed: byStatus[STATUS_SIGNED],
      expired: byStatus[STATUS_EXPIRED],
      replaySuspected: byStatus[STATUS_REPLAY],
      tampered: byStatus[STATUS_TAMPERED],
      undecryptable: byStatus[STATUS_UNDECRYPTABLE],
      unknown: byStatus[STATUS_UNKNOWN],
      problemCount: problemCount,
      duplicateIds: duplicateIds,
      problemIds: problemIds,
      earliestIat: earliest,
      latestIat: latest,
      checkedAt: now,
      checkedAtText: formatTime(now)
    };
  }

  // ---------------------------------------------------------------------------
  // 3. Key directory integrity — fingerprints recomputed from the
  //    published PEMs and compared with the pinned values (FILE-MAP §9,
  //    B5 keydir-verify.py is the Jarvis-side mirror of this check).
  //    Never displays a PEM or a full fingerprint — only the 8-char
  //    check-code and match / mismatch / no-key.
  //
  //    `fingerprintFn` is async (pem: string) => hex string, normally
  //    GhostChatCrypto.fingerprintPublicKey (A1). Tests inject a stub.
  //    When no fingerprint function is available the check reports
  //    "cannot-check" per key instead of guessing — fail-closed.
  // ---------------------------------------------------------------------------

  var VALID_STATUSES = ['unpinned', 'pinned', 'revoked'];
  var VALID_SIG_ALGS = ['Ed25519', 'ES256']; // D6; RSA-PSS is rejected.

  function scanForPrivateKeyText(value, where, issues) {
    if (typeof value === 'string' && value.indexOf('PRIVATE KEY') !== -1) {
      issues.push(where + ': private-key material present — must never be in the key directory.');
      return true;
    }
    return false;
  }

  async function verifyKeyDirectory(participants, fingerprintFn, options) {
    var opts = isPlainObject(options) ? options : {};
    var fn = fingerprintFn || null;
    if (!fn && typeof root !== 'undefined' && root.GhostChatCrypto &&
        typeof root.GhostChatCrypto.fingerprintPublicKey === 'function') {
      fn = root.GhostChatCrypto.fingerprintPublicKey;
    }
    // In a browser global scope `root` is window/self; in Node the
    // global above is `self`/`this` — also try the plain global name.
    if (!fn && typeof GhostChatCrypto !== 'undefined' &&
        GhostChatCrypto && typeof GhostChatCrypto.fingerprintPublicKey === 'function') {
      fn = GhostChatCrypto.fingerprintPublicKey;
    }

    var list = Array.isArray(participants) ? participants : [];
    var entries = [];
    var verifiedCount = 0;   // pinned + encryption fingerprint matches
    var mismatchCount = 0;
    var noKeyCount = 0;
    var issues = [];

    for (var i = 0; i < list.length; i++) {
      var p = isPlainObject(list[i]) ? list[i] : {};
      var id = typeof p.id === 'string' ? p.id : 'unknown';
      var entry = {
        id: id,
        displayName: typeof p.display_name === 'string' ? p.display_name : id,
        status: typeof p.status === 'string' ? p.status : 'unknown',
        sigAlg: typeof p.sig_alg === 'string' ? p.sig_alg : null,
        enc: { present: false, matches: null, checkCode: '—', checked: false },
        sig: { present: false, matches: null, checkCode: '—', checked: false },
        issues: [],
        note: null,
        ok: false
      };

      if (VALID_STATUSES.indexOf(entry.status) === -1) {
        entry.issues.push('Unknown status "' + entry.status + '" — expected unpinned, pinned, or revoked.');
      }
      if (entry.status === 'revoked') {
        entry.issues.push('Key is revoked — it verifies nothing.');
      }
      if (entry.sigAlg !== null && VALID_SIG_ALGS.indexOf(entry.sigAlg) === -1) {
        entry.issues.push('Signing algorithm "' + entry.sigAlg + '" is not accepted (Ed25519 or ES256 only).');
      }
      if (entry.status === 'pinned' && !p.enc_pub_pem && !p.sig_pub_pem) {
        entry.issues.push('Marked pinned but no public key is published for it.');
      }

      // Private-key scan: a PEM in this directory must never contain one.
      [p.enc_pub_pem, p.sig_pub_pem].forEach(function (pem) {
        if (typeof pem === 'string') scanForPrivateKeyText(pem, id, entry.issues);
      });

      // Encryption key: recompute the fingerprint from the PEM, compare
      // with the pinned value. Null/null (unpinned placeholder, B1) is
      // "no key", not a mismatch.
      if (typeof p.enc_pub_pem === 'string' && p.enc_pub_pem.length > 0) {
        entry.enc.present = true;
        entry.enc.checkCode = fingerprintShort(p.enc_fingerprint);
        if (!fn) {
          entry.issues.push('Encryption fingerprint could not be re-checked in this browser (no fingerprint function).');
        } else {
          try {
            var recomputedEnc = await fn(p.enc_pub_pem);
            entry.enc.checked = true;
            entry.enc.matches = typeof recomputedEnc === 'string' &&
              typeof p.enc_fingerprint === 'string' &&
              recomputedEnc.toLowerCase() === p.enc_fingerprint.toLowerCase();
            if (!entry.enc.matches) {
              entry.issues.push('Encryption fingerprint mismatch — recomputed value does not match the pinned value.');
            }
          } catch (e) {
            entry.issues.push('Encryption fingerprint could not be recomputed (' + (e && e.message ? e.message : 'error') + ').');
          }
        }
      } else if (typeof p.enc_fingerprint === 'string' && p.enc_fingerprint.length > 0) {
        entry.issues.push('Encryption fingerprint is listed but no public key is published to check it against.');
      }

      // Signing key: same check, independently.
      if (typeof p.sig_pub_pem === 'string' && p.sig_pub_pem.length > 0) {
        entry.sig.present = true;
        entry.sig.checkCode = fingerprintShort(p.sig_fingerprint);
        if (!fn) {
          entry.issues.push('Signing fingerprint could not be re-checked in this browser (no fingerprint function).');
        } else {
          try {
            var recomputedSig = await fn(p.sig_pub_pem);
            entry.sig.checked = true;
            entry.sig.matches = typeof recomputedSig === 'string' &&
              typeof p.sig_fingerprint === 'string' &&
              recomputedSig.toLowerCase() === p.sig_fingerprint.toLowerCase();
            if (!entry.sig.matches) {
              entry.issues.push('Signing fingerprint mismatch — recomputed value does not match the pinned value.');
            }
          } catch (e) {
            entry.issues.push('Signing fingerprint could not be recomputed (' + (e && e.message ? e.message : 'error') + ').');
          }
        }
      } else if (typeof p.sig_fingerprint === 'string' && p.sig_fingerprint.length > 0) {
        entry.issues.push('Signing fingerprint is listed but no public key is published to check it against.');
      }

      // Jarvis blocking check (D13): the pinned encryption fingerprint
      // must be exactly the verified value. Any other value is a STOP.
      if (id === 'jarvis' && typeof p.enc_fingerprint === 'string') {
        if (p.enc_fingerprint.toLowerCase() !== JARVIS_ENC_FINGERPRINT) {
          entry.issues.push('Jarvis encryption fingerprint does not match the verified value — STOP, do not send, tell Jarvis.');
        }
      }

      // B1 carries a separate "jarvis-signing" slot (not a fourth
      // participant): its signing key is added at wave-3 assembly from
      // A10's fingerprint record. An empty slot there is expected, not
      // a missing participant key — record it as a note, not an issue,
      // and do not count it in noKeyCount.
      if (!entry.enc.present && !entry.sig.present) {
        if (id === 'jarvis-signing') {
          entry.note = 'Jarvis signing key not yet published — added at wave-3 assembly from the A10 fingerprint record.';
        } else {
          noKeyCount += 1;
          if (entry.issues.length === 0) entry.issues.push(COPY.noKey);
        }
      }
      if (entry.issues.length > 0) {
        entry.issues.forEach(function (issue) {
          if (issue.indexOf('mismatch') !== -1 || issue.indexOf('STOP') !== -1) mismatchCount += 1;
        });
        issues.push.apply(issues, entry.issues.map(function (issue) {
          return id + ': ' + issue;
        }));
      }

      // "Verified" for the summary strip (UI-SPEC §2.5, N/3): pinned and
      // its published encryption fingerprint recomputed as a match. A
      // participant whose signing key is still unpinned (ChatGPT's key
      // is unpinned until the owner confirms it out-of-band, D17) does
      // not count as verified — and is not counted as a mismatch either.
      if (PARTICIPANTS.indexOf(id) !== -1 &&
          entry.status === 'pinned' && entry.enc.matches === true) {
        verifiedCount += 1;
      }
      entry.ok = entry.issues.length === 0;
      entries.push(entry);
    }

    // The key directory in B1 carries a separate "jarvis-signing" entry;
    // it is not a fourth participant — verifiedCount is over the three
    // real participants only (see PARTICIPANTS above).
    return {
      entries: entries,
      verifiedCount: verifiedCount,
      verifiedTotal: PARTICIPANTS.length,
      mismatchCount: mismatchCount,
      noKeyCount: noKeyCount,
      allOk: issues.length === 0,
      issues: issues,
      keyHistoryAvailable: !!(opts.keyHistory && Array.isArray(opts.keyHistory) &&
        opts.keyHistory.length > 0),
      keyHistory: Array.isArray(opts.keyHistory) ? opts.keyHistory : null
    };
  }

  // ---------------------------------------------------------------------------
  // 4. Store ciphertext-only confirmation.
  //    Checks the store snapshot WITHOUT ever returning a value from it:
  //    violations name the field/path only, never the content. A failure
  //    here is fail-closed: ciphertextOnly === false.
  //
  //    Rules (FILE-MAP §3 / D2 / D15):
  //      - envelopes carry only the allowlisted fields;
  //      - iv / ct / mac / sig / wk are base64url, no padding;
  //      - no field named text / plaintext / privateKey / passphrase,
  //        and no "PRIVATE KEY" marker anywhere in the snapshot;
  //      - manifest carries only metadata fields;
  //      - participants entries carry public keys only.
  // ---------------------------------------------------------------------------

  var FORBIDDEN_FIELD_NAMES = [
    'text', 'plaintext', 'plain_text', 'privateKey', 'private_key',
    'passphrase', 'password', 'secret', 'backup'
  ];

  function checkCiphertextOnly(snapshot) {
    var checks = [];
    var violations = [];
    function addCheck(name, pass, detail) {
      checks.push({ name: name, pass: !!pass, detail: detail || '' });
      if (!pass) violations.push({ location: name, issue: detail || 'check failed' });
    }
    function scanValue(value, path, depth) {
      if (depth > 6) return;
      if (typeof value === 'string') {
        if (value.indexOf('PRIVATE KEY') !== -1) {
          violations.push({ location: path, issue: 'private-key marker present' });
        }
        return;
      }
      if (Array.isArray(value)) {
        value.forEach(function (v, idx) { scanValue(v, path + '[' + idx + ']', depth + 1); });
        return;
      }
      if (isPlainObject(value)) {
        Object.keys(value).forEach(function (k) {
          if (FORBIDDEN_FIELD_NAMES.indexOf(k) !== -1) {
            violations.push({ location: path + '.' + k, issue: 'forbidden plaintext/secret field name' });
          }
          scanValue(value[k], path + '.' + k, depth + 1);
        });
      }
    }

    var snap = isPlainObject(snapshot) ? snapshot : {};
    var envelopes = Array.isArray(snap.envelopes) ? snap.envelopes : [];
    var manifest = isPlainObject(snap.manifest) ? snap.manifest : null;
    var participants = Array.isArray(snap.participants) ? snap.participants : null;

    // (a) Envelope shape: allowlisted fields only, right version/alg.
    var shapeBad = 0;
    envelopes.forEach(function (env, idx) {
      if (!isPlainObject(env)) { shapeBad += 1; return; }
      Object.keys(env).forEach(function (k) {
        if (ENVELOPE_FIELDS_WITH_SEQ.indexOf(k) === -1) shapeBad += 1;
      });
      if (env.v !== ENVELOPE_VERSION) shapeBad += 1;
      if (env.alg && env.alg !== 'A256CBC-HS256') shapeBad += 1;
      if (env.sig_alg && VALID_SIG_ALGS.indexOf(env.sig_alg) === -1) shapeBad += 1;
      if (isInteger(env.iat) && isInteger(env.exp) &&
          (env.exp <= env.iat || env.exp - env.iat > MAX_TTL_SECONDS)) shapeBad += 1;
    });
    addCheck('envelope-shape', shapeBad === 0,
      shapeBad === 0 ? envelopes.length + ' envelope(s) checked' : shapeBad + ' shape problem(s)');

    // (b) Crypto fields are base64url without padding (never plaintext).
    var encodingBad = 0;
    envelopes.forEach(function (env) {
      if (!isPlainObject(env)) return;
      ['iv', 'ct', 'mac', 'sig'].forEach(function (f) {
        if (typeof env[f] !== 'string' || !B64U_RE.test(env[f])) encodingBad += 1;
      });
      if (Array.isArray(env.wrapped_keys)) {
        env.wrapped_keys.forEach(function (wk) {
          if (!isPlainObject(wk) || typeof wk.wk !== 'string' || !B64U_RE.test(wk.wk)) encodingBad += 1;
        });
      } else {
        encodingBad += 1;
      }
    });
    addCheck('crypto-fields-base64url', encodingBad === 0,
      encodingBad === 0 ? 'iv/ct/mac/sig/wrapped_keys are base64url only' : encodingBad + ' encoding problem(s)');

    // (c) No private-key material and no plaintext/secret field anywhere.
    var before = violations.length;
    envelopes.forEach(function (env, idx) { scanValue(env, 'envelopes[' + idx + ']', 0); });
    if (manifest) scanValue(manifest, 'manifest', 0);
    if (participants) scanValue(participants, 'participants', 0);
    addCheck('no-private-key-or-plaintext-fields', violations.length === before,
      violations.length === before ? 'no private-key markers, no plaintext/secret fields' : (violations.length - before) + ' violation(s)');

    // (d) Manifest shape (metadata only).
    if (manifest) {
      var manifestBad = 0;
      Object.keys(manifest).forEach(function (k) {
        if (MANIFEST_FIELDS.indexOf(k) === -1) manifestBad += 1;
      });
      if (Array.isArray(manifest.messages)) {
        manifest.messages.forEach(function (m) {
          if (!isPlainObject(m)) { manifestBad += 1; return; }
          Object.keys(m).forEach(function (k) {
            if (MANIFEST_MESSAGE_FIELDS.indexOf(k) === -1) manifestBad += 1;
          });
        });
      }
      addCheck('manifest-shape', manifestBad === 0,
        manifestBad === 0 ? 'manifest carries metadata only' : manifestBad + ' problem(s)');
    } else {
      addCheck('manifest-shape', true, 'no manifest supplied — skipped, not a failure');
    }

    // (e) Key directory in the snapshot: public keys only (same scan as
    // the key-integrity check; here it is a store-level guarantee).
    if (participants) {
      var keyBad = 0;
      participants.forEach(function (p) {
        if (!isPlainObject(p)) { keyBad += 1; return; }
        if (typeof p.enc_pub_pem === 'string' && p.enc_pub_pem.indexOf('PRIVATE KEY') !== -1) keyBad += 1;
        if (typeof p.sig_pub_pem === 'string' && p.sig_pub_pem.indexOf('PRIVATE KEY') !== -1) keyBad += 1;
      });
      addCheck('key-directory-public-only', keyBad === 0,
        keyBad === 0 ? 'key directory holds public keys only' : keyBad + ' problem(s)');
    }

    return {
      ciphertextOnly: violations.length === 0,
      envelopesChecked: envelopes.length,
      checks: checks,
      violations: violations,
      note: COPY.plaintextNote
    };
  }

  // Plaintext handling, as a value the render can show verbatim:
  // the page holds no plaintext outside decrypted messages in memory.
  function plaintextHandlingNote() {
    return COPY.ciphertextOnlyOk + ' ' + COPY.plaintextNote;
  }

  // ---------------------------------------------------------------------------
  // 5. "Ask Jarvis" — the audit request the owner pastes to Jarvis in
  //    Muse chat (OWNER-JOIN §6b). Jarvis re-reads history from his own
  //    decryptable copy; the app never pastes scrambled text or key
  //    material. This request contains ONLY: counts, per-sender counts,
  //    8-char check-codes, and truncated message IDs (first 8 chars).
  //    A topic is optional and is capped at 120 chars; anything that
  //    looks like key material in it is rejected outright.
  // ---------------------------------------------------------------------------

  function sanitiseTopic(topic) {
    if (topic === undefined || topic === null || topic === '') return null;
    if (typeof topic !== 'string') throw new Error('Ask Jarvis: topic must be text.');
    var t = topic.trim().replace(/\s+/g, ' ');
    if (t.length > 120) t = t.slice(0, 120);
    if (/-----BEGIN|PRIVATE KEY|PRIVATE KEY-----|BEGIN .* PRIVATE/i.test(t)) {
      throw new Error('Ask Jarvis: that text looks like key material — it was not included.');
    }
    return t;
  }

  function buildAskJarvisRequest(counts, keyAudit, storeCheck, options) {
    var opts = isPlainObject(options) ? options : {};
    var c = isPlainObject(counts) ? counts : computeMessageCounts([], nowSeconds());
    var topic = sanitiseTopic(opts.topic);
    var dateLabel = typeof opts.dateLabel === 'string' && opts.dateLabel.length > 0
      ? opts.dateLabel
      : new Date().toISOString().slice(0, 10);
    var lines = [];
    lines.push('Hi Jarvis — please audit our locked chat for me.');
    lines.push('');
    var range = 'Audit from the app, ' + dateLabel + '. ' +
      c.total + ' message(s) in the loaded set' +
      (c.earliestIat && c.latestIat
        ? ' (' + formatTime(c.earliestIat) + ' to ' + formatTime(c.latestIat) + ')'
        : '') + '.';
    lines.push(range);
    lines.push('Signed ' + c.signed + ', expired ' + c.expired +
      ', replay-suspected ' + c.replaySuspected + ', tampered ' + c.tampered +
      ', undecryptable ' + c.undecryptable + ', not checked yet ' + c.unknown + '.');
    lines.push('By sender: Jarvis ' + c.perSender.jarvis +
      ', ChatGPT ' + c.perSender.chatgpt + ', owner ' + c.perSender.owner +
      (c.perSender.unknown ? ', unknown ' + c.perSender.unknown : '') + '.');
    if (keyAudit && typeof keyAudit.verifiedCount === 'number') {
      var keyLine = 'Key directory: ' + keyAudit.verifiedCount + '/' +
        keyAudit.verifiedTotal + ' verified.' +
        (keyAudit.allOk ? ' No key mismatches.' :
          ' ' + keyAudit.issues.length + ' key issue(s) — see the audit view.');
      lines.push(keyLine);
    }
    if (storeCheck) {
      lines.push(storeCheck.ciphertextOnly
        ? 'Store check: ciphertext only, no problems found.'
        : 'Store check: PROBLEM found — please check the store before anything else.');
    }
    var maxIds = isInteger(opts.maxProblemIds) ? opts.maxProblemIds : 5;
    var ids = Array.isArray(c.problemIds) ? c.problemIds.slice(0, maxIds) : [];
    if (ids.length > 0) {
      lines.push('Messages to check (short IDs only, no scrambled text): ' +
        ids.map(truncateMsgId).join(', ') +
        (c.problemIds.length > maxIds ? ' — and ' + (c.problemIds.length - maxIds) + ' more.' : ''));
    } else if (c.problemCount === 0) {
      lines.push('No problem messages in the loaded set.');
    }
    lines.push('');
    lines.push('Please re-read the history from your own copy and tell me in plain words what you and ChatGPT said' +
      (topic ? ' about ' + topic : '') +
      '. Don’t paste scrambled text or any key material — plain words only.');
    return lines.join('\n');
  }

  // Copy helper: clipboard API first, textarea fallback for older
  // browsers. Returns a Promise<boolean>. Never throws for a missing
  // clipboard — the render shows the manual-copy message instead.
  function copyText(text) {
    if (typeof navigator !== 'undefined' && navigator.clipboard &&
        typeof navigator.clipboard.writeText === 'function') {
      return navigator.clipboard.writeText(text).then(function () { return true; })
        .catch(function () { return copyTextFallback(text); });
    }
    return Promise.resolve(copyTextFallback(text));
  }

  function copyTextFallback(text) {
    try {
      if (typeof document === 'undefined') return false;
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      var ok = document.execCommand('copy');
      document.body.removeChild(ta);
      return !!ok;
    } catch (e) {
      return false;
    }
  }

  // ---------------------------------------------------------------------------
  // 6. Orchestrator — one call from app.js (C3): counts + key integrity
  //    + store check + the Ask-Jarvis text, from the same inputs.
  // ---------------------------------------------------------------------------

  async function computeAudit(inputs, options) {
    var inp = isPlainObject(inputs) ? inputs : {};
    var opts = isPlainObject(options) ? options : {};
    var now = isInteger(inp.nowSec) ? inp.nowSec : nowSeconds();
    var counts = computeMessageCounts(inp.messages, now);
    var keyAudit = await verifyKeyDirectory(
      inp.keyDirectory, inp.fingerprintFn || null, { keyHistory: inp.keyHistory });
    var storeCheck = checkCiphertextOnly(inp.storeSnapshot || { envelopes: inp.messagesEnvelopes || [] });
    // If the caller passed raw envelopes for the store check, use those;
    // otherwise the message records' envelopes (never rendered/copied).
    if (Array.isArray(inp.messages) && !inp.storeSnapshot && !inp.messagesEnvelopes) {
      var envs = [];
      inp.messages.forEach(function (m) {
        if (isPlainObject(m) && isPlainObject(m.envelope)) envs.push(m.envelope);
      });
      if (envs.length > 0) storeCheck = checkCiphertextOnly({ envelopes: envs });
    }
    var requestText = buildAskJarvisRequest(counts, keyAudit, storeCheck, opts);
    return {
      counts: counts,
      keyAudit: keyAudit,
      storeCheck: storeCheck,
      requestText: requestText,
      checkedAt: now,
      loadedRangeNote: COPY.loadedRange
    };
  }

  // ---------------------------------------------------------------------------
  // 7. Rendering — DOM only, textContent only (no innerHTML: message
  //    content is untrusted input and must never be parsed as HTML).
  //    The render NEVER writes ct / iv / mac / wk / sig / PEM values
  //    into the page, and never offers a "copy envelope" action
  //    (conflict C8-1, above). Snippets show at most the first 60
  //    characters of decrypted text already in memory; otherwise the
  //    "not locked for you" line. Filter state lives on the container
  //    (data attributes), so a re-render keeps the owner's filter.
  // ---------------------------------------------------------------------------

  function el(tag, text, className) {
    var node = document.createElement(tag);
    if (typeof text === 'string' && text.length > 0) node.textContent = text;
    if (className) node.className = className;
    return node;
  }

  function button(label, onClick, className) {
    var b = el('button', label, className || 'audit-btn');
    b.type = 'button';
    b.addEventListener('click', onClick);
    return b;
  }

  function renderAudit(container, audit, options) {
    if (typeof document === 'undefined') {
      throw new Error('renderAudit needs a browser DOM.');
    }
    var opts = isPlainObject(options) ? options : {};
    var host = container || document.getElementById('audit-view') ||
      document.getElementById('app');
    if (!host) throw new Error('renderAudit: no container element found.');
    var messages = Array.isArray(opts.messages) ? opts.messages : [];
    var now = isInteger(opts.nowSec) ? opts.nowSec : nowSeconds();
    var counts = audit.counts;
    var keyAudit = audit.keyAudit;
    var storeCheck = audit.storeCheck;

    // Filter state: kept on the host so re-renders keep the owner's view.
    var filter = host.getAttribute('data-audit-filter') || 'all';
    var senderFilter = host.getAttribute('data-audit-sender') || 'all';
    function setFilter(next, sender) {
      host.setAttribute('data-audit-filter', next);
      host.setAttribute('data-audit-sender', sender || senderFilter);
      renderAudit(host, audit, opts);
    }

    host.textContent = '';
    host.appendChild(el('h2', COPY.title, 'audit-title'));
    host.appendChild(el('p', COPY.intro, 'audit-intro'));

    // --- Summary strip (UI-SPEC §2.5) ---
    var strip = el('div', '', 'audit-summary' + (counts.problemCount > 0 ? ' audit-summary-problem' : ''));
    strip.appendChild(el('p', 'Messages: ' + counts.total +
      ' · ✓ Signed ' + counts.signed +
      ' · ⚠ Expired ' + counts.expired +
      ' · ⛔ Replay suspected ' + counts.replaySuspected +
      ' · ⛔ Tampered ' + counts.tampered +
      ' · ? Undecryptable ' + counts.undecryptable +
      ' · Keys verified ' + keyAudit.verifiedCount + '/' + keyAudit.verifiedTotal, 'audit-summary-line'));
    if (counts.problemCount > 0) {
      strip.appendChild(button(COPY.reviewProblems + ' (' + counts.problemCount + ')',
        function () { setFilter('problems', 'all'); }, 'audit-btn audit-btn-danger'));
    } else {
      strip.appendChild(el('p', COPY.noProblems, 'audit-ok'));
    }
    host.appendChild(strip);

    // --- Ask Jarvis (OWNER-JOIN §6b) ---
    var ask = el('section', '', 'audit-ask-jarvis');
    ask.appendChild(el('h3', COPY.askJarvisTitle, 'audit-section-title'));
    ask.appendChild(el('p', COPY.askJarvisNote, 'audit-note'));
    var requestBox = el('pre', audit.requestText, 'audit-request-text');
    ask.appendChild(requestBox);
    var copyStatus = el('p', '', 'audit-copy-status');
    ask.appendChild(button('Copy audit request for Jarvis', function () {
      copyText(audit.requestText).then(function (ok) {
        copyStatus.textContent = ok ? COPY.askJarvisCopied : COPY.askJarvisCopyFailed;
      });
    }, 'audit-btn audit-btn-primary'));
    ask.appendChild(copyStatus);
    host.appendChild(ask);

    // --- Key directory integrity ---
    var keysSection = el('section', '', 'audit-keys');
    keysSection.appendChild(el('h3', 'Key directory — checked just now', 'audit-section-title'));
    keyAudit.entries.forEach(function (entry) {
      var card = el('div', '', 'audit-key-card');
      card.appendChild(el('p', entry.displayName + ' — ' + entry.status +
        (entry.enc.present || entry.sig.present
          ? ' · check-code ' + (entry.enc.checkCode !== '—' ? entry.enc.checkCode : entry.sig.checkCode)
          : ' · ' + COPY.noKey), 'audit-key-line'));
      var verdict = entry.ok ? '✓ Fingerprints match the pinned values.'
        : entry.issues.length > 0 ? entry.issues.join(' ') : 'Not checked yet.';
      card.appendChild(el('p', verdict, entry.ok ? 'audit-ok' : 'audit-problem'));
      if (entry.note) card.appendChild(el('p', entry.note, 'audit-note'));
      keysSection.appendChild(card);
    });
    if (!keyAudit.keyHistoryAvailable) {
      keysSection.appendChild(el('p', COPY.keyHistoryUnavailable, 'audit-note'));
    }
    host.appendChild(keysSection);

    // --- Ciphertext-only confirmation ---
    var storeSection = el('section', '', 'audit-store');
    storeSection.appendChild(el('h3', COPY.ciphertextOnlyTitle, 'audit-section-title'));
    storeSection.appendChild(el('p',
      storeCheck.ciphertextOnly ? COPY.ciphertextOnlyOk : COPY.ciphertextOnlyBad,
      storeCheck.ciphertextOnly ? 'audit-ok' : 'audit-problem'));
    storeCheck.checks.forEach(function (check) {
      storeSection.appendChild(el('p',
        (check.pass ? '✓ ' : '⛔ ') + check.name +
        (check.detail ? ' — ' + check.detail : ''), check.pass ? 'audit-ok' : 'audit-problem'));
    });
    storeSection.appendChild(el('p', COPY.plaintextNote, 'audit-note'));
    host.appendChild(storeSection);

    // --- Filter bar (UI-SPEC §2.5) ---
    var filters = el('div', '', 'audit-filters');
    var filterDefs = [
      ['all', 'All'], ['signed', 'Signed'], ['expired', 'Expired'],
      ['replay_suspected', 'Replay'], ['tampered', 'Tampered'],
      ['undecryptable', 'Undecryptable'], ['problems', 'Problems only']
    ];
    filterDefs.forEach(function (def) {
      var b = button(def[1], function () { setFilter(def[0], senderFilter); },
        'audit-btn' + (filter === def[0] ? ' audit-btn-active' : ''));
      b.setAttribute('aria-pressed', filter === def[0] ? 'true' : 'false');
      filters.appendChild(b);
    });
    ['all', 'jarvis', 'chatgpt', 'owner'].forEach(function (sender) {
      var b = button(sender === 'all' ? 'All senders' : sender,
        function () { setFilter(filter, sender); },
        'audit-btn' + (senderFilter === sender ? ' audit-btn-active' : ''));
      b.setAttribute('aria-pressed', senderFilter === sender ? 'true' : 'false');
      filters.appendChild(b);
    });
    host.appendChild(filters);
    host.appendChild(el('p', COPY.loadedRange, 'audit-note'));

    // --- Audit list: one row per message, never a ciphertext dump ---
    var list = el('div', '', 'audit-list');
    var shown = 0;
    messages.forEach(function (rec) {
      var c = classifyMessage(rec, now);
      if (filter === 'problems' &&
          !(c.status === STATUS_REPLAY || c.status === STATUS_TAMPERED ||
            c.status === STATUS_UNDECRYPTABLE)) return;
      if (filter !== 'all' && filter !== 'problems' && c.status !== filter) return;
      if (senderFilter !== 'all' && c.sender !== senderFilter) return;
      shown += 1;

      var row = el('div', '', 'audit-row audit-row-' + c.status);
      row.appendChild(el('p', formatTime(rec.iat) + ' · ' + c.sender + ' · ' + c.badge, 'audit-row-head'));
      var snippet = (typeof rec.decryptedText === 'string' && rec.decryptedText.length > 0)
        ? rec.decryptedText.slice(0, 60)
        : COPY.notEncryptedForYou;
      row.appendChild(el('p', snippet, 'audit-row-snippet'));
      row.appendChild(el('p', 'ID ' + truncateMsgId(rec.msg_id) +
        ' · expires ' + formatTime(rec.exp), 'audit-row-meta'));
      if (c.recipientsNote) row.appendChild(el('p', c.recipientsNote, 'audit-problem'));
      var reverifyStatus = el('p', '', 'audit-reverify-status');
      var reverifyBtn = button(COPY.reverify, function () {
        if (typeof opts.onReverify === 'function') {
          var done = opts.onReverify(rec.msg_id, c);
          if (done && typeof done.then === 'function') {
            done.then(function (fresh) {
              reverifyStatus.textContent = COPY.reverifyDone + ' — ' +
                formatTime(nowSeconds()) + (fresh && fresh.badge ? ' — ' + fresh.badge : '');
            }).catch(function () {
              reverifyStatus.textContent = 'Re-check did not finish — try again.';
            });
          } else {
            reverifyStatus.textContent = COPY.reverifyDone + ' — ' + formatTime(nowSeconds());
          }
        } else {
          reverifyStatus.textContent = 'Re-check is not wired up in this view yet — ask Jarvis.';
        }
      }, 'audit-btn');
      row.appendChild(reverifyBtn);
      row.appendChild(reverifyStatus);
      // Message ID copy: the short ID only (metadata, not content).
      row.appendChild(button('Copy message ID', function () {
        if (rec.msg_id) copyText(rec.msg_id);
      }, 'audit-btn'));
      list.appendChild(row);
    });
    if (shown === 0) list.appendChild(el('p', COPY.noMessages, 'audit-note'));
    host.appendChild(list);
    return { shown: shown, filter: filter, senderFilter: senderFilter };
  }

  // Mount helper for app.js (C3): compute, then render, in one call.
  async function mountAuditView(container, inputs, options) {
    var audit = await computeAudit(inputs, options);
    var rendered = renderAudit(container, audit, {
      messages: Array.isArray(inputs.messages) ? inputs.messages : [],
      nowSec: inputs.nowSec,
      onReverify: options && options.onReverify
    });
    return { audit: audit, rendered: rendered };
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  return {
    // Constants
    ENVELOPE_VERSION: ENVELOPE_VERSION,
    MAX_TTL_SECONDS: MAX_TTL_SECONDS,
    PARTICIPANTS: PARTICIPANTS,
    DEFAULT_RECIPIENTS: DEFAULT_RECIPIENTS,
    JARVIS_ENC_FINGERPRINT: JARVIS_ENC_FINGERPRINT,
    ENVELOPE_FIELDS: ENVELOPE_FIELDS,
    BADGE_LABELS: BADGE_LABELS,
    COPY: COPY,

    // Pure / testable core (no DOM, no network, no keys)
    classifyMessage: classifyMessage,
    computeMessageCounts: computeMessageCounts,
    checkCiphertextOnly: checkCiphertextOnly,
    plaintextHandlingNote: plaintextHandlingNote,
    buildAskJarvisRequest: buildAskJarvisRequest,
    fingerprintShort: fingerprintShort,
    truncateMsgId: truncateMsgId,
    formatTime: formatTime,

    // Async key check (needs a fingerprint function — A1 or an injected stub)
    verifyKeyDirectory: verifyKeyDirectory,

    // Orchestrator + rendering (browser)
    computeAudit: computeAudit,
    copyText: copyText,
    renderAudit: renderAudit,
    mountAuditView: mountAuditView
  };
});
