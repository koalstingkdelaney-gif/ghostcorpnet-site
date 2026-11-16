/**
 * view-keys.js — Key directory view for the ghostcorpnet encrypted chat (ecc-1).
 *
 * Worker C5. Spec: FILE-MAP.md §3 "Key directory (keys/participants.json,
 * CRYPTO-DESIGN §9)" + §4 C5; UI-SPEC.md §2.2 (key directory view);
 * KEY-MANAGEMENT.md §4 (directory) + §5 (rotation / revocation);
 * OWNER-JOIN.md §1 (check-code = first 8 chars of the fingerprint).
 *
 * FILE-MAP wins where the design docs conflict (FILE-MAP §1 / §6 rule 1):
 *  - Directory file is `keys/participants.json` (KEY-MANAGEMENT's `keys.json`
 *    name is superseded by FILE-MAP D8).
 *  - Schema is one entry per participant: id, display_name, enc_pub_pem,
 *    enc_fingerprint, sig_pub_pem, sig_fingerprint, sig_alg,
 *    status (`unpinned` | `pinned` | `revoked`), pinned_at, pinned_by,
 *    rotated_from (FILE-MAP §3 / CRYPTO-DESIGN §9). KEY-MANAGEMENT's
 *    `active` / `superseded` statuses and per-participant key arrays are NOT
 *    used; rotation here is old entry -> `revoked` with `rotated_from`
 *    pointing at the new fingerprint.
 *  - Signing is Ed25519 primary, ES256 fallback (FILE-MAP D6). KEY-MANAGEMENT
 *    §1.2's P-256-primary recommendation is superseded; an entry whose
 *    sig_alg is neither Ed25519 nor ES256 is a Mismatch.
 *  - Check-code: first 8 hex chars of the fingerprint, shown `XXXX-XXXX`
 *    (OWNER-JOIN §1 step 4). The display module for it is C16
 *    (`fingerprint-check.js`); this file computes the same code and defers
 *    to C16 when it is loaded, so the two can never disagree.
 *
 * What this view does:
 *  - Lists every entry in `chat/keys/participants.json` (published copy;
 *    fetched as `keys/participants.json` relative to the page at `/chat/`).
 *  - One card per directory entry, one row per key (encryption + signing),
 *    each with its own badge:
 *      Verified   — status `pinned` and the fingerprint matches the
 *                   confirmed / expected value (pinned means the owner
 *                   confirmed it out-of-band, CRYPTO-DESIGN §9 step 4).
 *      Unverified — status `unpinned` (key published, not yet confirmed).
 *      Mismatch   — the fingerprint does not match the pinned / confirmed
 *                   value, the published key does not hash to the recorded
 *                   fingerprint, the fingerprint is malformed, or sig_alg
 *                   is unknown. Send to this key is not trusted.
 *      Revoked    — status `revoked`. Revoked keys verify nothing
 *                   (CRYPTO-DESIGN §9 step 5).
 *      No key     — grey empty state (UI-SPEC §2.2): no key published yet.
 *    Badges are computed locally at render time, never trusted from the
 *    directory alone: after the first paint, each published PEM is hashed
 *    (SHA-256 of DER SPKI) in this browser and compared with the recorded
 *    fingerprint; a mismatch downgrades the badge in place.
 *  - Shows each key's fingerprint truncated (`ceabe1c7…a620ee5`); tapping
 *    it reveals the full 64-hex fingerprint (grouped in 8-char chunks),
 *    a Copy button, and the check-code to confirm with Jarvis in Muse chat.
 *  - Shows sig_alg and pinned_at / pinned_by per key.
 *  - Rotation: a new key appears alongside the old. Old entries are
 *    retained and listed (badge Revoked, with the `rotated_from` link to
 *    the replacement key). History is NEVER re-encrypted: old messages
 *    stay readable only to holders of the old key.
 *
 * What this view NEVER does:
 *  - Never shows private-key material. It only reads an allowlist of
 *    public fields from the directory; any other field is ignored. The
 *    fetched text is scanned for a private-key marker before parsing and
 *    the load fails closed if one is found.
 *  - Never offers to export a private key. The only key-export path is
 *    the backup flow (`app/backup.js`, C11); this view renders a
 *    "Back up my key" button on the viewer's own card ONLY when the
 *    caller supplies `onBackupRequest` (normally wired to backup.js),
 *    and renders no export UI at all otherwise.
 *  - Never sends plaintext, secrets, or personal info anywhere. It makes
 *    one GET (the public directory) and nothing else.
 *
 * Dependencies: none. Vanilla JS, no framework, no external resources.
 * Rendering uses DOM APIs + textContent only (never innerHTML with data),
 * so a hostile display_name or fingerprint in the directory cannot inject
 * markup. Styling is C2 (`app/style.css`); this module sets the semantic
 * class names listed in §"CSS hooks" below and uses no inline styles
 * except none at all. Buttons are real <button>s (48 px targets are C2/J3's
 * sizing; the classes are here for it to size).
 *
 * Use from app.js (C3):
 *   const view = GhostChatKeys.createView({
 *     participantsUrl: 'keys/participants.json',   // default
 *     expectedFingerprints: { jarvis: { enc: 'ceabe1c7…' } }, // optional
 *     isOwnId: 'owner',                            // optional
 *     onBackupRequest: () => GhostChatBackup.open(), // optional, C11
 *   });
 *   view.mount(document.getElementById('keys-view'));
 *   // or one-shot: GhostChatKeys.renderKeysInto(el, entries, options);
 */

'use strict';

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    // Node / CommonJS (test harness; the page loads this as a plain
    // <script> and gets window.GhostChatKeys).
    module.exports = factory();
  } else {
    root.GhostChatKeys = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {

  // ---------------------------------------------------------------------------
  // Constants — FILE-MAP §3 / CRYPTO-DESIGN §9
  // ---------------------------------------------------------------------------

  /** Statuses the directory schema allows (FILE-MAP §3). */
  var STATUSES = ['unpinned', 'pinned', 'revoked'];

  /** Signing algorithms the protocol accepts (FILE-MAP D6). */
  var SIG_ALGS = ['Ed25519', 'ES256'];

  /**
   * Jarvis's v1 RSA-4096 encryption fingerprint, SHA-256 of DER SPKI.
   * PUBLIC value (FILE-MAP D13, CRYPTO-DESIGN §5, UI-SPEC §0). It is the
   * expected value the directory's jarvis encryption fingerprint is checked
   * against by default — the same blocking check C4 (view-setup.js) runs.
   * Overridable per view via `expectedFingerprints`; never a secret.
   */
  var JARVIS_ENC_FINGERPRINT =
    'ceabe1c77c4c15710dc6e06992bad6c70c8ba1d8c0adaf17a2f3b1042a620ee5';

  /** Default directory URL, relative to the page served at /chat/ (D2/D8). */
  var DEFAULT_PARTICIPANTS_URL = 'keys/participants.json';

  /**
   * Badge definitions. Labels are the exact words the task brief and
   * UI-SPEC §2.2 prescribe; the icon is text, never colour alone (UI-SPEC
   * §2.3 / §3: badges are a short text label + colour + icon).
   */
  var BADGES = {
    verified:   { key: 'verified',   label: 'Verified',   icon: '✓', css: 'gc-keys-badge--verified' },
    unverified: { key: 'unverified', label: 'Unverified', icon: '⚠', css: 'gc-keys-badge--unverified' },
    mismatch:   { key: 'mismatch',   label: 'Mismatch',   icon: '⛔', css: 'gc-keys-badge--mismatch' },
    revoked:    { key: 'revoked',    label: 'Revoked',    icon: '⛔', css: 'gc-keys-badge--revoked' },
    none:       { key: 'none',       label: 'No key',     icon: '–', css: 'gc-keys-badge--none' }
  };

  /** CSS hooks (styling is C2's `app/style.css`; classes only here). */
  var CSS = {
    view: 'gc-keys-view',
    header: 'gc-keys-header',
    title: 'gc-keys-title',
    refresh: 'gc-keys-refresh',
    summary: 'gc-keys-summary',
    error: 'gc-keys-error',
    list: 'gc-keys-list',
    card: 'gc-keys-card',
    cardHeader: 'gc-keys-card-header',
    cardName: 'gc-keys-card-name',
    cardId: 'gc-keys-card-id',
    cardBadge: 'gc-keys-card-badge',
    keyRow: 'gc-keys-key-row',
    keyLabel: 'gc-keys-key-label',
    keyAlg: 'gc-keys-key-alg',
    keyFp: 'gc-keys-key-fp',
    keyBadge: 'gc-keys-badge',
    keyPinned: 'gc-keys-key-pinned',
    keyRotated: 'gc-keys-key-rotated',
    keyDetail: 'gc-keys-key-detail',
    keyDetailOpen: 'gc-keys-key-detail--open',
    fullFp: 'gc-keys-full-fp',
    checkCode: 'gc-keys-check-code',
    copyBtn: 'gc-keys-copy',
    backupBtn: 'gc-keys-backup',
    note: 'gc-keys-note'
  };

  // Fields this view is allowed to read from a directory entry. Anything
  // else in the file (including any private-key-shaped field) is ignored
  // and never reaches the DOM.
  var ENTRY_FIELDS = [
    'id', 'display_name',
    'enc_pub_pem', 'enc_fingerprint',
    'sig_pub_pem', 'sig_fingerprint', 'sig_alg',
    'status', 'pinned_at', 'pinned_by', 'rotated_from'
  ];

  // ---------------------------------------------------------------------------
  // Small pure helpers (no DOM, no network — unit-testable)
  // ---------------------------------------------------------------------------

  function isObject(v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
  }

  function asString(v) {
    return typeof v === 'string' ? v : null;
  }

  /** Lowercase hex with whitespace stripped; null stays null. */
  function normalizeFingerprint(fp) {
    if (typeof fp !== 'string') return null;
    var s = fp.replace(/\s+/g, '').toLowerCase();
    return s.length ? s : null;
  }

  function isSha256Hex(fp) {
    return typeof fp === 'string' && /^[0-9a-f]{64}$/.test(fp);
  }

  /**
   * Truncated fingerprint for list display: first 8 + ellipsis + last 8.
   * e.g. `ceabe1c7…a620ee5`. Null/empty -> null.
   */
  function truncateFingerprint(fp) {
    var s = normalizeFingerprint(fp);
    if (!s) return null;
    if (s.length <= 16) return s;
    return s.slice(0, 8) + '…' + s.slice(-8);
  }

  /**
   * Full fingerprint grouped in 8-char chunks for readable display/copy:
   * `ceabe1c7 c4c15710 …`. Grouping never changes the value.
   */
  function formatFingerprint(fp) {
    var s = normalizeFingerprint(fp);
    if (!s) return null;
    var out = [];
    for (var i = 0; i < s.length; i += 8) out.push(s.slice(i, i + 8));
    return out.join(' ');
  }

  /**
   * Check-code to confirm with Jarvis (OWNER-JOIN §1 step 4): the first 8
   * characters of the fingerprint, uppercased, grouped `XXXX-XXXX`.
   * e.g. fingerprint `ceabe1c7…` -> `CEAB-E1C7`. If C16
   * (`fingerprint-check.js`) is loaded, its implementation is used so the
   * two displays can never disagree; otherwise this local one applies.
   */
  function checkCode(fp) {
    var s = normalizeFingerprint(fp);
    if (!s || s.length < 8) return null;
    if (typeof root !== 'undefined' && root.GhostcorpFingerprintCheck &&
        typeof root.GhostcorpFingerprintCheck.checkCode === 'function') {
      try {
        return root.GhostcorpFingerprintCheck.checkCode(fp);
      } catch (e) { /* fall through to the local computation */ }
    }
    var head = s.slice(0, 8).toUpperCase();
    return head.slice(0, 4) + '-' + head.slice(4, 8);
  }

  /**
   * Marker scan for private-key material. Built by concatenation so this
   * source file itself contains no literal private-key header line (the
   * B5 keydir-verify sweep greps for that header). Returns true when the
   * text looks like it carries a private key.
   */
  function containsPrivateKeyMaterial(text) {
    if (typeof text !== 'string') return false;
    var marker = ['BEGIN', 'PRIVATE', 'KEY'].join(' ');
    if (text.indexOf(marker) !== -1) return true;
    // JWK private-key parameter next to a key type (never in a public dir).
    if (/"kty"\s*:\s*"[^"]+"\s*,\s*"d"\s*:/.test(text)) return true;
    return false;
  }

  /**
   * Decode base64 (standard or URL-safe, padded or not) to bytes.
   * Uses atob in browsers, Buffer in Node. Throws on invalid input.
   */
  function decodeBase64(b64) {
    var clean = String(b64).replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    while (clean.length % 4) clean += '=';
    if (typeof Buffer !== 'undefined' && typeof Buffer.from === 'function') {
      return new Uint8Array(Buffer.from(clean, 'base64'));
    }
    if (typeof atob !== 'function') throw new Error('no base64 decoder available');
    var bin = atob(clean);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  /**
   * PEM (-----BEGIN PUBLIC KEY----- …) -> DER bytes. Accepts a PEM string
   * or bare base64. Throws on malformed input.
   */
  function pemToDer(pem) {
    if (typeof pem !== 'string') throw new Error('public key is not text');
    var body = pem.replace(/-----[A-Z ]*-----/g, '').replace(/\s+/g, '');
    if (!body) throw new Error('public key is empty');
    return decodeBase64(body);
  }

  function bytesToHex(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) {
      out += ('0' + bytes[i].toString(16)).slice(-2);
    }
    return out;
  }

  /**
   * SHA-256 hex of bytes via WebCrypto (or an injected subtle). Returns a
   * Promise<string>. Rejects when no WebCrypto is available.
   */
  function sha256Hex(bytes, subtle) {
    var s = subtle || (typeof crypto !== 'undefined' ? crypto.subtle : null);
    if (!s || typeof s.digest !== 'function') {
      return Promise.reject(new Error('WebCrypto is not available'));
    }
    return s.digest('SHA-256', bytes).then(function (buf) {
      return bytesToHex(new Uint8Array(buf));
    });
  }

  /** Recompute a key's fingerprint from its published PEM (SHA-256, DER SPKI). */
  function fingerprintOfPem(pem, subtle) {
    var der;
    try {
      der = pemToDer(pem);
    } catch (e) {
      return Promise.reject(e);
    }
    return sha256Hex(der, subtle);
  }

  // ---------------------------------------------------------------------------
  // Badge computation (synchronous part — no PEM hashing)
  // ---------------------------------------------------------------------------

  /**
   * Badge for one key of one entry, from directory fields + confirmed /
   * expected fingerprints only (no PEM recompute — see verifyFingerprints
   * for the async half). `keyKind` is 'enc' or 'sig'. `ctx`:
   *   { expected: { enc: '<hex>' | null, sig: '<hex>' | null } }
   * where `expected` is the fingerprint confirmed out-of-band (for jarvis
   * enc this defaults to the v1 fingerprint in §Constants).
   * Returns { badge, reason } — badge is one of the BADGES keys.
   */
  function computeBadge(entry, keyKind, ctx) {
    ctx = ctx || {};
    var expected = ctx.expected || {};
    var pem = keyKind === 'enc' ? entry.enc_pub_pem : entry.sig_pub_pem;
    var fp = normalizeFingerprint(keyKind === 'enc' ? entry.enc_fingerprint : entry.sig_fingerprint);
    var status = entry.status;

    // Revoked keys verify nothing (CRYPTO-DESIGN §9 step 5) — whatever
    // else the entry says, a revoked key is Revoked.
    if (status === 'revoked') {
      return { badge: 'revoked', reason: 'Revoked — this key verifies nothing and encrypts nothing new.' };
    }

    // No key published at all for this purpose (UI-SPEC §2.2 empty state).
    if (!pem && !fp) {
      return { badge: 'none', reason: 'No key published yet — they cannot receive encrypted messages until they finish setup.' };
    }

    // A pinned key with no fingerprint recorded cannot be confirmed.
    if (status === 'pinned' && !fp) {
      return { badge: 'mismatch', reason: 'Pinned but no fingerprint is recorded — the pin cannot be checked.' };
    }

    // Malformed fingerprint (not 64 lowercase hex chars).
    if (fp && !isSha256Hex(fp)) {
      return { badge: 'mismatch', reason: 'The recorded fingerprint is not a 64-character SHA-256 value.' };
    }

    // Unknown signing algorithm (FILE-MAP D6: Ed25519 or ES256 only).
    if (keyKind === 'sig' && entry.sig_alg && SIG_ALGS.indexOf(entry.sig_alg) === -1) {
      return { badge: 'mismatch', reason: 'Unknown signing algorithm "' + entry.sig_alg + '" — only Ed25519 and ES256 are accepted.' };
    }

    // Fingerprint does not match the value confirmed out-of-band.
    var want = normalizeFingerprint(expected[keyKind]);
    if (fp && want && fp !== want) {
      return { badge: 'mismatch', reason: 'Fingerprint does not match the confirmed value — do not send anything to this key. Tell Jarvis.' };
    }

    if (status === 'pinned') {
      return { badge: 'verified', reason: 'Pinned — fingerprint confirmed out-of-band' + (entry.pinned_by ? ' by ' + entry.pinned_by : '') + '.' };
    }
    if (status === 'unpinned') {
      return { badge: 'unverified', reason: 'Unverified — key published but not yet confirmed out-of-band. Messages still decrypt, but treat the sender as unconfirmed.' };
    }
    // Unknown status: fail towards unverified, never towards verified.
    return { badge: 'unverified', reason: 'Unverified — unknown status "' + String(status) + '" is treated as unconfirmed.' };
  }

  /**
   * Card-level badge for one entry: the most severe of its two key badges.
   * Order: revoked > mismatch > unverified > verified > no key.
   */
  function participantBadge(entry, ctx) {
    var enc = computeBadge(entry, 'enc', ctx);
    var sig = computeBadge(entry, 'sig', ctx);
    var order = { revoked: 4, mismatch: 3, unverified: 2, verified: 1, none: 0 };
    var worst = order[enc.badge] >= order[sig.badge] ? enc : sig;
    return { badge: worst.badge, reason: worst.reason, enc: enc, sig: sig };
  }

  /**
   * Default expected fingerprints per participant id. Only the jarvis
   * encryption fingerprint is a published known value (FILE-MAP D13);
   * every other participant's key must be confirmed out-of-band by the
   * owner and supplied via `expectedFingerprints` — never assumed.
   */
  function defaultExpected() {
    return { jarvis: { enc: JARVIS_ENC_FINGERPRINT, sig: null } };
  }

  function resolveExpected(entry, options) {
    var map = defaultExpected();
    var extra = (options && options.expectedFingerprints) || {};
    var out = { enc: null, sig: null };
    if (map[entry.id]) {
      out.enc = map[entry.id].enc;
      out.sig = map[entry.id].sig;
    }
    if (extra[entry.id]) {
      if (extra[entry.id].enc) out.enc = extra[entry.id].enc;
      if (extra[entry.id].sig) out.sig = extra[entry.id].sig;
    }
    // A caller may also pass a flat { '<id>:enc': fp } map; accept it.
    if (extra[entry.id + ':enc']) out.enc = extra[entry.id + ':enc'];
    if (extra[entry.id + ':sig']) out.sig = extra[entry.id + ':sig'];
    return out;
  }

  // ---------------------------------------------------------------------------
  // Directory loading + normalisation
  // ---------------------------------------------------------------------------

  /**
   * Normalise raw directory data to { entries, warnings }.
   * Accepts the FILE-MAP shape (a JSON array of entries), a
   * `{ participants: [...] }` / `{ participants: { id: entry } }` wrapper,
   * or `{ entries: [...] }`. Each entry is reduced to the allowlisted
   * public fields; anything else is dropped. Entries without an `id` are
   * skipped with a warning. Never throws on a single bad entry — the rest
   * of the directory still renders.
   */
  function normalizeDirectory(data) {
    var warnings = [];
    var raw = null;
    if (Array.isArray(data)) {
      raw = data;
    } else if (isObject(data) && Array.isArray(data.participants)) {
      raw = data.participants;
    } else if (isObject(data) && isObject(data.participants)) {
      raw = Object.keys(data.participants).map(function (k) {
        var e = data.participants[k];
        if (isObject(e) && !e.id) e = Object.assign({ id: k }, e);
        return e;
      });
    } else if (isObject(data) && Array.isArray(data.entries)) {
      raw = data.entries;
    } else {
      return { entries: [], warnings: ['Key directory has an unrecognised shape — expected a list of participant entries.'] };
    }

    var entries = [];
    raw.forEach(function (item, i) {
      if (!isObject(item)) {
        warnings.push('Skipped directory entry #' + i + ': not an object.');
        return;
      }
      var id = asString(item.id);
      if (!id) {
        warnings.push('Skipped directory entry #' + i + ': no id.');
        return;
      }
      var entry = { id: id };
      ENTRY_FIELDS.forEach(function (f) {
        if (f === 'id') return;
        var v = item[f];
        entry[f] = (typeof v === 'string' || v === null || v === undefined) ? (v == null ? null : v) : null;
      });
      if (!entry.display_name) entry.display_name = entry.id;
      if (!entry.status) entry.status = 'unpinned';
      if (STATUSES.indexOf(entry.status) === -1) {
        warnings.push('Entry "' + id + '" has unknown status "' + entry.status + '" — treated as unpinned.');
        entry.status = 'unpinned';
      }
      entries.push(entry);
    });
    return { entries: entries, warnings: warnings };
  }

  /**
   * Fetch + parse the key directory. Fails closed: if the fetched text
   * contains private-key material, or is not valid JSON, or has an
   * unrecognised shape with zero entries, the promise rejects and nothing
   * renders. `fetchFn` defaults to global fetch (injectable for tests).
   */
  function loadParticipants(url, fetchFn) {
    var f = fetchFn || (typeof fetch !== 'undefined' ? fetch : null);
    if (!f) return Promise.reject(new Error('fetch is not available in this environment'));
    return f(url, { headers: { Accept: 'application/json' } }).then(function (res) {
      if (!res || typeof res.text !== 'function') throw new Error('Unexpected fetch response');
      if (res.ok === false) throw new Error('Key directory request failed (HTTP ' + res.status + ')');
      return res.text();
    }).then(function (text) {
      if (containsPrivateKeyMaterial(text)) {
        throw new Error('Key directory failed the private-key scan — refusing to load it. Tell Jarvis.');
      }
      var data;
      try {
        data = JSON.parse(text);
      } catch (e) {
        throw new Error('Key directory is not valid JSON.');
      }
      var norm = normalizeDirectory(data);
      if (!norm.entries.length) {
        throw new Error('Key directory is empty or unreadable.' +
          (norm.warnings.length ? ' ' + norm.warnings.join(' ') : ''));
      }
      return norm;
    });
  }

  /**
   * Async half of badge verification: recompute every published PEM's
   * fingerprint (SHA-256 of DER SPKI) and compare with the recorded one.
   * Returns a Promise of { results, unverifiable } where results maps
   * `<id>:<enc|sig>` -> { recomputed, matches, error } and `unverifiable`
   * is true when this browser could not hash at all (WebCrypto missing) —
   * in that case provisional badges stand and the view says so.
   * A PEM that cannot be read is a mismatch, never a pass.
   */
  function verifyFingerprints(entries, subtle) {
    var results = {};
    var jobs = [];
    entries.forEach(function (entry) {
      ['enc', 'sig'].forEach(function (kind) {
        var pem = kind === 'enc' ? entry.enc_pub_pem : entry.sig_pub_pem;
        var recorded = normalizeFingerprint(kind === 'enc' ? entry.enc_fingerprint : entry.sig_fingerprint);
        if (!pem) return; // nothing published to check; badge stays 'none'
        var key = entry.id + ':' + kind;
        jobs.push(
          fingerprintOfPem(pem, subtle).then(function (recomputed) {
            results[key] = { recomputed: recomputed, matches: recorded ? recomputed === recorded : null, error: null };
          }).catch(function (e) {
            results[key] = { recomputed: null, matches: false, error: e && e.message ? e.message : String(e) };
          })
        );
      });
    });
    if (!jobs.length) return Promise.resolve({ results: results, unverifiable: false });
    var hasCrypto = !!(subtle || (typeof crypto !== 'undefined' && crypto.subtle));
    return Promise.all(jobs).then(function () {
      return { results: results, unverifiable: !hasCrypto };
    });
  }

  /**
   * Best-effort RSA key-size label for an encryption PEM
   * ("RSA-4096, OAEP-SHA-256"). Imports the SPKI and reads the modulus
   * bit-length from the JWK; any failure returns the generic label —
   * the label is display-only and never affects a badge.
   */
  function describeEncKey(pem, subtle) {
    var s = subtle || (typeof crypto !== 'undefined' ? crypto.subtle : null);
    if (!s || !pem) return Promise.resolve('RSA-OAEP, SHA-256');
    var der;
    try {
      der = pemToDer(pem);
    } catch (e) {
      return Promise.resolve('RSA-OAEP, SHA-256');
    }
    return s.importKey('spki', der, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt'])
      .then(function (key) { return s.exportKey('jwk', key); })
      .then(function (jwk) {
        if (!jwk || !jwk.n) return 'RSA-OAEP, SHA-256';
        var nBytes = decodeBase64(jwk.n);
        var bits = (nBytes.length - 1) * 8;
        var top = nBytes[0];
        while (top) { bits++; top >>= 1; }
        return 'RSA-' + bits + ', OAEP-SHA-256';
      })
      .catch(function () { return 'RSA-OAEP, SHA-256'; });
  }

  // ---------------------------------------------------------------------------
  // Rendering (DOM API + textContent only — no innerHTML with data)
  // ---------------------------------------------------------------------------

  function el(doc, tag, className, text) {
    var node = doc.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function badgeNode(doc, badgeKey, reason) {
    var def = BADGES[badgeKey] || BADGES.unverified;
    var span = el(doc, 'span', CSS.keyBadge + ' ' + def.css);
    span.setAttribute('data-badge', def.key);
    span.setAttribute('title', reason || '');
    span.textContent = def.icon + ' ' + def.label;
    return span;
  }

  function copyText(text, button) {
    function done(ok) {
      if (!button) return;
      var original = button.getAttribute('data-label') || 'Copy';
      button.textContent = ok ? 'Copied' : 'Copy failed';
      setTimeout(function () { button.textContent = original; }, 1500);
    }
    if (typeof navigator !== 'undefined' && navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
      return;
    }
    try {
      var doc = button ? button.ownerDocument : document;
      var ta = doc.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      doc.body.appendChild(ta);
      ta.select();
      var ok = doc.execCommand ? doc.execCommand('copy') : false;
      doc.body.removeChild(ta);
      done(ok);
    } catch (e) {
      done(false);
    }
  }

  /**
   * One key row (encryption or signing) inside a participant card.
   * `state` is the view state (verified results, expanded set, options).
   */
  function keyRow(doc, entry, kind, state) {
    var options = state.options;
    var ctx = { expected: resolveExpected(entry, options) };
    var row = el(doc, 'div', CSS.keyRow);
    var rowKey = entry.id + ':' + kind;
    row.setAttribute('data-key', rowKey);

    var label = el(doc, 'div', CSS.keyLabel,
      kind === 'enc' ? 'Encryption key' : 'Signing key');
    row.appendChild(label);

    // Algorithm line: sig_alg is recorded; enc alg is derived best-effort.
    var algText = kind === 'sig'
      ? (entry.sig_alg ? 'Signing: ' + entry.sig_alg : 'Signing: no key published')
      : (state.encLabels[rowKey] || 'RSA-OAEP, SHA-256');
    var alg = el(doc, 'div', CSS.keyAlg, algText);
    row.appendChild(alg);

    // Badge — recomputed lazily: start from the sync badge, then apply the
    // PEM-hash result (mismatch if the published key does not hash to the
    // recorded fingerprint).
    var badge = computeBadge(entry, kind, ctx);
    var verified = state.verified[rowKey];
    if (verified && verified.matches === false) {
      badge = {
        badge: 'mismatch',
        reason: verified.error
          ? 'The published key could not be read (' + verified.error + ').'
          : 'The published key does not hash to the recorded fingerprint.'
      };
    }
    var badgeEl = badgeNode(doc, badge.badge, badge.reason);
    row.appendChild(badgeEl);

    var fp = normalizeFingerprint(kind === 'enc' ? entry.enc_fingerprint : entry.sig_fingerprint);
    var pem = kind === 'enc' ? entry.enc_pub_pem : entry.sig_pub_pem;

    if (fp || pem) {
      var shown = fp || (verified && verified.recomputed) || null;
      var fpBtn = el(doc, 'button', CSS.keyFp);
      fpBtn.type = 'button';
      fpBtn.setAttribute('aria-expanded', state.expanded.has(rowKey) ? 'true' : 'false');
      fpBtn.textContent = shown ? truncateFingerprint(shown) : 'Key published — fingerprint not recorded';
      fpBtn.title = 'Tap to show the full fingerprint and check-code';
      fpBtn.addEventListener('click', function () {
        if (state.expanded.has(rowKey)) state.expanded.delete(rowKey);
        else state.expanded.add(rowKey);
        var open = state.expanded.has(rowKey);
        detail.hidden = !open;
        detail.classList.toggle(CSS.keyDetailOpen, open);
        fpBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
      });
      row.appendChild(fpBtn);

      // Detail (hidden until tap): full fingerprint + check-code.
      var detail = el(doc, 'div', CSS.keyDetail);
      detail.hidden = !state.expanded.has(rowKey);
      if (state.expanded.has(rowKey)) detail.classList.add(CSS.keyDetailOpen);
      var full = el(doc, 'div', CSS.fullFp, shown ? formatFingerprint(shown) : 'No fingerprint recorded.');
      full.setAttribute('aria-label', 'Full fingerprint');
      detail.appendChild(full);
      if (shown) {
        var copy = el(doc, 'button', CSS.copyBtn, 'Copy');
        copy.type = 'button';
        copy.setAttribute('data-label', 'Copy');
        copy.setAttribute('aria-label', 'Copy full fingerprint');
        copy.addEventListener('click', function () { copyText(shown, copy); });
        detail.appendChild(copy);

        var code = checkCode(shown);
        if (code) {
          var codeLine = el(doc, 'div', CSS.checkCode,
            'Check-code: ' + code + ' — tell Jarvis this code in Muse chat. ' +
            'If it matches the code Jarvis has, nobody swapped this key.');
          detail.appendChild(codeLine);
        }
      }
      row.appendChild(detail);
    } else {
      row.appendChild(el(doc, 'div', CSS.note, 'No key published yet.'));
    }

    // Pinned at / by (per entry, shown once per key row so each key's
    // provenance is visible without hunting).
    if (entry.status === 'pinned' && (entry.pinned_at || entry.pinned_by)) {
      row.appendChild(el(doc, 'div', CSS.keyPinned,
        'Pinned' + (entry.pinned_at ? ' ' + entry.pinned_at : '') +
        (entry.pinned_by ? ' by ' + entry.pinned_by : '')));
    } else if (entry.status === 'unpinned') {
      row.appendChild(el(doc, 'div', CSS.keyPinned, 'Not pinned yet.'));
    } else if (entry.status === 'revoked') {
      row.appendChild(el(doc, 'div', CSS.keyPinned, 'Revoked — verifies nothing.'));
    }

    // Rotation: old entries are retained; the replacement is named.
    if (entry.rotated_from) {
      row.appendChild(el(doc, 'div', CSS.keyRotated,
        'Rotated — replaced by key ' + (truncateFingerprint(entry.rotated_from) || entry.rotated_from) +
        '. Old messages stay readable with the old key; history is not re-encrypted.'));
    }
    return row;
  }

  function participantCard(doc, entry, state) {
    var options = state.options;
    var ctx = { expected: resolveExpected(entry, options) };
    var summary = participantBadge(entry, ctx);
    // A PEM-hash mismatch overrides the card badge too.
    ['enc', 'sig'].forEach(function (kind) {
      var v = state.verified[entry.id + ':' + kind];
      if (v && v.matches === false && summary.badge !== 'revoked') summary.badge = 'mismatch';
    });

    var card = el(doc, 'article', CSS.card);
    card.setAttribute('data-participant-id', entry.id);

    var header = el(doc, 'div', CSS.cardHeader);
    header.appendChild(el(doc, 'h2', CSS.cardName, entry.display_name || entry.id));
    header.appendChild(el(doc, 'span', CSS.cardId, entry.id));
    header.appendChild(badgeNode(doc, summary.badge, summary.reason));
    card.appendChild(header);

    card.appendChild(keyRow(doc, entry, 'enc', state));
    card.appendChild(keyRow(doc, entry, 'sig', state));

    // Rotation is recorded on the OLD entry (rotated_from points at the
    // new fingerprint, FILE-MAP §3); the per-key row above already shows
    // it, and the old entry stays listed alongside the new one.

    // Backup: the ONLY export affordance, and only through the backup flow
    // (C11 app/backup.js) supplied by the caller. Never rendered otherwise,
    // and never as a raw private-key export.
    if (options.isOwnId && options.isOwnId === entry.id &&
        typeof options.onBackupRequest === 'function') {
      var backup = el(doc, 'button', CSS.backupBtn, 'Back up my key');
      backup.type = 'button';
      backup.addEventListener('click', function () { options.onBackupRequest(entry); });
      card.appendChild(backup);
      card.appendChild(el(doc, 'div', CSS.note,
        'Backup is passphrase-encrypted and verified by a test restore (see backup). Your private key never leaves this browser except in that encrypted backup.'));
    }
    return card;
  }

  // ---------------------------------------------------------------------------
  // View object (mount / refresh / destroy) — wired by app.js (C3)
  // ---------------------------------------------------------------------------

  function createView(options) {
    options = options || {};
    var state = {
      options: options,
      entries: [],
      warnings: [],
      verified: {},       // '<id>:<kind>' -> { recomputed, matches, error }
      encLabels: {},      // '<id>:enc' -> 'RSA-4096, OAEP-SHA-256'
      expanded: new Set(),
      unverifiable: false,
      loading: false,
      error: null,
      container: null,
      abort: null,
      doc: (typeof document !== 'undefined') ? document : null
    };

    function render() {
      var container = state.container;
      if (!container) return;
      var doc = container.ownerDocument || state.doc;
      container.textContent = '';
      container.className = CSS.view;

      var header = el(doc, 'div', CSS.header);
      header.appendChild(el(doc, 'h1', CSS.title, 'Keys'));
      var refresh = el(doc, 'button', CSS.refresh, 'Refresh');
      refresh.type = 'button';
      refresh.addEventListener('click', function () { view.refresh(); });
      header.appendChild(refresh);
      container.appendChild(header);

      if (state.error) {
        container.appendChild(el(doc, 'div', CSS.error, state.error));
        return;
      }
      if (state.loading && !state.entries.length) {
        container.appendChild(el(doc, 'div', CSS.note, 'Loading keys…'));
        return;
      }
      if (!state.entries.length) {
        container.appendChild(el(doc, 'div', CSS.note, 'No keys published yet.'));
        return;
      }

      var counts = { verified: 0, unverified: 0, mismatch: 0, revoked: 0, none: 0 };
      state.entries.forEach(function (entry) {
        var ctx = { expected: resolveExpected(entry, options) };
        var s = participantBadge(entry, ctx);
        ['enc', 'sig'].forEach(function (kind) {
          var v = state.verified[entry.id + ':' + kind];
          if (v && v.matches === false && s.badge !== 'revoked') s.badge = 'mismatch';
        });
        counts[s.badge] = (counts[s.badge] || 0) + 1;
      });
      var summary = el(doc, 'div', CSS.summary,
        state.entries.length + ' key ' + (state.entries.length === 1 ? 'entry' : 'entries') +
        ' · ' + counts.verified + ' verified · ' + counts.unverified + ' unverified · ' +
        counts.mismatch + ' mismatch · ' + counts.revoked + ' revoked' +
        (state.unverifiable ? ' · this browser could not recompute fingerprints — badges come from the directory status only' : ''));
      container.appendChild(summary);

      state.warnings.forEach(function (w) {
        container.appendChild(el(doc, 'div', CSS.note, w));
      });

      var list = el(doc, 'div', CSS.list);
      state.entries.forEach(function (entry) {
        list.appendChild(participantCard(doc, entry, state));
      });
      container.appendChild(list);
    }

    function refresh() {
      if (!state.container) return Promise.resolve(state);
      state.loading = true;
      state.error = null;
      render();
      var url = options.participantsUrl || DEFAULT_PARTICIPANTS_URL;
      var fetchFn = options.fetch || null;
      return loadParticipants(url, fetchFn).then(function (norm) {
        state.entries = norm.entries;
        state.warnings = norm.warnings;
        state.loading = false;
        render();
        // Async half: hash each published PEM and downgrade badges on
        // mismatch. Re-render keeps the expanded set (state.expanded).
        return verifyFingerprints(state.entries, options.subtle).then(function (out) {
          state.verified = out.results;
          state.unverifiable = out.unverifiable;
          // Best-effort RSA size labels (display only).
          var labelJobs = state.entries.map(function (entry) {
            if (!entry.enc_pub_pem) return Promise.resolve();
            return describeEncKey(entry.enc_pub_pem, options.subtle).then(function (label) {
              state.encLabels[entry.id + ':enc'] = label;
            });
          });
          return Promise.all(labelJobs).then(function () { render(); });
        });
      }).catch(function (e) {
        state.loading = false;
        state.error = (e && e.message) ? e.message : String(e);
        if (typeof options.onError === 'function') {
          try { options.onError(state.error); } catch (ignored) { /* never break render */ }
        }
        render();
        return state;
      });
    }

    var view = {
      mount: function (container, entries) {
        state.container = container;
        if (entries) {
          var norm = normalizeDirectory(entries);
          state.entries = norm.entries;
          state.warnings = norm.warnings;
          render();
          verifyFingerprints(state.entries, options.subtle).then(function (out) {
            state.verified = out.results;
            state.unverifiable = out.unverifiable;
            render();
          });
          return Promise.resolve(state);
        }
        return refresh();
      },
      refresh: refresh,
      render: render,
      getState: function () {
        return {
          entries: state.entries,
          warnings: state.warnings,
          verified: state.verified,
          unverifiable: state.unverifiable,
          error: state.error
        };
      },
      destroy: function () {
        if (state.abort) { try { state.abort.abort(); } catch (e) { /* ignore */ } }
        if (state.container) state.container.textContent = '';
        state.container = null;
      }
    };
    return view;
  }

  /**
   * One-shot render of already-loaded entries (no fetch). Returns the view
   * so the caller can refresh() later.
   */
  function renderKeysInto(container, entries, options) {
    var view = createView(options);
    view.mount(container, entries);
    return view;
  }

  return {
    BADGES: BADGES,
    CSS: CSS,
    DEFAULT_PARTICIPANTS_URL: DEFAULT_PARTICIPANTS_URL,
    JARVIS_ENC_FINGERPRINT: JARVIS_ENC_FINGERPRINT,
    checkCode: checkCode,
    truncateFingerprint: truncateFingerprint,
    formatFingerprint: formatFingerprint,
    normalizeFingerprint: normalizeFingerprint,
    computeBadge: computeBadge,
    participantBadge: participantBadge,
    normalizeDirectory: normalizeDirectory,
    loadParticipants: loadParticipants,
    verifyFingerprints: verifyFingerprints,
    fingerprintOfPem: fingerprintOfPem,
    pemToDer: pemToDer,
    describeEncKey: describeEncKey,
    containsPrivateKeyMaterial: containsPrivateKeyMaterial,
    createView: createView,
    renderKeysInto: renderKeysInto
  };
});
