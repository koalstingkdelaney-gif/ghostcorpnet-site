/**
 * backup.js — passphrase-encrypted private-key backup export / restore
 * for the ghostcorpnet encrypted chat (worker C11).
 *
 * FILE-MAP (authoritative) §C11 + D16, and the backup format spec
 * owner/backup-format.md (G2, FINAL):
 *   - Passphrase-encrypted JWK backup: PBKDF2-SHA-256, >= 600,000
 *     iterations + AES-256-GCM, of the owner's private keys.
 *   - File layout (G2 §3): exactly two parts, LF line endings:
 *       Line 1: GHOSTCORP-CHAT-BACKUP v1
 *       Line 2: ONE JSON object on a single line (G2 §4), then a final
 *               newline. Nothing else in the file.
 *   - Outer JSON fields (exactly these 13, no others): v, participant,
 *     device, created, sig_alg, enc_fingerprint, sig_fingerprint,
 *     check_code, kdf, iterations, salt, nonce, ciphertext.
 *     The 12-byte GCM nonce field is named "nonce" (G2 §9.2) — the same
 *     bytes WebCrypto's AES-GCM parameter takes as its nonce value.
 *   - Lock (G2 §5): PBKDF2-SHA-256, file's salt (16 bytes) and
 *     iterations (>= 600,000) -> 256-bit key; AES-256-GCM with the
 *     file's nonce (12 bytes). The GCM tag is the last 16 bytes of
 *     ciphertext. G2 §5 defines NO additional authenticated data:
 *     decrypt with no AAD, so a G2 file and any file that binds AAD
 *     are mutually undecryptable.
 *   - Plaintext inside the ciphertext (G2 §6): exactly
 *     {"encryption": <RSA-OAEP private JWK>, "signing": <signing private JWK>}
 *     and nothing else. No passphrase, no check-code, no conversation
 *     text, no personal info inside.
 *   - Filename: ghostcorp-chat-backup-<device>-<YYYY-MM-DD>.txt, device
 *     exactly "phone" or "pc"; the device in the filename must match
 *     the device field inside the file (G2 §2).
 *   - participant is exactly "owner" (G2 §4). Callers may still pass
 *     options.owner for call compatibility; the file always records
 *     "owner".
 *   - The private key is NEVER stored bare.
 *   - MANDATORY test-restore: after creating a backup, the app must
 *     verify it restores (decrypt with the same passphrase, re-derive
 *     the public keys, compare fingerprints) before Join completes.
 *   - Restore: read a backup file, decrypt with the passphrase, import
 *     keys into IndexedDB via app/keys-store.js (C17).
 *   - Warn: never store the backup in chat / Notion / email / screenshot;
 *     keep on phone Files + PC, optionally printed.
 *
 * Layout history (G2 §9 — FILE-MAP wins where design docs differ):
 *   - The superseded OWNER-JOIN.md §2 layout (multi-line metadata
 *     header lines plus a PEM-style BEGIN/END block of base64) is GONE.
 *     This file implements the G2 layout only and REJECTS the old
 *     layout: a file with header lines or a PEM-style block fails the
 *     strict §3 parse (wrong line count / header mismatch).
 *   - The KEY-MANAGEMENT.md §3.3 field name for the GCM nonce is
 *     superseded: this file uses "nonce", never the old name.
 *   - KEY-MANAGEMENT.md §1.2 / §3.1 prescribes ECDSA P-256 signing;
 *     FILE-MAP D6 makes Ed25519 primary with ES256 (P-256) as fallback
 *     only. This file backs up whichever signing key it is handed
 *     (Ed25519 or P-256) and records it in the outer "sig_alg" field,
 *     so a restore can never silently swap one for the other.
 *   - FILE-MAP D5 overrides AES-256-GCM for the MESSAGE envelope
 *     (ecc-1 uses AES-256-CBC + HMAC). That override is about the
 *     envelope only. The BACKUP layer is a different layer and its
 *     normative cipher is AES-256-GCM per FILE-MAP C11 and G2 §5 —
 *     this file uses GCM for the backup only and never for message
 *     envelopes. G2 §5.4 states the reason: the backup runs in the
 *     owner's browser via WebCrypto, which has GCM; Jarvis's durable
 *     openssl-CLI path does not.
 *   - OWNER-JOIN.md §2 says the backup phrase must not be a one-word
 *     phrase. The exact strength rule was a builder decision: this
 *     file requires >= 2 words (or a single token >= 20 chars) and
 *     >= 8 chars total (see validatePassphrase).
 *   - G2 §4 check-code is the first 8 hex chars of the encryption
 *     public-key fingerprint, displayed XXXX-XXXX (uppercase).
 *
 * What this file NEVER does:
 *   - Never writes a bare private key anywhere (file, log, error, DOM).
 *   - Never stores the passphrase (not in the file, not in IndexedDB,
 *     not in memory beyond the single PBKDF2 derivation; the byte
 *     buffer is zeroed afterwards).
 *   - Never returns private-key bytes or private CryptoKey handles to
 *     callers. createBackup returns file text + public metadata only;
 *     restore stores keys through the keys-store adapter and returns
 *     public metadata only.
 *   - Never uses localStorage for keys (KEY-MANAGEMENT §3.2).
 *   - $0 spend. No network calls. No external resources.
 *
 * Dependencies: WebCrypto only (globalThis.crypto.subtle). No import of
 * crypto-core.js is required — this module uses subtle directly so it
 * works standalone in the page and under Node >= 18 (globalThis.crypto).
 * Fingerprints are computed directly as SHA-256 of the DER SPKI, which
 * is the same definition (CRYPTO-DESIGN §9 / FILE-MAP §3).
 *
 * Keys-store interface (C17, app/keys-store.js — parallel worker, NOT
 * yet landed at the time this file was written):
 *   options.keysStore (or window.GhostChatKeysStore) must provide:
 *     putKey(record) -> Promise<void>
 *   where record is:
 *     { key_id, participant: 'owner', device, purpose, algorithm,
 *       publicKey: CryptoKey, privateKey: CryptoKey,
 *       fingerprint: <64-hex>, created: 'YYYY-MM-DD', updated: <ISO> }
 *   key_id is 'owner-enc-<device>' for the encryption key and
 *   'owner-sign-<device>' for the signing key (stable per device, so a
 *   re-restore overwrites the same record instead of duplicating it).
 *   Private keys are stored extractable:false (day-to-day form,
 *   KEY-MANAGEMENT §3.2); the extractable form exists only transiently
 *   during backup export.
 *   If no keys-store adapter is present, restoreBackup falls back to a
 *   minimal built-in IndexedDB writer (database 'ghostcorp-chat',
 *   object store 'keys', keyPath 'key_id') holding CryptoKey objects.
 *   That fallback is PROVISIONAL: wave-3 assembly must confirm it
 *   matches C17's real schema, and prefer the real adapter whenever
 *   it is present.
 *
 * Browser support: any secure context (HTTPS / localhost) with
 * WebCrypto + PBKDF2 + AES-GCM + RSA-OAEP / Ed25519. If Ed25519 is
 * unavailable the caller must not pass an Ed25519 key here (the
 * ES256/P-256 path is handled the same way, by JWK shape).
 */

'use strict';

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.GhostChatBackup = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {

  // ---------------------------------------------------------------------------
  // §0. Constants — FILE-MAP C11 + G2 §4/§5 (normative)
  // ---------------------------------------------------------------------------

  var BACKUP_FORMAT = 'GHOSTCORP-CHAT-BACKUP v1';
  var BACKUP_FORMAT_VERSION = 1;

  var PBKDF2_ITERATIONS = 600000;   // >= 600k per FILE-MAP C11 / G2 §5
  var PBKDF2_HASH = 'SHA-256';
  var KDF_NAME = 'PBKDF2-SHA-256';
  var SALT_BYTES = 16;              // random 16-byte salt (G2 §4)
  var NONCE_BYTES = 12;             // random 12-byte GCM nonce (G2 §4)
  var AES_KEY_BITS = 256;
  var MIN_PASSPHRASE_CHARS = 8;
  var MIN_PASSPHRASE_WORDS = 2;     // OWNER-JOIN §2: refuse a one-word phrase
  var MIN_SINGLE_TOKEN_CHARS = 20;  // ...unless it is one long token
  var MAX_FILE_BYTES = 64 * 1024;   // G2 §3: files larger than 64 KiB reject

  // The 13 top-level fields of the G2 §4 JSON object — exactly these,
  // no others. Unknown fields reject (G2 §3).
  var OUTER_FIELDS = [
    'v', 'participant', 'device', 'created', 'sig_alg',
    'enc_fingerprint', 'sig_fingerprint', 'check_code',
    'kdf', 'iterations', 'salt', 'nonce', 'ciphertext'
  ];

  // IndexedDB fallback (provisional — see header; C17 is authoritative).
  var FALLBACK_DB_NAME = 'ghostcorp-chat';
  var FALLBACK_STORE_NAME = 'keys';
  var FALLBACK_DB_VERSION = 1;

  // Plain-words copy for the UI (C19/J1 own the canonical deck; these
  // strings match G2 §7/§8 wording until J1 lands — wave 3 to confirm).
  var COPY = {
    storageWarning:
      'Keep this file somewhere safe — your phone\'s Files and your PC, ' +
      'or printed at home. Never put it in the chat, in Notion, in an ' +
      'email, or in a screenshot. Anyone who finds this file AND your ' +
      'backup phrase can pretend to be you.',
    passphrasePrompt:
      'Pick a phrase only you know — like four random words. You\'ll need ' +
      'it if you ever restore. Jarvis cannot recover it for you if you ' +
      'forget it.',
    wrongPassphrase:
      'That phrase doesn\'t unlock this backup. Try again — check ' +
      'spelling and spaces.',
    skipBackupWarning:
      'If you skip the backup and lose this device, your old messages ' +
      'cannot be opened with a new key. Jarvis can re-share the history ' +
      'locked for your new key, but only if you ask.',
    keyNotExtractable:
      'This key was made so it cannot be copied out of the browser, so ' +
      'no backup can be made from it. Make a new key with backup turned ' +
      'on, then save the backup before you join.'
  };

  // ---------------------------------------------------------------------------
  // §1. Errors
  // ---------------------------------------------------------------------------

  function BackupError(code, message) {
    var e = new Error(message);
    e.name = 'BackupError';
    e.code = code;
    return e;
  }

  // ---------------------------------------------------------------------------
  // §2. Environment + small byte helpers (no crypto-core dependency)
  // ---------------------------------------------------------------------------

  function subtle() {
    var c = (typeof crypto !== 'undefined') ? crypto : null;
    if (!c || !c.subtle) {
      throw BackupError('NO_WEBCRYPTO',
        'WebCrypto is unavailable: this page must be served over HTTPS or localhost.');
    }
    return c.subtle;
  }

  function getRandomValues(buf) {
    var c = (typeof crypto !== 'undefined') ? crypto : null;
    if (!c || !c.getRandomValues) {
      throw BackupError('NO_WEBCRYPTO', 'crypto.getRandomValues is unavailable.');
    }
    return c.getRandomValues(buf);
  }

  function textToBytes(text) {
    return new TextEncoder().encode(text);
  }

  function bytesToText(bytes) {
    return new TextDecoder().decode(bytes);
  }

  function bytesToHex(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) {
      out += ('0' + bytes[i].toString(16)).slice(-2);
    }
    return out;
  }

  var B64U_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

  // base64url, no padding (RFC 4648 §5) — the only binary encoding in
  // the G2 file, for salt / nonce / ciphertext (G2 §4).
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

  // Strict canonical base64url decode: rejects padding, characters
  // outside the alphabet, impossible lengths, and non-canonical
  // trailing bits (re-encode must reproduce the input exactly).
  function base64urlToBytes(s) {
    if (typeof s !== 'string' || /=/.test(s) || !/^[A-Za-z0-9_-]*$/.test(s)) {
      throw BackupError('BAD_ENCODING',
        'Expected unpadded base64url (no "=" padding, alphabet A-Za-z0-9_-).');
    }
    if (s.length % 4 === 1) {
      throw BackupError('BAD_ENCODING',
        'Base64url length cannot leave a remainder of 1 mod 4.');
    }
    var rev = {};
    for (var i = 0; i < B64U_ALPHABET.length; i++) rev[B64U_ALPHABET[i]] = i;
    var outLen = Math.floor((s.length * 6) / 8);
    var out = new Uint8Array(outLen);
    var o = 0;
    var acc = 0;
    var bits = 0;
    for (var j = 0; j < s.length; j++) {
      acc = (acc << 6) | rev[s[j]];
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        if (o < outLen) out[o++] = (acc >> bits) & 0xff;
      }
    }
    if (bytesToBase64url(out) !== s) {
      throw BackupError('BAD_ENCODING',
        'Base64url value is non-canonical (trailing bits are not zero).');
    }
    return out;
  }

  // ---------------------------------------------------------------------------
  // §3. Dates, device labels, filenames, check-codes
  // ---------------------------------------------------------------------------

  function todayDateString(date) {
    var d = date || new Date();
    var y = d.getUTCFullYear();
    var m = String(d.getUTCMonth() + 1).padStart(2, '0');
    var day = String(d.getUTCDate()).padStart(2, '0');
    return y + '-' + m + '-' + day;
  }

  function isValidDateString(s) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
    var parts = s.split('-');
    var y = parseInt(parts[0], 10);
    var m = parseInt(parts[1], 10);
    var d = parseInt(parts[2], 10);
    if (m < 1 || m > 12 || d < 1 || d > 31) return false;
    var dt = new Date(Date.UTC(y, m - 1, d));
    return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 &&
      dt.getUTCDate() === d;
  }

  // G2 §2/§4: device is exactly "phone" or "pc" — no other label.
  function validateDevice(device) {
    if (device !== 'phone' && device !== 'pc') {
      throw BackupError('BAD_DEVICE',
        'Device must be "phone" or "pc" (G2 §2).');
    }
    return device;
  }

  // Filename per FILE-MAP C11 / G2 §2:
  // ghostcorp-chat-backup-<device>-<YYYY-MM-DD>.txt
  function backupFilename(device, dateString) {
    validateDevice(device);
    var created = dateString || todayDateString();
    if (!isValidDateString(created)) {
      throw BackupError('BAD_DATE', 'Created date must be YYYY-MM-DD.');
    }
    return 'ghostcorp-chat-backup-' + device + '-' + created + '.txt';
  }

  // Parse a backup filename; returns { device, created } or null.
  function parseBackupFilename(filename) {
    if (typeof filename !== 'string') return null;
    var m = /^ghostcorp-chat-backup-(phone|pc)-(\d{4}-\d{2}-\d{2})\.txt$/.exec(filename);
    if (!m || !isValidDateString(m[2])) return null;
    return { device: m[1], created: m[2] };
  }

  // Check-code (G2 §4): first 8 hex chars of the encryption fingerprint,
  // displayed XXXX-XXXX, uppercase. Fingerprints are public-key metadata.
  function formatCheckCode(fingerprintHex) {
    if (typeof fingerprintHex !== 'string' ||
        !/^[0-9a-fA-F]{64}$/.test(fingerprintHex)) {
      throw BackupError('BAD_FINGERPRINT',
        'Fingerprint must be 64 lowercase hex chars (SHA-256 of DER SPKI).');
    }
    var f = fingerprintHex.toLowerCase();
    return (f.slice(0, 4) + '-' + f.slice(4, 8)).toUpperCase();
  }

  function isValidCheckCode(s) {
    return typeof s === 'string' && /^[0-9A-F]{4}-[0-9A-F]{4}$/.test(s);
  }

  // Fingerprint = SHA-256 hex of the DER SPKI (FILE-MAP §3 / CRYPTO-DESIGN §9).
  async function fingerprintPublicKey(publicKey) {
    var der = await subtle().exportKey('spki', publicKey);
    var digest = await subtle().digest('SHA-256', der);
    return bytesToHex(new Uint8Array(digest));
  }

  // ---------------------------------------------------------------------------
  // §4. Passphrase rules (OWNER-JOIN §2 — builder decision, see header)
  // ---------------------------------------------------------------------------

  function validatePassphrase(passphrase) {
    if (typeof passphrase !== 'string') {
      throw BackupError('BAD_PASSPHRASE', COPY.passphrasePrompt);
    }
    var trimmed = passphrase.trim();
    if (trimmed.length < MIN_PASSPHRASE_CHARS) {
      throw BackupError('BAD_PASSPHRASE',
        'That phrase is too short. ' + COPY.passphrasePrompt);
    }
    var words = trimmed.split(/\s+/).filter(Boolean);
    if (words.length < MIN_PASSPHRASE_WORDS &&
        trimmed.replace(/\s+/g, '').length < MIN_SINGLE_TOKEN_CHARS) {
      throw BackupError('BAD_PASSPHRASE',
        'One word is not enough for a backup phrase. ' + COPY.passphrasePrompt);
    }
    return trimmed;
  }

  // ---------------------------------------------------------------------------
  // §5. Key derivation + AES-256-GCM wrap / unwrap (G2 §5)
  //
  // PBKDF2-SHA-256 (file's salt, file's iterations >= 600,000) -> 256-bit
  // AES-GCM key; AES-256-GCM with the file's 12-byte nonce. The GCM tag
  // is the last 16 bytes of the ciphertext (WebCrypto AES-GCM output
  // layout). G2 §5 defines NO additional authenticated data: encrypt and
  // decrypt pass no AAD, so a file written with AAD bound in will not
  // decrypt here, and a G2 file will not decrypt under an AAD reader.
  // ---------------------------------------------------------------------------

  // Derive the 256-bit AES-GCM backup key from the passphrase.
  // The passphrase bytes are zeroed by the caller after this returns.
  async function deriveBackupKey(passphraseBytes, salt, iterations) {
    var iters = iterations || PBKDF2_ITERATIONS;
    if (iters < PBKDF2_ITERATIONS) {
      throw BackupError('WEAK_KDF',
        'Backup KDF iterations (' + iters + ') are below the 600,000 minimum.');
    }
    var baseKey = await subtle().importKey(
      'raw', passphraseBytes, { name: 'PBKDF2' }, false, ['deriveKey']);
    return subtle().deriveKey(
      { name: 'PBKDF2', salt: salt, iterations: iters, hash: PBKDF2_HASH },
      baseKey,
      { name: 'AES-GCM', length: AES_KEY_BITS },
      false, ['encrypt', 'decrypt']);
  }

  // ---------------------------------------------------------------------------
  // §6. JWK import / export + public-key re-derivation
  //
  // The backup carries exactly two keys (G2 §6): the RSA-OAEP encryption
  // key and the signing key (Ed25519 primary, P-256 / ES256 fallback).
  //   RSA-OAEP (kty RSA)              -> encryption, usages ['decrypt']
  //   Ed25519  (kty OKP, crv Ed25519) -> signing, usages ['sign']
  //   P-256    (kty EC, crv P-256)    -> signing (ES256 fallback), ['sign']
  // ---------------------------------------------------------------------------

  function jwkAlgorithm(jwk) {
    if (!jwk || typeof jwk !== 'object') return null;
    if (jwk.kty === 'RSA') return { name: 'RSA-OAEP', hash: 'SHA-256' };
    if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') return { name: 'Ed25519' };
    if (jwk.kty === 'EC' && jwk.crv === 'P-256') {
      return { name: 'ECDSA', namedCurve: 'P-256' };
    }
    return null;
  }

  function jwkPurpose(jwk) {
    if (jwk.kty === 'RSA') return 'encryption';
    if (jwk.kty === 'OKP' || jwk.kty === 'EC') return 'signing';
    return null;
  }

  function jwkSigAlg(jwk) {
    if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') return 'Ed25519';
    if (jwk.kty === 'EC' && jwk.crv === 'P-256') return 'ES256';
    return null;
  }

  function jwkPrivateUsages(jwk) {
    if (jwk.kty === 'RSA') return ['decrypt'];
    return ['sign'];
  }

  // A private JWK must carry its private parameter, or it is not a backup
  // of a private key at all. (A public-only JWK here is a corrupt backup,
  // not a usable restore — reject, never silently store a public key as
  // if it were the owner's identity.)
  function assertPrivateJwk(jwk) {
    if (!jwk || typeof jwk !== 'object' || typeof jwk.kty !== 'string' ||
        typeof jwk.d !== 'string' || jwk.d.length === 0) {
      throw BackupError('BAD_KEY',
        'Backup entry is not a private key (JWK has no "d" parameter).');
    }
    if (!jwkAlgorithm(jwk)) {
      throw BackupError('UNSUPPORTED_KEY',
        'Backup key type is not supported (want RSA-OAEP, Ed25519 or P-256).');
    }
  }

  // Re-derive the PUBLIC JWK from a private JWK (public parts are embedded
  // in every private JWK: RSA n/e, OKP x, EC x/y). Used by the mandatory
  // test-restore to prove the restored key is the same key.
  function publicJwkFromPrivateJwk(jwk) {
    assertPrivateJwk(jwk);
    if (jwk.kty === 'RSA') {
      return { kty: 'RSA', n: jwk.n, e: jwk.e };
    }
    if (jwk.kty === 'OKP') {
      return { kty: 'OKP', crv: jwk.crv, x: jwk.x };
    }
    // EC P-256
    return { kty: 'EC', crv: jwk.crv, x: jwk.x, y: jwk.y };
  }

  async function importPrivateJwk(jwk) {
    assertPrivateJwk(jwk);
    var alg = jwkAlgorithm(jwk);
    return subtle().importKey('jwk', jwk, alg, false, jwkPrivateUsages(jwk));
  }

  async function importPublicJwk(jwk) {
    var alg = jwkAlgorithm(jwk);
    if (!alg) {
      throw BackupError('UNSUPPORTED_KEY',
        'Public key type is not supported (want RSA-OAEP, Ed25519 or P-256).');
    }
    var usages = (jwk.kty === 'RSA') ? ['encrypt'] : ['verify'];
    return subtle().importKey('jwk', jwk, alg, true, usages);
  }

  // Fingerprint of the public key re-derived from a private JWK.
  async function fingerprintOfPrivateJwk(jwk) {
    var pubJwk = publicJwkFromPrivateJwk(jwk);
    var pubKey = await importPublicJwk(pubJwk);
    return fingerprintPublicKey(pubKey);
  }

  // ---------------------------------------------------------------------------
  // §7. Backup file format (G2 §3/§4 — normative)
  //
  // Text file, LF line endings, exactly:
  //
  //   Line 1: GHOSTCORP-CHAT-BACKUP v1
  //   Line 2: <one JSON object, single line>
  //   (final newline)
  //
  // The JSON object has exactly the 13 fields of OUTER_FIELDS:
  //   { "v": 1, "participant": "owner", "device": "phone",
  //     "created": "YYYY-MM-DD", "sig_alg": "Ed25519",
  //     "enc_fingerprint": "<64 hex>", "sig_fingerprint": "<64 hex>",
  //     "check_code": "XXXX-XXXX", "kdf": "PBKDF2-SHA-256",
  //     "iterations": 600000, "salt": "<base64url, 16 bytes>",
  //     "nonce": "<base64url, 12 bytes>",
  //     "ciphertext": "<base64url, AES-256-GCM of the inner bundle>" }
  // Inner bundle (the GCM plaintext — JWKs live ONLY here, encrypted):
  //   { "encryption": <RSA-OAEP private JWK>,
  //     "signing": <Ed25519 (or P-256) private JWK> }
  // ---------------------------------------------------------------------------

  function buildFileText(outer) {
    var json = JSON.stringify(outer);
    return BACKUP_FORMAT + '\n' + json + '\n';
  }

  // Strict parse (G2 §3): fail closed, no partial restore. Returns
  // { header, outer } — outer is the decoded JSON object; NOTHING here
  // decrypts anything.
  // expectedFilename (optional): when given, the device and date in the
  // filename must match the device and created fields inside the file
  // (G2 §2 filename/device binding).
  function parseBackupText(fileText, expectedFilename) {
    if (typeof fileText !== 'string' || fileText.length === 0) {
      throw BackupError('BAD_FORMAT', 'Backup file is empty.');
    }
    if (textToBytes(fileText).length > MAX_FILE_BYTES) {
      throw BackupError('BAD_FORMAT',
        'Backup file is larger than 64 KiB — rejected as malformed.');
    }
    if (fileText.charCodeAt(0) === 0xFEFF) {
      throw BackupError('BAD_FORMAT',
        'Backup file starts with a byte-order mark — rejected as malformed.');
    }
    var lines = fileText.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
    // Exactly header + one JSON line + final newline: 3 parts, last empty.
    if (lines.length !== 3 || lines[2] !== '') {
      throw BackupError('BAD_FORMAT',
        'Backup file must be exactly two lines — the "GHOSTCORP-CHAT-BACKUP v1" ' +
        'header and one JSON line — followed by a final newline. Extra lines, ' +
        'missing lines, or trailing content are rejected.');
    }
    if (lines[0] !== BACKUP_FORMAT) {
      throw BackupError('BAD_FORMAT',
        'Not a GhostCorp chat backup (first line must be "' + BACKUP_FORMAT + '").');
    }
    var outer;
    try {
      outer = JSON.parse(lines[1]);
    } catch (e) {
      throw BackupError('BAD_FORMAT', 'Backup line 2 is not valid JSON.');
    }
    if (!outer || typeof outer !== 'object' || Array.isArray(outer)) {
      throw BackupError('BAD_FORMAT', 'Backup line 2 is not a JSON object.');
    }
    // Exactly the 13 G2 fields: unknown fields reject, missing fields reject.
    var keys = Object.keys(outer);
    for (var i = 0; i < keys.length; i++) {
      if (OUTER_FIELDS.indexOf(keys[i]) === -1) {
        throw BackupError('BAD_FORMAT',
          'Backup has an unknown top-level field: "' + keys[i] + '".');
      }
    }
    for (var j = 0; j < OUTER_FIELDS.length; j++) {
      if (!(OUTER_FIELDS[j] in outer)) {
        throw BackupError('BAD_FORMAT',
          'Backup is missing required field: "' + OUTER_FIELDS[j] + '".');
      }
    }
    if (outer.v !== 1) {
      throw BackupError('BAD_FORMAT',
        'Backup version is not 1 (v=' + JSON.stringify(outer.v) + ').');
    }
    if (outer.participant !== 'owner') {
      throw BackupError('BAD_FORMAT',
        'Backup participant must be "owner".');
    }
    if (outer.device !== 'phone' && outer.device !== 'pc') {
      throw BackupError('BAD_FORMAT',
        'Backup device must be "phone" or "pc".');
    }
    if (!isValidDateString(outer.created)) {
      throw BackupError('BAD_FORMAT',
        'Backup created date must be YYYY-MM-DD.');
    }
    if (outer.sig_alg !== 'Ed25519' && outer.sig_alg !== 'ES256') {
      throw BackupError('BAD_FORMAT',
        'Backup sig_alg must be "Ed25519" or "ES256".');
    }
    if (typeof outer.enc_fingerprint !== 'string' ||
        !/^[0-9a-f]{64}$/.test(outer.enc_fingerprint)) {
      throw BackupError('BAD_FORMAT',
        'Backup enc_fingerprint must be 64 lowercase hex chars.');
    }
    if (typeof outer.sig_fingerprint !== 'string' ||
        !/^[0-9a-f]{64}$/.test(outer.sig_fingerprint)) {
      throw BackupError('BAD_FORMAT',
        'Backup sig_fingerprint must be 64 lowercase hex chars.');
    }
    if (!isValidCheckCode(outer.check_code)) {
      throw BackupError('BAD_FORMAT',
        'Backup check_code must look like XXXX-XXXX (uppercase hex).');
    }
    if (formatCheckCode(outer.enc_fingerprint) !== outer.check_code) {
      throw BackupError('BAD_FORMAT',
        'Backup check_code does not match enc_fingerprint.');
    }
    if (outer.kdf !== KDF_NAME) {
      throw BackupError('BAD_FORMAT',
        'Backup kdf must be "' + KDF_NAME + '".');
    }
    if (typeof outer.iterations !== 'number' ||
        Math.floor(outer.iterations) !== outer.iterations ||
        outer.iterations < PBKDF2_ITERATIONS) {
      throw BackupError('WEAK_KDF',
        'Backup KDF iterations (' + outer.iterations + ') are below the 600,000 minimum.');
    }
    // salt / nonce / ciphertext must be canonical base64url of the right
    // sizes (ciphertext at least 17 bytes: 1 byte of plaintext + 16 tag).
    var salt;
    var nonce;
    var ciphertext;
    try {
      salt = base64urlToBytes(outer.salt);
      nonce = base64urlToBytes(outer.nonce);
      ciphertext = base64urlToBytes(outer.ciphertext);
    } catch (e) {
      if (e && e.code) throw e;
      throw BackupError('BAD_FORMAT',
        'Backup salt, nonce or ciphertext is not valid base64url.');
    }
    if (salt.length !== SALT_BYTES) {
      throw BackupError('BAD_FORMAT', 'Backup salt must be 16 bytes.');
    }
    if (nonce.length !== NONCE_BYTES) {
      throw BackupError('BAD_FORMAT', 'Backup nonce must be 12 bytes.');
    }
    if (ciphertext.length < 17) {
      throw BackupError('BAD_FORMAT',
        'Backup ciphertext is too short to hold a GCM tag.');
    }
    // Filename/device/date binding (G2 §2).
    if (typeof expectedFilename === 'string' && expectedFilename !== '') {
      var fn = parseBackupFilename(expectedFilename);
      if (!fn) {
        throw BackupError('BAD_FORMAT',
          'Backup filename must look like ghostcorp-chat-backup-<phone|pc>-<YYYY-MM-DD>.txt.');
      }
      if (fn.device !== outer.device) {
        throw BackupError('BAD_FORMAT',
          'Backup filename device "' + fn.device + '" does not match the device ' +
          'inside the file ("' + outer.device + '").');
      }
      if (fn.created !== outer.created) {
        throw BackupError('BAD_FORMAT',
          'Backup filename date "' + fn.created + '" does not match the created ' +
          'date inside the file ("' + outer.created + '").');
      }
    }

    return {
      header: {
        participant: outer.participant,
        device: outer.device,
        created: outer.created,
        sigAlg: outer.sig_alg,
        encFingerprint: outer.enc_fingerprint,
        sigFingerprint: outer.sig_fingerprint,
        checkCode: outer.check_code,
        kdf: outer.kdf,
        iterations: outer.iterations
      },
      outer: outer
    };
  }

  // ---------------------------------------------------------------------------
  // §8. Decrypt + import (shared by restore and by the mandatory test-restore)
  //
  // Order (fail-closed, nothing stored until EVERY check passes):
  //   1. parse + shape checks (§7, incl. filename binding when a
  //      filename is given)
  //   2. PBKDF2 derive + AES-256-GCM decrypt with NO additional data
  //      (G2 §5). Auth failure = wrong passphrase OR tampered file —
  //      indistinguishable by design, and reported in the owner's words
  //      from G2 §7 step 4.
  //   3. inner bundle shape checks: exactly {encryption, signing},
  //      both private JWKs, encryption RSA, signing matching sig_alg
  //   4. import each private JWK, re-derive its public key, compare the
  //      fingerprint against the outer object (and against
  //      options.expectedFingerprints when given)
  //   5. ONLY then store (unless options.storeKeys === false, the
  //      dry-run / test-restore path)
  // ---------------------------------------------------------------------------

  async function decryptAndImport(fileText, passphrase, options) {
    var opts = options || {};
    var parsed = parseBackupText(fileText, opts.filename || null);
    var outer = parsed.outer;

    var pw = validatePassphrase(passphrase);
    var pwBytes = textToBytes(pw);
    var salt = base64urlToBytes(outer.salt);
    var nonce = base64urlToBytes(outer.nonce);
    var ciphertext = base64urlToBytes(outer.ciphertext);

    var aesKey;
    var plainBytes;
    try {
      aesKey = await deriveBackupKey(pwBytes, salt, outer.iterations);
      plainBytes = new Uint8Array(await subtle().decrypt(
        { name: 'AES-GCM', iv: nonce },
        aesKey, ciphertext));
    } catch (e) {
      // GCM auth failure: wrong passphrase or a tampered file. The two
      // cannot be told apart; the owner-facing words cover the common
      // case (G2 §7 step 4) and the code names both.
      throw BackupError('DECRYPT_FAILED',
        COPY.wrongPassphrase + ' (Or the file was changed — a backup that ' +
        'does not decrypt is never trusted.)');
    } finally {
      pwBytes.fill(0);
    }

    var inner;
    try {
      inner = JSON.parse(bytesToText(plainBytes));
    } catch (e) {
      throw BackupError('BAD_FORMAT', 'Backup decrypted, but its contents are not valid JSON.');
    } finally {
      plainBytes.fill(0);
    }

    if (!inner || typeof inner !== 'object' || Array.isArray(inner)) {
      throw BackupError('BAD_FORMAT', 'Backup contents are not a JSON object.');
    }
    var innerKeys = Object.keys(inner).sort();
    if (innerKeys.length !== 2 || innerKeys[0] !== 'encryption' ||
        innerKeys[1] !== 'signing') {
      throw BackupError('BAD_FORMAT',
        'Backup contents must hold exactly the "encryption" and "signing" keys, nothing else.');
    }
    if (!inner.encryption || typeof inner.encryption !== 'object' ||
        inner.encryption.kty !== 'RSA') {
      throw BackupError('BAD_FORMAT',
        'Backup "encryption" key is not an RSA-OAEP private JWK.');
    }
    if (!inner.signing || typeof inner.signing !== 'object' ||
        (inner.signing.kty !== 'OKP' && inner.signing.kty !== 'EC')) {
      throw BackupError('BAD_FORMAT',
        'Backup "signing" key is not an Ed25519 or P-256 private JWK.');
    }
    var signingAlg = jwkSigAlg(inner.signing);
    if (!signingAlg || signingAlg !== outer.sig_alg) {
      throw BackupError('BAD_FORMAT',
        'Backup signing key type does not match the file\'s sig_alg ("' +
        outer.sig_alg + '").');
    }

    // Import both keys and re-derive + compare both fingerprints BEFORE
    // storing anything.
    var imported = [];
    var roles = ['encryption', 'signing'];
    for (var i = 0; i < roles.length; i++) {
      var role = roles[i];
      var jwk = inner[role];
      var privateKey;
      try {
        privateKey = await importPrivateJwk(jwk);
      } catch (e) {
        if (e && e.code) throw e;
        throw BackupError('BAD_KEY',
          'Backup "' + role + '" key could not be imported: ' + e.message);
      }
      var fingerprint = await fingerprintOfPrivateJwk(jwk);
      var expectedFp = (role === 'encryption')
        ? outer.enc_fingerprint : outer.sig_fingerprint;
      if (fingerprint !== expectedFp) {
        throw BackupError('FINGERPRINT_MISMATCH',
          'Restored "' + role + '" key does not match the fingerprint ' +
          'in the backup — the backup is refused, nothing was stored.');
      }
      if (opts.expectedFingerprints &&
          opts.expectedFingerprints[role] &&
          fingerprint !== opts.expectedFingerprints[role]) {
        throw BackupError('FINGERPRINT_MISMATCH',
          'Restored "' + role + '" key does not match the expected ' +
          'fingerprint — the backup is refused, nothing was stored.');
      }
      if (opts.expectedSigAlg && role === 'signing' &&
          signingAlg !== opts.expectedSigAlg) {
        throw BackupError('FINGERPRINT_MISMATCH',
          'Restored signing key algorithm "' + signingAlg + '" does not match ' +
          'the expected "' + opts.expectedSigAlg + '" — the backup is refused.');
      }
      // Public key handle for the keys-store record (re-derived, never
      // trusted from the file's stored copy alone — it was just proven
      // to match the fingerprint above).
      var publicKey = await importPublicJwk(publicJwkFromPrivateJwk(jwk));
      imported.push({
        key_id: 'owner-' + (role === 'encryption' ? 'enc' : 'sign') + '-' + outer.device,
        participant: outer.participant,
        device: outer.device,
        purpose: role,
        algorithm: role === 'encryption' ? 'RSA-OAEP-SHA256' : signingAlg,
        publicKey: publicKey,
        privateKey: privateKey,
        fingerprint: fingerprint,
        checkCode: formatCheckCode(fingerprint),
        created: outer.created
      });
    }

    var fingerprints = {};
    var checkCodes = {};
    imported.forEach(function (r) {
      fingerprints[r.purpose] = r.fingerprint;
      checkCodes[r.purpose] = r.checkCode;
    });

    var result = {
      participant: outer.participant,
      device: outer.device,
      created: outer.created,
      sigAlg: outer.sig_alg,
      keyIds: ['encryption', 'signing'],
      fingerprints: fingerprints,
      checkCodes: checkCodes,
      checkCode: checkCodes.encryption,
      encFingerprint: fingerprints.encryption,
      sigFingerprint: fingerprints.signing,
      needsFreshBackup: true
    };

    if (opts.storeKeys === false) {
      return { result: result, imported: imported };
    }

    // Store via C17 (or the provisional fallback). All-or-nothing intent:
    // every key was already verified above, so a mid-store failure is a
    // storage failure, not a bad backup — report it as such.
    var store = resolveKeysStore(opts);
    try {
      for (var s = 0; s < imported.length; s++) {
        var rec = imported[s];
        await store.putKey({
          key_id: rec.key_id,
          participant: rec.participant,
          device: rec.device,
          purpose: rec.purpose,
          algorithm: rec.algorithm,
          publicKey: rec.publicKey,
          privateKey: rec.privateKey,
          fingerprint: rec.fingerprint,
          created: rec.created,
          updated: new Date().toISOString()
        });
      }
    } catch (e) {
      throw BackupError('STORAGE_FAILED',
        'Keys decrypted and verified, but saving them failed: ' + e.message +
        ' — no key was trusted; try the restore again.');
    }
    return { result: result, imported: imported };
  }

  // ---------------------------------------------------------------------------
  // §9. Keys-store resolution (C17 adapter, else provisional IndexedDB)
  // ---------------------------------------------------------------------------

  function resolveKeysStore(options) {
    var opts = options || {};
    if (opts.keysStore && typeof opts.keysStore.putKey === 'function') {
      return opts.keysStore;
    }
    if (typeof root !== 'undefined' && root.GhostChatKeysStore &&
        typeof root.GhostChatKeysStore.putKey === 'function') {
      return root.GhostChatKeysStore;
    }
    // Provisional fallback — see header. Browser-only (no IndexedDB in Node).
    if (typeof indexedDB === 'undefined') {
      throw BackupError('STORAGE_UNAVAILABLE',
        'No keys store is available: pass options.keysStore (app/keys-store.js, C17).');
    }
    return { putKey: fallbackPutKey };
  }

  function fallbackOpenDb() {
    return new Promise(function (resolve, reject) {
      var req = indexedDB.open(FALLBACK_DB_NAME, FALLBACK_DB_VERSION);
      req.onupgradeneeded = function () {
        if (!req.result.objectStoreNames.contains(FALLBACK_STORE_NAME)) {
          req.result.createObjectStore(FALLBACK_STORE_NAME, { keyPath: 'key_id' });
        }
      };
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () { reject(req.error || new Error('IndexedDB open failed')); };
    });
  }

  function fallbackPutKey(record) {
    return fallbackOpenDb().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(FALLBACK_STORE_NAME, 'readwrite');
        tx.objectStore(FALLBACK_STORE_NAME).put(record);
        tx.oncomplete = function () { db.close(); resolve(); };
        tx.onerror = function () {
          db.close();
          reject(tx.error || new Error('IndexedDB put failed'));
        };
      });
    });
  }

  // ---------------------------------------------------------------------------
  // §10. Public API
  // ---------------------------------------------------------------------------

  // Create a backup file for one device's keys.
  //
  // keys: array of EXACTLY 2 entries (G2 §6), one per purpose:
  //   { purpose: 'encryption'|'signing',
  //     algorithm?: string (e.g. 'RSA-OAEP-SHA256', 'Ed25519', 'ES256'),
  //     privateKey: CryptoKey (extractable), publicKey: CryptoKey,
  //     fingerprint?: <64-hex, else computed from publicKey> }
  //   — or, for tests only, { privateJwk, publicJwk } in place of the
  //     CryptoKey pair. Production callers pass CryptoKeys.
  // device: 'phone' | 'pc'.
  // passphrase: the owner's backup phrase (validated, never stored).
  // options: { owner?: string (accepted for call compatibility; the file
  //   always records participant "owner" per G2 §4), created?: 'YYYY-MM-DD' }
  //
  // Returns { fileText, filename, participant, device, created, sigAlg,
  //   encFingerprint, sigFingerprint, checkCode, keyIds,
  //   fingerprints, checkCodes, verified: true }.
  // verified:true means the MANDATORY test-restore already passed inside
  // this call (decrypt with the same passphrase, re-derive each public
  // key, compare every fingerprint). Join must not complete on a backup
  // that was not verified this way.
  async function createBackup(keys, device, passphrase, options) {
    var opts = options || {};
    var participant = 'owner'; // G2 §4: participant is exactly "owner".
    validateDevice(device);
    var created = opts.created || todayDateString();
    if (!isValidDateString(created)) {
      throw BackupError('BAD_DATE', 'Created date must be YYYY-MM-DD.');
    }
    if (!Array.isArray(keys) || keys.length !== 2) {
      throw BackupError('BAD_KEYS',
        'Backup needs exactly 2 keys: one "encryption" and one "signing" (G2 §6).');
    }
    var pw = validatePassphrase(passphrase);

    // Export each private key as JWK + compute its fingerprint.
    // A non-extractable key throws here BY DESIGN (crypto-core A1):
    // only keys generated extractable for backup can be backed up.
    var encJwk = null;
    var sigJwk = null;
    var encFingerprint = null;
    var sigFingerprint = null;
    var sigAlg = null;
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i] || {};
      if (k.purpose !== 'encryption' && k.purpose !== 'signing') {
        throw BackupError('BAD_KEYS',
          'Each backup key needs purpose "encryption" or "signing".');
      }
      if ((k.purpose === 'encryption' && encJwk) ||
          (k.purpose === 'signing' && sigJwk)) {
        throw BackupError('BAD_KEYS',
          'Duplicate "' + k.purpose + '" key in backup — exactly one of each.');
      }
      var privateJwk;
      if (k.privateJwk) {
        privateJwk = k.privateJwk; // test-only path (throwaway keys)
      } else if (k.privateKey) {
        try {
          privateJwk = await subtle().exportKey('jwk', k.privateKey);
        } catch (e) {
          throw BackupError('KEY_NOT_EXTRACTABLE', COPY.keyNotExtractable);
        }
      } else {
        throw BackupError('BAD_KEYS',
          'Backup key "' + k.purpose + '" has no privateKey or privateJwk.');
      }
      assertPrivateJwk(privateJwk);
      if (jwkPurpose(privateJwk) !== k.purpose) {
        throw BackupError('BAD_KEYS',
          'Backup key purpose "' + k.purpose + '" does not match its JWK type.');
      }
      var fingerprint;
      if (k.publicKey) {
        fingerprint = await fingerprintPublicKey(k.publicKey);
      } else if (k.publicJwk) {
        var pubKey = await importPublicJwk(k.publicJwk);
        fingerprint = await fingerprintPublicKey(pubKey);
      } else if (typeof k.fingerprint === 'string' &&
          /^[0-9a-f]{64}$/.test(k.fingerprint)) {
        fingerprint = k.fingerprint;
      } else {
        // Last resort: re-derive the public key from the private JWK.
        fingerprint = await fingerprintOfPrivateJwk(privateJwk);
      }
      // Cross-check: the fingerprint from the public key must equal the
      // one re-derived from the private JWK, or the pair does not match.
      var derivedFp = await fingerprintOfPrivateJwk(privateJwk);
      if (derivedFp !== fingerprint) {
        throw BackupError('FINGERPRINT_MISMATCH',
          'Backup key "' + k.purpose + '": public key does not match the private key.');
      }
      if (k.purpose === 'encryption') {
        encJwk = privateJwk;
        encFingerprint = fingerprint;
      } else {
        sigJwk = privateJwk;
        sigFingerprint = fingerprint;
        sigAlg = jwkSigAlg(privateJwk);
        if (!sigAlg) {
          throw BackupError('UNSUPPORTED_KEY',
            'Backup signing key must be Ed25519 or P-256 (got kty ' +
            privateJwk.kty + ', crv ' + privateJwk.crv + ').');
        }
      }
    }
    if (!encJwk || !sigJwk) {
      throw BackupError('BAD_KEYS',
        'Backup needs exactly one "encryption" and one "signing" key (G2 §6).');
    }

    // Encrypt the inner bundle (JWKs live ONLY here, under AES-256-GCM,
    // no additional data — G2 §5/§6).
    var inner = {
      encryption: encJwk,
      signing: sigJwk
    };
    var salt = getRandomValues(new Uint8Array(SALT_BYTES));
    var nonce = getRandomValues(new Uint8Array(NONCE_BYTES));
    var pwBytes = textToBytes(pw);
    var aesKey;
    var ciphertext;
    try {
      aesKey = await deriveBackupKey(pwBytes, salt, PBKDF2_ITERATIONS);
      ciphertext = new Uint8Array(await subtle().encrypt(
        { name: 'AES-GCM', iv: nonce },
        aesKey, textToBytes(JSON.stringify(inner))));
    } finally {
      pwBytes.fill(0);
    }

    // Outer JSON object: exactly the 13 G2 §4 fields (public metadata —
    // fingerprints / check-code / KDF parameters identify the keys, they
    // cannot unlock them).
    var outer = {
      "v": 1,
      "participant": participant,
      "device": device,
      "created": created,
      "sig_alg": sigAlg,
      "enc_fingerprint": encFingerprint,
      "sig_fingerprint": sigFingerprint,
      "check_code": formatCheckCode(encFingerprint),
      "kdf": KDF_NAME,
      "iterations": PBKDF2_ITERATIONS,
      "salt": bytesToBase64url(salt),
      "nonce": bytesToBase64url(nonce),
      "ciphertext": bytesToBase64url(ciphertext)
    };

    var fileText = buildFileText(outer);
    var filename = backupFilename(device, created);

    // MANDATORY test-restore (FILE-MAP C11 / G2 §7): decrypt the file
    // just built with the same passphrase, re-derive each public key,
    // compare every fingerprint — before Join completes. A backup that
    // fails its own test-restore is never handed to the owner.
    try {
      await decryptAndImport(fileText, pw, {
        storeKeys: false,
        filename: filename,
        expectedFingerprints: {
          encryption: encFingerprint,
          signing: sigFingerprint
        },
        expectedSigAlg: sigAlg
      });
    } catch (e) {
      throw BackupError('BACKUP_SELF_TEST_FAILED',
        'Backup was created but its mandatory test-restore failed (' +
        (e.code || 'UNKNOWN') + ': ' + e.message + '). The backup was NOT saved.');
    }

    return {
      fileText: fileText,
      filename: filename,
      participant: participant,
      device: device,
      created: created,
      sigAlg: sigAlg,
      encFingerprint: encFingerprint,
      sigFingerprint: sigFingerprint,
      checkCode: formatCheckCode(encFingerprint),
      keyIds: ['encryption', 'signing'],
      fingerprints: { encryption: encFingerprint, signing: sigFingerprint },
      checkCodes: {
        encryption: formatCheckCode(encFingerprint),
        signing: formatCheckCode(sigFingerprint)
      },
      verified: true
    };
  }

  // Restore a backup file: decrypt with the passphrase, verify every
  // fingerprint, then import the keys into IndexedDB via C17.
  // options: { filename?: string (checked against the device/date inside
  //   the file, G2 §2), expectedFingerprints?: { encryption, signing },
  //   expectedSigAlg?: 'Ed25519'|'ES256', keysStore?, storeKeys?: false }
  // Returns { participant, device, created, sigAlg, keyIds, fingerprints,
  //   checkCodes, checkCode, encFingerprint, sigFingerprint,
  //   needsFreshBackup: true }.
  // After a restore the app must prompt for a FRESH backup from the
  // restored device (G2 §7 step 5) — needsFreshBackup says so.
  // Wrong passphrase -> BackupError code DECRYPT_FAILED, owner wording.
  async function restoreBackup(fileText, passphrase, options) {
    var out = await decryptAndImport(fileText, passphrase, options);
    return out.result;
  }

  // Verify a backup WITHOUT storing anything (dry-run restore).
  // Use for "check this file" UI and for tests. Returns the same
  // metadata shape as restoreBackup, minus needsFreshBackup.
  // options: { filename?, expectedFingerprints?, expectedSigAlg? }
  async function verifyBackupText(fileText, passphrase, options) {
    var opts = options || {};
    opts.storeKeys = false;
    var out = await decryptAndImport(fileText, passphrase, opts);
    var r = out.result;
    delete r.needsFreshBackup;
    return r;
  }

  // Download the backup file in the browser (Blob + temporary link).
  // The file is offered as a download to phone Files / PC — never pasted
  // into chat, Notion, email or a screenshot (see COPY.storageWarning).
  function downloadBackup(fileText, filename) {
    if (typeof document === 'undefined' || typeof Blob === 'undefined' ||
        typeof URL === 'undefined' || !URL.createObjectURL) {
      throw BackupError('NO_DOWNLOAD',
        'Download is unavailable here — copy the backup text to a file yourself, ' +
        'and never paste it into chat, Notion or email.');
    }
    var blob = new Blob([fileText], { type: 'text/plain;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    return filename;
  }

  // Print the backup (paper copy at home, G2 §8 option 2).
  // The printed file never carries the passphrase — the file does not
  // contain it, and this function must never be passed it.
  function printBackup(fileText) {
    if (typeof window === 'undefined' || typeof window.open !== 'function') {
      throw BackupError('NO_PRINT', 'Printing is unavailable here.');
    }
    var w = window.open('', '_blank');
    if (!w) {
      throw BackupError('NO_PRINT',
        'The browser blocked the print window — allow pop-ups for this page and try again.');
    }
    var esc = fileText
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    w.document.write(
      '<!doctype html><html><head><meta charset="utf-8"><title>GhostCorp chat backup</title>' +
      '<style>body{font:14px monospace;white-space:pre-wrap;word-break:break-all}</style>' +
      '</head><body>' + esc +
      '<p><strong>Keep this paper somewhere only you can reach. ' +
      'Never write your backup phrase on it.</strong></p>' +
      '</body></html>');
    w.document.close();
    w.focus();
    w.print();
    return true;
  }

  return {
    // Format constants
    BACKUP_FORMAT: BACKUP_FORMAT,
    BACKUP_FORMAT_VERSION: BACKUP_FORMAT_VERSION,
    PBKDF2_ITERATIONS: PBKDF2_ITERATIONS,
    SALT_BYTES: SALT_BYTES,
    NONCE_BYTES: NONCE_BYTES,
    IV_BYTES: NONCE_BYTES, // legacy alias: the G2 field is "nonce"
    COPY: COPY,

    // Core flows
    createBackup: createBackup,
    restoreBackup: restoreBackup,
    verifyBackupText: verifyBackupText,

    // Parsing / validation (also used by tests and by the Join gate)
    parseBackupText: parseBackupText,
    validatePassphrase: validatePassphrase,
    backupFilename: backupFilename,
    parseBackupFilename: parseBackupFilename,
    formatCheckCode: formatCheckCode,
    fingerprintPublicKey: fingerprintPublicKey,

    // Device delivery
    downloadBackup: downloadBackup,
    printBackup: printBackup,

    // Error type (check e.code: BAD_FORMAT | DECRYPT_FAILED |
    // BAD_PASSPHRASE | KEY_NOT_EXTRACTABLE | FINGERPRINT_MISMATCH |
    // BACKUP_SELF_TEST_FAILED | STORAGE_FAILED | STORAGE_UNAVAILABLE |
    // WEAK_KDF | UNSUPPORTED_KEY | BAD_KEY | BAD_ENCODING | NO_WEBCRYPTO |
    // BAD_DEVICE | BAD_DATE | BAD_KEYS)
    BackupError: BackupError
  };
});
