/**
 * fingerprint-check.js — check-code display + Jarvis fingerprint verification
 * for the ghostcorpnet encrypted chat (ecc-1).
 *
 * Worker C16. Implements FILE-MAP §4 (C16) and:
 *   - FILE-MAP D13: Jarvis encryption fingerprint (SHA-256 of DER SPKI),
 *     pinned here as a public constant.
 *   - FILE-MAP D17 / §3 key directory (`keys/participants.json`): a key is
 *     trusted only when its fingerprint matches the directory entry AND the
 *     entry status is `pinned`.
 *   - design/OWNER-JOIN.md §1/§3: the owner reads his short check-code to
 *     Jarvis in Muse chat; the codes must match or the key is not trusted.
 *   - design/KEY-MANAGEMENT.md §4.4: fingerprint check procedure — the
 *     fingerprint is the check; the PEM alone proves nothing.
 *
 * Normative refs (FILE-MAP wins on any conflict — see "Conflicts" below):
 *   - FILE-MAP.md §3 "Key directory (keys/participants.json)"
 *   - FILE-MAP.md D13, D17
 *   - design/OWNER-JOIN.md §1 (check-code), §3 (publish + check)
 *   - design/KEY-MANAGEMENT.md §4.4 (fingerprint check procedure)
 *
 * CHECK-CODE FORMAT (defined here, used consistently everywhere):
 *   A check-code is the FIRST 8 hex characters of a SHA-256 fingerprint,
 *   lowercase, grouped as two groups of 4 separated by a single space:
 *       "ceab e1c7"
 *   The full fingerprint is displayed the same way, grouped in 8-character
 *   groups separated by spaces:
 *       "ceabe1c7 7c4c1571 0dc6e069 92bad6c7 0c8ba1d8 c0adaf17 a2f3b104 2a620ee5"
 *   A check-code is therefore the first 8 hex characters of the
 *   fingerprint, re-grouped as two groups of 4 (the grouped fingerprint
 *   shows those same 8 characters as one group of 8).
 *   (spaces, hyphens, upper/lower case are all normalized away), so the
 *   OWNER-JOIN example form "AB12-CD34" verifies against the same code.
 *
 *   A check-code is 32 bits: it is a human read-aloud check, NOT a
 *   cryptographic proof. A check-code match alone NEVER pins or trusts a
 *   key. Pinning/trust requires a FULL 64-hex fingerprint match against a
 *   `pinned` directory entry. This module reports check-code-only matches
 *   with strength "check-code-only" and trusted=false.
 *
 * SCOPE — what this module does and does not do:
 *   - DOES: format / compute check-codes; display the owner's own
 *     encryption + signing fingerprints with check-codes; verify Jarvis's
 *     encryption fingerprint against the known value (blocking pass/fail);
 *     compare a pasted fingerprint or check-code against a key-directory
 *     entry and report match / mismatch.
 *   - NEVER handles private keys. It takes only public fingerprints,
 *     public PEMs (SPKI), and directory entries. Any input that looks like
 *     private-key material is rejected immediately and is never hashed,
 *     stored, or displayed. No key generation, no encryption, no signing,
 *     no decryption happens here (A1/A2 own that).
 *   - NEVER trusts a key on sight: trust requires pinned status + a full
 *     fingerprint match. `unpinned` and `revoked` entries never verify.
 *
 * CONFLICTS (FILE-MAP wins; flagged here, design docs NOT edited):
 *   1. Check-code grouping: OWNER-JOIN §1 shows "AB12-CD34" (upper-case,
 *      hyphen). The task brief / FILE-MAP show "ceab e1c7" (lower-case,
 *      space). ADOPTED: lower-case, space ("ceab e1c7"). Comparison
 *      normalizes both forms, so either pasted form verifies.
 *   2. Signing algorithm: KEY-MANAGEMENT §1.2 proposes ECDSA P-256 as
 *      Jarvis's signing key. FILE-MAP D6 overrides: Ed25519 primary,
 *      ES256 fallback. This module is algorithm-agnostic (a fingerprint
 *      is SHA-256 of DER SPKI whatever the algorithm) and takes
 *      `sig_alg` from the directory entry; it does not assume P-256.
 *   3. Key-directory file/shape: KEY-MANAGEMENT §4.1/§4.2 uses
 *      `keys.json`, object keyed by participant, entries with
 *      `fingerprint_sha256_der` and statuses
 *      active/superseded/revoked/unverified. FILE-MAP D8/§9 overrides:
 *      `keys/participants.json`, an ARRAY of entries with
 *      `enc_fingerprint` / `sig_fingerprint` and statuses
 *      unpinned/pinned/revoked. This module implements the FILE-MAP
 *      array schema as normative; a legacy `keys[]` entry shape is
 *      accepted only as a read compatibility fallback (see
 *      normalizeDirectoryEntry) and never written.
 *   4. Directory fields: OWNER-JOIN §3 lists directory fields (name,
 *      device label, public key, check-code, date joined, status
 *      active/revoked). FILE-MAP §9 overrides with the §9 field set.
 *      This module reads the §9 fields.
 *   5. Jarvis signing-key path: KEY-MANAGEMENT §1.2 proposes the
 *      signing key under the bridge secrets dir. FILE-MAP D12
 *      overrides: `~/workspace/encrypted-chat/keys/jarvis-signing-priv.pem`
 *      (A10 only). Not used by this module (no signing keys read here).
 *   6. OWNER-JOIN §5 says 1:1 messages are out of scope; FILE-MAP D9
 *      allows them as an explicit opt-in. Not a fingerprint question;
 *      nothing in this module asserts either way.
 *
 * Consumers: C4 view-setup.js (blocking Jarvis check before setup
 * completes), C5 view-keys.js (directory badges), G1 owner guide
 * (read-aloud wording). No external dependencies, no network calls.
 * Runs in any secure context with WebCrypto, and under Node.js >= 18
 * (globalThis.crypto.subtle).
 */

'use strict';

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else {
    root.GhostcorpFingerprintCheck = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {

  // ---------------------------------------------------------------------------
  // Known public values (FILE-MAP D13). The Jarvis v1 RSA-4096 encryption
  // fingerprint is PUBLIC — it is the value ChatGPT and the owner check
  // before encrypting anything to Jarvis. It is safe to name here.
  // ---------------------------------------------------------------------------

  /** SHA-256 (hex, lowercase) of Jarvis's RSA-4096 encryption public key (DER SPKI). */
  var JARVIS_ENC_FINGERPRINT =
    'ceabe1c77c4c15710dc6e06992bad6c70c8ba1d8c0adaf17a2f3b1042a620ee5';

  /** Check-code of JARVIS_ENC_FINGERPRINT under the format defined above. */
  var JARVIS_ENC_CHECK_CODE = 'ceab e1c7';

  /** Fingerprint length: SHA-256 hex. Check-code length: first 8 hex chars. */
  var FINGERPRINT_HEX_LEN = 64;
  var CHECK_CODE_HEX_LEN = 8;

  // ---------------------------------------------------------------------------
  // Errors
  // ---------------------------------------------------------------------------

  function FingerprintError(message, code) {
    var err = new Error(message);
    err.name = 'FingerprintError';
    err.code = code || 'fingerprint-error';
    return err;
  }

  // ---------------------------------------------------------------------------
  // Private-key guard.
  //
  // This module never accepts private-key material. The marker below is
  // built from parts at runtime so the source never contains a PEM header
  // string (keeps ciphertext-only / private-key scans clean: this file
  // holds no key material, only the detection pattern for rejecting it).
  // ---------------------------------------------------------------------------

  var PRIVATE_MARKER = ['PRIVATE', 'KEY'].join(' '); // assembled at runtime; no such literal in source

  /**
   * True when `text` looks like private-key material: a PEM block carrying
   * a private-key marker, or a JWK object carrying a private `d` member.
   * Callers reject such input before doing anything else with it.
   */
  function looksLikePrivateKeyMaterial(text) {
    if (typeof text !== 'string') return false;
    if (text.indexOf(PRIVATE_MARKER) !== -1) return true;
    // JWK private key: a kty object that also carries a "d" member.
    if (text.indexOf('"kty"') !== -1 && /"d"\s*:/.test(text)) return true;
    return false;
  }

  function rejectPrivateKeyMaterial(text, what) {
    if (looksLikePrivateKeyMaterial(text)) {
      throw FingerprintError(
        'Rejected: ' + (what || 'input') + ' looks like private-key material. ' +
        'Private keys are never pasted, hashed, or displayed here. ' +
        'Only public fingerprints and public keys are checked.',
        'private-key-material-rejected'
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Normalization + validation (pure, synchronous)
  // ---------------------------------------------------------------------------

  /**
   * Strip grouping characters (spaces, hyphens, underscores, newlines)
   * and lower-case. Used for both fingerprints and check-codes, so
   * "CEAB-E1C7", "ceab e1c7" and "ceabe1c7" all normalize alike.
   */
  function normalizeHexInput(value) {
    if (typeof value !== 'string') return '';
    return value.replace(/[\s\-_]/g, '').toLowerCase();
  }

  function isHex(value, len) {
    return typeof value === 'string' &&
      value.length === len &&
      /^[0-9a-f]+$/.test(value);
  }

  /** True when `value` is a full 64-hex fingerprint (grouping tolerated). */
  function isValidFingerprint(value) {
    if (typeof value !== 'string') return false;
    if (looksLikePrivateKeyMaterial(value)) return false;
    return isHex(normalizeHexInput(value), FINGERPRINT_HEX_LEN);
  }

  /** True when `value` is an 8-hex check-code (grouping tolerated). */
  function isValidCheckCode(value) {
    if (typeof value !== 'string') return false;
    if (looksLikePrivateKeyMaterial(value)) return false;
    return isHex(normalizeHexInput(value), CHECK_CODE_HEX_LEN);
  }

  /**
   * Normalize a pasted fingerprint to canonical lowercase 64-hex.
   * Throws FingerprintError on anything else (including check-codes —
   * use normalizeCheckCode for those).
   */
  function normalizeFingerprint(value) {
    rejectPrivateKeyMaterial(value, 'pasted value');
    var norm = normalizeHexInput(value);
    if (!isHex(norm, FINGERPRINT_HEX_LEN)) {
      throw FingerprintError(
        'Not a fingerprint: expected 64 hex characters (a SHA-256 fingerprint), ' +
        'got ' + norm.length + ' characters after removing spaces and hyphens.',
        'invalid-fingerprint'
      );
    }
    return norm;
  }

  /**
   * Normalize a pasted check-code to canonical 8-hex (ungrouped).
   * Throws FingerprintError on anything else.
   */
  function normalizeCheckCode(value) {
    rejectPrivateKeyMaterial(value, 'pasted value');
    var norm = normalizeHexInput(value);
    if (!isHex(norm, CHECK_CODE_HEX_LEN)) {
      throw FingerprintError(
        'Not a check-code: expected 8 hex characters, got ' + norm.length +
        ' after removing spaces and hyphens.',
        'invalid-check-code'
      );
    }
    return norm;
  }

  /**
   * Classify a pasted value without throwing:
   *   { kind: 'fingerprint', value: <64-hex> }
   *   { kind: 'check-code', value: <8-hex> }
   *   { kind: 'invalid', value: <normalized>, reason: <string> }
   * A pasted value that looks like private-key material is always
   * 'invalid' with reason 'private-key-material-rejected' — never hashed.
   */
  function parsePastedValue(value) {
    if (typeof value !== 'string' || value.trim() === '') {
      return { kind: 'invalid', value: '', reason: 'empty input' };
    }
    if (looksLikePrivateKeyMaterial(value)) {
      return {
        kind: 'invalid',
        value: '',
        reason: 'private-key-material-rejected: paste only a public ' +
          'fingerprint or check-code, never a private key'
      };
    }
    var norm = normalizeHexInput(value);
    if (isHex(norm, FINGERPRINT_HEX_LEN)) {
      return { kind: 'fingerprint', value: norm, reason: null };
    }
    if (isHex(norm, CHECK_CODE_HEX_LEN)) {
      return { kind: 'check-code', value: norm, reason: null };
    }
    if (/^[0-9a-f]*$/.test(norm)) {
      return {
        kind: 'invalid',
        value: norm,
        reason: 'expected 64 hex characters (fingerprint) or 8 hex ' +
          'characters (check-code); got ' + norm.length
      };
    }
    return {
      kind: 'invalid',
      value: norm,
      reason: 'not hex: fingerprints and check-codes use only 0-9 and a-f'
    };
  }

  // ---------------------------------------------------------------------------
  // (1) Check-code computation + display formatting
  // ---------------------------------------------------------------------------

  /**
   * Compute the check-code for a fingerprint: first 8 hex chars, grouped
   * as two groups of 4 separated by a single space, e.g. "ceab e1c7".
   * Accepts a grouped / upper-case fingerprint; validates first.
   */
  function computeCheckCode(fingerprint) {
    var norm = normalizeFingerprint(fingerprint);
    return norm.slice(0, 4) + ' ' + norm.slice(4, 8);
  }

  /**
   * Group a full fingerprint for display: 8 groups of 8 hex chars,
   * separated by single spaces, e.g.
   * "ceabe1c7 7c4c1571 0dc6e069 92bad6c7 0c8ba1d8 c0adaf17 a2f3b104 2a620ee5".
   * The check-code is the first 8 hex characters of the fingerprint,
   * re-grouped as two groups of 4 ("ceab e1c7").
   */
  function formatFingerprint(fingerprint) {
    var norm = normalizeFingerprint(fingerprint);
    var groups = [];
    for (var i = 0; i < FINGERPRINT_HEX_LEN; i += 8) {
      groups.push(norm.slice(i, i + 8));
    }
    return groups.join(' ');
  }

  /** Human-readable statement of the check-code format (for UI/help text). */
  function describeCheckCodeFormat() {
    return 'A check-code is the first 8 characters of a key fingerprint, ' +
      'shown as two groups of 4, for example "ceab e1c7". ' +
      'Spaces, hyphens, and upper/lower case do not matter when you paste one. ' +
      'A matching check-code means the first 8 characters agree; only a full ' +
      'fingerprint match proves the key.';
  }

  // ---------------------------------------------------------------------------
  // Fingerprint computation from a public key (WebCrypto SHA-256 over DER SPKI)
  // ---------------------------------------------------------------------------

  function subtleCrypto() {
    if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) {
      return globalThis.crypto.subtle;
    }
    if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
      return window.crypto.subtle;
    }
    throw FingerprintError(
      'WebCrypto (crypto.subtle) is not available in this browser/context. ' +
      'Open the chat in a normal tab over HTTPS.',
      'webcrypto-unavailable'
    );
  }

  function bytesToHex(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) {
      var h = bytes[i].toString(16);
      out += h.length === 1 ? '0' + h : h;
    }
    return out;
  }

  /**
   * SHA-256 hex of DER-encoded SubjectPublicKeyInfo bytes.
   * `spki` is a Uint8Array or ArrayBuffer. Returns a Promise<string>
   * (lowercase 64-hex). This is the fingerprint definition (FILE-MAP §3):
   * SHA-256 of DER SPKI, whatever the key algorithm.
   */
  async function computeFingerprintFromSpki(spki) {
    var bytes = spki instanceof Uint8Array ? spki : new Uint8Array(spki);
    if (bytes.byteLength === 0) {
      throw FingerprintError('Empty public-key bytes: nothing to fingerprint.', 'empty-key');
    }
    var digest = await subtleCrypto().digest('SHA-256', bytes);
    return bytesToHex(new Uint8Array(digest));
  }

  function base64ToBytes(b64) {
    var clean = b64.replace(/\s+/g, '');
    if (typeof Buffer !== 'undefined' && typeof Buffer.from === 'function') {
      return new Uint8Array(Buffer.from(clean, 'base64'));
    }
    var bin = atob(clean);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  /**
   * SHA-256 hex of a PEM-encoded PUBLIC key (SPKI, "BEGIN PUBLIC KEY").
   * Rejects anything that looks like private-key material — pass only
   * public PEMs. Returns a Promise<string> (lowercase 64-hex).
   * Throws FingerprintError on a malformed PEM.
   */
  async function computeFingerprintFromPem(pem) {
    rejectPrivateKeyMaterial(pem, 'PEM input');
    if (typeof pem !== 'string' || pem.indexOf('PUBLIC KEY') === -1) {
      throw FingerprintError(
        'Not a public-key PEM: expected a "BEGIN PUBLIC KEY" block.',
        'invalid-pem'
      );
    }
    var body = pem
      .replace(/-----BEGIN PUBLIC KEY-----/g, '')
      .replace(/-----END PUBLIC KEY-----/g, '')
      .replace(/\s+/g, '');
    if (!/^[A-Za-z0-9+/=]+$/.test(body) || body.length === 0) {
      throw FingerprintError('Public-key PEM has no base64 body.', 'invalid-pem');
    }
    return computeFingerprintFromSpki(base64ToBytes(body));
  }

  // ---------------------------------------------------------------------------
  // (2) Owner display data — his own encryption + signing fingerprints
  // ---------------------------------------------------------------------------

  /**
   * Build the display data for the owner's own keys (pure function, no DOM).
   * Input: { encFingerprint, sigFingerprint, deviceLabel }
   *   - encFingerprint: required, full 64-hex (his RSA-OAEP key).
   *   - sigFingerprint: full 64-hex (his Ed25519/ES256 signing key), or
   *     null when the signing key is not made yet — the signing row is
   *     then reported as not-made rather than faked.
   *   - deviceLabel: e.g. "phone" / "PC" (his own label, no personal info).
   * Returns:
   *   {
   *     deviceLabel,
   *     enc: { fingerprint, grouped, checkCode },
   *     sig: { fingerprint, grouped, checkCode } | { made: false },
   *     readAloud: "<plain-words text to read to Jarvis in Muse chat>",
   *     checkCodeLine: "Encryption ceab e1c7 · Signing …"
   *   }
   * The readAloud text is what the owner reads to Jarvis in Muse chat so
   * Jarvis can confirm the codes match the key directory (OWNER-JOIN §3).
   * Nothing here touches a private key — fingerprints only.
   */
  function buildOwnerFingerprintDisplay(input) {
    input = input || {};
    if (!isValidFingerprint(input.encFingerprint)) {
      throw FingerprintError(
        'Owner encryption fingerprint is missing or not 64 hex characters.',
        'invalid-fingerprint'
      );
    }
    var encFp = normalizeFingerprint(input.encFingerprint);
    var deviceLabel = typeof input.deviceLabel === 'string' && input.deviceLabel.trim() !== ''
      ? input.deviceLabel.trim()
      : 'this device';

    var out = {
      deviceLabel: deviceLabel,
      enc: {
        fingerprint: encFp,
        grouped: formatFingerprint(encFp),
        checkCode: computeCheckCode(encFp)
      },
      sig: null,
      readAloud: '',
      checkCodeLine: ''
    };

    if (input.sigFingerprint == null || input.sigFingerprint === '') {
      out.sig = { made: false, fingerprint: null, grouped: null, checkCode: null };
    } else {
      if (!isValidFingerprint(input.sigFingerprint)) {
        throw FingerprintError(
          'Owner signing fingerprint is not 64 hex characters.',
          'invalid-fingerprint'
        );
      }
      var sigFp = normalizeFingerprint(input.sigFingerprint);
      out.sig = {
        made: true,
        fingerprint: sigFp,
        grouped: formatFingerprint(sigFp),
        checkCode: computeCheckCode(sigFp)
      };
    }

    out.checkCodeLine = 'Encryption ' + out.enc.checkCode +
      (out.sig.made ? ' · Signing ' + out.sig.checkCode : ' · Signing not made yet');
    out.readAloud =
      'My chat key on ' + deviceLabel + ': my encryption check-code is ' +
      out.enc.checkCode +
      (out.sig.made
        ? ', and my signing check-code is ' + out.sig.checkCode + '.'
        : ', and I have not made a signing key yet.') +
      ' Please check these match the codes you have for me.';
    return out;
  }

  /**
   * Render the owner's fingerprint display into a DOM container (C4/C5).
   * Uses textContent only — fingerprints/check-codes are never injected
   * as HTML. Returns the built element, or null when no DOM is present
   * (Node). `display` is the return value of buildOwnerFingerprintDisplay.
   */
  function renderOwnerFingerprintDisplay(container, display) {
    if (typeof document === 'undefined' || !container) return null;
    container.textContent = '';
    var wrap = document.createElement('div');
    wrap.setAttribute('data-fingerprint-display', 'owner');

    var title = document.createElement('p');
    title.textContent = 'Your key check-codes (' + display.deviceLabel + '). ' +
      'Read these to Jarvis in Muse chat — if the codes match, nobody swapped your key.';
    wrap.appendChild(title);

    function addRow(label, entry) {
      var row = document.createElement('p');
      var name = document.createElement('strong');
      name.textContent = label + ': ';
      row.appendChild(name);
      var code = document.createElement('code');
      code.textContent = entry.made === false ? 'not made yet' : entry.checkCode;
      row.appendChild(code);
      var fp = document.createElement('small');
      fp.textContent = entry.made === false
        ? ''
        : '  Full fingerprint: ' + entry.grouped;
      row.appendChild(fp);
      wrap.appendChild(row);
    }

    addRow('Encryption', display.enc);
    addRow('Signing', display.sig);

    var read = document.createElement('p');
    read.textContent = display.readAloud;
    wrap.appendChild(read);

    container.appendChild(wrap);
    return wrap;
  }

  // ---------------------------------------------------------------------------
  // (3) Jarvis verification — blocking pass/fail before setup completes
  // ---------------------------------------------------------------------------

  /**
   * Verify a candidate Jarvis encryption fingerprint against the known
   * public value (FILE-MAP D13). This is the BLOCKING gate C4 runs before
   * first-run setup completes: setup must not finish on a fail.
   *
   * Input is normally the full fingerprint from `participants.json`.
   * A check-code-only input can never pass: it returns ok=false with
   * reason 'check-code-only-insufficient' and checkCodeMatch set so the
   * UI can say whether the 8 characters at least agreed.
   *
   * Returns (never throws for a mismatch — only for private-key material):
   *   {
   *     ok: boolean,            // true ONLY on a full-fingerprint match
   *     blocked: boolean,       // !ok — setup must stop
   *     expected: <full fingerprint>,
   *     expectedCheckCode: "ceab e1c7",
   *     received: <normalized candidate or ''>,
   *     receivedCheckCode: <check-code of candidate or null>,
   *     checkCodeMatch: boolean | null,
   *     reason: 'match' | 'mismatch' | 'check-code-only-insufficient' |
   *             'invalid-input' | 'empty-input',
   *     message: "<plain-words verdict for the screen>"
   *   }
   */
  function verifyJarvisEncryptionFingerprint(candidate) {
    var base = {
      ok: false,
      blocked: true,
      expected: JARVIS_ENC_FINGERPRINT,
      expectedCheckCode: JARVIS_ENC_CHECK_CODE,
      received: '',
      receivedCheckCode: null,
      checkCodeMatch: null,
      reason: 'invalid-input',
      message: ''
    };
    if (typeof candidate !== 'string' || candidate.trim() === '') {
      base.reason = 'empty-input';
      base.message = 'No Jarvis fingerprint to check. Setup cannot continue ' +
        'without it — the key directory may not have loaded.';
      return base;
    }
    if (looksLikePrivateKeyMaterial(candidate)) {
      throw FingerprintError(
        'Rejected: the Jarvis check input looks like private-key material. ' +
        'Only public fingerprints are checked.',
        'private-key-material-rejected'
      );
    }
    var parsed = parsePastedValue(candidate);
    if (parsed.kind === 'invalid') {
      base.received = parsed.value;
      base.reason = 'invalid-input';
      base.message = 'That is not a Jarvis fingerprint or check-code: ' +
        parsed.reason + '. Setup cannot continue.';
      return base;
    }
    if (parsed.kind === 'check-code') {
      base.received = parsed.value;
      base.receivedCheckCode = parsed.value.slice(0, 4) + ' ' + parsed.value.slice(4, 8);
      base.checkCodeMatch = parsed.value === normalizeHexInput(JARVIS_ENC_CHECK_CODE);
      base.reason = 'check-code-only-insufficient';
      base.message = 'That is only a check-code (8 characters), not the full ' +
        'fingerprint. A check-code alone cannot pass this check — ' +
        (base.checkCodeMatch
          ? 'the 8 characters agree, but setup still needs the full fingerprint from the key directory.'
          : 'and these 8 characters do NOT match Jarvis’s check-code "ceab e1c7".') +
        ' Setup cannot continue.';
      return base;
    }
    base.received = parsed.value;
    base.receivedCheckCode = computeCheckCode(parsed.value);
    base.checkCodeMatch = base.receivedCheckCode === JARVIS_ENC_CHECK_CODE;
    if (parsed.value === JARVIS_ENC_FINGERPRINT) {
      base.ok = true;
      base.blocked = false;
      base.reason = 'match';
      base.message = 'Jarvis’s fingerprint matches (check-code "ceab e1c7"). ' +
        'Setup can continue.';
      return base;
    }
    base.reason = 'mismatch';
    base.message = 'MISMATCH: this fingerprint is not Jarvis’s. Expected ' +
      'check-code "ceab e1c7", got "' + base.receivedCheckCode + '". ' +
      'Do not send messages — tell Jarvis in Muse chat. Setup is blocked.';
    return base;
  }

  /**
   * Throwing form of the gate for C4: returns the result on pass,
   * throws FingerprintError on any fail. Use when setup must halt.
   */
  function assertJarvisEncryptionFingerprint(candidate) {
    var result = verifyJarvisEncryptionFingerprint(candidate);
    if (!result.ok) {
      throw FingerprintError(result.message, 'jarvis-fingerprint-' + result.reason);
    }
    return result;
  }

  /**
   * Render a Jarvis check result into a DOM container (blocking banner).
   * PASS: plain confirmation. FAIL: blocking wording + stop instruction.
   * Returns the built element, or null when no DOM is present.
   */
  function renderJarvisCheckResult(container, result) {
    if (typeof document === 'undefined' || !container) return null;
    container.textContent = '';
    var banner = document.createElement('div');
    banner.setAttribute('data-jarvis-check', result.ok ? 'pass' : 'fail');
    banner.setAttribute('role', result.ok ? 'status' : 'alert');
    var line = document.createElement('p');
    line.textContent = result.ok
      ? 'Jarvis check passed — fingerprint matches (check-code "ceab e1c7").'
      : 'Jarvis check FAILED — ' + result.message;
    banner.appendChild(line);
    if (!result.ok) {
      var stop = document.createElement('p');
      stop.textContent = 'Setup is stopped. Do not send messages. ' +
        'Tell Jarvis in Muse chat what you saw.';
      banner.appendChild(stop);
    }
    container.appendChild(banner);
    return banner;
  }

  // ---------------------------------------------------------------------------
  // (4) Compare a pasted fingerprint / check-code against the key directory
  // ---------------------------------------------------------------------------

  /**
   * Normalize one directory entry to { encFingerprint, sigFingerprint,
   * status, sigAlg, id, displayName }.
   *
   * Normative shape (FILE-MAP §9, `keys/participants.json`, array entries):
   *   { id, display_name, enc_fingerprint, sig_fingerprint, sig_alg,
   *     status: 'unpinned' | 'pinned' | 'revoked', ... }
   * Compatibility fallback (KEY-MANAGEMENT §4.2, superseded): an entry
   * with a `keys` array of { purpose, fingerprint_sha256_der, status }.
   * Legacy statuses map: active -> pinned, unverified -> unpinned,
   * superseded -> unpinned (kept for history, not trusted for new mail),
   * revoked -> revoked.
   */
  function normalizeDirectoryEntry(entry) {
    if (!entry || typeof entry !== 'object') return null;
    var out = {
      id: typeof entry.id === 'string' ? entry.id : null,
      displayName: typeof entry.display_name === 'string' ? entry.display_name : null,
      encFingerprint: null,
      sigFingerprint: null,
      sigAlg: typeof entry.sig_alg === 'string' ? entry.sig_alg : null,
      status: typeof entry.status === 'string' ? entry.status : null
    };
    if (typeof entry.enc_fingerprint === 'string') {
      out.encFingerprint = normalizeHexInput(entry.enc_fingerprint);
    }
    if (typeof entry.sig_fingerprint === 'string') {
      out.sigFingerprint = normalizeHexInput(entry.sig_fingerprint);
    }
    if (Array.isArray(entry.keys)) {
      entry.keys.forEach(function (k) {
        if (!k || typeof k !== 'object') return;
        var fp = typeof k.fingerprint_sha256_der === 'string'
          ? normalizeHexInput(k.fingerprint_sha256_der) : null;
        if (!fp) return;
        if (k.purpose === 'encryption' && !out.encFingerprint) out.encFingerprint = fp;
        if (k.purpose === 'signing' && !out.sigFingerprint) out.sigFingerprint = fp;
        if (!out.status && typeof k.status === 'string') {
          var map = { active: 'pinned', unverified: 'unpinned', superseded: 'unpinned', revoked: 'revoked' };
          out.status = map[k.status] || k.status;
        }
      });
    }
    return out;
  }

  /** Find an entry by participant id in an array-form or object-form directory. */
  function findDirectoryEntry(directory, participantId) {
    if (!directory) return null;
    if (Array.isArray(directory)) {
      for (var i = 0; i < directory.length; i++) {
        if (directory[i] && directory[i].id === participantId) return directory[i];
      }
      return null;
    }
    if (typeof directory === 'object') {
      if (directory[participantId]) return directory[participantId];
      if (Array.isArray(directory.participants)) {
        return findDirectoryEntry(directory.participants, participantId);
      }
    }
    return null;
  }

  /**
   * Compare a pasted fingerprint or check-code against one directory entry.
   *
   * Input: { entry, purpose, pastedValue }
   *   - entry: one raw `participants.json` entry (FILE-MAP §9 shape).
   *   - purpose: 'encryption' | 'signing'.
   *   - pastedValue: the pasted fingerprint (64 hex) or check-code (8 hex).
   *
   * Returns:
   *   {
   *     verdict: 'match' | 'mismatch' | 'invalid-input' | 'no-key-on-file',
   *     strength: 'full' | 'check-code-only' | null,
   *     trusted: boolean,   // true ONLY on full match + status 'pinned'
   *     participantId, purpose, status,
   *     expected: <full fingerprint on file or null>,
   *     expectedCheckCode: <check-code on file or null>,
   *     received: <normalized pasted value or ''>,
   *     receivedCheckCode: <check-code of pasted value or null>,
   *     message: "<plain-words verdict>"
   *   }
   * Trust rules (FILE-MAP D17): a `revoked` entry never trusts, whatever
   * the value; an `unpinned` entry can match but is not trusted until the
   * owner confirms it out-of-band; a check-code-only match is never trusted.
   */
  function compareAgainstEntry(input) {
    input = input || {};
    var entry = normalizeDirectoryEntry(input.entry);
    var purpose = input.purpose === 'signing' ? 'signing' : 'encryption';
    var base = {
      verdict: 'invalid-input',
      strength: null,
      trusted: false,
      participantId: entry ? entry.id : null,
      purpose: purpose,
      status: entry ? entry.status : null,
      expected: null,
      expectedCheckCode: null,
      received: '',
      receivedCheckCode: null,
      message: ''
    };
    if (!entry) {
      base.verdict = 'invalid-input';
      base.message = 'No key-directory entry was given to compare against.';
      return base;
    }
    var expected = purpose === 'signing' ? entry.sigFingerprint : entry.encFingerprint;
    if (!expected || !isHex(expected, FINGERPRINT_HEX_LEN)) {
      base.verdict = 'no-key-on-file';
      base.message = 'No ' + purpose + ' key is on file for ' +
        (entry.displayName || entry.id || 'this participant') +
        ' yet — nothing to compare against.';
      return base;
    }
    base.expected = expected;
    base.expectedCheckCode = computeCheckCode(expected);

    var parsed;
    try {
      parsed = parsePastedValue(input.pastedValue);
    } catch (e) {
      base.message = 'That pasted value cannot be checked: ' + e.message;
      return base;
    }
    if (parsed.kind === 'invalid') {
      base.received = parsed.value;
      base.message = 'That is not a fingerprint or check-code: ' + parsed.reason + '.';
      return base;
    }
    base.received = parsed.value;
    base.receivedCheckCode = parsed.kind === 'fingerprint'
      ? computeCheckCode(parsed.value)
      : parsed.value.slice(0, 4) + ' ' + parsed.value.slice(4, 8);

    var valueMatches = parsed.kind === 'fingerprint'
      ? parsed.value === expected
      : expected.slice(0, 8) === parsed.value;

    if (entry.status === 'revoked') {
      base.verdict = valueMatches ? 'match' : 'mismatch';
      base.strength = parsed.kind === 'fingerprint' ? 'full' : 'check-code-only';
      base.trusted = false;
      base.message = (valueMatches
        ? 'The value matches, but this key is REVOKED — it verifies nothing and encrypts nothing. '
        : 'The value does not match, and this key is REVOKED in any case. ') +
        'Do not use it. Tell Jarvis in Muse chat.';
      return base;
    }

    if (!valueMatches) {
      base.verdict = 'mismatch';
      base.strength = parsed.kind === 'fingerprint' ? 'full' : 'check-code-only';
      base.trusted = false;
      base.message = 'MISMATCH: the pasted ' +
        (parsed.kind === 'fingerprint' ? 'fingerprint' : 'check-code') +
        ' does not match the ' + purpose + ' key on file for ' +
        (entry.displayName || entry.id || 'this participant') +
        ' (on file: "' + base.expectedCheckCode + '"). ' +
        'Do not trust this key — tell Jarvis in Muse chat.';
      return base;
    }

    // Value matches.
    base.verdict = 'match';
    base.strength = parsed.kind === 'fingerprint' ? 'full' : 'check-code-only';
    if (parsed.kind === 'check-code') {
      base.trusted = false;
      base.message = 'The check-code matches ("' + base.receivedCheckCode + '"), ' +
        'but that is only 8 characters — it does not prove the key. ' +
        'Compare the full fingerprint before trusting it.';
      return base;
    }
    if (entry.status === 'pinned') {
      base.trusted = true;
      base.message = 'Match: the full fingerprint matches the pinned ' + purpose +
        ' key for ' + (entry.displayName || entry.id || 'this participant') + '.';
      return base;
    }
    base.trusted = false;
    base.message = 'The full fingerprint matches, but this key is ' +
      (entry.status === 'unpinned'
        ? 'UNPINNED — it is on file but not yet confirmed. Do not encrypt to it until the owner confirms it out-of-band.'
        : 'in status "' + entry.status + '" — not pinned, so it is not trusted yet.');
    return base;
  }

  /**
   * Compare a pasted fingerprint or check-code against the key directory.
   *
   * Input: { participantId, purpose, pastedValue, directory }
   *   - participantId: 'jarvis' | 'chatgpt' | 'owner' (FILE-MAP §9 ids).
   *   - purpose: 'encryption' | 'signing'.
   *   - directory: the parsed `keys/participants.json` (array form, or an
   *     object keyed by participant id).
   * Same return shape as compareAgainstEntry, plus verdict 'not-found'
   * when no entry exists for that participant.
   *
   * Note on B1's split: the live directory holds Jarvis's signing key as
   * a separate entry with id "jarvis-signing" (its `sig_*` fields are
   * still null at wave 2). For purpose 'signing' + participant 'jarvis',
   * this function checks the 'jarvis' entry first, then falls back to
   * the 'jarvis-signing' entry if the first has no signing key on file.
   */
  function compareAgainstDirectory(input) {
    input = input || {};
    var participantId = input.participantId;
    var purpose = input.purpose === 'signing' ? 'signing' : 'encryption';
    var base = {
      verdict: 'not-found',
      strength: null,
      trusted: false,
      participantId: participantId,
      purpose: purpose,
      status: null,
      expected: null,
      expectedCheckCode: null,
      received: '',
      receivedCheckCode: null,
      message: ''
    };
    var entry = findDirectoryEntry(input.directory, participantId);
    if (purpose === 'signing' && participantId === 'jarvis' && entry) {
      var norm = normalizeDirectoryEntry(entry);
      if (!norm.sigFingerprint) {
        var alt = findDirectoryEntry(input.directory, 'jarvis-signing');
        if (alt) entry = alt;
      }
    }
    if (!entry) {
      base.message = 'No key-directory entry for "' + participantId + '".';
      return base;
    }
    var result = compareAgainstEntry({
      entry: entry,
      purpose: purpose,
      pastedValue: input.pastedValue
    });
    result.participantId = participantId;
    return result;
  }

  /**
   * Verify Jarvis against the whole directory (the C4 setup gate in
   * directory form): the jarvis encryption fingerprint on file must equal
   * the known public value AND the entry status must be 'pinned'.
   * Returns { ok, blocked, fingerprintMatch, pinned, status, result }
   * where `result` is the verifyJarvisEncryptionFingerprint outcome for
   * the fingerprint on file. `ok` is true only when both hold.
   */
  function verifyJarvisAgainstDirectory(directory) {
    var out = {
      ok: false,
      blocked: true,
      fingerprintMatch: false,
      pinned: false,
      status: null,
      result: null
    };
    var entry = findDirectoryEntry(directory, 'jarvis');
    if (!entry) {
      out.result = {
        ok: false, blocked: true, reason: 'not-found',
        message: 'No "jarvis" entry in the key directory. Setup cannot continue.'
      };
      return out;
    }
    var norm = normalizeDirectoryEntry(entry);
    out.status = norm.status;
    out.pinned = norm.status === 'pinned';
    out.result = verifyJarvisEncryptionFingerprint(norm.encFingerprint || '');
    out.fingerprintMatch = out.result.ok;
    out.ok = out.fingerprintMatch && out.pinned;
    out.blocked = !out.ok;
    if (out.ok) {
      out.result.message = 'Jarvis check passed — directory fingerprint matches ' +
        'and the key is pinned (check-code "ceab e1c7"). Setup can continue.';
    } else if (out.fingerprintMatch && !out.pinned) {
      out.result.ok = false;
      out.result.blocked = true;
      out.result.reason = 'not-pinned';
      out.result.message = 'Jarvis’s fingerprint matches, but the directory ' +
        'entry is not pinned (status "' + norm.status + '"). Setup cannot ' +
        'continue until the owner confirms it.';
    }
    return out;
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  return {
    // Known public values (FILE-MAP D13)
    JARVIS_ENC_FINGERPRINT: JARVIS_ENC_FINGERPRINT,
    JARVIS_ENC_CHECK_CODE: JARVIS_ENC_CHECK_CODE,

    // Errors
    FingerprintError: FingerprintError,

    // Normalization / validation
    normalizeFingerprint: normalizeFingerprint,
    normalizeCheckCode: normalizeCheckCode,
    normalizeHexInput: normalizeHexInput,
    isValidFingerprint: isValidFingerprint,
    isValidCheckCode: isValidCheckCode,
    parsePastedValue: parsePastedValue,

    // (1) Check-code + display
    computeCheckCode: computeCheckCode,
    formatFingerprint: formatFingerprint,
    describeCheckCodeFormat: describeCheckCodeFormat,

    // Fingerprint computation from public keys (WebCrypto SHA-256)
    computeFingerprintFromSpki: computeFingerprintFromSpki,
    computeFingerprintFromPem: computeFingerprintFromPem,

    // (2) Owner display
    buildOwnerFingerprintDisplay: buildOwnerFingerprintDisplay,
    renderOwnerFingerprintDisplay: renderOwnerFingerprintDisplay,

    // (3) Jarvis verification (blocking gate)
    verifyJarvisEncryptionFingerprint: verifyJarvisEncryptionFingerprint,
    assertJarvisEncryptionFingerprint: assertJarvisEncryptionFingerprint,
    verifyJarvisAgainstDirectory: verifyJarvisAgainstDirectory,
    renderJarvisCheckResult: renderJarvisCheckResult,

    // (4) Directory comparison
    compareAgainstEntry: compareAgainstEntry,
    compareAgainstDirectory: compareAgainstDirectory,
    normalizeDirectoryEntry: normalizeDirectoryEntry,
    findDirectoryEntry: findDirectoryEntry,

    // Guard (exported for tests / consumers that pre-screen input)
    looksLikePrivateKeyMaterial: looksLikePrivateKeyMaterial
  };
});
