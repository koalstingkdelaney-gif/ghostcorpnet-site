/**
 * crypto-core.js — WebCrypto core for the ghostcorpnet encrypted chat (ecc-1).
 *
 * Implements FILE-MAP §3 (envelope fields / canonical JSON) and
 * CRYPTO-DESIGN.md §3 (AES-256-CBC + HMAC-SHA-256, encrypt-then-MAC),
 * §4 (Ed25519 primary signing), §5 (RSA-OAEP-SHA-256 key wrap),
 * §13.1 (browser WebCrypto notes).
 *
 * Scope (worker A1): RSA-OAEP-4096 keygen, AES-256-CBC + HMAC-SHA-256
 * encrypt/decrypt, Ed25519 sign/verify, key import/export (JWK/PEM),
 * base64url (no padding) helpers. No external dependencies, no network calls.
 *
 * Out of scope (other workers):
 *   - Canonical JSON serialization .......... A3 app/js/canonical-json.js
 *     (this module signs/verifies raw Uint8Array bytes; the caller passes the
 *     canonical bytes produced by A3).
 *   - Envelope build/parse/validate .......... A4 app/js/envelope.js
 *     (this module produces/consumes the envelope's crypto fields —
 *     iv / ct / mac / wrapped_keys / sig — as base64url strings).
 *   - ES256 (ECDSA P-256) fallback ........... A2 app/js/crypto-p256.js
 *     (this module registers Ed25519 only; A2 registers ES256 through the
 *     registerSigAlg() hook below so verifySignature() can dispatch on
 *     sig_alg without this file knowing ES256).
 *   - Key storage / backup ................... C17 keys-store.js, C11 backup.js
 *
 * Security notes (CRYPTO-DESIGN §12): no forward secrecy in ecc-1 — the
 * per-message key is RSA-wrapped under long-lived static keys. Never claim
 * forward secrecy. Private keys are created extractable:false by default
 * (see generate*Keypair); export them only through the explicit backup path.
 * HMAC is verified (constant-time) BEFORE any decryption — a tampered
 * ciphertext is never decrypted.
 *
 * Runs in any secure context (HTTPS / localhost) where WebCrypto exists.
 * Also works under Node.js >= 18 (globalThis.crypto.subtle).
 */

'use strict';

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    // Node / CommonJS (used by the test harness; the page loads this as a
    // plain <script> and gets window.GhostChatCrypto).
    module.exports = factory();
  } else {
    root.GhostChatCrypto = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {

  // ---------------------------------------------------------------------------
  // Constants — FILE-MAP §3 / CRYPTO-DESIGN §1, §6
  // ---------------------------------------------------------------------------

  var ENVELOPE_VERSION = 'ecc-1';
  var ALG = 'A256CBC-HS256';
  var SIG_ALG_ED25519 = 'Ed25519';
  var SIG_ALG_ES256 = 'ES256';

  var RSA_MODULUS_LENGTH = 4096;      // §5: RSA-4096 recommended (owner: 2048 min)
  var RSA_PUBLIC_EXPONENT = new Uint8Array([1, 0, 1]);
  var RSA_HASH = 'SHA-256';

  var ENC_KEY_BYTES = 32;             // AES-256
  var MAC_KEY_BYTES = 32;             // HMAC-SHA-256
  var WRAPPED_KEY_BYTES = ENC_KEY_BYTES + MAC_KEY_BYTES; // 64
  var IV_BYTES = 16;                  // AES-CBC IV
  var MAC_BYTES = 32;                 // HMAC-SHA-256 output
  var ED25519_SIG_BYTES = 64;
  var MAX_PLAINTEXT_BYTES = 64 * 1024; // FILE-MAP §3: max 64 KiB plaintext

  // ---------------------------------------------------------------------------
  // Environment
  // ---------------------------------------------------------------------------

  function subtle() {
    var c = (typeof crypto !== 'undefined') ? crypto : null;
    if (!c || !c.subtle) {
      throw new Error('WebCrypto (crypto.subtle) is unavailable: this page must be served over HTTPS or localhost');
    }
    return c.subtle;
  }

  function getRandomValues(buf) {
    var c = (typeof crypto !== 'undefined') ? crypto : null;
    if (!c || !c.getRandomValues) {
      throw new Error('crypto.getRandomValues is unavailable');
    }
    return c.getRandomValues(buf);
  }

  // ---------------------------------------------------------------------------
  // Errors
  // ---------------------------------------------------------------------------

  function CryptoError(code, message) {
    var e = new Error(message);
    e.name = 'CryptoError';
    e.code = code;
    return e;
  }

  // ---------------------------------------------------------------------------
  // base64url (RFC 4648 §5) — no padding, strict decoding
  // FILE-MAP §3 / CRYPTO-DESIGN §6.3: decoders reject non-canonical input
  // (padding present, or characters outside the alphabet).
  // ---------------------------------------------------------------------------

  var B64U_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  var B64U_RE = /^[A-Za-z0-9_-]*$/;

  function bytesToBase64url(bytes) {
    bytes = toUint8(bytes, 'bytesToBase64url');
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
    return out; // never padded
  }

  function base64urlToBytes(str) {
    if (typeof str !== 'string') {
      throw CryptoError('BAD_ENCODING', 'base64url input must be a string');
    }
    if (str.indexOf('=') !== -1) {
      throw CryptoError('BAD_ENCODING', 'base64url input must not contain padding ("=")');
    }
    if (!B64U_RE.test(str)) {
      throw CryptoError('BAD_ENCODING', 'base64url input contains characters outside the base64url alphabet');
    }
    if (str.length % 4 === 1) {
      throw CryptoError('BAD_ENCODING', 'base64url input has an impossible length (length % 4 == 1)');
    }
    // Decode via standard base64: translate -_ to +/, then pad to a multiple of 4.
    var b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4 !== 0) b64 += '=';
    var bin;
    if (typeof atob === 'function') {
      bin = atob(b64);
    } else {
      // Node (no atob in older runtimes): Buffer is available.
      bin = Buffer.from(b64, 'base64').toString('binary');
    }
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i) & 0xff;
    // Round-trip check: re-encoding must reproduce the input exactly, so a
    // non-canonical trailing-bits encoding is rejected, not silently accepted.
    if (bytesToBase64url(out) !== str) {
      throw CryptoError('BAD_ENCODING', 'base64url input is not canonically encoded');
    }
    return out;
  }

  // ---------------------------------------------------------------------------
  // Byte / text helpers
  // ---------------------------------------------------------------------------

  function toUint8(value, what) {
    if (value instanceof Uint8Array) return value;
    if (value instanceof ArrayBuffer) return new Uint8Array(value);
    if (typeof Buffer !== 'undefined' && Buffer.isBuffer(value)) {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    throw CryptoError('BAD_TYPE', (what || 'value') + ' must be a Uint8Array or ArrayBuffer');
  }

  var _encoder = (typeof TextEncoder !== 'undefined') ? new TextEncoder() : null;
  var _decoder = (typeof TextDecoder !== 'undefined') ? new TextDecoder('utf-8', { fatal: true }) : null;

  function textToBytes(text) {
    if (typeof text !== 'string') {
      throw CryptoError('BAD_TYPE', 'textToBytes expects a string');
    }
    if (_encoder) return _encoder.encode(text);
    return Buffer.from(text, 'utf-8');
  }

  function bytesToText(bytes) {
    bytes = toUint8(bytes, 'bytesToText');
    if (_decoder) return _decoder.decode(bytes);
    return Buffer.from(bytes).toString('utf-8');
  }

  function concatBytes() {
    var total = 0;
    var parts = [];
    for (var i = 0; i < arguments.length; i++) {
      var p = toUint8(arguments[i], 'concatBytes part');
      parts.push(p);
      total += p.length;
    }
    var out = new Uint8Array(total);
    var off = 0;
    for (var j = 0; j < parts.length; j++) {
      out.set(parts[j], off);
      off += parts[j].length;
    }
    return out;
  }

  function randomBytes(n) {
    if (!Number.isInteger(n) || n <= 0) {
      throw CryptoError('BAD_TYPE', 'randomBytes expects a positive integer');
    }
    var buf = new Uint8Array(n);
    getRandomValues(buf);
    return buf;
  }

  // Constant-time equality (CRYPTO-DESIGN §7 step 7: HMAC verified
  // constant-time). Returns false on length mismatch rather than throwing,
  // so callers never leak which check failed first.
  function constantTimeEqual(a, b) {
    a = toUint8(a, 'constantTimeEqual');
    b = toUint8(b, 'constantTimeEqual');
    if (a.length !== b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) diff |= (a[i] ^ b[i]);
    return diff === 0;
  }

  function bytesToHex(bytes) {
    bytes = toUint8(bytes, 'bytesToHex');
    var out = '';
    for (var i = 0; i < bytes.length; i++) {
      out += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return out;
  }

  function hexToBytes(hex) {
    if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
      throw CryptoError('BAD_ENCODING', 'hex input must be an even-length hex string');
    }
    var out = new Uint8Array(hex.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }

  // ---------------------------------------------------------------------------
  // PEM / DER helpers
  // ---------------------------------------------------------------------------

  var PEM_LINE = 64;

  function derToPem(derBytes, label) {
    derBytes = toUint8(derBytes, 'derToPem');
    var b64;
    if (typeof btoa === 'function') {
      var bin = '';
      for (var i = 0; i < derBytes.length; i++) bin += String.fromCharCode(derBytes[i]);
      b64 = btoa(bin);
    } else {
      b64 = Buffer.from(derBytes).toString('base64');
    }
    var lines = ['-----BEGIN ' + label + '-----'];
    for (var j = 0; j < b64.length; j += PEM_LINE) lines.push(b64.slice(j, j + PEM_LINE));
    lines.push('-----END ' + label + '-----');
    return lines.join('\n') + '\n';
  }

  function pemToDer(pem, label) {
    if (typeof pem !== 'string') {
      throw CryptoError('BAD_ENCODING', 'PEM input must be a string');
    }
    var begin = '-----BEGIN ' + label + '-----';
    var end = '-----END ' + label + '-----';
    var b = pem.indexOf(begin);
    var e = pem.indexOf(end);
    if (b === -1 || e === -1 || e <= b) {
      throw CryptoError('BAD_ENCODING', 'PEM input is not a ' + label + ' block');
    }
    var b64 = pem.slice(b + begin.length, e).replace(/\s+/g, '');
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) {
      throw CryptoError('BAD_ENCODING', 'PEM body contains characters outside the base64 alphabet');
    }
    var bin;
    if (typeof atob === 'function') {
      bin = atob(b64);
    } else {
      bin = Buffer.from(b64, 'base64').toString('binary');
    }
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i) & 0xff;
    return out;
  }

  // Fingerprint (CRYPTO-DESIGN §2.1 / §9): SHA-256 hex of the DER SPKI.
  // Accepts a CryptoKey (public), a PEM string, or DER bytes.
  async function fingerprintPublicKey(keyOrPemOrDer) {
    var der;
    if (typeof keyOrPemOrDer === 'string') {
      der = pemToDer(keyOrPemOrDer, 'PUBLIC KEY');
    } else if (keyOrPemOrDer instanceof CryptoKey) {
      der = await subtle().exportKey('spki', keyOrPemOrDer);
    } else {
      der = toUint8(keyOrPemOrDer, 'fingerprintPublicKey');
    }
    var digest = await subtle().digest('SHA-256', der);
    return bytesToHex(new Uint8Array(digest));
  }

  // ---------------------------------------------------------------------------
  // Key generation — CRYPTO-DESIGN §13.1
  // ---------------------------------------------------------------------------

  // RSA-OAEP encryption keypair. extractable defaults to false for the private
  // key: private keys stay in the holder's IndexedDB (C17), never localStorage,
  // and are exported only via the explicit backup path (C11). Pass
  // { extractable: true } only when the caller genuinely needs to export
  // (e.g. first-run backup creation).
  async function generateEncryptionKeypair(options) {
    var opts = options || {};
    var pair = await subtle().generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: opts.modulusLength || RSA_MODULUS_LENGTH,
        publicExponent: RSA_PUBLIC_EXPONENT,
        hash: RSA_HASH
      },
      opts.extractable === true,
      ['encrypt', 'decrypt']
    );
    return pair;
  }

  // Ed25519 signing keypair (primary, §4). Rejects on browsers without
  // Ed25519 WebCrypto support — callers must feature-detect with
  // supportsEd25519() first and fall back to the A2 ES256 path.
  async function generateSigningKeypair(options) {
    var opts = options || {};
    var pair = await subtle().generateKey(
      { name: 'Ed25519' },
      opts.extractable === true,
      ['sign', 'verify']
    );
    return pair;
  }

  // Feature-detect Ed25519 keygen (CRYPTO-DESIGN §4.4 trigger).
  async function supportsEd25519() {
    try {
      var pair = await subtle().generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
      return !!pair && !!pair.publicKey;
    } catch (e) {
      return false;
    }
  }

  // ---------------------------------------------------------------------------
  // Key import / export
  // ---------------------------------------------------------------------------

  // --- Public keys -----------------------------------------------------------

  // Import an RSA-OAEP public key from SPKI DER or PEM. Usages: ['encrypt'].
  async function importEncryptionPublicKey(spkiDerOrPem) {
    var der = (typeof spkiDerOrPem === 'string')
      ? pemToDer(spkiDerOrPem, 'PUBLIC KEY')
      : toUint8(spkiDerOrPem, 'importEncryptionPublicKey');
    return subtle().importKey(
      'spki', der,
      { name: 'RSA-OAEP', hash: RSA_HASH },
      true, ['encrypt']
    );
  }

  // Import an Ed25519 public key from SPKI DER or PEM. Usages: ['verify'].
  async function importSigningPublicKey(spkiDerOrPem) {
    var der = (typeof spkiDerOrPem === 'string')
      ? pemToDer(spkiDerOrPem, 'PUBLIC KEY')
      : toUint8(spkiDerOrPem, 'importSigningPublicKey');
    return subtle().importKey('spki', der, { name: 'Ed25519' }, true, ['verify']);
  }

  // Import an Ed25519 public key from JWK (as exported by exportPublicKeyJwk).
  async function importSigningPublicKeyJwk(jwk) {
    if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
      throw CryptoError('BAD_KEY', 'JWK is not an Ed25519 public key');
    }
    return subtle().importKey('jwk', jwk, { name: 'Ed25519' }, true, ['verify']);
  }

  // Import an RSA-OAEP public key from JWK.
  async function importEncryptionPublicKeyJwk(jwk) {
    if (!jwk || jwk.kty !== 'RSA' || typeof jwk.n !== 'string' || typeof jwk.e !== 'string') {
      throw CryptoError('BAD_KEY', 'JWK is not an RSA public key');
    }
    return subtle().importKey(
      'jwk', jwk,
      { name: 'RSA-OAEP', hash: RSA_HASH },
      true, ['encrypt']
    );
  }

  // Export a public key as SPKI DER, then PEM ("-----BEGIN PUBLIC KEY-----").
  // This is the form published in keys/participants.json (enc_pub_pem /
  // sig_pub_pem, CRYPTO-DESIGN §9).
  async function exportPublicKeyPem(publicKey) {
    var der = await subtle().exportKey('spki', publicKey);
    return derToPem(new Uint8Array(der), 'PUBLIC KEY');
  }

  async function exportPublicKeyDer(publicKey) {
    var der = await subtle().exportKey('spki', publicKey);
    return new Uint8Array(der);
  }

  async function exportPublicKeyJwk(publicKey) {
    return subtle().exportKey('jwk', publicKey);
  }

  // --- Private keys ----------------------------------------------------------
  // Private keys are exported ONLY as JWK (for the passphrase-encrypted
  // backup, C11) or PKCS#8 PEM. Both require the key to have been generated
  // or imported with extractable:true. A non-extractable key throws here —
  // that is by design, not a bug.

  async function exportPrivateKeyJwk(privateKey) {
    return subtle().exportKey('jwk', privateKey);
  }

  async function exportPrivateKeyPem(privateKey) {
    var der = await subtle().exportKey('pkcs8', privateKey);
    return derToPem(new Uint8Array(der), 'PRIVATE KEY');
  }

  // Import an RSA-OAEP private key from PKCS#8 DER/PEM or JWK.
  async function importEncryptionPrivateKey(input) {
    if (typeof input === 'string') {
      var der = pemToDer(input, 'PRIVATE KEY');
      return subtle().importKey(
        'pkcs8', der,
        { name: 'RSA-OAEP', hash: RSA_HASH },
        false, ['decrypt']
      );
    }
    if (input && input.kty === 'RSA') {
      return subtle().importKey(
        'jwk', input,
        { name: 'RSA-OAEP', hash: RSA_HASH },
        false, ['decrypt']
      );
    }
    throw CryptoError('BAD_KEY', 'RSA private key input must be a PKCS#8 PEM string or a JWK');
  }

  // Import an Ed25519 private key from PKCS#8 DER/PEM or JWK.
  async function importSigningPrivateKey(input) {
    if (typeof input === 'string') {
      var der = pemToDer(input, 'PRIVATE KEY');
      return subtle().importKey('pkcs8', der, { name: 'Ed25519' }, false, ['sign']);
    }
    if (input && input.kty === 'OKP' && input.crv === 'Ed25519') {
      return subtle().importKey('jwk', input, { name: 'Ed25519' }, false, ['sign']);
    }
    throw CryptoError('BAD_KEY', 'Ed25519 private key input must be a PKCS#8 PEM string or a JWK');
  }

  // Import an AES-256 key (raw 32 bytes) for the content layer — used by
  // tests / vector re-verification, NOT by the normal send path (which
  // generates fresh per-message keys internally).
  async function importAesKey(rawBytes, usages) {
    var raw = toUint8(rawBytes, 'importAesKey');
    if (raw.length !== ENC_KEY_BYTES) {
      throw CryptoError('BAD_KEY', 'AES-256 key must be 32 bytes');
    }
    return subtle().importKey('raw', raw, { name: 'AES-CBC' }, false, usages || ['encrypt', 'decrypt']);
  }

  // Import an HMAC-SHA-256 key (raw 32 bytes).
  async function importHmacKey(rawBytes, usages) {
    var raw = toUint8(rawBytes, 'importHmacKey');
    if (raw.length !== MAC_KEY_BYTES) {
      throw CryptoError('BAD_KEY', 'HMAC key must be 32 bytes');
    }
    return subtle().importKey(
      'raw', raw,
      { name: 'HMAC', hash: 'SHA-256' },
      false, usages || ['sign', 'verify']
    );
  }

  // ---------------------------------------------------------------------------
  // Symmetric layer — CRYPTO-DESIGN §3
  // AES-256-CBC (PKCS#7) + HMAC-SHA-256 over IV || ct, encrypt-then-MAC.
  // ---------------------------------------------------------------------------

  // Encrypt plaintext bytes for one or more recipients.
  //
  // plaintextBytes : Uint8Array — the inner plaintext (UTF-8 JSON
  //   {"text": "..."} per FILE-MAP §3; this module does not parse it).
  // recipientPublicKeys : [{ recipient: "<id>", publicKey: CryptoKey }, ...]
  //   — RSA-OAEP public keys, one per recipient. May be empty only when the
  //   caller wants the content layer alone (then wrapped_keys is []).
  //
  // Returns { iv, ct, mac, wrapped_keys } — all base64url, no padding —
  // exactly the envelope crypto fields of FILE-MAP §3 / CRYPTO-DESIGN §6.1.
  // Fresh random ENC_KEY (32 B), MAC_KEY (32 B), IV (16 B) per message.
  async function encryptMessage(plaintextBytes, recipientPublicKeys) {
    var plaintext = toUint8(plaintextBytes, 'encryptMessage plaintext');
    if (plaintext.length > MAX_PLAINTEXT_BYTES) {
      throw CryptoError('TOO_LARGE', 'plaintext exceeds the 64 KiB per-message limit');
    }
    var recipients = recipientPublicKeys || [];
    if (!Array.isArray(recipients)) {
      throw CryptoError('BAD_TYPE', 'recipientPublicKeys must be an array');
    }

    var encKeyBytes = randomBytes(ENC_KEY_BYTES);
    var macKeyBytes = randomBytes(MAC_KEY_BYTES);
    var iv = randomBytes(IV_BYTES);

    var encKey = await importAesKey(encKeyBytes, ['encrypt']);
    var macKey = await importHmacKey(macKeyBytes, ['sign']);

    var ctBuf = await subtle().encrypt({ name: 'AES-CBC', iv: iv }, encKey, plaintext);
    var ct = new Uint8Array(ctBuf);

    // HMAC over IV || ciphertext (raw bytes) — encrypt-then-MAC.
    var macBuf = await subtle().sign({ name: 'HMAC', hash: 'SHA-256' }, macKey, concatBytes(iv, ct));
    var mac = new Uint8Array(macBuf);

    // Wrap ENC_KEY || MAC_KEY (64 bytes) under each recipient's RSA-OAEP key.
    var wrapped = concatBytes(encKeyBytes, macKeyBytes);
    var wrappedKeys = [];
    for (var i = 0; i < recipients.length; i++) {
      var entry = recipients[i];
      if (!entry || typeof entry.recipient !== 'string' || !entry.publicKey) {
        throw CryptoError('BAD_TYPE', 'each recipient entry needs { recipient: string, publicKey: CryptoKey }');
      }
      var wkBuf = await subtle().encrypt({ name: 'RSA-OAEP' }, entry.publicKey, wrapped);
      wrappedKeys.push({ recipient: entry.recipient, wk: bytesToBase64url(new Uint8Array(wkBuf)) });
    }

    return {
      iv: bytesToBase64url(iv),
      ct: bytesToBase64url(ct),
      mac: bytesToBase64url(mac),
      wrapped_keys: wrappedKeys
    };
  }

  // Decrypt an envelope's content layer for this recipient.
  //
  // fields : { iv, ct, mac, wrapped_keys } — base64url strings, as produced
  //   by encryptMessage() / as carried in the envelope.
  // recipientId : string — this participant's id; selects their wrapped_keys
  //   entry (no entry -> reject, CRYPTO-DESIGN §7 step 6).
  // privateKey : CryptoKey — this recipient's RSA-OAEP private key.
  //
  // Returns the plaintext bytes. Order (CRYPTO-DESIGN §7 steps 6-8):
  //   unwrap -> HMAC verify (constant-time) -> decrypt. A MAC mismatch
  //   rejects WITHOUT decrypting.
  async function decryptMessage(fields, recipientId, privateKey) {
    if (!fields || typeof fields !== 'object') {
      throw CryptoError('BAD_ENVELOPE', 'decryptMessage requires the envelope crypto fields');
    }
    if (typeof recipientId !== 'string' || recipientId.length === 0) {
      throw CryptoError('BAD_TYPE', 'recipientId must be a non-empty string');
    }
    if (!privateKey) {
      throw CryptoError('BAD_KEY', 'decryptMessage requires the recipient private key');
    }
    if (!Array.isArray(fields.wrapped_keys)) {
      throw CryptoError('BAD_ENVELOPE', 'wrapped_keys must be an array');
    }

    var iv = base64urlToBytes(fields.iv);
    var ct = base64urlToBytes(fields.ct);
    var mac = base64urlToBytes(fields.mac);

    if (iv.length !== IV_BYTES) {
      throw CryptoError('BAD_ENVELOPE', 'iv must decode to 16 bytes');
    }
    if (mac.length !== MAC_BYTES) {
      throw CryptoError('BAD_ENVELOPE', 'mac must decode to 32 bytes');
    }
    if (ct.length === 0 || ct.length % 16 !== 0) {
      throw CryptoError('BAD_ENVELOPE', 'ct must decode to a non-empty multiple of 16 bytes (AES-CBC block)');
    }

    var entry = null;
    for (var i = 0; i < fields.wrapped_keys.length; i++) {
      if (fields.wrapped_keys[i] && fields.wrapped_keys[i].recipient === recipientId) {
        entry = fields.wrapped_keys[i];
        break;
      }
    }
    if (!entry || typeof entry.wk !== 'string') {
      throw CryptoError('NO_WRAPPED_KEY', 'no wrapped_keys entry for recipient "' + recipientId + '"');
    }

    // Step 6: unwrap ENC_KEY || MAC_KEY (64 bytes) with RSA-OAEP-SHA-256.
    var wkBytes = base64urlToBytes(entry.wk);
    var unwrappedBuf;
    try {
      unwrappedBuf = await subtle().decrypt({ name: 'RSA-OAEP' }, privateKey, wkBytes);
    } catch (e) {
      throw CryptoError('UNWRAP_FAILED', 'RSA-OAEP unwrap failed (wrong key or corrupted wrap)');
    }
    var unwrapped = new Uint8Array(unwrappedBuf);
    if (unwrapped.length !== WRAPPED_KEY_BYTES) {
      throw CryptoError('UNWRAP_FAILED', 'unwrapped key material must be 64 bytes (ENC_KEY || MAC_KEY)');
    }
    var encKeyBytes = unwrapped.slice(0, ENC_KEY_BYTES);
    var macKeyBytes = unwrapped.slice(ENC_KEY_BYTES);

    // Step 7: HMAC verify over IV || ct BEFORE decrypting (EtM order).
    // Recompute the MAC (usage 'sign') and compare constant-time — the
    // verify path is equivalent, but sign+compare keeps the comparison
    // explicitly constant-time.
    var macKey = await importHmacKey(macKeyBytes, ['sign']);
    var expectedMacBuf = await subtle().sign(
      { name: 'HMAC', hash: 'SHA-256' }, macKey, concatBytes(iv, ct)
    );
    var expectedMac = new Uint8Array(expectedMacBuf);
    if (!constantTimeEqual(mac, expectedMac)) {
      throw CryptoError('MAC_MISMATCH', 'HMAC verification failed — ciphertext rejected, not decrypted');
    }

    // Step 8: decrypt (PKCS#7 unpadding is WebCrypto's default; bad padding
    // fails here — after the HMAC already passed, so it cannot be an oracle).
    var encKey = await importAesKey(encKeyBytes, ['decrypt']);
    var plainBuf;
    try {
      plainBuf = await subtle().decrypt({ name: 'AES-CBC', iv: iv }, encKey, ct);
    } catch (e) {
      throw CryptoError('DECRYPT_FAILED', 'AES-256-CBC decryption failed');
    }
    var plaintext = new Uint8Array(plainBuf);
    if (plaintext.length > MAX_PLAINTEXT_BYTES) {
      throw CryptoError('TOO_LARGE', 'decrypted plaintext exceeds the 64 KiB per-message limit');
    }
    return plaintext;
  }

  // ---------------------------------------------------------------------------
  // Signing — CRYPTO-DESIGN §4 (Ed25519 primary)
  // ---------------------------------------------------------------------------

  // Signature-algorithm registry. Ed25519 is registered here; the A2 ES256
  // fallback registers itself via registerSigAlg('ES256', {...}) so that
  // signBytes/verifySignature dispatch on sig_alg without this file
  // implementing ECDSA. A sender has exactly one pinned sig_alg (§4.4) and
  // receivers must accept both — the registry is how both verify paths stay
  // mandatory for receivers while keeping the fallback in its own file.
  var sigAlgs = {};

  function registerSigAlg(name, handlers) {
    if (typeof name !== 'string' || !handlers ||
        typeof handlers.sign !== 'function' || typeof handlers.verify !== 'function') {
      throw CryptoError('BAD_TYPE', 'registerSigAlg needs a name and { sign, verify } functions');
    }
    sigAlgs[name] = handlers;
  }

  // Ed25519: signs the bytes directly (PureEdDSA, no pre-hash — §6.2).
  // `data` is the canonical JSON bytes (produced by A3 canonical-json.js).
  async function signEd25519(data, privateKey) {
    var bytes = toUint8(data, 'signEd25519 data');
    var sigBuf = await subtle().sign({ name: 'Ed25519' }, privateKey, bytes);
    var sig = new Uint8Array(sigBuf);
    if (sig.length !== ED25519_SIG_BYTES) {
      throw CryptoError('SIGN_FAILED', 'Ed25519 signature must be 64 bytes');
    }
    return sig;
  }

  async function verifyEd25519(data, signature, publicKey) {
    var bytes = toUint8(data, 'verifyEd25519 data');
    var sig = toUint8(signature, 'verifyEd25519 signature');
    if (sig.length !== ED25519_SIG_BYTES) return false;
    return subtle().verify({ name: 'Ed25519' }, publicKey, sig, bytes);
  }

  sigAlgs[SIG_ALG_ED25519] = { sign: signEd25519, verify: verifyEd25519 };

  // Sign canonical bytes with the given algorithm. Returns base64url (no
  // padding) — the envelope `sig` field. Default sig_alg is Ed25519.
  async function signBytes(data, privateKey, sigAlg) {
    var alg = sigAlg || SIG_ALG_ED25519;
    var handler = sigAlgs[alg];
    if (!handler) {
      throw CryptoError('UNKNOWN_SIG_ALG',
        'no signing handler registered for sig_alg "' + alg + '"' +
        (alg === SIG_ALG_ES256 ? ' — load app/js/crypto-p256.js (A2)' : ''));
    }
    var sig = await handler.sign(toUint8(data, 'signBytes data'), privateKey);
    return bytesToBase64url(sig);
  }

  // Verify a base64url signature over canonical bytes against a public key.
  // Returns true/false — never throws for a bad signature (a bad signature is
  // a REJECT, not an exception; CRYPTO-DESIGN §7 step 5). Throws only for
  // malformed inputs (bad base64url, unknown sig_alg with no handler).
  async function verifySignature(data, sigBase64url, publicKey, sigAlg) {
    var alg = sigAlg || SIG_ALG_ED25519;
    var handler = sigAlgs[alg];
    if (!handler) {
      throw CryptoError('UNKNOWN_SIG_ALG',
        'no verification handler registered for sig_alg "' + alg + '"' +
        (alg === SIG_ALG_ES256 ? ' — load app/js/crypto-p256.js (A2)' : ''));
    }
    var sig = base64urlToBytes(sigBase64url); // strict: rejects padding / bad chars
    return handler.verify(toUint8(data, 'verifySignature data'), sig, publicKey);
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
    RSA_MODULUS_LENGTH: RSA_MODULUS_LENGTH,
    ENC_KEY_BYTES: ENC_KEY_BYTES,
    MAC_KEY_BYTES: MAC_KEY_BYTES,
    IV_BYTES: IV_BYTES,
    MAC_BYTES: MAC_BYTES,
    MAX_PLAINTEXT_BYTES: MAX_PLAINTEXT_BYTES,

    // Encoding
    bytesToBase64url: bytesToBase64url,
    base64urlToBytes: base64urlToBytes,
    bytesToHex: bytesToHex,
    hexToBytes: hexToBytes,
    textToBytes: textToBytes,
    bytesToText: bytesToText,
    concatBytes: concatBytes,
    randomBytes: randomBytes,
    constantTimeEqual: constantTimeEqual,
    toUint8: toUint8,

    // PEM / DER
    derToPem: derToPem,
    pemToDer: pemToDer,
    fingerprintPublicKey: fingerprintPublicKey,

    // Key generation
    generateEncryptionKeypair: generateEncryptionKeypair,
    generateSigningKeypair: generateSigningKeypair,
    supportsEd25519: supportsEd25519,

    // Key import / export
    importEncryptionPublicKey: importEncryptionPublicKey,
    importSigningPublicKey: importSigningPublicKey,
    importEncryptionPublicKeyJwk: importEncryptionPublicKeyJwk,
    importSigningPublicKeyJwk: importSigningPublicKeyJwk,
    importEncryptionPrivateKey: importEncryptionPrivateKey,
    importSigningPrivateKey: importSigningPrivateKey,
    importAesKey: importAesKey,
    importHmacKey: importHmacKey,
    exportPublicKeyPem: exportPublicKeyPem,
    exportPublicKeyDer: exportPublicKeyDer,
    exportPublicKeyJwk: exportPublicKeyJwk,
    exportPrivateKeyJwk: exportPrivateKeyJwk,
    exportPrivateKeyPem: exportPrivateKeyPem,

    // Symmetric layer (§3)
    encryptMessage: encryptMessage,
    decryptMessage: decryptMessage,

    // Signing (§4)
    signEd25519: signEd25519,
    verifyEd25519: verifyEd25519,
    signBytes: signBytes,
    verifySignature: verifySignature,
    registerSigAlg: registerSigAlg,

    CryptoError: CryptoError
  };
});
