/**
 * crypto-p256.js — ES256 (ECDSA P-256 / SHA-256) fallback for the encrypted chat.
 *
 * ecc-1 envelope, FILE-MAP.md D6 + CRYPTO-DESIGN.md §4.4 (normative), §6.2, §7.
 *
 *   - Ed25519 is the PRIMARY signing scheme for every participant.
 *   - ES256 is the fallback for OLDER BROWSERS ONLY. It is triggered exactly
 *     when the browser's `crypto.subtle.generateKey({ name: "Ed25519" })`
 *     rejects (feature-detect at key-generation time; a modern browser never
 *     triggers it). A sender has exactly ONE pinned `sig_alg` (per-sender,
 *     not per-message); receivers must accept both `Ed25519` and `ES256`,
 *     and MUST reject an envelope whose `sig_alg` does not match the sender's
 *     pinned `sig_alg` (no silent downgrade — that check lives in the
 *     envelope verifier, A4, against participants.json; this module only
 *     supplies the primitives and the `sig_alg` value to pin).
 *
 * Wire format (normative, §4.4 / FILE-MAP §3):
 *   - ES256 signature in the envelope is RAW `R || S`, exactly 64 bytes,
 *     base64url, no padding. NEVER DER in the envelope.
 *   - WebCrypto `subtle.sign({ name: "ECDSA", hash: "SHA-256" })` returns
 *     raw R||S natively (JWS ES256), so no conversion is needed on the
 *     browser side. The DER<->raw converters below exist ONLY for interop
 *     with the Jarvis (openssl `dgst -sha256 -verify`, which expects DER)
 *     and ChatGPT (`cryptography`, which emits DER) sides — they never
 *     touch the envelope bytes.
 *   - ES256 signs SHA-256 of the canonical JSON bytes (WebCrypto ECDSA does
 *     the hashing internally). Ed25519 signs the canonical bytes directly
 *     (no pre-hash). Do not pre-hash for Ed25519.
 *
 * No external dependencies. WebCrypto only. Works in a secure context
 * (HTTPS / localhost) — WebCrypto is unavailable otherwise.
 * No private-key material, plaintext, secrets, or personal info in this file.
 * Exposed as `window.GhostCorpP256` (browser) and `module.exports` (Node,
 * for testing only — the app loads it as a plain <script>).
 *
 * Companion modules (separate workers, separate files):
 *   crypto-core.js    — RSA-OAEP / AES-CBC+HMAC / Ed25519 primitives (A1)
 *   canonical-json.js — canonical JSON, byte-identical to Python (A3)
 *   envelope.js       — envelope build/parse/validate, incl. sig_alg pin
 *                       check and verification order §7 (A4)
 * This module is self-contained (its own base64url helpers) so it does not
 * depend on A1 having landed first.
 */
(function (global) {
  'use strict';

  /* ------------------------------------------------------------------ */
  /* Constants                                                           */
  /* ------------------------------------------------------------------ */

  var SIG_ALG_ED25519 = 'Ed25519';
  var SIG_ALG_ES256 = 'ES256';
  var SUPPORTED_SIG_ALGS = [SIG_ALG_ED25519, SIG_ALG_ES256];

  /** Raw signature length for both schemes: Ed25519 64 B, ES256 R||S 64 B. */
  var RAW_SIG_LEN = 64;
  /** One ECDSA coordinate (P-256 field element) in bytes. */
  var COORD_LEN = 32;
  var NAMED_CURVE = 'P-256';

  /* ------------------------------------------------------------------ */
  /* Small helpers                                                       */
  /* ------------------------------------------------------------------ */

  function subtle() {
    if (!global.crypto || !global.crypto.subtle) {
      throw new Error('WebCrypto subtle is unavailable (needs a secure context: HTTPS or localhost)');
    }
    return global.crypto.subtle;
  }

  function isWebCryptoAvailable() {
    try {
      return !!(global.crypto && global.crypto.subtle &&
        typeof global.crypto.subtle.generateKey === 'function');
    } catch (e) {
      return false;
    }
  }

  function toBytes(data, name) {
    if (data instanceof Uint8Array) return data;
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (typeof data === 'string') return new TextEncoder().encode(data);
    throw new TypeError((name || 'data') + ' must be a Uint8Array, ArrayBuffer, or string');
  }

  function bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  function isSupportedSigAlg(sigAlg) {
    return sigAlg === SIG_ALG_ED25519 || sigAlg === SIG_ALG_ES256;
  }

  function inferSigAlgFromKey(key) {
    if (!key || !key.algorithm || typeof key.algorithm.name !== 'string') {
      throw new TypeError('key has no algorithm name');
    }
    if (key.algorithm.name === 'Ed25519') return SIG_ALG_ED25519;
    if (key.algorithm.name === 'ECDSA') return SIG_ALG_ES256;
    throw new Error('unsupported signing key algorithm: ' + key.algorithm.name);
  }

  /* ------------------------------------------------------------------ */
  /* base64url (RFC 4648 §5, no padding) — strict decode.                */
  /* Decoders reject non-canonical input (padding, or chars outside the  */
  /* alphabet) rather than silently accepting standard base64 (§6.3).    */
  /* ------------------------------------------------------------------ */

  var B64U_RE = /^[A-Za-z0-9_-]*$/;

  function base64urlEncode(bytes) {
    var b = toBytes(bytes, 'bytes');
    var bin = '';
    for (var i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]);
    return global.btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function base64urlDecode(str) {
    if (typeof str !== 'string' || !B64U_RE.test(str)) {
      throw new Error('invalid base64url: characters outside the alphabet');
    }
    if (str.indexOf('=') !== -1) {
      throw new Error('invalid base64url: padding is not allowed');
    }
    // A canonical base64url string never has length % 4 == 1.
    if (str.length % 4 === 1) {
      throw new Error('invalid base64url: non-canonical length');
    }
    var std = str.replace(/-/g, '+').replace(/_/g, '/');
    while (std.length % 4 !== 0) std += '=';
    var bin = global.atob(std);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    // Re-encode and compare: rejects non-canonical trailing bits.
    if (base64urlEncode(out) !== str) {
      throw new Error('invalid base64url: non-canonical encoding');
    }
    return out;
  }

  /** Decode an envelope `sig` field: must be exactly 64 raw bytes. */
  function base64urlDecodeSignature(str) {
    var raw = base64urlDecode(str);
    if (raw.length !== RAW_SIG_LEN) {
      throw new Error('invalid signature: expected 64 bytes, got ' + raw.length);
    }
    return raw;
  }

  /* ------------------------------------------------------------------ */
  /* Feature detection — §4.4 trigger                                     */
  /*                                                                     */
  /* The ONLY trigger for the ES256 fallback is Ed25519 keygen           */
  /* rejecting. This function performs that probe with a throwaway key   */
  /* (generated, never stored, immediately discarded) and caches the     */
  /* result. A modern browser returns true and never falls back.         */
  /* ------------------------------------------------------------------ */

  var _ed25519SupportCache = null; // null = unknown, else boolean

  function detectEd25519Support() {
    if (_ed25519SupportCache !== null) return Promise.resolve(_ed25519SupportCache);
    var s;
    try {
      s = subtle();
    } catch (e) {
      _ed25519SupportCache = false;
      return Promise.resolve(false);
    }
    return s.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify'])
      .then(function () { _ed25519SupportCache = true; return true; })
      .catch(function () { _ed25519SupportCache = false; return false; });
  }

  /* ------------------------------------------------------------------ */
  /* Key generation                                                      */
  /*                                                                     */
  /* extractable defaults to false (CRYPTO-DESIGN §13.1: private keys    */
  /* extractable:false where possible, stored via IndexedDB). Pass       */
  /* { extractable: true } only when the caller must export the key     */
  /* (e.g. the passphrase-encrypted backup flow, C11) — never by        */
  /* default, and never to put a private key in the store or a doc.      */
  /* ------------------------------------------------------------------ */

  function generateEd25519Keypair(options) {
    var extractable = !!(options && options.extractable);
    return subtle().generateKey(
      { name: 'Ed25519' },
      extractable,
      ['sign', 'verify']
    );
  }

  function generateP256Keypair(options) {
    var extractable = !!(options && options.extractable);
    return subtle().generateKey(
      { name: 'ECDSA', namedCurve: NAMED_CURVE },
      extractable,
      ['sign', 'verify']
    );
  }

  /**
   * Generate this participant's signing keypair (the §4.4 decision point).
   *
   * Tries Ed25519 first. Falls back to P-256 ONLY when Ed25519 keygen
   * rejects. Returns { privateKey, publicKey, sigAlg } where sigAlg is
   * 'Ed25519' or 'ES256' — the value this participant registers/pins in
   * participants.json (`sig_alg`). Fallback is per-sender, not per-message:
   * call once at setup, pin the returned sigAlg, then always sign with it.
   *
   * options:
   *   extractable   — as above (default false)
   *   preferred     — 'Ed25519' (default) or 'ES256'. 'ES256' skips the
   *                   Ed25519 attempt (testing / explicit opt-in only);
   *                   it is NOT a silent downgrade — the pinned sig_alg
   *                   still records 'ES256' and receivers check it.
   *   forceFallback — test-only: behave as if Ed25519 keygen rejected,
   *                   exercising the fallback path on a modern browser.
   *                   Never set in production.
   */
  function generateSigningKeypair(options) {
    options = options || {};
    var extractable = !!options.extractable;
    if (options.preferred === SIG_ALG_ES256 || options.forceFallback) {
      return generateP256Keypair({ extractable: extractable }).then(function (kp) {
        return { privateKey: kp.privateKey, publicKey: kp.publicKey, sigAlg: SIG_ALG_ES256 };
      });
    }
    return generateEd25519Keypair({ extractable: extractable })
      .then(function (kp) {
        return { privateKey: kp.privateKey, publicKey: kp.publicKey, sigAlg: SIG_ALG_ED25519 };
      })
      .catch(function () {
        // §4.4 trigger: Ed25519 keygen rejected -> P-256 fallback.
        return generateP256Keypair({ extractable: extractable }).then(function (kp) {
          return { privateKey: kp.privateKey, publicKey: kp.publicKey, sigAlg: SIG_ALG_ES256 };
        });
      });
  }

  /* ------------------------------------------------------------------ */
  /* Sign / verify                                                       */
  /*                                                                     */
  /* `data` is the canonical JSON bytes (§6.2) as Uint8Array/ArrayBuffer */
  /* (A3 canonical-json.js produces them; callers must sign exactly     */
  /* those bytes — never a re-serialised envelope).                      */
  /*                                                                     */
  /* Ed25519: signs the bytes directly (no pre-hash).                    */
  /* ES256:   signs SHA-256 of the bytes; WebCrypto ECDSA hashes        */
  /*          internally, so the caller passes the raw canonical bytes. */
  /* Both return / accept exactly 64 raw bytes, never DER.              */
  /* ------------------------------------------------------------------ */

  function signEd25519(data, privateKey) {
    var bytes = toBytes(data, 'canonical bytes');
    return subtle().sign({ name: 'Ed25519' }, privateKey, bytes)
      .then(function (sig) {
        var raw = new Uint8Array(sig);
        if (raw.length !== RAW_SIG_LEN) {
          throw new Error('Ed25519 signature is not 64 bytes: ' + raw.length);
        }
        return raw;
      });
  }

  function signEs256(data, privateKey) {
    var bytes = toBytes(data, 'canonical bytes');
    return subtle().sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, bytes)
      .then(function (sig) {
        var raw = new Uint8Array(sig);
        if (raw.length === RAW_SIG_LEN) return raw;
        // Defensive only: WebCrypto ECDSA must return raw R||S. If an
        // engine ever returned DER, normalise it — the envelope still
        // carries raw R||S, never DER.
        if (isDerSignature(raw)) return derToRawSignature(raw);
        throw new Error('ECDSA signature is neither 64-byte raw nor DER: ' + raw.length + ' bytes');
      });
  }

  /**
   * Sign canonical bytes. sigAlg may be omitted (inferred from the key);
   * if given it must agree with the key's algorithm, else throw — a
   * caller must never sign ES256 bytes with an Ed25519 key or vice versa.
   * Returns a Promise<Uint8Array> of exactly 64 raw bytes.
   */
  function sign(data, privateKey, sigAlg) {
    var alg = sigAlg || inferSigAlgFromKey(privateKey);
    if (!isSupportedSigAlg(alg)) throw new Error('unknown sig_alg: ' + alg);
    if (sigAlg && inferSigAlgFromKey(privateKey) !== alg) {
      throw new Error('sig_alg ' + alg + ' does not match signing key algorithm');
    }
    if (alg === SIG_ALG_ES256) return signEs256(data, privateKey);
    return signEd25519(data, privateKey);
  }

  function verifyEd25519(data, signature, publicKey) {
    var bytes = toBytes(data, 'canonical bytes');
    var sig = toBytes(signature, 'signature');
    if (sig.length !== RAW_SIG_LEN) return Promise.resolve(false);
    return subtle().verify({ name: 'Ed25519' }, publicKey, sig, bytes)
      .then(function (ok) { return !!ok; })
      .catch(function () { return false; });
  }

  function verifyEs256(data, signature, publicKey) {
    var bytes = toBytes(data, 'canonical bytes');
    var sig = toBytes(signature, 'signature');
    // Envelope signatures are raw R||S only. A DER signature here is a
    // protocol violation, not a format to accept — reject, fail closed.
    if (sig.length !== RAW_SIG_LEN) return Promise.resolve(false);
    return subtle().verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, sig, bytes)
      .then(function (ok) { return !!ok; })
      .catch(function () { return false; });
  }

  /**
   * Verify a 64-byte raw signature over canonical bytes. sigAlg may be
   * omitted (inferred from the key). Returns Promise<boolean>; false on
   * any verification failure or malformed signature — never throws for a
   * bad signature. (Throws TypeError only for wrong argument types.)
   * The caller (A4 envelope.js) must check the envelope's sig_alg
   * against the sender's PINNED sig_alg BEFORE calling this — this
   * function verifies the bytes, it does not enforce pinning.
   */
  function verify(data, signature, publicKey, sigAlg) {
    var alg = sigAlg || inferSigAlgFromKey(publicKey);
    if (!isSupportedSigAlg(alg)) throw new Error('unknown sig_alg: ' + alg);
    if (sigAlg && inferSigAlgFromKey(publicKey) !== alg) return Promise.resolve(false);
    if (alg === SIG_ALG_ES256) return verifyEs256(data, signature, publicKey);
    return verifyEd25519(data, signature, publicKey);
  }

  /* ------------------------------------------------------------------ */
  /* DER <-> raw R||S conversion (interop ONLY — never in the envelope)  */
  /*                                                                     */
  /* DER form: SEQUENCE { INTEGER r, INTEGER s }, each INTEGER possibly  */
  /* 0x00-padded to keep it positive. Raw form: r and s each left-      */
  /* padded to exactly 32 bytes, concatenated (64 bytes total).         */
  /* Round-trip is byte-identical (CRYPTO-TEST-VECTORS.md run 1, §2.4). */
  /* ------------------------------------------------------------------ */

  function isDerSignature(bytes) {
    var b = toBytes(bytes, 'signature');
    return b.length >= 8 && b[0] === 0x30;
  }

  function _readDerLength(b, pos) {
    var len = b[pos++];
    if (len < 0x80) return { length: len, next: pos };
    var n = len & 0x7f;
    if (n === 0 || n > 2) throw new Error('unsupported DER length encoding');
    var v = 0;
    for (var i = 0; i < n; i++) v = (v << 8) | b[pos++];
    return { length: v, next: pos };
  }

  function _readDerInteger(b, pos) {
    if (b[pos++] !== 0x02) throw new Error('DER signature: expected INTEGER');
    var l = _readDerLength(b, pos);
    var start = l.next;
    var end = start + l.length;
    if (end > b.length) throw new Error('DER signature: INTEGER overruns input');
    var intBytes = b.slice(start, end);
    // Strip leading 0x00 pads (sign-bit padding), keep at least one byte.
    var i = 0;
    while (i < intBytes.length - 1 && intBytes[i] === 0x00) i++;
    var stripped = intBytes.slice(i);
    if (stripped.length > COORD_LEN) throw new Error('DER signature: INTEGER exceeds 32 bytes');
    return { value: stripped, next: end };
  }

  function derToRawSignature(der) {
    var b = toBytes(der, 'DER signature');
    if (!isDerSignature(b)) throw new Error('not a DER signature (expected 0x30 SEQUENCE)');
    var seq = _readDerLength(b, 1);
    if (seq.next + seq.length !== b.length) {
      throw new Error('DER signature: trailing bytes after SEQUENCE');
    }
    var r = _readDerInteger(b, seq.next);
    var s = _readDerInteger(b, r.next);
    if (s.next !== b.length) throw new Error('DER signature: trailing bytes after INTEGER s');
    var raw = new Uint8Array(RAW_SIG_LEN);
    raw.set(r.value, COORD_LEN - r.value.length);
    raw.set(s.value, COORD_LEN + (COORD_LEN - s.value.length));
    return raw;
  }

  function _derEncodeInteger(coord) {
    // coord: Uint8Array, up to 32 bytes, leading zeros already stripped
    // except a single zero byte is kept if the value is zero.
    var i = 0;
    while (i < coord.length - 1 && coord[i] === 0x00) i++;
    var v = coord.slice(i);
    var needsPad = (v[0] & 0x80) !== 0;
    var out = new Uint8Array(2 + v.length + (needsPad ? 1 : 0));
    out[0] = 0x02;
    out[1] = v.length + (needsPad ? 1 : 0);
    var at = 2;
    if (needsPad) out[at++] = 0x00;
    out.set(v, at);
    return out;
  }

  function rawToDerSignature(raw) {
    var b = toBytes(raw, 'raw signature');
    if (b.length !== RAW_SIG_LEN) {
      throw new Error('raw signature must be 64 bytes, got ' + b.length);
    }
    var rDer = _derEncodeInteger(b.slice(0, COORD_LEN));
    var sDer = _derEncodeInteger(b.slice(COORD_LEN));
    var bodyLen = rDer.length + sDer.length;
    var der;
    if (bodyLen < 0x80) {
      der = new Uint8Array(2 + bodyLen);
      der[0] = 0x30;
      der[1] = bodyLen;
      der.set(rDer, 2);
      der.set(sDer, 2 + rDer.length);
    } else {
      // Total is at most 2 + 35 + 35 = 72, so one long-form length byte.
      der = new Uint8Array(3 + bodyLen);
      der[0] = 0x30;
      der[1] = 0x81;
      der[2] = bodyLen;
      der.set(rDer, 3);
      der.set(sDer, 3 + rDer.length);
    }
    return der;
  }

  /* ------------------------------------------------------------------ */
  /* Key import / export (P-256)                                         */
  /*                                                                     */
  /* SPKI (public) / PKCS#8 (private) DER is the interchange form used   */
  /* for fingerprints and for the Jarvis/ChatGPT sides; JWK is the      */
  /* IndexedDB-friendly form. Ed25519 import/export lives in A1          */
  /* (crypto-core.js) — this module covers only the P-256 fallback keys. */
  /* ------------------------------------------------------------------ */

  function importP256PublicKeySpki(spkiDer) {
    return subtle().importKey(
      'spki', toBytes(spkiDer, 'SPKI DER'), { name: 'ECDSA', namedCurve: NAMED_CURVE },
      true, ['verify']
    );
  }

  function importP256PublicKeyJwk(jwk) {
    if (!jwk || jwk.kty !== 'EC' || jwk.crv !== NAMED_CURVE) {
      throw new TypeError('not a P-256 JWK public key');
    }
    return subtle().importKey(
      'jwk', jwk, { name: 'ECDSA', namedCurve: NAMED_CURVE },
      true, ['verify']
    );
  }

  function importP256PrivateKeyPkcs8(pkcs8Der, extractable) {
    return subtle().importKey(
      'pkcs8', toBytes(pkcs8Der, 'PKCS#8 DER'), { name: 'ECDSA', namedCurve: NAMED_CURVE },
      !!extractable, ['sign']
    );
  }

  function importP256PrivateKeyJwk(jwk, extractable) {
    if (!jwk || jwk.kty !== 'EC' || jwk.crv !== NAMED_CURVE || typeof jwk.d !== 'string') {
      throw new TypeError('not a P-256 JWK private key');
    }
    return subtle().importKey(
      'jwk', jwk, { name: 'ECDSA', namedCurve: NAMED_CURVE },
      !!extractable, ['sign']
    );
  }

  function exportP256PublicKeySpki(publicKey) {
    return subtle().exportKey('spki', publicKey).then(function (der) { return new Uint8Array(der); });
  }

  function exportP256PublicKeyJwk(publicKey) {
    return subtle().exportKey('jwk', publicKey);
  }

  function exportP256PrivateKeyPkcs8(privateKey) {
    return subtle().exportKey('pkcs8', privateKey).then(function (der) { return new Uint8Array(der); });
  }

  function exportP256PrivateKeyJwk(privateKey) {
    return subtle().exportKey('jwk', privateKey);
  }

  /* ------------------------------------------------------------------ */
  /* Fingerprint + PEM helpers                                           */
  /*                                                                     */
  /* Fingerprint = SHA-256 hex of DER SPKI (CRYPTO-DESIGN §2.1/§9) —    */
  /* the same computation openssl uses; this is what the owner confirms  */
  /* out-of-band before pinning.                                         */
  /* ------------------------------------------------------------------ */

  function _bytesToHex(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) {
      out += ('0' + bytes[i].toString(16)).slice(-2);
    }
    return out;
  }

  function _pemEncode(label, derBytes) {
    var b64 = global.btoa(String.fromCharCode.apply(null, derBytes));
    var lines = b64.match(/.{1,64}/g) || [];
    return '-----BEGIN ' + label + '-----\n' + lines.join('\n') + '\n-----END ' + label + '-----\n';
  }

  function pemToDer(pem) {
    if (typeof pem !== 'string') throw new TypeError('PEM must be a string');
    var b64 = pem.replace(/-----BEGIN [^-]+-----/g, '')
      .replace(/-----END [^-]+-----/g, '')
      .replace(/\s+/g, '');
    if (!/^[A-Za-z0-9+/=]*$/.test(b64)) throw new Error('invalid PEM base64');
    var bin = global.atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function computeSpkiFingerprint(publicKey) {
    return exportP256PublicKeySpki(publicKey)
      .then(function (der) { return subtle().digest('SHA-256', der); })
      .then(function (hash) { return _bytesToHex(new Uint8Array(hash)); });
  }

  function exportP256PublicKeyPem(publicKey) {
    return exportP256PublicKeySpki(publicKey).then(function (der) {
      return _pemEncode('PUBLIC KEY', der);
    });
  }

  /* ------------------------------------------------------------------ */
  /* Self-registration with crypto-core (P2)                           */
  /*                                                                     */
  /* crypto-core.js dispatches sign/verify on sig_alg through its       */
  /* registerSigAlg() registry, and registers Ed25519 itself — but it   */
  /* knows nothing about ES256. This module therefore registers its     */
  /* own ES256 handlers on load, so GhostChatCrypto.signBytes() /       */
  /* verifySignature() can reach ES256 without any caller wiring.       */
  /*                                                                     */
  /* Guards:                                                             */
  /*   - No-op when crypto-core is not loaded yet (browser: the page     */
  /*     loads this file before crypto-core.js, or not at all). The      */
  /*     caller can retry later via the exported registerWithCore().     */
  /*   - No-op when already registered (idempotent; re-registering      */
  /*     would just overwrite the same handlers).                        */
  /*   - Never throws at load: a failed registration leaves the module  */
  /*     fully usable standalone (its own sign/verify still work).      */
  /*                                                                     */
  /* Handler shape (crypto-core registerSigAlg contract):                */
  /*   sign(data, privateKey) -> Promise<Uint8Array> (64 raw bytes)     */
  /*   verify(data, signature, publicKey) -> Promise<boolean>            */
  /* Both delegate to this module's existing P-256 implementation.       */
  /* ------------------------------------------------------------------ */

  var _es256Registered = false;

  function _es256Handlers() {
    return {
      sign: function (data, privateKey) { return signEs256(data, privateKey); },
      verify: function (data, signature, publicKey) { return verifyEs256(data, signature, publicKey); }
    };
  }

  /**
   * Register the ES256 handlers on a crypto-core instance.
   *
   * core: a GhostChatCrypto object (optional). When omitted, looks for
   *   global.GhostChatCrypto (browser: window.GhostChatCrypto, set when
   *   crypto-core.js loads as a plain <script>) and, under Node/CommonJS,
   *   falls back to require('./crypto-core.js') — the same module the
   *   test harness loads, so registration lands on the shared instance.
   * Returns true when ES256 is registered (including already-registered),
   * false when no crypto-core instance could be found. Never throws.
   */
  function registerWithCore(core) {
    if (_es256Registered) return true;
    var c = core || null;
    if (!c && global.GhostChatCrypto &&
        typeof global.GhostChatCrypto.registerSigAlg === 'function') {
      c = global.GhostChatCrypto;
    }
    if (!c && typeof require === 'function') {
      try { c = require('./crypto-core.js'); } catch (e) { c = null; }
    }
    if (!c || typeof c.registerSigAlg !== 'function') return false;
    c.registerSigAlg(SIG_ALG_ES256, _es256Handlers());
    _es256Registered = true;
    return true;
  }

  function isEs256Registered() {
    return _es256Registered;
  }

  // Attempt self-registration on load; silently a no-op when crypto-core
  // is not loaded yet (call registerWithCore() after both scripts load).
  try { registerWithCore(); } catch (e) { /* leave unregistered; retry later */ }

  /* ------------------------------------------------------------------ */
  /* Public API                                                          */
  /* ------------------------------------------------------------------ */

  var api = {
    // Constants
    SIG_ALG_ED25519: SIG_ALG_ED25519,
    SIG_ALG_ES256: SIG_ALG_ES256,
    SUPPORTED_SIG_ALGS: SUPPORTED_SIG_ALGS,
    RAW_SIG_LEN: RAW_SIG_LEN,
    NAMED_CURVE: NAMED_CURVE,

    // Environment / feature detection
    isWebCryptoAvailable: isWebCryptoAvailable,
    detectEd25519Support: detectEd25519Support,
    isSupportedSigAlg: isSupportedSigAlg,
    inferSigAlgFromKey: inferSigAlgFromKey,

    // Key generation (§4.4)
    generateEd25519Keypair: generateEd25519Keypair,
    generateP256Keypair: generateP256Keypair,
    generateSigningKeypair: generateSigningKeypair,

    // Sign / verify (raw 64-byte wire format, never DER in the envelope)
    sign: sign,
    signEd25519: signEd25519,
    signEs256: signEs256,
    verify: verify,
    verifyEd25519: verifyEd25519,
    verifyEs256: verifyEs256,

    // DER <-> raw conversion (interop only: openssl / cryptography sides)
    derToRawSignature: derToRawSignature,
    rawToDerSignature: rawToDerSignature,
    isDerSignature: isDerSignature,

    // base64url (strict, no padding)
    base64urlEncode: base64urlEncode,
    base64urlDecode: base64urlDecode,
    base64urlDecodeSignature: base64urlDecodeSignature,

    // P-256 key import / export
    importP256PublicKeySpki: importP256PublicKeySpki,
    importP256PublicKeyJwk: importP256PublicKeyJwk,
    importP256PrivateKeyPkcs8: importP256PrivateKeyPkcs8,
    importP256PrivateKeyJwk: importP256PrivateKeyJwk,
    exportP256PublicKeySpki: exportP256PublicKeySpki,
    exportP256PublicKeyJwk: exportP256PublicKeyJwk,
    exportP256PrivateKeyPkcs8: exportP256PrivateKeyPkcs8,
    exportP256PrivateKeyJwk: exportP256PrivateKeyJwk,

    // Fingerprint / PEM
    computeSpkiFingerprint: computeSpkiFingerprint,
    exportP256PublicKeyPem: exportP256PublicKeyPem,
    pemToDer: pemToDer,

    // Self-registration with crypto-core (P2): ES256 handlers for
    // GhostChatCrypto.signBytes()/verifySignature(). registerWithCore()
    // is also the retry path when this file loads before crypto-core.js.
    registerWithCore: registerWithCore,
    isEs256Registered: isEs256Registered
  };

  global.GhostCorpP256 = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;

})(typeof globalThis !== 'undefined' ? globalThis : this);
