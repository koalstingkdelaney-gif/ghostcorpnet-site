// Encrypted chat — verification badges (worker C10, wave 2).
//
// Single export: badgeFor(envelope, context) -> Promise<result>.
// Computes ONE verification badge per message, LOCALLY, at render time,
// from the raw envelope + the local key directory + the local seen-ledger
// state. A relay-supplied verdict is NEVER trusted: the relay returns raw
// envelopes, and this module re-does every check itself (UI-SPEC §2.3 rule).
//
// Sources (FILE-MAP is authoritative; it wins where docs conflict):
//   FILE-MAP §3  — envelope "ecc-1" (§6.1 fields), canonical JSON, §7
//                  verification order, §9 key directory, §8 replay ledger.
//   FILE-MAP D5/D6/D9/D10 — CBC+HMAC (not GCM), Ed25519 primary / ES256
//                  fallback, all-three recipients default, 24 h TTL max.
//   FILE-MAP §4 C10 — the badge set (this file adds "? Unverified", which
//                  the task brief specifies and FILE-MAP C10 omits; see
//                  "Conflicts" below).
//   CRYPTO-DESIGN §7 — verification order, mirrored step for step.
//   UI-SPEC §2.3 — badge table, body behaviour, detail-sheet needs;
//                  §2.5 "Re-verify now"; §6 dedup / pending-vs-polled.
//
// Badges (exactly one per call; `result.badge` is the label, `result.status`
// is the machine-readable code):
//   "✓ Signed"           status "signed"         — every §7 check passed.
//   "⚠ Expired"          status "expired"        — exp has passed.
//   "⛔ Replay suspected" status "replay"         — msg_id already seen.
//   "⛔ Tampered"        status "tampered"       — shape invalid, signature
//                                                  fails, or HMAC fails.
//   "? Undecryptable"    status "undecryptable"   — no wrapped_keys entry
//                                                  for this recipient, or
//                                                  unwrap/decrypt fails
//                                                  after the signature passed.
//   "? Unverified"       status "unverified"     — sender unpinned, unknown,
//                                                  revoked, or sig_alg
//                                                  mismatch (no pinned key
//                                                  to verify against).
//
// Precedence = CRYPTO-DESIGN §7 first-failure order (FILE-MAP §3):
//   shape -> expiry -> pinned -> replay -> signature -> unwrap -> HMAC
//   -> decrypt -> Signed. The first failing step decides the badge.
//   In particular expiry is checked BEFORE the signature, and the replay
//   check BEFORE the signature, exactly as §7 orders them.
//
// What this module does NOT do:
//   - It never returns plaintext. Step 8 decrypts only to confirm the
//     plaintext parses per §6.4 ({"text": string}, <= 64 KiB); the
//     plaintext is then discarded. The thread view (C6) decrypts
//     separately for display; the audit view (C8) re-verifies via this
//     module. Nothing decrypted here ever leaves this function.
//   - It never touches the recipient private key before the signature has
//     verified (code order enforces §7: unwrap is step 6, signature step 5).
//     A message that fails signature verification never reaches the RSA
//     private key.
//   - It never writes to, or reads from, the seen-ledger file itself. The
//     caller passes the ledger state in (see "Caller contract" below) and
//     records the ID only on success, exactly as §7 step 8 requires.
//   - It has no network, storage, or DOM access. Pure computation over its
//     two arguments, plus WebCrypto (crypto.subtle).
//
// Caller contract (read this before wiring it into C6/C8/C9):
//   - context.me: the local participant id ("jarvis" | "chatgpt" |
//     "owner"). Defaults to "owner". The wrapped_keys entry looked up is
//     the one for `me`.
//   - context.keyDirectory: the local key directory — an array of
//     participant entries, or { participants: [...] }, or a Map keyed by
//     participant id. Each entry: { id, status, sig_alg, sig_pub_pem
//     and/or sig_pub_jwk, sig_fingerprint? }. Only status "pinned"
//     entries verify anything (FILE-MAP §9: revoked verifies nothing).
//   - context.seenIds: the seen-ledger state as it stood BEFORE this
//     envelope was first accepted — a Set, an Array, or an object with a
//     has(id) method. IMPORTANT: a message already accepted into the
//     ledger HAS its id recorded, so calling badgeFor on an already
//     accepted message with the live ledger will (correctly, per §7
//     step 4) report Replay. Call badgeFor when the envelope first
//     arrives, before recording its id; for re-verification of an
//     already-accepted message (UI-SPEC §2.3 "Verify all", §2.5
//     "Re-verify now") pass context.reverify = true, which skips the
//     replay step — the replay question was already settled at
//     acceptance time. The poller (C9) owns silent dedup of same-ID +
//     same-bytes re-deliveries before calling this module (UI-SPEC §6).
//   - context.privateKey (CryptoKey, RSA-OAEP, "decrypt" usage) OR
//     context.unwrapKey (async function: wk bytes -> 64-byte
//     ENC_KEY||MAC_KEY). One of them is needed for steps 6-8. If neither
//     is present (e.g. a visitor with no key in this browser), every
//     message whose signature passes reports "? Undecryptable" with
//     reason "no-private-key" — which is the UI-SPEC §4.2 Mode A
//     behaviour for keyless visitors. The signature is still verified
//     first, so a tampered message is still reported Tampered, never
//     silently shown as merely undecryptable.
//   - context.now: unix epoch seconds used for the expiry checks.
//     Defaults to Math.floor(Date.now() / 1000). Pass an explicit value
//     in tests; never pass a sender-supplied clock.
//   - context.ownerVerified (optional): a Set/Array of participant ids
//     the owner has marked verified out-of-band in this browser
//     (UI-SPEC §2.2). This does NOT change the primary badge: it is
//     reported as result.senderOwnerVerified so the thread view can
//     render UI-SPEC's second, smaller "⚠ Unverified key" tag alongside
//     "✓ Signed" when the sender is pinned but not owner-marked. Pinning
//     (protocol gate) and owner-marking (UI trust mark) are different
//     things; do not conflate them.
//   - The result object is { badge, status, reason, detail, sender,
//     msgId, senderOwnerVerified, checks }. `detail` is a plain-words
//     sentence for the message detail sheet; the canonical UI copy deck
//     (J1) owns the final user-visible strings, so C6/C8 should prefer
//     J1's strings when they land and treat `detail` as the fallback.
//     `checks` records per-step pass/fail (true/false/null = not
//     reached) for the detail sheet.
//   - badgeFor is async (WebCrypto). While awaiting it the view shows
//     UI-SPEC's transient "… Decrypting" placeholder; if it is still
//     pending after ~5 s the view falls back to "? Undecryptable" with a
//     Retry button (UI-SPEC §2.3). badgeFor itself never returns the
//     transient state.
//   - If WebCrypto is unavailable, or the browser cannot verify the
//     pinned sig_alg at all, badgeFor THROWS (it never fabricates a
//     badge from checks it could not run). The caller surfaces the
//     blocking "browser can't do the encryption" state (UI-SPEC §2.1d).
//   - The relay-added `seq` field (FILE-MAP §3: assigned on receipt, not
//     part of the signed bytes) is tolerated and stripped before shape
//     validation and canonicalisation. Any OTHER unknown field rejects
//     the envelope as malformed.
//
// Conflicts found (FILE-MAP wins; implemented to FILE-MAP, flagged here):
//   1. FILE-MAP §4 C10 lists five badges; the task brief adds a sixth,
//      "? Unverified" (sender unpinned / unknown). Implemented — the
//      sixth badge is §7 step 3 made visible.
//   2. UI-SPEC §2.3 defines "⚠ Expired" as "signature valid but the
//      message's expiry time has passed", which implies signature-first.
//      FILE-MAP §3 / CRYPTO-DESIGN §7 check expiry (step 2) BEFORE the
//      signature (step 5). Implemented to FILE-MAP: an expired message
//      reports Expired even if its signature would also fail.
//   3. UI-SPEC §2.3 puts "decryption produced garbage" under "⛔ Tampered".
//      The task brief (and §7 order) puts unwrap/decrypt failure AFTER a
//      passing signature under "? Undecryptable". Implemented to the
//      brief: post-signature decrypt failure is Undecryptable; only
//      signature and HMAC failures are Tampered.
//   4. UI-SPEC §2.3's "⚠ Unverified key" is a SECOND tag shown alongside
//      "✓ Signed" (owner-marked verification, §2.2). It is NOT one of
//      this module's six badges; it is exposed as
//      result.senderOwnerVerified for the view to render.
//   5. FILE-MAP §4 A1-A3 live under app/js/ while the C-series (this
//      file included) lives directly under app/. This module is
//      self-contained (it does not import app/js/canonical-json.js) so
//      it loads with no cross-file ordering dependency; its inline
//      canonicaliser must stay byte-identical to A3 (both are checked
//      against the run-2 canonical payload in CRYPTO-TEST-VECTORS.md).
//   6. ENGINE DIVERGENCE (found while testing, 2026-11-16, Node 24.22.1):
//      W3C WebCrypto ECDSA sign/verify uses DER signatures, but Node's
//      WebCrypto uses raw R || S (P1363) for both. The app runs in a
//      browser, so DER is tried first; raw is the fallback so the same
//      code also verifies under Node (test harness, Jarvis-side checks).
//      A2 (crypto-p256.js) and I11 (test-p256-fallback.py) should know:
//      a DER-only implementation fails under Node, a raw-only one fails
//      in browsers — both encodings must be accepted on verify.
//   7. TEST-VECTOR DEVIATION (CRYPTO-TEST-VECTORS.md §1, the published
//      primary vector): its envelope lists recipients ["test-recipient"]
//      without the sender, violating the normative FILE-MAP §3 rule
//      "recipients not containing sender -> reject", and its thread_id
//      is the placeholder "thread-test-0001", not a UUID. Per FILE-MAP
//      the recipients rule is enforced (the vector as published reports
//      Tampered/malformed); thread_id is checked as a non-empty string
//      only, so the vector's placeholder does not by itself reject it.
//      The vector's signature, HMAC, and decrypt still re-verify from
//      its published parts (see the /tmp harness, cases 35-40).
//
// No real keys, no plaintext conversation content, no secrets, and no
// personal info appear in this file. Test fixtures use throwaway keys
// only (see the /tmp test harness, never committed here). $0 spend.

"use strict";

// ---------------------------------------------------------------------------
// Badge labels (exact UI strings — UI-SPEC §2.3, task brief).
// ---------------------------------------------------------------------------

const BADGES = {
  signed: "✓ Signed",
  expired: "⚠ Expired",
  replay: "⛔ Replay suspected",
  tampered: "⛔ Tampered",
  undecryptable: "? Undecryptable",
  unverified: "? Unverified",
};

// Protocol constants (FILE-MAP §3 / CRYPTO-DESIGN §6, §11).
const ENVELOPE_VERSION = "ecc-1";
const ENVELOPE_ALG = "A256CBC-HS256";
const MAX_TTL_SECONDS = 86400; // 24 h, default AND maximum (FILE-MAP D10).
const FUTURE_TOLERANCE_SECONDS = 300; // iat beyond now + 300 -> reject.
const MAX_PLAINTEXT_BYTES = 65536; // 64 KiB inner plaintext (§6.4).
const MAX_RECIPIENTS = 10;
const UUID_V4_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const B64URL_RE = /^[A-Za-z0-9_-]*$/;

// Exact envelope field set (§6.1). `seq` is the single tolerated extra
// field: the relay adds it on receipt and it is never part of the signed
// bytes (FILE-MAP §3). Any other unknown field -> malformed.
const ENVELOPE_FIELDS = [
  "v", "msg_id", "sender", "recipients", "iat", "exp", "reply_to",
  "thread_id", "alg", "sig_alg", "iv", "ct", "mac", "wrapped_keys", "sig",
];

const _textEncoder = new TextEncoder();
const _textDecoder = new TextDecoder("utf-8", { fatal: true });

// ---------------------------------------------------------------------------
// Small encoding helpers (strict base64url, PEM, hex).
// ---------------------------------------------------------------------------

function _b64Encode(bytes) {
  // bytes -> standard base64 (with padding). btoa is available in browsers
  // and in Node >= 16; Buffer is the fallback.
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  if (typeof globalThis.btoa === "function") return globalThis.btoa(binary);
  return Buffer.from(binary, "latin1").toString("base64");
}

function _b64Decode(str) {
  // standard base64 -> Uint8Array, or null on invalid input.
  try {
    let binary;
    if (typeof globalThis.atob === "function") binary = globalThis.atob(str);
    else binary = Buffer.from(str, "base64").toString("latin1");
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  } catch (_e) {
    return null;
  }
}

function encodeB64url(bytes) {
  return _b64Encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeB64url(str) {
  // Strict base64url, no padding (RFC 4648 §5, CRYPTO-DESIGN §6.3):
  // reject padding, characters outside the alphabet, and a length that
  // can never decode (length % 4 === 1). A re-encode round-trip rejects
  // non-canonical trailing bits.
  if (typeof str !== "string" || !B64URL_RE.test(str)) return null;
  if (str.length % 4 === 1) return null;
  const padded = str.replace(/-/g, "+").replace(/_/g, "/") +
    "==".slice(0, (4 - (str.length % 4)) % 4);
  const bytes = _b64Decode(padded);
  if (bytes === null) return null;
  if (encodeB64url(bytes) !== str) return null;
  return bytes;
}

function pemToDer(pem) {
  if (typeof pem !== "string") return null;
  const body = pem
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && line.indexOf("-----") !== 0)
    .join("");
  if (!/^[A-Za-z0-9+/=]+$/.test(body)) return null;
  return _b64Decode(body);
}

function bytesToHex(bytes) {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

// Constant-time equality (no early exit). Used for the HMAC comparison
// (CRYPTO-DESIGN §7 step 7: constant-time).
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ---------------------------------------------------------------------------
// Canonical JSON (RFC 8785 JCS subset, CRYPTO-DESIGN §6.2 / FILE-MAP §3).
// Keys sorted lexicographically by UTF-8 byte order; separators "," and
// ":"; strings raw UTF-8 (no \u escaping except JSON-mandatory escapes);
// integers plain decimal; null as null. Must stay byte-identical to
// app/js/canonical-json.js (A3); both are checked against the run-2
// canonical payload in CRYPTO-TEST-VECTORS.md.
// ---------------------------------------------------------------------------

function _compareUtf8(a, b) {
  const ab = _textEncoder.encode(a);
  const bb = _textEncoder.encode(b);
  const n = Math.min(ab.length, bb.length);
  for (let i = 0; i < n; i++) {
    if (ab[i] !== bb[i]) return ab[i] - bb[i];
  }
  return ab.length - bb.length;
}

function canonicalize(value) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "string") return JSON.stringify(value);
  if (t === "number") {
    if (!Number.isFinite(value)) throw new Error("canonicalize: non-finite number");
    return JSON.stringify(value);
  }
  if (t === "boolean") return value ? "true" : "false";
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalize).join(",") + "]";
  }
  if (t === "object") {
    const keys = Object.keys(value).sort(_compareUtf8);
    const parts = keys.map(
      (k) => JSON.stringify(k) + ":" + canonicalize(value[k])
    );
    return "{" + parts.join(",") + "}";
  }
  throw new Error("canonicalize: unsupported value");
}

// ---------------------------------------------------------------------------
// ES256 wire conversion: WebCrypto ECDSA verify expects a DER signature;
// the envelope carries raw R || S (64 bytes, CRYPTO-DESIGN §4.4).
// ---------------------------------------------------------------------------

function _trimLeadingZeros(bytes) {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  return bytes.subarray(i);
}

function rawSigToDer(raw) {
  // raw: 64 bytes R || S, each 32 bytes big-endian.
  let r = _trimLeadingZeros(raw.subarray(0, 32));
  let s = _trimLeadingZeros(raw.subarray(32, 64));
  // An INTEGER with its high bit set needs a 0x00 prefix in DER.
  if (r[0] & 0x80) r = _concatBytes(new Uint8Array([0]), r);
  if (s[0] & 0x80) s = _concatBytes(new Uint8Array([0]), s);
  const innerLen = 2 + r.length + 2 + s.length;
  const out = new Uint8Array(2 + innerLen);
  let o = 0;
  out[o++] = 0x30; // SEQUENCE
  out[o++] = innerLen;
  out[o++] = 0x02; // INTEGER
  out[o++] = r.length;
  out.set(r, o); o += r.length;
  out[o++] = 0x02; // INTEGER
  out[o++] = s.length;
  out.set(s, o); o += s.length;
  return out;
}

function _concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

// ---------------------------------------------------------------------------
// Context normalisation.
// ---------------------------------------------------------------------------

function _normalizeKeyDirectory(keyDirectory) {
  // Accepts: array of entries | { participants: [...] } | Map id -> entry.
  // Returns a Map keyed by participant id (first entry wins on duplicates).
  const map = new Map();
  if (!keyDirectory) return map;
  let entries = null;
  if (Array.isArray(keyDirectory)) entries = keyDirectory;
  else if (Array.isArray(keyDirectory.participants)) entries = keyDirectory.participants;
  else if (typeof keyDirectory.get === "function") {
    for (const entry of keyDirectory.values()) {
      if (entry && typeof entry.id === "string" && !map.has(entry.id)) map.set(entry.id, entry);
    }
    return map;
  } else if (typeof keyDirectory === "object") {
    entries = Object.values(keyDirectory);
  }
  if (entries) {
    for (const entry of entries) {
      if (entry && typeof entry.id === "string" && !map.has(entry.id)) {
        map.set(entry.id, entry);
      }
    }
  }
  return map;
}

function _normalizeSeenIds(seenIds) {
  if (!seenIds) return { has: () => false };
  if (typeof seenIds.has === "function") return seenIds;
  if (Array.isArray(seenIds)) {
    const set = new Set(seenIds);
    return { has: (id) => set.has(id) };
  }
  return { has: () => false };
}

function _normalizeOwnerVerified(ownerVerified) {
  if (!ownerVerified) return new Set();
  if (ownerVerified instanceof Set) return ownerVerified;
  if (Array.isArray(ownerVerified)) return new Set(ownerVerified);
  if (typeof ownerVerified.has === "function") return ownerVerified;
  return new Set();
}

// ---------------------------------------------------------------------------
// Pinned-key import (Ed25519 primary, ES256 fallback — FILE-MAP D6).
// Returns { key, der } or throws an Error with a machine-readable `code`.
// ---------------------------------------------------------------------------

async function importPinnedSigningKey(entry) {
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!subtle) {
    const err = new Error("WebCrypto is unavailable in this context");
    err.code = "webcrypto-unavailable";
    throw err;
  }
  const sigAlg = entry.sig_alg;
  let key = null;
  let der = null;
  if (entry.sig_pub_jwk && typeof entry.sig_pub_jwk === "object") {
    const params = sigAlg === "ES256"
      ? { name: "ECDSA", namedCurve: "P-256" }
      : { name: "Ed25519" };
    try {
      key = await subtle.importKey("jwk", entry.sig_pub_jwk, params, true, ["verify"]);
    } catch (e) {
      const err = new Error("pinned signing key (JWK) cannot be imported");
      err.code = "key-unusable";
      err.cause = e;
      throw err;
    }
    // No DER available from a JWK import; fingerprint check is skipped.
    return { key, der: null };
  }
  der = pemToDer(entry.sig_pub_pem);
  if (der === null) {
    const err = new Error("pinned signing key (PEM) cannot be parsed");
    err.code = "key-unusable";
    throw err;
  }
  try {
    if (sigAlg === "ES256") {
      key = await subtle.importKey(
        "spki", der, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]
      );
    } else {
      key = await subtle.importKey("spki", der, { name: "Ed25519" }, true, ["verify"]);
    }
  } catch (e) {
    const err = new Error("pinned signing key cannot be imported");
    err.code = "key-unusable";
    err.cause = e;
    throw err;
  }
  return { key, der };
}

// ---------------------------------------------------------------------------
// Shape validation (§7 step 1 + §6.1). Returns { ok: true } or
// { ok: false, reason } — every failure here is "⛔ Tampered" (malformed).
// ---------------------------------------------------------------------------

function validateShape(env) {
  const fail = (reason) => ({ ok: false, reason });

  if (env === null || typeof env !== "object" || Array.isArray(env)) {
    return fail("malformed");
  }
  // `seq` is tolerated (relay-assigned, never signed) and stripped by the
  // caller before this runs; any other unknown field rejects (§6.1).
  const keys = Object.keys(env);
  for (const k of keys) {
    if (k !== "seq" && ENVELOPE_FIELDS.indexOf(k) === -1) return fail("malformed");
  }
  for (const f of ENVELOPE_FIELDS) {
    if (!(f in env)) return fail("malformed");
  }
  if (env.seq !== undefined && !Number.isInteger(env.seq)) return fail("malformed");

  if (env.v !== ENVELOPE_VERSION) return fail("malformed");
  if (env.alg !== ENVELOPE_ALG) return fail("malformed");
  if (env.sig_alg !== "Ed25519" && env.sig_alg !== "ES256") return fail("malformed");

  if (typeof env.msg_id !== "string" || !UUID_V4_RE.test(env.msg_id)) {
    return fail("malformed");
  }
  if (typeof env.sender !== "string" || env.sender.length === 0) {
    return fail("malformed");
  }
  if (typeof env.thread_id !== "string" || env.thread_id.length === 0) {
    // NOTE: deliberately NOT a UUID check. §6.1 defines thread_id as the
    // root msg_id (a UUID in production), but the published primary test
    // vector (CRYPTO-TEST-VECTORS.md §1.4) uses the placeholder string
    // "thread-test-0001", so a UUID requirement here would reject that
    // vector. Threading is signed metadata, not a security boundary;
    // non-empty string is the fail-closed-enough check. msg_id below
    // stays strict UUIDv4 — it is the replay-ledger key.
    return fail("malformed");
  }
  if (env.reply_to !== null &&
      (typeof env.reply_to !== "string" || env.reply_to.length === 0)) {
    return fail("malformed");
  }
  if (!Number.isInteger(env.iat) || !Number.isInteger(env.exp)) {
    return fail("malformed");
  }
  if (!Array.isArray(env.recipients) ||
      env.recipients.length < 1 || env.recipients.length > MAX_RECIPIENTS) {
    return fail("malformed");
  }
  const recipSeen = new Set();
  for (const r of env.recipients) {
    if (typeof r !== "string" || r.length === 0 || recipSeen.has(r)) {
      return fail("malformed");
    }
    recipSeen.add(r);
  }
  // §6.1: recipients must contain the sender.
  if (!recipSeen.has(env.sender)) return fail("malformed");

  // Binary fields: strict base64url, exact decoded lengths where the
  // spec fixes them (§6.1). ct must be a whole number of AES blocks.
  const iv = decodeB64url(env.iv);
  if (iv === null || iv.length !== 16) return fail("malformed");
  const ct = decodeB64url(env.ct);
  if (ct === null || ct.length === 0 || ct.length % 16 !== 0) return fail("malformed");
  const mac = decodeB64url(env.mac);
  if (mac === null || mac.length !== 32) return fail("malformed");
  const sig = decodeB64url(env.sig);
  if (sig === null || sig.length !== 64) return fail("malformed");

  if (!Array.isArray(env.wrapped_keys) || env.wrapped_keys.length === 0) {
    return fail("malformed");
  }
  const wkSeen = new Set();
  for (const entry of env.wrapped_keys) {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      return fail("malformed");
    }
    const wkKeys = Object.keys(entry);
    if (wkKeys.length !== 2 ||
        wkKeys.indexOf("recipient") === -1 || wkKeys.indexOf("wk") === -1) {
      return fail("malformed");
    }
    if (typeof entry.recipient !== "string" ||
        !recipSeen.has(entry.recipient) || wkSeen.has(entry.recipient)) {
      return fail("malformed");
    }
    wkSeen.add(entry.recipient);
    if (decodeB64url(entry.wk) === null) return fail("malformed");
  }

  return { ok: true };
}

// ---------------------------------------------------------------------------
// badgeFor — the single export.
// ---------------------------------------------------------------------------

async function badgeFor(envelope, context) {
  const ctx = context && typeof context === "object" ? context : {};
  const me = typeof ctx.me === "string" && ctx.me.length > 0 ? ctx.me : "owner";
  const now = Number.isInteger(ctx.now)
    ? ctx.now
    : Math.floor(Date.now() / 1000);
  const keyDirectory = _normalizeKeyDirectory(ctx.keyDirectory);
  const seen = _normalizeSeenIds(ctx.seenIds);
  const ownerVerified = _normalizeOwnerVerified(ctx.ownerVerified);
  const reverify = ctx.reverify === true;

  // Per-step record for the detail sheet (true = passed, false = failed,
  // null = not reached).
  const checks = {
    shape: null, expiry: null, pinned: null, replay: null,
    signature: null, unwrap: null, hmac: null, decrypt: null,
  };

  // Best-effort identity for the result, even when the envelope is broken.
  const rawSender = envelope && typeof envelope === "object" && !Array.isArray(envelope)
    ? envelope.sender : null;
  const sender = typeof rawSender === "string" ? rawSender : null;
  const rawMsgId = envelope && typeof envelope === "object" && !Array.isArray(envelope)
    ? envelope.msg_id : null;
  const msgId = typeof rawMsgId === "string" ? rawMsgId : null;
  const senderOwnerVerified = sender !== null &&
    (ownerVerified.has(sender) ||
     (keyDirectory.get(sender) && keyDirectory.get(sender).verifiedByOwner === true));

  const result = (badge, status, reason, detail) => ({
    badge,
    status,
    reason,
    detail,
    sender,
    msgId,
    senderOwnerVerified,
    checks: Object.assign({}, checks),
  });

  // Parse: a JSON string is accepted for callers holding the raw text.
  let env = envelope;
  if (typeof env === "string") {
    try {
      env = JSON.parse(env);
    } catch (_e) {
      checks.shape = false;
      return result(BADGES.tampered, "tampered", "malformed",
        "This message is not well-formed and cannot be checked. Do not act on it.");
    }
  }

  // --- §7 step 1: parse / shape. -------------------------------------------
  const shape = validateShape(env);
  if (!shape.ok) {
    checks.shape = false;
    return result(BADGES.tampered, "tampered", "malformed",
      "This message is not well-formed and cannot be checked. Do not act on it.");
  }
  checks.shape = true;

  // The relay-added `seq` is stripped here: it is never part of the signed
  // bytes, so it must not reach canonicalisation or shape-sensitive code.
  const signed = {};
  for (const k of ENVELOPE_FIELDS) {
    if (k !== "sig") signed[k] = env[k];
  }

  // --- §7 step 2: expiry / future. -----------------------------------------
  // Checked BEFORE the signature, exactly as §7 orders it. An expired
  // message reports Expired even if its signature would also fail.
  if (!(env.exp > now)) {
    checks.expiry = false;
    const when = new Date(env.exp * 1000).toISOString();
    return result(BADGES.expired, "expired", "expired",
      "This message expired at " + when + ". It was valid when sent.");
  }
  if (env.iat > now + FUTURE_TOLERANCE_SECONDS) {
    checks.expiry = false;
    return result(BADGES.tampered, "tampered", "future-dated",
      "This message claims to be from the future. Do not act on it.");
  }
  if (!(env.exp > env.iat)) {
    checks.expiry = false;
    return result(BADGES.tampered, "tampered", "exp-not-after-iat",
      "This message has an expiry that is not after its sent time. Do not act on it.");
  }
  if (env.exp - env.iat > MAX_TTL_SECONDS) {
    checks.expiry = false;
    return result(BADGES.tampered, "tampered", "ttl-exceeded",
      "This message claims a lifetime longer than the 24-hour maximum. Do not act on it.");
  }
  checks.expiry = true;

  // --- §7 step 3: sender pinned. -------------------------------------------
  // No pinned key, no verification: the sender is unpinned, unknown,
  // revoked, or on a different signature algorithm than the pinned one.
  const entry = keyDirectory.get(env.sender);
  if (!entry) {
    checks.pinned = false;
    return result(BADGES.unverified, "unverified", "unknown-sender",
      "The sender has no key in the key directory, so this message cannot be checked yet.");
  }
  if (entry.status === "revoked") {
    checks.pinned = false;
    return result(BADGES.unverified, "unverified", "revoked",
      "The sender's key was revoked, so this message cannot be checked against it.");
  }
  if (entry.status !== "pinned") {
    checks.pinned = false;
    return result(BADGES.unverified, "unverified", "unpinned",
      "The sender's key has not been confirmed yet, so this message cannot be checked against it.");
  }
  if (entry.sig_alg !== env.sig_alg) {
    checks.pinned = false;
    return result(BADGES.unverified, "unverified", "sig-alg-mismatch",
      "The sender's message uses a different signature method than their confirmed key. Do not act on it.");
  }
  checks.pinned = true;

  // --- §7 step 4: ID unseen (replay). ---------------------------------------
  // Skipped only for explicit re-verification of an already-accepted
  // message (context.reverify); see the caller contract above.
  if (!reverify && seen.has(env.msg_id)) {
    checks.replay = false;
    return result(BADGES.replay, "replay", "replay",
      "Possible replay — the same message ID was seen before. Do not act on it until Jarvis confirms it.");
  }
  checks.replay = true;

  // --- §7 step 5: signature verifies (BEFORE any decrypt). -----------------
  // Everything from here on needs WebCrypto; if it is unavailable, throw
  // rather than fabricate a badge (UI-SPEC §2.1d blocking state).
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!subtle) {
    const err = new Error("WebCrypto is unavailable, so the signature cannot be checked");
    err.code = "webcrypto-unavailable";
    throw err;
  }
  let pinnedKey;
  try {
    pinnedKey = await importPinnedSigningKey(entry);
  } catch (e) {
    if (e && e.code === "webcrypto-unavailable") throw e;
    checks.pinned = false;
    return result(BADGES.unverified, "unverified", "pinned-key-unusable",
      "The sender's confirmed key cannot be used, so this message cannot be checked.");
  }
  // Defence in depth: the pinned key's fingerprint must match the directory
  // record (B5's job in the first place; re-checked here so a tampered
  // directory cannot silently substitute a key). Skipped for JWK entries,
  // which carry no DER to hash.
  if (pinnedKey.der !== null && typeof entry.sig_fingerprint === "string") {
    const digest = await subtle.digest("SHA-256", pinnedKey.der);
    const fingerprint = bytesToHex(new Uint8Array(digest));
    if (fingerprint.toLowerCase() !== entry.sig_fingerprint.toLowerCase()) {
      checks.pinned = false;
      return result(BADGES.unverified, "unverified", "fingerprint-mismatch",
        "The sender's confirmed key does not match its recorded fingerprint. Do not act on this message.");
    }
  }

  const canonicalBytes = _textEncoder.encode(canonicalize(signed));
  const sigBytes = decodeB64url(env.sig);
  let signatureOk = false;
  try {
    if (env.sig_alg === "ES256") {
      // WebCrypto ECDSA verify takes a DER signature and hashes the data
      // with SHA-256 internally; the envelope carries raw R || S (§4.4).
      // One engine divergence, verified 2026-11-16 on Node 24.22.1:
      // browsers (W3C WebCrypto) expect DER, but Node's WebCrypto expects
      // raw R || S (P1363) for both sign and verify. Try DER first (the
      // deployment target — the app runs in a browser), then raw. Trying
      // both encodings is safe: they are two spellings of the same (R, S)
      // pair, so a signature verifies under an encoding iff that (R, S)
      // is genuine; no forgery becomes possible by offering both.
      // A NotSupportedError from either attempt means the engine cannot
      // do ECDSA at all and is re-thrown as a capability error below.
      const derSig = rawSigToDer(sigBytes);
      let derOk = false;
      let derUnsupported = false;
      try {
        derOk = await subtle.verify(
          { name: "ECDSA", hash: "SHA-256" },
          pinnedKey.key,
          derSig,
          canonicalBytes
        );
      } catch (e) {
        if (e && e.name === "NotSupportedError") derUnsupported = true;
      }
      if (derOk) {
        signatureOk = true;
      } else if (derUnsupported) {
        // The engine cannot do ECDSA at all: surface it as a capability
        // error (outer catch converts the name), never as Tampered.
        const unsupported = new Error("ECDSA not supported in this engine");
        unsupported.name = "NotSupportedError";
        throw unsupported;
      } else {
        try {
          signatureOk = await subtle.verify(
            { name: "ECDSA", hash: "SHA-256" },
            pinnedKey.key,
            sigBytes,
            canonicalBytes
          );
        } catch (e) {
          if (e && e.name === "NotSupportedError") throw e;
          signatureOk = false;
        }
      }
    } else {
      signatureOk = await subtle.verify(
        { name: "Ed25519" },
        pinnedKey.key,
        sigBytes,
        canonicalBytes
      );
    }
  } catch (e) {
    if (e && (e.name === "NotSupportedError" || e.name === "OperationError")) {
      const err = new Error(
        "This browser cannot verify " + env.sig_alg + " signatures"
      );
      err.code = "sig-alg-unsupported";
      err.cause = e;
      throw err;
    }
    signatureOk = false;
  }
  if (!signatureOk) {
    checks.signature = false;
    return result(BADGES.tampered, "tampered", "bad-signature",
      "Signature failed — this message may have been changed. Do not act on it.");
  }
  checks.signature = true;

  // --- §7 step 6: unwrap (private key exercised ONLY after step 5). --------
  const myEntry = env.wrapped_keys.find((w) => w.recipient === me);
  if (!myEntry) {
    checks.unwrap = false;
    return result(BADGES.undecryptable, "undecryptable", "no-entry",
      "This message was not encrypted for your key. Check the key directory.");
  }
  const wkBytes = decodeB64url(myEntry.wk);
  let keyMaterial = null;
  try {
    if (typeof ctx.unwrapKey === "function") {
      keyMaterial = await ctx.unwrapKey(wkBytes, env);
    } else if (ctx.privateKey) {
      keyMaterial = new Uint8Array(await subtle.decrypt(
        { name: "RSA-OAEP" }, ctx.privateKey, wkBytes
      ));
    } else {
      checks.unwrap = false;
      return result(BADGES.undecryptable, "undecryptable", "no-private-key",
        "No private key is available in this browser, so this message cannot be decrypted here.");
    }
  } catch (_e) {
    checks.unwrap = false;
    return result(BADGES.undecryptable, "undecryptable", "unwrap-failed",
      "This message could not be decrypted with your key. Check the key directory.");
  }
  if (!(keyMaterial instanceof Uint8Array) || keyMaterial.length !== 64) {
    checks.unwrap = false;
    return result(BADGES.undecryptable, "undecryptable", "unwrap-failed",
      "This message could not be decrypted with your key. Check the key directory.");
  }
  checks.unwrap = true;
  const encKeyBytes = keyMaterial.slice(0, 32);
  const macKeyBytes = keyMaterial.slice(32, 64);

  // --- §7 step 7: HMAC verifies (constant-time), BEFORE decrypting. --------
  const ivBytes = decodeB64url(env.iv);
  const ctBytes = decodeB64url(env.ct);
  const macBytes = decodeB64url(env.mac);
  const macKey = await subtle.importKey(
    "raw", macKeyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const computedMac = new Uint8Array(await subtle.sign(
    "HMAC", macKey, _concatBytes(ivBytes, ctBytes)
  ));
  if (!constantTimeEqual(computedMac, macBytes)) {
    checks.hmac = false;
    return result(BADGES.tampered, "tampered", "hmac-mismatch",
      "This message failed its integrity check — it may have been changed. Do not act on it.");
  }
  checks.hmac = true;

  // --- §7 step 8: decrypt + plaintext parses (§6.4). -----------------------
  // The plaintext is verified and then DISCARDED: it is never returned,
  // stored, or logged by this module.
  let plaintextBytes;
  try {
    const encKey = await subtle.importKey(
      "raw", encKeyBytes, { name: "AES-CBC", length: 256 }, false, ["decrypt"]
    );
    plaintextBytes = new Uint8Array(await subtle.decrypt(
      { name: "AES-CBC", iv: ivBytes }, encKey, ctBytes
    ));
  } catch (_e) {
    checks.decrypt = false;
    return result(BADGES.undecryptable, "undecryptable", "decrypt-failed",
      "This message could not be decrypted with your key. Check the key directory.");
  }
  if (plaintextBytes.length > MAX_PLAINTEXT_BYTES) {
    checks.decrypt = false;
    return result(BADGES.undecryptable, "undecryptable", "plaintext-too-large",
      "This message decrypted to content larger than the 64 KiB limit. Do not act on it.");
  }
  let inner;
  try {
    inner = JSON.parse(_textDecoder.decode(plaintextBytes));
  } catch (_e) {
    checks.decrypt = false;
    return result(BADGES.undecryptable, "undecryptable", "bad-plaintext",
      "This message decrypted but its contents are not a readable message. Check the key directory.");
  }
  if (inner === null || typeof inner !== "object" || Array.isArray(inner) ||
      typeof inner.text !== "string") {
    checks.decrypt = false;
    return result(BADGES.undecryptable, "undecryptable", "bad-plaintext",
      "This message decrypted but its contents are not a readable message. Check the key directory.");
  }
  checks.decrypt = true;

  // --- All §7 checks passed. -----------------------------------------------
  return result(BADGES.signed, "signed", "signed",
    "Signed by the sender's confirmed key, not expired, and decrypted for you.");
}

// ---------------------------------------------------------------------------
// UMD-style export: browser global + CommonJS (same pattern as
// app/js/crypto-core.js, app/js/crypto-p256.js, app/errors.js). No build
// step, no module loader required (FILE-MAP D18).
// ---------------------------------------------------------------------------
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }
  root.GhostChatBadges = api;
  if (typeof window !== "undefined") window.GhostChatBadges = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  return {
    badgeFor: badgeFor,
  };
});
