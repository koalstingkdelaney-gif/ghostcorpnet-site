#!/usr/bin/env node
/**
 * embed-log.js — publish-time inline-log embedder (worker C15).
 *
 * Builds the `<script type="application/json" id="chat-log">` fragment that
 * C1 (`app/index.html`) inlines at publish time, from the ciphertext store.
 *
 *   Input : a store directory holding `manifest.json` + `messages/*.json`
 *           (the published `chat/` tree layout, FILE-MAP §3 / D2).
 *   Output: an HTML fragment — a short human-readable header comment plus
 *           one `<script type="application/json" id="chat-log">` block whose
 *           contents are the current message log: an array of envelope
 *           objects, ciphertext only, in relay-seq order.
 *
 * This runs at PUBLISH time (invoked by E2 `site/embed-log.py` / the publish
 * bundle step), NOT in the browser at runtime. The browser never runs this
 * file; it only reads the fragment this file produced.
 *
 * What this file does NOT do (by design):
 *   - It does NOT verify signatures, decrypt anything, or check key pinning.
 *     Signature/expiry/replay verification is the verifier's job (A9 / §7);
 *     the publish gate (D5) enforces ciphertext-only on every publish.
 *     This embedder only validates envelope SHAPE (required `ecc-1` fields,
 *     types, base64url canonicality, `seq` consistency) and fails closed on
 *     any inconsistency, so a corrupt or mixed-up store can never be
 *     silently embedded as a partial log.
 *   - It does NOT invent, reorder by sender clock, or drop messages. Order
 *     is relay `seq` from `manifest.json` (FILE-MAP §3; UI-SPEC §6: order by
 *     relay sequence, never by sender clock). A `seq` gap is fine (purged
 *     messages leave gaps); a duplicate `seq` or `msg_id` is an error.
 *   - It holds no keys and emits no plaintext: envelope objects are copied
 *     verbatim from `messages/*.json` (ciphertext only). Any top-level
 *     plaintext-looking field (`text`, `plaintext`, `body`, `message`) in a
 *     message file is rejected — a plaintext slip must fail the publish,
 *     never be embedded.
 *
 * Normative sources (FILE-MAP is authoritative; it wins on any conflict):
 *   - FILE-MAP §3 envelope (`ecc-1`), manifest, and store layout.
 *   - FILE-MAP D4: the page MUST embed the current message log inline at
 *     publish time so a fetch that does not run JS still sees the log.
 *   - TRANSPORT-DECISION §5 step 4 (same inline-log requirement).
 *   - UI-SPEC §6: ordering by relay sequence; dedup by `msg_id`.
 *
 * Conflicts resolved in favour of FILE-MAP (see report): UI-SPEC §§7/9 and
 * RELAY-SPEC describe an AES-GCM envelope with `message_id` / `ciphertext`
 * fields; FILE-MAP D5 overrides that with `ecc-1` / `A256CBC-HS256` and the
 * §6.1 fields (`msg_id`, `ct`, `mac`, `wrapped_keys`, `sig`, ...). This
 * embedder implements the FILE-MAP fields only.
 *
 * Usage (CLI):
 *   node app/embed-log.js <store-dir> [output-file]
 *   node app/embed-log.js --store <store-dir> [--out <output-file>]
 *   node app/embed-log.js --help
 *
 *   <store-dir>  directory containing `manifest.json` and `messages/`.
 *   [output-file] file to write the fragment to; omitted = stdout.
 *   Exit 0 on success; exit 1 on a store/validation error (nothing is
 *   written — no partial fragment); exit 2 on usage error.
 *   Errors go to stderr. On success with --out, a one-line summary goes
 *   to stderr and the fragment goes only to the file.
 *
 * Programmatic use (e.g. from a publish script):
 *   const { buildInlineLog, buildInlineLogFragment } = require('./embed-log');
 *   const fragment = buildInlineLog(storeDir);   // throws on any error
 *
 * Node.js stdlib only. No keys, no network, $0.
 */

'use strict';

const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Constants — envelope shape, FILE-MAP §3 / CRYPTO-DESIGN §6.1 (`ecc-1`).
// ---------------------------------------------------------------------------

/** Required envelope fields (all of them, exactly these plus optional `seq`). */
const REQUIRED_FIELDS = [
  'v', 'msg_id', 'sender', 'recipients', 'iat', 'exp', 'reply_to',
  'thread_id', 'alg', 'sig_alg', 'iv', 'ct', 'mac', 'wrapped_keys', 'sig',
];

/**
 * The only field allowed beyond REQUIRED_FIELDS: `seq`, added by the relay
 * on receipt (FILE-MAP §3: "messages/<msg_id>.json: one envelope, exactly as
 * signed (plus `seq` added by the relay)"). Unknown fields are rejected
 * (CRYPTO-DESIGN §6.1: unknown fields → reject).
 */
const OPTIONAL_FIELDS = ['seq'];

/** Top-level fields that would mean plaintext leaked into the store. */
const PLAINTEXT_FIELDS = ['text', 'plaintext', 'body', 'message', 'content'];

const KNOWN_ALGS = ['A256CBC-HS256'];
const KNOWN_SIG_ALGS = ['Ed25519', 'ES256'];
const KNOWN_SENDERS = ['jarvis', 'chatgpt', 'owner'];

/** UUIDv4, lowercase (FILE-MAP §3). */
const UUID_V4_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** base64url without padding, RFC 4648 §5 (CRYPTO-DESIGN §6.3). */
const B64URL_RE = /^[A-Za-z0-9_-]+$/;

const MAX_TTL_SECONDS = 86400; // D10: 24 h TTL default AND maximum.

function fail(message) {
  throw new Error(`embed-log: ${message}`);
}

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function b64urlByteLength(value) {
  // base64url without padding: every 4 chars encode 3 bytes, minus the
  // short final group. Length is exact for canonical (unpadded) input.
  const len = value.length;
  const rem = len % 4;
  if (rem === 1) return -1; // a single trailing char can never be valid.
  return Math.floor(len / 4) * 3 + (rem === 0 ? 0 : rem - 1);
}

function checkB64url(value, field, source) {
  if (typeof value !== 'string' || !B64URL_RE.test(value)) {
    fail(`${source}: field ${field} is not canonical base64url (no padding)`);
  }
  if (b64urlByteLength(value) < 0) {
    fail(`${source}: field ${field} has an impossible base64url length`);
  }
}

// ---------------------------------------------------------------------------
// Envelope shape validation (shape only — no signature / decrypt / pinning).
// ---------------------------------------------------------------------------

function validateEnvelope(envelope, source) {
  if (!isPlainObject(envelope)) {
    fail(`${source}: envelope is not a JSON object`);
  }

  // Plaintext leak: fail closed before anything is embedded.
  for (const field of PLAINTEXT_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(envelope, field)) {
      fail(
        `${source}: top-level field "${field}" looks like plaintext — ` +
          'ciphertext-only store violated, refusing to embed',
      );
    }
  }

  // Unknown fields → reject (CRYPTO-DESIGN §6.1). `seq` is the one
  // relay-added exception (FILE-MAP §3).
  const allowed = new Set([...REQUIRED_FIELDS, ...OPTIONAL_FIELDS]);
  for (const key of Object.keys(envelope)) {
    if (!allowed.has(key)) {
      fail(`${source}: unknown envelope field "${key}"`);
    }
  }
  for (const field of REQUIRED_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(envelope, field)) {
      fail(`${source}: missing required envelope field "${field}"`);
    }
  }

  if (envelope.v !== 'ecc-1') {
    fail(`${source}: v is ${JSON.stringify(envelope.v)}, expected "ecc-1"`);
  }
  if (typeof envelope.msg_id !== 'string' || !UUID_V4_RE.test(envelope.msg_id)) {
    fail(`${source}: msg_id is not a lowercase UUIDv4`);
  }
  if (typeof envelope.sender !== 'string' || !KNOWN_SENDERS.includes(envelope.sender)) {
    fail(`${source}: sender ${JSON.stringify(envelope.sender)} is not a known participant`);
  }
  if (
    !Array.isArray(envelope.recipients) ||
    envelope.recipients.length < 1 ||
    envelope.recipients.length > 10 ||
    envelope.recipients.some((r) => typeof r !== 'string' || !KNOWN_SENDERS.includes(r)) ||
    new Set(envelope.recipients).size !== envelope.recipients.length
  ) {
    fail(`${source}: recipients must be 1-10 unique known participant ids`);
  }
  if (!envelope.recipients.includes(envelope.sender)) {
    fail(`${source}: recipients does not include the sender`);
  }
  if (!Number.isInteger(envelope.iat) || envelope.iat < 0) {
    fail(`${source}: iat is not a non-negative integer (unix seconds)`);
  }
  if (!Number.isInteger(envelope.exp) || envelope.exp < 0) {
    fail(`${source}: exp is not a non-negative integer (unix seconds)`);
  }
  if (envelope.exp <= envelope.iat) {
    fail(`${source}: exp must be > iat`);
  }
  if (envelope.exp - envelope.iat > MAX_TTL_SECONDS) {
    fail(`${source}: exp - iat exceeds the 86400 s maximum TTL (D10)`);
  }
  if (
    envelope.reply_to !== null &&
    (typeof envelope.reply_to !== 'string' || !UUID_V4_RE.test(envelope.reply_to))
  ) {
    fail(`${source}: reply_to must be null or a lowercase UUIDv4`);
  }
  if (typeof envelope.thread_id !== 'string' || !UUID_V4_RE.test(envelope.thread_id)) {
    fail(`${source}: thread_id is not a lowercase UUIDv4`);
  }
  if (envelope.alg !== 'A256CBC-HS256') {
    fail(`${source}: alg is ${JSON.stringify(envelope.alg)}, expected "A256CBC-HS256"`);
  }
  if (!KNOWN_SIG_ALGS.includes(envelope.sig_alg)) {
    fail(`${source}: sig_alg ${JSON.stringify(envelope.sig_alg)} is not Ed25519/ES256`);
  }

  checkB64url(envelope.iv, 'iv', source);
  checkB64url(envelope.ct, 'ct', source);
  checkB64url(envelope.mac, 'mac', source);
  checkB64url(envelope.sig, 'sig', source);
  if (b64urlByteLength(envelope.iv) !== 16) {
    fail(`${source}: iv must decode to 16 bytes`);
  }
  if (b64urlByteLength(envelope.mac) !== 32) {
    fail(`${source}: mac must decode to 32 bytes (HMAC-SHA-256)`);
  }
  if (b64urlByteLength(envelope.sig) !== 64) {
    fail(`${source}: sig must decode to 64 bytes (Ed25519 raw / ES256 R||S)`);
  }

  if (!Array.isArray(envelope.wrapped_keys) || envelope.wrapped_keys.length < 1) {
    fail(`${source}: wrapped_keys must be a non-empty array`);
  }
  const wrappedRecipients = [];
  for (const entry of envelope.wrapped_keys) {
    if (!isPlainObject(entry)) {
      fail(`${source}: wrapped_keys entry is not an object`);
    }
    const keys = Object.keys(entry);
    if (keys.length !== 2 || !keys.includes('recipient') || !keys.includes('wk')) {
      fail(`${source}: wrapped_keys entry must have exactly {recipient, wk}`);
    }
    if (typeof entry.recipient !== 'string' || !KNOWN_SENDERS.includes(entry.recipient)) {
      fail(`${source}: wrapped_keys recipient ${JSON.stringify(entry.recipient)} is not a known participant`);
    }
    checkB64url(entry.wk, 'wrapped_keys[].wk', source);
    wrappedRecipients.push(entry.recipient);
  }
  // One wrapped key per recipient, exactly the recipient set (D9 default is
  // all three participants; 1:1 is an explicit opt-in, still exact here).
  const wrappedSet = new Set(wrappedRecipients);
  if (
    wrappedSet.size !== wrappedRecipients.length ||
    wrappedSet.size !== envelope.recipients.length ||
    !envelope.recipients.every((r) => wrappedSet.has(r))
  ) {
    fail(`${source}: wrapped_keys recipients must match recipients exactly (one entry each)`);
  }

  if (Object.prototype.hasOwnProperty.call(envelope, 'seq')) {
    if (!Number.isInteger(envelope.seq) || envelope.seq < 0) {
      fail(`${source}: seq must be a non-negative integer`);
    }
  }
}

// ---------------------------------------------------------------------------
// Store loading: manifest.json + messages/*.json, in relay-seq order.
// ---------------------------------------------------------------------------

function readJsonFile(filePath, source) {
  let raw;
  try {
    raw = fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    fail(`${source}: cannot read ${filePath} (${err.code || err.message})`);
  }
  try {
    return JSON.parse(raw);
  } catch (err) {
    fail(`${source}: invalid JSON in ${filePath} (${err.message})`);
  }
}

/**
 * Load the store and return the envelopes in relay-seq order.
 * Throws (fail closed, no partial log) on any inconsistency.
 */
function loadStoreEnvelopes(storeDir) {
  if (!storeDir || typeof storeDir !== 'string') {
    fail('store directory is required');
  }
  const manifestPath = path.join(storeDir, 'manifest.json');
  const manifest = readJsonFile(manifestPath, 'manifest.json');
  if (!isPlainObject(manifest)) {
    fail('manifest.json: not a JSON object');
  }
  if (manifest.v !== 'ecc-1') {
    fail(`manifest.json: v is ${JSON.stringify(manifest.v)}, expected "ecc-1"`);
  }
  if (!Number.isInteger(manifest.seq) || manifest.seq < 0) {
    fail('manifest.json: seq must be a non-negative integer');
  }
  if (!Array.isArray(manifest.messages)) {
    fail('manifest.json: messages must be an array');
  }

  const seenMsgIds = new Set();
  const seenSeqs = new Set();
  const entries = [];

  for (const entry of manifest.messages) {
    const where = `manifest.json entry ${JSON.stringify(entry && entry.msg_id)}`;
    if (!isPlainObject(entry)) {
      fail('manifest.json: each messages entry must be an object');
    }
    if (typeof entry.msg_id !== 'string' || !UUID_V4_RE.test(entry.msg_id)) {
      fail(`${where}: msg_id is not a lowercase UUIDv4`);
    }
    if (seenMsgIds.has(entry.msg_id)) {
      fail(`${where}: duplicate msg_id in manifest`);
    }
    seenMsgIds.add(entry.msg_id);
    if (!Number.isInteger(entry.seq) || entry.seq < 0) {
      fail(`${where}: seq must be a non-negative integer`);
    }
    if (seenSeqs.has(entry.seq)) {
      fail(`${where}: duplicate seq ${entry.seq} in manifest`);
    }
    seenSeqs.add(entry.seq);
    // FILE-MAP §3: url is exactly "messages/<msg_id>.json". Enforce it so a
    // crafted manifest cannot make the embedder read outside messages/.
    if (entry.url !== `messages/${entry.msg_id}.json`) {
      fail(`${where}: url must be "messages/${entry.msg_id}.json"`);
    }
    if (typeof entry.sender !== 'string' || !KNOWN_SENDERS.includes(entry.sender)) {
      fail(`${where}: sender ${JSON.stringify(entry.sender)} is not a known participant`);
    }
    for (const field of ['iat', 'exp']) {
      if (!Number.isInteger(entry[field]) || entry[field] < 0) {
        fail(`${where}: ${field} must be a non-negative integer`);
      }
    }
    entries.push(entry);
  }

  // Relay-seq order: sort by manifest seq (never by sender clock / iat).
  entries.sort((a, b) => a.seq - b.seq);

  // The manifest's top-level seq is the latest relay seq; it must not lag
  // behind any message it lists. (It may run ahead: a counter for the next
  // assignment is still consistent.)
  if (entries.length > 0 && manifest.seq < entries[entries.length - 1].seq) {
    fail(
      `manifest.json: top-level seq ${manifest.seq} is below the highest ` +
        `message seq ${entries[entries.length - 1].seq}`,
    );
  }

  const envelopes = [];
  for (const entry of entries) {
    const filePath = path.join(storeDir, 'messages', `${entry.msg_id}.json`);
    const source = `messages/${entry.msg_id}.json`;
    const envelope = readJsonFile(filePath, source);
    validateEnvelope(envelope, source);

    if (envelope.msg_id !== entry.msg_id) {
      fail(`${source}: msg_id ${envelope.msg_id} does not match manifest ${entry.msg_id}`);
    }
    if (envelope.sender !== entry.sender) {
      fail(`${source}: sender ${envelope.sender} does not match manifest ${entry.sender}`);
    }
    if (envelope.iat !== entry.iat || envelope.exp !== entry.exp) {
      fail(`${source}: iat/exp do not match the manifest entry`);
    }
    // The relay adds `seq` to the stored file (FILE-MAP §3). If the file
    // carries one it must agree with the manifest; if it does not, attach
    // the manifest seq so the embedded log carries the ordering explicitly.
    if (Object.prototype.hasOwnProperty.call(envelope, 'seq')) {
      if (envelope.seq !== entry.seq) {
        fail(`${source}: seq ${envelope.seq} does not match manifest seq ${entry.seq}`);
      }
    } else {
      envelope.seq = entry.seq;
    }
    envelopes.push(envelope);
  }

  return { manifest, envelopes };
}

// ---------------------------------------------------------------------------
// Fragment building — the part that must be safe to inline into index.html.
// ---------------------------------------------------------------------------

/**
 * Escape a JSON text so it can sit inside `<script type="application/json">`
 * without ever terminating the block early. `</script` (any case) is the
 * break-out sequence; `<!--` is escaped too so the block cannot open an
 * HTML comment inside it. U+2028/U+2029 are escaped to their `\u` forms so
 * the text is safe for every JS/JSON parser that might read it.
 * Valid `ecc-1` envelopes cannot contain these sequences (every string field
 * is base64url, a UUID, or an enum), so this is defence in depth — it must
 * still hold if a future field ever carries free text.
 */
function escapeForInlineScript(jsonText) {
  return jsonText
    .replace(/<\/script/gi, '<\\/script')
    .replace(/<!--/g, '<\\!--')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

function buildInlineLogFragment(manifest, envelopes) {
  const count = envelopes.length;
  const firstSeq = count > 0 ? envelopes[0].seq : null;
  const lastSeq = count > 0 ? envelopes[count - 1].seq : null;
  const range =
    count === 0
      ? 'empty log'
      : count === 1
        ? `1 message, seq ${firstSeq}`
        : `${count} messages, seq ${firstSeq}-${lastSeq}`;

  const jsonText = JSON.stringify(envelopes, null, 2);
  const safeJson = escapeForInlineScript(jsonText);

  // Keep the count in the comment too, so a no-JS fetch (ChatGPT's read
  // path, TRANSPORT-DECISION §5 step 4) can see at a glance what it got.
  const lines = [
    `<!-- Encrypted chat log (${range}): ciphertext only. No plaintext, no private keys.`,
    '     This log is unreadable without JavaScript: the page decrypts each',
    '     message in the browser with the reader\'s own private key. -->',
    `<script type="application/json" id="chat-log">`,
    safeJson,
    '</script>',
  ];
  return `${lines.join('\n')}\n`;
}

/** Build the fragment from a store directory. Throws on any error. */
function buildInlineLog(storeDir) {
  const { manifest, envelopes } = loadStoreEnvelopes(storeDir);
  return buildInlineLogFragment(manifest, envelopes);
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function printUsage(stream) {
  stream.write(
    [
      'Usage: node app/embed-log.js <store-dir> [output-file]',
      '       node app/embed-log.js --store <store-dir> [--out <output-file>]',
      '',
      'Build the inline-log HTML fragment for the encrypted chat page from a',
      'ciphertext store (manifest.json + messages/*.json), in relay-seq order.',
      'Writes the fragment to stdout, or to <output-file> / --out if given.',
      'Fails closed (exit 1, nothing written) on any store inconsistency.',
      '',
      'Options:',
      '  --store <dir>   store directory (same as the positional <store-dir>)',
      '  --out <file>    write the fragment to <file> instead of stdout',
      '  --help, -h      show this help',
      '',
    ].join('\n'),
  );
}

function parseArgs(argv) {
  const positionals = [];
  let store = null;
  let out = null;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') return { help: true };
    if (arg === '--store') {
      if (i + 1 >= argv.length) return { error: '--store needs a directory argument' };
      store = argv[i + 1];
      i += 1;
    } else if (arg.startsWith('--store=')) {
      store = arg.slice('--store='.length);
    } else if (arg === '--out') {
      if (i + 1 >= argv.length) return { error: '--out needs a file argument' };
      out = argv[i + 1];
      i += 1;
    } else if (arg.startsWith('--out=')) {
      out = arg.slice('--out='.length);
    } else if (arg.startsWith('-')) {
      return { error: `unknown option: ${arg}` };
    } else {
      positionals.push(arg);
    }
  }
  if (positionals.length > 2) return { error: 'too many arguments' };
  if (positionals.length >= 1) {
    if (store !== null && store !== positionals[0]) {
      return { error: '--store and <store-dir> disagree' };
    }
    store = positionals[0];
  }
  if (positionals.length === 2) {
    if (out !== null && out !== positionals[1]) {
      return { error: '--out and [output-file] disagree' };
    }
    out = positionals[1];
  }
  if (store === null) return { error: 'store directory is required' };
  return { store, out };
}

function main(argv) {
  const parsed = parseArgs(argv);
  if (parsed.help) {
    printUsage(process.stdout);
    return 0;
  }
  if (parsed.error) {
    process.stderr.write(`embed-log: ${parsed.error}\n`);
    printUsage(process.stderr);
    return 2;
  }

  let fragment;
  let count;
  try {
    const { manifest, envelopes } = loadStoreEnvelopes(parsed.store);
    fragment = buildInlineLogFragment(manifest, envelopes);
    count = envelopes.length;
  } catch (err) {
    // Fail closed: nothing is written anywhere on any store error.
    process.stderr.write(`${err.message}\n`);
    return 1;
  }

  if (parsed.out) {
    try {
      fs.writeFileSync(parsed.out, fragment, 'utf8');
    } catch (err) {
      process.stderr.write(`embed-log: cannot write ${parsed.out} (${err.code || err.message})\n`);
      return 1;
    }
    process.stderr.write(`embed-log: wrote ${count} message(s) to ${parsed.out}\n`);
  } else {
    process.stdout.write(fragment);
  }
  return 0;
}

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}

module.exports = {
  buildInlineLog,
  buildInlineLogFragment,
  loadStoreEnvelopes,
  validateEnvelope,
  escapeForInlineScript,
  REQUIRED_FIELDS,
};
