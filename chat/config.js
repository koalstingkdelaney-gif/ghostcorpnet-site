// Encrypted chat — room config (worker C20, wave 2).
//
// Single CONFIG object. No secrets, no keys, no tokens, no private data.
// All values from ~/workspace/encrypted-chat/FILE-MAP.md (authoritative);
// where a design doc conflicts, FILE-MAP wins (see notes below).
//
// Sources:
//   FILE-MAP D1/D2  — store base URL, public-repo store layout.
//   FILE-MAP D9     — default recipients: all three participants.
//   FILE-MAP D10    — TTL 24 h default AND maximum (86400 s).
//   FILE-MAP D11    — polling 15 s, backoff 5 s -> 60 s. SUPERSEDED by the
//                     P4 fast-reads patch (STATE-OF-THE-ART-BAR pillar 2,
//                     owner order 2026-11-16): poll interval is now 5 s
//                     while visible; backoff stays 5 s -> 60 s. See the
//                     P4 report for the conflict flag.
//   FILE-MAP D18    — CSP connect-src allows 'self',
//                     https://api.github.com, https://ghostcorpnet.com.
//                     P4 ADDS https://raw.githubusercontent.com (the
//                     no-PAT read tier) — see app/index.html CSP line.
//   FILE-MAP §3     — envelope "ecc-1", inner plaintext max 64 KiB,
//                     relay caps, manifest / messages / tombstones layout.
//   FILE-MAP §4 C7  — compose limit 4,000 chars.
//   TRANSPORT-DECISION §2.2 — site repo owner/repo, verified from the
//     live clone: git -C ~/workspace/ghostcorpnet-site remote -v
//     => https://github.com/koalstingkdelaney-gif/ghostcorpnet-site.git
//
// Conflicts resolved in favour of FILE-MAP (do not "fix" by reverting):
//   - RELAY-SPEC §2/§3.3 allows up to 7-day TTL and a 30-day default
//     when omitted; FILE-MAP D10 overrides: max TTL is 86400 s.
//   - RELAY-SPEC §1.1 recommends <= 16,384 bytes plaintext; FILE-MAP §3
//     sets the inner-plaintext max at 64 KiB (65536 bytes).
//   - UI-SPEC §2.4 proposes a 7-day expiry-picker default; FILE-MAP D10
//     overrides: default TTL is 86400 s.
//   - RELAY-SPEC uses AES-256-GCM / part+parts / created_at+expires_at
//     strings; FILE-MAP D5 overrides with ecc-1 (AES-256-CBC + HMAC,
//     iat/exp integer epoch seconds). No crypto fields live here.

"use strict";

const CONFIG = {
  // Room identity. Public, non-sensitive identifier (UI-SPEC §1).
  roomId: "ghostcorp-chat-1",

  // Envelope protocol version (FILE-MAP D5, §3).
  envelopeVersion: "ecc-1",

  // Participants, in canonical order. Default recipients for every
  // message: all three, including the sender (FILE-MAP D9).
  participants: ["jarvis", "chatgpt", "owner"],
  defaultRecipients: ["jarvis", "chatgpt", "owner"],

  // Store (public repo, ciphertext only — FILE-MAP D2, §3).
  // Served via GitHub Pages at https://ghostcorpnet.com/chat/.
  storeBaseUrl: "https://ghostcorpnet.com/chat/",
  keyDirectoryUrl: "https://ghostcorpnet.com/chat/keys/participants.json",
  manifestUrl: "https://ghostcorpnet.com/chat/manifest.json",
  messagesUrlPrefix: "https://ghostcorpnet.com/chat/messages/",
  tombstonesUrl: "https://ghostcorpnet.com/chat/tombstones.jsonl",

  // Polling (P4 fast reads — STATE-OF-THE-ART-BAR pillar 2, supersedes
  // FILE-MAP D11's 15 s; UI-SPEC §6).
  // 5 s while visible; on failure back off 5 s -> 15 s -> 30 s -> 60 s (cap).
  pollIntervalMs: 5000,
  pollBackoffMs: [5000, 15000, 30000, 60000],
  pollBackoffStartMs: 5000,
  pollBackoffMaxMs: 60000,

  // Fresh reads (P4). Live reads bypass GitHub Pages (publish lag ~2-3 min):
  // the GitHub Contents API first when the owner's PAT is present (fresh,
  // authoritative, immediate after any write lands in the repo), falling
  // back to raw.githubusercontent.com with a cache-buster (?t=<epoch>)
  // when no PAT is present; the inline <script id="chat-log"> snapshot in
  // the page is the initial history for first paint (no fetch needed).
  // Store layout per FILE-MAP D2 / §3 (verified against site/publish.sh +
  // relay/manifest.py): repo koalstingkdelaney-gif/ghostcorpnet-site,
  // branch main, store dir chat/, manifest chat/manifest.json, messages
  // chat/messages/<msg_id>.json. Read order, first to last:
  readOrder: ["api", "raw", "inline"],
  githubBranch: "main",
  githubChatDir: "chat",
  githubManifestPath: "chat/manifest.json",
  githubRawBaseUrl: "https://raw.githubusercontent.com",

  // Expiry (FILE-MAP D10): 24 h default AND maximum.
  // exp = iat + TTL; exp - iat must be <= 86400; future-dated iat
  // beyond now + 300 s is rejected (FILE-MAP §3 verification order).
  defaultTtlSeconds: 86400,
  maxTtlSeconds: 86400,
  maxFutureSkewSeconds: 300,

  // Message size limits.
  // Inner plaintext max 64 KiB (FILE-MAP §3); compose limit 4,000
  // characters (FILE-MAP §4 C7).
  maxPlaintextBytes: 65536,
  maxMessageChars: 4000,

  // Relay caps (FILE-MAP §3; RELAY-SPEC §6.2).
  maxEnvelopeBytes: 65536,
  maxCiphertextBytes: 24576,
  rateLimitPerSender: {
    perMinute: 30,
    perHour: 300,
    perDay: 2000
  },
  rateLimitReadsPerMinute: 120,
  maxStoreMessages: 10000,

  // GitHub (publish / PAT write path — FILE-MAP D1/D3).
  // API base only; no token here — the owner's PAT lives in his
  // browser's IndexedDB only (worker C13), never in page source.
  githubApiBaseUrl: "https://api.github.com",
  siteRepoOwner: "koalstingkdelaney-gif",
  siteRepoName: "ghostcorpnet-site"
};

Object.freeze(CONFIG);
Object.freeze(CONFIG.participants);
Object.freeze(CONFIG.defaultRecipients);
Object.freeze(CONFIG.rateLimitPerSender);
Object.freeze(CONFIG.readOrder);
Object.freeze(CONFIG.pollBackoffMs);
