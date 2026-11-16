/* app/view-setup.js — C4: first-run key setup / onboarding view.
 *
 * FILE-MAP §4 C4. Implements FILE-MAP §3 / §6 + UI-SPEC §2.1 + OWNER-JOIN §1–§3.
 * FILE-MAP WINS where it conflicts with the design docs (see "Conflicts" below).
 *
 * Steps the user sees (P7 — four user-facing steps, matching
 * OWNER-JOIN §1 / owner/join-instructions.md "about 5 taps"):
 *   1  Make your key — display name (public) + device label, then
 *      Generate: RSA-OAEP 4096 encryption keypair + Ed25519 signing
 *      keypair via WebCrypto. Mobile timing warning shown while
 *      generating (deck waiting line, then the slow line after 10 s).
 *      ES256 (P-256) signing fallback ONLY if Ed25519 keygen rejects.
 *      Import path (collapsed) for a key made elsewhere.
 *   2  Check your code — the check-code (first 8 hex of the enc
 *      fingerprint, XXXX-XXXX) for the owner to confirm with Jarvis
 *      in Muse chat (anti-swap check). Full fingerprints are behind a
 *      collapsed "Show full fingerprints" — the check-code is the
 *      hero, the long codes are not what the owner compares by eye.
 *      Inside step 2, two automatic sub-steps run with no tap:
 *      (a) Verify Jarvis — BLOCKING. The app fetches Jarvis's
 *      published public key and compares its fingerprint against the
 *      pinned value below. Join is impossible while this is not
 *      MATCH. Mismatch and cannot-check are both blocking, with a
 *      Retry button. (b) Publish public key — posts ONLY the public
 *      keys + display name + fingerprints to the key directory (never
 *      the private keys). When no publish endpoint is configured
 *      (the FILE-MAP store design: git repo, no POST /keys) this is
 *      recorded as pending automatically — no tap — and the owner
 *      shares the check-code with Jarvis, who publishes it.
 *   3  Save your backup — passphrase-locked backup file (via
 *      app/backup.js, C11) with a mandatory test-restore inside the
 *      save, OR the owner explicitly accepts the skip-backup warning.
 *      No silent skip. Join completes ONLY after this step.
 *   4  Join — Enter chat. Shows "✓ You're in" in place and holds it
 *      briefly (~1 s) before calling options.onComplete(state) /
 *      app.js routing, so the user actually sees the confirmation.
 * A progress indicator ("Step N of 4 — <label>") sits above the steps
 * and is updated by refreshProgress() on every state change.
 *
 * Storage: private keys go through app/keys-store.js (C17, IndexedDB) ONLY.
 * Never localStorage, never the URL, never the page source. The private key
 * is NEVER displayed in full and is never copyable on this screen; export
 * happens only through the backup path.
 *
 * Dependencies (resolved lazily at mount time, with fallbacks):
 *   - Crypto: window.GhostChatCrypto (A1, app/js/crypto-core.js) or a dynamic
 *     import of ./js/crypto-core.js; else direct WebCrypto calls in this file.
 *     P-256 fallback: window.GhostCorpP256 (A2, app/js/crypto-p256.js).
 *   - Keys store: window.GhostChatKeysStore (C17) — real API
 *     saveKeys({encPrivate, sigPrivate, encPublic, sigPublic, fingerprints},
 *     roomId?) / loadKeys / hasKeys (IndexedDB, per room); adapted in
 *     resolveKeysStore(). A minimal built-in IndexedDB store is used only
 *     when C17 is not loaded.
 *   - Backup: window.GhostChatBackup (C11) — REQUIRED, no fallback in
 *     this file. Real API createBackup(keys, device, passphrase,
 *     options) returning { fileText, filename, verified } with the
 *     mandatory test-restore run inside the call; downloadBackup
 *     (fileText, filename) for delivery. It writes the G2 layout
 *     (owner/backup-format.md). When C11 is absent, saveBackup() fails
 *     closed (COPY.backupUnavailable, reload the page); Join stays
 *     blocked on the backup step unless the owner explicitly accepts
 *     the skip warning. C1's index.html loads backup.js before this
 *     file, so C11 is always loaded in the shipped page.
 *   - Copy deck: app/copy-deck.md (J1) had NOT landed when this file was
 *     written, so all strings here are plain words, no jargon, written in
 *     this file. When J1 lands, C-workers should swap these strings for the
 *     deck strings verbatim — the string table is COPY below, in one place.
 *   - Config: options.config / window.GhostChatConfig (C20) if present, else
 *     the DEFAULTS below (key directory URL, room id).
 *   NOTE (wave-2 timing): C11, C17 and C20 landed while this file was being
 *   written; the adapters above were verified against their actual exports
 *   (not assumed signatures). The fallbacks stay so setup still works if
 *   any of them is not loaded by C1/C3.
 *
 * Conflicts / FILE-MAP overrides applied (FILE-MAP wins):
 *   - UI-SPEC §2.1 step 3 shows Jarvis's fingerprint as "ceabe1c7…a620ee5"
 *     and treats the relay GET /keys as an open dependency. FILE-MAP D13
 *     pins the FULL fingerprint (below) and D2/D8 put the key directory at
 *     chat/keys/participants.json in the public repo. This view fetches that
 *     file (configurable) and compares the full 64-hex value, not a prefix.
 *   - UI-SPEC §2.1c exports a bare .pem private key. FILE-MAP C11 + D16
 *     require a passphrase-encrypted backup (PBKDF2 >= 600k + AES-256-GCM)
 *     and OWNER-JOIN §2 requires the backup file to hold a LOCKED key, never
 *     a bare one. This view never offers a bare private-key export.
 *   - OWNER-JOIN §1 says the owner joins with "about 5 taps" and lists
 *     Make my key -> Save my backup -> Join. The Jarvis fingerprint check
 *     is a non-tappable blocking gate inside step 2; it adds no tap when
 *     it passes (it runs automatically). The Publish tap is likewise gone
 *     in the no-endpoint case (P7: auto-recorded as pending). Tap count
 *     is now 4 (open link, Make my key, Save my backup, Join) + typing
 *     the backup phrase; 5 when a publish endpoint IS configured.
 *   - UI-SPEC §2.1 step 4 (publish) assumes a POST /keys relay endpoint.
 *     No such endpoint exists in the FILE-MAP store design (D2: the store
 *     is a git repo; publishing is a git write by Jarvis, D3). So publish
 *     here is: use options.onPublishPublicKey if app.js supplies one;
 *     otherwise record the public key as "publish pending" and say so
 *     plainly — the owner shares the check-code with Jarvis in Muse chat
 *     and Jarvis publishes it. A configured publish endpoint that FAILS
 *     blocks Join (with Retry); a missing endpoint does NOT block Join,
 *     because blocking forever on a not-yet-built endpoint would deadlock
 *     first contact. See publishPublicKey() and §8 OPEN DEPENDENCY.
 *
 * No real keys are generated by this file's tests. Verification uses
 * throwaway keys only. No private-key material, plaintext conversation,
 * secret, or personal info is written into any file by this module.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.GhostChatSetup = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /* ------------------------------------------------------------------ */
  /* Constants — pinned values (FILE-MAP D13, CRYPTO-DESIGN §9)         */
  /* ------------------------------------------------------------------ */

  // Jarvis's v1 RSA-4096 encryption public-key fingerprint:
  // SHA-256 of DER SPKI, lowercase hex. NEVER a private key; the public
  // fingerprint is safe to show. Blocking check target (step 3).
  var JARVIS_ENC_FINGERPRINT =
    'ceabe1c77c4c15710dc6e06992bad6c70c8ba1d8c0adaf17a2f3b1042a620ee5';

  var RSA_MODULUS_LENGTH = 4096;
  var BACKUP_FORMAT = 'GHOSTCORP-CHAT-BACKUP v1';
  var KEYS_DB_NAME = 'ghostcorp-chat';
  var KEYS_STORE_NAME = 'keys';
  var OWNER_KEY_RECORD_ID = 'owner';

  var DEFAULTS = {
    // Key directory (FILE-MAP D2/D8). First URL tried, then the fallback.
    keyDirectoryUrls: ['chat/keys/participants.json', 'keys/participants.json'],
    displayNameDefault: 'Owner'
  };

  /* ------------------------------------------------------------------ */
  /* Copy — plain words, no jargon. Strings marked [J1 …] are verbatim */
  /* from app/copy-deck.md §1 (J1, canonical — it has landed, so the    */
  /* wave-2 placeholder strings are replaced here). Strings marked      */
  /* [code] have no deck equivalent, or the deck string contradicts     */
  /* the rule this view enforces (noted inline — see the report).       */
  /* Every error/blocked string below is one line that says what to do  */
  /* next; where the deck string itself states no action, the action    */
  /* is the button beside it (labelled with the deck retry string).     */
  /* ------------------------------------------------------------------ */

  var COPY = {
    headline: 'Private chat for Jarvis, ChatGPT and you. Only the three of you can read it.', // [J1 setup.title]
    subhead: 'This chat is locked. Only you, Jarvis and ChatGPT can read it. Your device will now make your private key — this takes a few seconds and never leaves your device.', // [J1 setup.intro]
    nameLabel: 'Your name in the chat', // [J1 setup.name.label]
    nameHint: 'This name is public inside the chat. It is not a secret.', // [J1 setup.name.hint]
    deviceLabel: 'This device', // [code]
    devicePhone: 'Phone', // [code]
    devicePc: 'Computer', // [code]
    deviceOther: 'Other device', // [code]
    generateButton: 'Make my key', // [J1 setup.make_key.button]
    generating: 'Making your key… keep this tab open.', // [J1 setup.make_key.waiting]
    generatingSlow: 'Making your key… this can take about 10 to 30 seconds on a phone. Please wait — do not tap twice.', // [J1 setup.make_key.slow]
    generateFailed: 'Your browser could not make a key. Try again in a normal tab — not a private or incognito tab — in a current browser.', // [J1 setup.make_key.failed]
    retryButton: 'Try again', // [J1 setup.make_key.retry]
    retryCheckButton: 'Retry check', // [J1 setup.verify_jarvis.retry]
    retryPublishButton: 'Retry publish', // [J1 setup.publish.retry]
    webcryptoMissing: 'This browser can’t do the encryption this chat needs.', // [J1 setup.no_crypto.title]
    webcryptoBody: 'Use a current browser over HTTPS. There is no weaker way to join this chat.', // [J1 setup.no_crypto.body]
    keyReady: 'Your key is ready.', // [J1 setup.key_made.title]
    storageNote: 'Your private key stays in this browser only. It is never sent to the chat. If you clear this browser’s site data, you lose it — save a backup below before you need it.', // [J1 setup.key_made.note]
    encFingerprintLabel: 'Your lock fingerprint (encryption key)', // [code — deck has one singular label; this view shows two keys]
    sigFingerprintLabel: 'Your signature fingerprint (signing key)', // [code — see above]
    fingerprintsToggle: 'Show full fingerprints', // [code]
    fingerprintsExplain: 'This long code is your key’s fingerprint. It is safe to share. It proves this key is yours.', // [J1 setup.fingerprint.explain]
    checkCodeLabel: 'Your check-code', // [J1 setup.check_code.label]
    checkCodeHint: 'This code proves this key is yours. Jarvis will show you the same code in Muse chat — if the codes match, nobody swapped your key.', // [J1 setup.check_code.explain]
    copyButton: 'Copy', // [J1 setup.check_code.copy]
    copied: 'Copied.', // [code]
    importToggle: 'I already have a key — import it', // [J1 setup.import.link]
    importHint: 'Paste your private key here to bring back a key you already made. It never leaves this device.', // [J1 setup.import.hint]
    importButton: 'Import my key', // [J1 setup.import.button]
    importFailed: 'That doesn’t look like a valid private key. Nothing was sent.', // [J1 setup.import.bad]
    importDone: 'Key imported. Check the fingerprint above matches your backup before you go on.', // [code — no deck string]
    jarvisTitle: 'Check Jarvis’s key', // [J1 setup.verify_jarvis.title]
    jarvisChecking: 'Checking Jarvis’s key…', // [J1 setup.verify_jarvis.waiting]
    jarvisMatch: 'Jarvis’s key matches the verified fingerprint. You can trust messages from Jarvis.', // [J1 setup.verify_jarvis.match]
    jarvisMismatch: 'STOP. The key the chat shows for Jarvis does NOT match the verified fingerprint. Do not send anything. Tell Jarvis.', // [J1 setup.verify_jarvis.mismatch]
    jarvisUnavailable: 'Could not check Jarvis’s key right now. The chat could not be reached, or Jarvis’s key is not published yet.', // [J1 setup.verify_jarvis.cannot_check]
    jarvisExpectedLabel: 'Verified fingerprint for Jarvis', // [code]
    jarvisSeenLabel: 'Fingerprint the chat is showing for Jarvis', // [code]
    publishTitle: 'Publish your public key', // [code — sub-heading inside step 2]
    publishButton: 'Publish my public key to the chat', // [J1 setup.publish.button]
    publishing: 'Publishing your public key…', // [J1 setup.publish.waiting]
    publishDone: 'Your public key is published. Jarvis and ChatGPT can now lock messages for you.', // [J1 setup.publish.done]
    publishPending: 'Your public key is saved on this device as “waiting to publish”. Share your check-code with Jarvis in Muse chat and he will publish it — you can still join.', // [code — no deck string for the no-endpoint case]
    publishFailed: 'Publish failed — your key is saved in this browser. Retry publish.', // [J1 setup.publish.failed]
    backupHint: 'Pick a phrase only you know — like four random words. You’ll need it if you ever restore. Jarvis cannot recover it for you if you forget it.', // [J1 setup.backup.phrase_prompt]
    backupPhraseLabel: 'Backup phrase', // [code]
    // [code — deck setup.backup.phrase_too_short says "more than one
    // word", but this view enforces >= 4 words or >= 12 chars, so the
    // message states the enforced rule instead.]
    backupPhraseWeak: 'Pick a longer phrase — at least four words, or 12 characters.',
    backupButton: 'Save my backup', // [J1 setup.backup.button]
    backupSaving: 'Saving your backup…', // [code — no deck string]
    backupDone: 'Backup saved. Keep the file somewhere only you can reach — not in the chat, not in an email, and never as a screenshot.', // [J1 setup.backup.saved]
    backupFailed: 'The backup could not be saved. Try again — do not join without a backup unless you accept the risk below.', // [code — no deck string]
    backupUnavailable: 'The backup tool did not load. Reload the page and try again.', // [code — no deck string; shown only when C11 failed to load]
    backupTestFailed: 'The backup file did not open again with your phrase. It was not saved as a good backup. Try again.', // [code — no deck string]
    skipWarning: 'If you skip this and lose this device, your old messages cannot be opened again. Jarvis can re-share the conversation for you, but only if you ask him to.', // [J1 setup.backup.skip_warning]
    skipAccept: 'I’ll risk it — skip backup', // [J1 setup.backup.skip]
    skipAccepted: 'You chose to skip the backup. You can save one later from Settings.', // [code — no deck string]
    joinButton: 'Join the chat', // [J1 setup.join.button]
    joinDoneButton: '✓ You’re in', // [code — join-button label after a successful join]
    // Join-blocked reasons: one line each, naming the next action.
    // Deck setup.join.disabled_reason covers the key + Jarvis cases;
    // setup.join.disabled_backup covers the backup case.
    joinBlockedReason: 'Finish the steps above first — make your key, save a backup, and check Jarvis’s key.', // [J1 setup.join.disabled_reason]
    joinBlockedBackup: 'Save a backup first, or tap “I’ll risk it — skip backup” if you accept losing old messages if this device is lost.', // [J1 setup.join.disabled_backup]
    joinBlockedPublish: 'Publish failed — your key is saved in this browser. Retry publish.', // [J1 setup.publish.failed]
    joinDone: '✓ You’re in — welcome to the locked chat.', // [code — no deck string]
    publishFirst: 'Publish your public key first, or wait for Jarvis to publish it.', // [code — no deck string]
    noKeyStored: 'No key found in this browser — make a new one or restore from your backup. Old messages locked for the lost key will stay unreadable on this device.', // [J1 setup.no_key.body]
    alreadyHaveKey: 'You already have a key in this browser.', // [code]
    enterChatButton: 'Enter the chat', // [code]
    // Progress steps (P7): the four user-facing steps, in order.
    progressSteps: ['Make your key', 'Check your code', 'Save your backup', 'Join the chat']
  };

  /* ------------------------------------------------------------------ */
  /* Pure helpers (no DOM, no crypto — unit-testable in Node)            */
  /* ------------------------------------------------------------------ */

  function isHex64(s) {
    return typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
  }

  // Group a 64-hex fingerprint in 8-char chunks: "ceabe1c7 7c4c1571 …".
  function groupFingerprint(hex) {
    if (typeof hex !== 'string') return '';
    var clean = hex.toLowerCase().replace(/[^0-9a-f]/g, '');
    var out = [];
    for (var i = 0; i < clean.length; i += 8) out.push(clean.slice(i, i + 8));
    return out.join(' ');
  }

  // Check-code (OWNER-JOIN §1): first 8 hex chars, "AB12-CD34" form.
  function checkCodeFromFingerprint(hex) {
    if (typeof hex !== 'string') return '';
    var clean = hex.toLowerCase().replace(/[^0-9a-f]/g, '');
    if (clean.length < 8) return '';
    return (clean.slice(0, 4) + '-' + clean.slice(4, 8)).toUpperCase();
  }

  // Constant-time-ish equality for same-length hex strings (no early exit
  // on the common path; length mismatch still returns false).
  function fingerprintsEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    var x = a.toLowerCase();
    var y = b.toLowerCase();
    if (x.length !== y.length) return false;
    var diff = 0;
    for (var i = 0; i < x.length; i++) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
    return diff === 0;
  }

  // Jarvis check — OWNED by C16 fingerprint-check.js (B-H assembly
  // decision, 2026-11-16): this file no longer implements the check
  // itself; it delegates to GhostcorpFingerprintCheck and maps the
  // result onto this view's 'match' | 'mismatch' | 'unavailable'
  // verdict. Fail-closed: when the C16 module has not loaded (its
  // script tag precedes this one in index.html, so this only happens
  // if that load failed), the verdict is 'unavailable' — setup cannot
  // proceed without a verified Jarvis key. A C16 verdict other than
  // 'match' / 'mismatch' (invalid input, check-code-only) is likewise
  // 'unavailable': the directory did not supply a checkable
  // fingerprint. Either way joining stays blocked (canJoin requires
  // 'match'), so no verdict here can ever pass a bad key.
  function verifyJarvisFingerprint(seenFingerprint) {
    var mod = null;
    try {
      if (typeof self !== 'undefined' && self.GhostcorpFingerprintCheck) {
        mod = self.GhostcorpFingerprintCheck;
      } else if (typeof window !== 'undefined' && window.GhostcorpFingerprintCheck) {
        mod = window.GhostcorpFingerprintCheck;
      } else if (typeof globalThis !== 'undefined' && globalThis.GhostcorpFingerprintCheck) {
        mod = globalThis.GhostcorpFingerprintCheck;
      }
    } catch (e) { mod = null; }
    if (!mod || typeof mod.verifyJarvisEncryptionFingerprint !== 'function') {
      return 'unavailable';
    }
    var result;
    try {
      result = mod.verifyJarvisEncryptionFingerprint(seenFingerprint);
    } catch (e) {
      return 'mismatch'; // e.g. private-key-looking input: block, never pass
    }
    if (result && result.ok) return 'match';
    if (result && result.reason === 'mismatch') return 'mismatch';
    return 'unavailable';
  }

  // Join gate (pure): every condition that must hold before Join completes.
  // state: { keysReady, jarvisCheck, backupSaved, skipBackupAccepted,
  //          publishState } where publishState is
  //          'done' | 'pending-no-endpoint' | 'failed' | 'not-started'.
  // Every reason is one line naming the next action (P7).
  function joinBlockReason(state) {
    if (!state) return COPY.joinBlockedReason;
    if (!state.keysReady) return COPY.joinBlockedReason;
    if (state.jarvisCheck !== 'match') return COPY.joinBlockedReason;
    if (state.publishState === 'failed') return COPY.joinBlockedPublish;
    if (state.publishState === 'not-started') return COPY.publishFirst;
    if (!state.backupSaved && !state.skipBackupAccepted) return COPY.joinBlockedBackup;
    return null; // allowed
  }

  function canJoin(state) {
    return joinBlockReason(state) === null;
  }

  // Pure progress (P7): which of the 4 user-facing steps is current and
  // which are done. Step 2 counts as done only when the Jarvis check
  // matched AND the public key is published or recorded pending.
  function setupProgress(state) {
    var done = [false, false, false, false];
    if (!state) return { current: 1, done: done };
    done[0] = !!state.keysReady;
    done[1] = state.jarvisCheck === 'match' &&
      (state.publishState === 'done' || state.publishState === 'pending-no-endpoint');
    done[2] = !!(state.backupSaved || state.skipBackupAccepted);
    done[3] = !!state.joined;
    var current = 4;
    for (var i = 0; i < 4; i++) {
      if (!done[i]) { current = i + 1; break; }
    }
    return { current: current, done: done };
  }

  function backupPhraseIsStrong(phrase) {
    if (typeof phrase !== 'string') return false;
    var trimmed = phrase.trim();
    if (trimmed.length < 12) return false;
    var words = trimmed.split(/\s+/).filter(Boolean);
    return words.length >= 4 || trimmed.length >= 20;
  }

  /* ------------------------------------------------------------------ */
  /* Browser helpers                                                     */
  /* ------------------------------------------------------------------ */

  function getSubtle() {
    if (typeof crypto === 'undefined' || !crypto.subtle) return null;
    return crypto.subtle;
  }

  function isSecureContextOk() {
    if (typeof window !== 'undefined' && typeof window.isSecureContext !== 'undefined') {
      return !!window.isSecureContext;
    }
    return true; // non-browser / test runtimes: let getSubtle() decide.
  }

  function getCryptoModule() {
    if (typeof window !== 'undefined' && window.GhostChatCrypto) return window.GhostChatCrypto;
    if (typeof globalThis !== 'undefined' && globalThis.GhostChatCrypto) return globalThis.GhostChatCrypto;
    return null;
  }

  function getP256Module() {
    if (typeof window !== 'undefined' && window.GhostCorpP256) return window.GhostCorpP256;
    if (typeof globalThis !== 'undefined' && globalThis.GhostCorpP256) return globalThis.GhostCorpP256;
    return null;
  }

  function getBackupModule() {
    if (typeof window !== 'undefined' && window.GhostChatBackup) return window.GhostChatBackup;
    if (typeof globalThis !== 'undefined' && globalThis.GhostChatBackup) return globalThis.GhostChatBackup;
    return null;
  }

  function getKeysStoreModule() {
    if (typeof window !== 'undefined' && window.GhostChatKeysStore) return window.GhostChatKeysStore;
    if (typeof globalThis !== 'undefined' && globalThis.GhostChatKeysStore) return globalThis.GhostChatKeysStore;
    return null;
  }

  function getConfig(options) {
    var cfg = (options && options.config) || {};
    if (typeof window !== 'undefined' && window.GhostChatConfig) {
      var w = window.GhostChatConfig;
      cfg = Object.assign({}, w, cfg);
    }
    var urls = cfg.keyDirectoryUrls || (cfg.keyDirectoryUrl ? [cfg.keyDirectoryUrl] : null) || DEFAULTS.keyDirectoryUrls;
    // Prefer the live absolute URL when config supplies one, then the
    // relative fallbacks (works when the page is served from the store).
    if (cfg.keyDirectoryUrl && urls.indexOf(cfg.keyDirectoryUrl) !== 0) {
      urls = [cfg.keyDirectoryUrl].concat(urls.filter(function (u) { return u !== cfg.keyDirectoryUrl; }));
    }
    return {
      roomId: cfg.roomId || options && options.roomId || 'ghostcorp-chat-1',
      keyDirectoryUrls: urls,
      displayNameDefault: cfg.displayNameDefault || DEFAULTS.displayNameDefault,
      onPublishPublicKey: (options && options.onPublishPublicKey) || cfg.onPublishPublicKey || null,
      fetchFn: (options && options.fetchFn) || (typeof fetch !== 'undefined' ? fetch : null)
    };
  }

  function detectDeviceLabel() {
    if (typeof navigator === 'undefined') return 'other';
    var ua = (navigator.userAgent || '').toLowerCase();
    if (/android|iphone|ipad|mobile/.test(ua)) return 'phone';
    return 'pc';
  }

  /* ------------------------------------------------------------------ */
  /* Key generation (step 1) — WebCrypto, via A1/A2 when loaded          */
  /* ------------------------------------------------------------------ */

  // Generate the signing keypair. Ed25519 primary (FILE-MAP D6); P-256
  // ES256 fallback ONLY if Ed25519 keygen rejects (older browsers).
  // Returns { keypair, sigAlg } where sigAlg is 'Ed25519' or 'ES256'.
  async function generateSigningKeypair() {
    var cryptoMod = getCryptoModule();
    var p256 = getP256Module();
    // Preferred path: A2's generateSigningKeypair already does
    // Ed25519-then-P-256 with the same fallback rule.
    if (p256 && typeof p256.generateSigningKeypair === 'function') {
      var kp = await p256.generateSigningKeypair({ extractable: true });
      var alg = (p256.inferSigAlgFromKey && kp.publicKey)
        ? p256.inferSigAlgFromKey(kp.publicKey)
        : (kp.publicKey && kp.publicKey.algorithm && kp.publicKey.algorithm.name === 'ECDSA' ? 'ES256' : 'Ed25519');
      return { keypair: kp, sigAlg: alg };
    }
    if (cryptoMod && typeof cryptoMod.generateSigningKeypair === 'function') {
      try {
        var pair = await cryptoMod.generateSigningKeypair({ extractable: true });
        return { keypair: pair, sigAlg: 'Ed25519' };
      } catch (e) {
        // Ed25519 rejected — fall through to the P-256 path below.
      }
    }
    // Direct WebCrypto fallback (no A1/A2 loaded).
    var subtle = getSubtle();
    if (!subtle) throw new Error('webcrypto-unavailable');
    try {
      var ed = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
      return { keypair: ed, sigAlg: 'Ed25519' };
    } catch (e) {
      var p = await subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
      return { keypair: p, sigAlg: 'ES256' };
    }
  }

  async function generateEncryptionKeypair() {
    var cryptoMod = getCryptoModule();
    if (cryptoMod && typeof cryptoMod.generateEncryptionKeypair === 'function') {
      return cryptoMod.generateEncryptionKeypair({ extractable: true, modulusLength: RSA_MODULUS_LENGTH });
    }
    var subtle = getSubtle();
    if (!subtle) throw new Error('webcrypto-unavailable');
    return subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: RSA_MODULUS_LENGTH, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true, ['encrypt', 'decrypt']);
  }

  async function fingerprintOf(publicKey) {
    var cryptoMod = getCryptoModule();
    if (cryptoMod && typeof cryptoMod.fingerprintPublicKey === 'function') {
      return cryptoMod.fingerprintPublicKey(publicKey);
    }
    var subtle = getSubtle();
    var der = await subtle.exportKey('spki', publicKey);
    var digest = await subtle.digest('SHA-256', der);
    var bytes = new Uint8Array(digest);
    var hex = '';
    for (var i = 0; i < bytes.length; i++) hex += ('0' + bytes[i].toString(16)).slice(-2);
    return hex;
  }

  /* ------------------------------------------------------------------ */
  /* Private-key storage — C17 (IndexedDB only, never localStorage)      */
  /* ------------------------------------------------------------------ */

  // Minimal built-in IndexedDB store, used ONLY when app/keys-store.js
  // (C17) has not been loaded. Same record shape C17 is specified to use:
  // { id, displayName, deviceLabel, sigAlg, encPrivateKey, sigPrivateKey,
  //   encPublicKeyJwk, sigPublicKeyJwk, encFingerprint, sigFingerprint,
  //   createdAt }. CryptoKey objects are stored directly (structured clone).
  function builtinKeysStore() {
    function openDb() {
      return new Promise(function (resolve, reject) {
        if (typeof indexedDB === 'undefined') return reject(new Error('indexeddb-unavailable'));
        var req = indexedDB.open(KEYS_DB_NAME, 1);
        req.onupgradeneeded = function () {
          if (!req.result.objectStoreNames.contains(KEYS_STORE_NAME)) {
            req.result.createObjectStore(KEYS_STORE_NAME, { keyPath: 'id' });
          }
        };
        req.onsuccess = function () { resolve(req.result); };
        req.onerror = function () { reject(req.error || new Error('indexeddb-open-failed')); };
      });
    }
    function putRecord(record) {
      return openDb().then(function (db) {
        return new Promise(function (resolve, reject) {
          var t = db.transaction([KEYS_STORE_NAME], 'readwrite');
          var req = t.objectStore(KEYS_STORE_NAME).put(record);
          req.onsuccess = function () { resolve(); };
          req.onerror = function () { reject(req.error || new Error('indexeddb-put-failed')); };
          t.oncomplete = function () { db.close(); };
          t.onerror = function () { db.close(); };
        });
      });
    }
    return {
      saveOwnerKeys: function (record) { return putRecord(record); },
      loadOwnerKeys: function () {
        return openDb().then(function (db) {
          return new Promise(function (resolve, reject) {
            var t = db.transaction([KEYS_STORE_NAME], 'readonly');
            var req = t.objectStore(KEYS_STORE_NAME).get(OWNER_KEY_RECORD_ID);
            req.onsuccess = function () { db.close(); resolve(req.result || null); };
            req.onerror = function () { db.close(); reject(req.error || new Error('indexeddb-read-failed')); };
          });
        });
      },
      hasOwnerKeys: function () {
        return this.loadOwnerKeys().then(function (r) { return !!r; });
      }
    };
  }

  // Adapter: the real C17 module (window.GhostChatKeysStore) exposes
  // saveKeys({encPrivate, sigPrivate, encPublic, sigPublic, fingerprints},
  // roomId?) / loadKeys(roomId?) / hasKeys(roomId?) — IndexedDB, one
  // record per room. Wrap it to this view's internal record shape so the
  // rest of the view does not care which store implementation is loaded.
  // Falls back to the minimal built-in IndexedDB store when C17 is absent.
  function resolveKeysStore(roomId) {
    var mod = getKeysStoreModule();
    if (mod && typeof mod.saveKeys === 'function' && typeof mod.loadKeys === 'function') {
      return {
        saveOwnerKeys: function (record) {
          return mod.saveKeys({
            encPrivate: record.encPrivateKey,
            sigPrivate: record.sigPrivateKey,
            encPublic: record.encPublicKey,
            sigPublic: record.sigPublicKey,
            fingerprints: { enc: record.encFingerprint, sig: record.sigFingerprint }
          }, roomId);
        },
        loadOwnerKeys: function () {
          return mod.loadKeys(roomId).then(function (ks) {
            if (!ks) return null;
            return {
              id: OWNER_KEY_RECORD_ID,
              displayName: null,
              deviceLabel: null,
              sigAlg: (ks.sigPrivate && ks.sigPrivate.algorithm && ks.sigPrivate.algorithm.name === 'ECDSA') ? 'ES256' : 'Ed25519',
              encPrivateKey: ks.encPrivate,
              sigPrivateKey: ks.sigPrivate,
              encPublicKey: ks.encPublic,
              sigPublicKey: ks.sigPublic,
              encFingerprint: ks.fingerprints && ks.fingerprints.enc,
              sigFingerprint: ks.fingerprints && ks.fingerprints.sig,
              prior: ks.prior || []
            };
          });
        },
        hasOwnerKeys: function () {
          return mod.hasKeys(roomId);
        }
      };
    }
    if (mod && typeof mod.saveOwnerKeys === 'function' && typeof mod.loadOwnerKeys === 'function') return mod;
    return builtinKeysStore();
  }

  /* ------------------------------------------------------------------ */
  /* Backup (step 3) — C11 (app/backup.js) ONLY. There is deliberately  */
  /* NO second backup writer in this file any more (P7 follow-up,       */
  /* 2026-11-16): the old built-in fallback wrote the SUPERSEDED        */
  /* OWNER-JOIN §2 layout (multi-line metadata header + BEGIN/END       */
  /* block, field "iv", plaintext {encPrivateKeyJwk, sigPrivateKeyJwk,  */
  /* ...}) while C11 writes the G2 layout (owner/backup-format.md:      */
  /* header line + one single-line JSON object, 13 fields, field        */
  /* "nonce", plaintext exactly {"encryption","signing"} JWKs, no AAD).  */
  /* A fallback-made backup passed its own test-restore yet could not   */
  /* be read by C11 restore — a silently incompatible backup, worse     */
  /* than a clear failure. So when C11 is absent, saveBackup() fails    */
  /* closed with COPY.backupUnavailable (reload the page) and Join      */
  /* stays blocked on this step unless the owner explicitly accepts     */
  /* the skip warning. C11 is always loaded in practice: C1's           */
  /* index.html loads backup.js before view-setup.js (both defer, in    */
  /* document order). No test or other file used the removed fallback   */
  /* (verified by grep before removal).                                 */
  /* ------------------------------------------------------------------ */

  function downloadText(filename, text) {
    var blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.rel = 'noopener';
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(url); a.remove(); }, 1000);
  }

  /* ------------------------------------------------------------------ */
  /* Jarvis fingerprint check (step 3 — BLOCKING)                        */
  /* ------------------------------------------------------------------ */

  async function fetchJarvisFingerprint(urls, fetchFn) {
    if (!fetchFn) return null;
    for (var i = 0; i < urls.length; i++) {
      try {
        var res = await fetchFn(urls[i], { cache: 'no-store' });
        if (!res || !res.ok) continue;
        var dir = await res.json();
        var list = Array.isArray(dir) ? dir : (dir && dir.participants);
        if (!Array.isArray(list)) continue;
        for (var j = 0; j < list.length; j++) {
          if (list[j] && list[j].id === 'jarvis' && typeof list[j].enc_fingerprint === 'string') {
            return list[j].enc_fingerprint;
          }
        }
        return null; // directory loaded but no Jarvis entry: unavailable.
      } catch (e) {
        continue; // try the next URL, then report unavailable.
      }
    }
    return null;
  }

  /* ------------------------------------------------------------------ */
  /* Key import (UI-SPEC §2.1b, collapsed secondary path)                */
  /* ------------------------------------------------------------------ */

  function pemToDer(pem) {
    var b64 = pem.replace(/-----BEGIN [^-]+-----/g, '').replace(/-----END [^-]+-----/g, '').replace(/\s+/g, '');
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function importPrivateKeyText(text, kind, sigAlgHint) {
    var subtle = getSubtle();
    if (!subtle) throw new Error('webcrypto-unavailable');
    var trimmed = String(text || '').trim();
    if (!trimmed) throw new Error('empty-key');
    var cryptoMod = getCryptoModule();
    if (trimmed.charAt(0) === '{') {
      var jwk = JSON.parse(trimmed);
      if (cryptoMod) {
        if (kind === 'enc' && cryptoMod.importEncryptionPrivateKey) return cryptoMod.importEncryptionPrivateKey(jwk);
        if (kind === 'sig' && cryptoMod.importSigningPrivateKey) return cryptoMod.importSigningPrivateKey(jwk);
      }
      if (kind === 'enc') return subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']);
      if (sigAlgHint === 'ES256' || jwk.crv === 'P-256') return subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
      return subtle.importKey('jwk', jwk, { name: 'Ed25519' }, true, ['sign']);
    }
    // PEM PKCS#8.
    var der = pemToDer(trimmed);
    if (kind === 'enc') return subtle.importKey('pkcs8', der, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']);
    if (sigAlgHint === 'ES256') return subtle.importKey('pkcs8', der, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
    return subtle.importKey('pkcs8', der, { name: 'Ed25519' }, true, ['sign']);
  }

  /* ------------------------------------------------------------------ */
  /* View — DOM mount                                                    */
  /* ------------------------------------------------------------------ */

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  function copyButton(textToCopy, label) {
    var btn = el('button', 'setup-copy', label || COPY.copyButton);
    btn.type = 'button';
    btn.setAttribute('aria-label', (label || COPY.copyButton) + ' — value shown beside it');
    btn.addEventListener('click', function () {
      function done() { btn.textContent = COPY.copied; setTimeout(function () { btn.textContent = label || COPY.copyButton; }, 1500); }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(textToCopy).then(done, function () { fallbackCopy(textToCopy); done(); });
      } else {
        fallbackCopy(textToCopy); done();
      }
    });
    return btn;
  }

  function fallbackCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (e) { /* clipboard unavailable */ }
    ta.remove();
  }

  function fingerprintBlock(label, hex) {
    var wrap = el('div', 'setup-fingerprint');
    wrap.appendChild(el('div', 'setup-fingerprint-label', label));
    var code = el('code', 'setup-fingerprint-value', groupFingerprint(hex));
    wrap.appendChild(code);
    wrap.appendChild(copyButton(hex, COPY.copyButton));
    return wrap;
  }

  // Mount the setup view into `container`. Returns a controller with
  // { state, canJoin, join, destroy }. options:
  //   { config, onPublishPublicKey, onComplete, onJoin, fetchFn,
  //     displayName, deviceLabel }
  function mount(container, options) {
    options = options || {};
    var cfg = getConfig(options);
    if (!container) throw new Error('setup-view: container is required');

    // WebCrypto gate (UI-SPEC §2.1d): blocking, no weaker fallback.
    if (!isSecureContextOk() || !getSubtle()) {
      container.textContent = '';
      var blocked = el('div', 'setup-blocked');
      blocked.appendChild(el('h1', 'setup-headline', COPY.webcryptoMissing));
      blocked.appendChild(el('p', 'setup-subhead', COPY.webcryptoBody));
      container.appendChild(blocked);
      return { state: { keysReady: false, jarvisCheck: 'unavailable', backupSaved: false, skipBackupAccepted: false, publishState: 'not-started' }, canJoin: function () { return false; }, join: function () { return Promise.reject(new Error('webcrypto-unavailable')); }, destroy: function () {} };
    }

    var state = {
      displayName: options.displayName || cfg.displayNameDefault,
      deviceLabel: options.deviceLabel || detectDeviceLabel(),
      encKeypair: null,
      sigKeypair: null,
      sigAlg: null,
      encFingerprint: null,
      sigFingerprint: null,
      checkCode: null,
      keysReady: false,
      jarvisCheck: 'pending', // pending | match | mismatch | unavailable
      jarvisSeenFingerprint: null,
      publishState: 'not-started', // not-started | done | pending-no-endpoint | failed
      backupSaved: false,
      skipBackupAccepted: false,
      joined: false
    };
    var keysStore = resolveKeysStore(cfg.roomId);
    var record = null; // stored key record (after save)
    var destroyed = false;
    var genTimer = null; // swaps the "making key" line to the slow variant

    /* --- DOM skeleton (plain words; ids for app.js / tests) --- */
    container.textContent = '';
    var rootEl = el('section', 'setup-view');
    rootEl.setAttribute('aria-label', 'First-run key setup');
    container.appendChild(rootEl);

    rootEl.appendChild(el('h1', 'setup-headline', COPY.headline));
    rootEl.appendChild(el('p', 'setup-subhead', COPY.subhead));

    // P7 progress: "Step N of 4 — <label>", one item per user-facing
    // step, refreshed by refreshProgress() (called from refreshJoin()).
    // Plain <ol> markup so it reads sensibly even before C2 styles it.
    var progressNav = el('nav', 'setup-progress');
    progressNav.setAttribute('aria-label', 'Setup progress');
    var progressList = el('ol', 'setup-progress-list');
    progressNav.appendChild(progressList);
    rootEl.appendChild(progressNav);

    // Step 1 — identity + generate
    var step0 = el('div', 'setup-step', null);
    step0.id = 'setup-step-identity';
    step0.appendChild(el('h2', null, 'Step 1 of 4 — Make your key'));
    var nameLabel = el('label', 'setup-label', COPY.nameLabel);
    nameLabel.setAttribute('for', 'setup-display-name');
    step0.appendChild(nameLabel);
    var nameInput = el('input', 'setup-input');
    nameInput.id = 'setup-display-name';
    nameInput.type = 'text';
    nameInput.value = state.displayName;
    nameInput.setAttribute('autocomplete', 'off');
    nameInput.setAttribute('maxlength', '40');
    step0.appendChild(nameInput);
    step0.appendChild(el('p', 'setup-hint', COPY.nameHint));
    var devLabel = el('label', 'setup-label', COPY.deviceLabel);
    devLabel.setAttribute('for', 'setup-device');
    step0.appendChild(devLabel);
    var devSelect = el('select', 'setup-input');
    devSelect.id = 'setup-device';
    [['phone', COPY.devicePhone], ['pc', COPY.devicePc], ['other', COPY.deviceOther]].forEach(function (pair) {
      var opt = el('option', null, pair[1]);
      opt.value = pair[0];
      if (pair[0] === state.deviceLabel) opt.selected = true;
      devSelect.appendChild(opt);
    });
    step0.appendChild(devSelect);
    rootEl.appendChild(step0);

    // Step 1 (continued) — generate. No second heading: the button
    // carries the step ("Make my key") and the section is one step.
    var step1 = el('div', 'setup-step');
    step1.id = 'setup-step-generate';
    var genBtn = el('button', 'setup-primary', COPY.generateButton);
    genBtn.type = 'button';
    genBtn.id = 'setup-generate';
    step1.appendChild(genBtn);
    var genStatus = el('p', 'setup-status', '');
    genStatus.setAttribute('role', 'status');
    step1.appendChild(genStatus);
    step1.appendChild(el('p', 'setup-hint', COPY.storageNote));

    // Import (collapsed secondary path, UI-SPEC §2.1b)
    var importDetails = el('details', 'setup-import');
    var importSummary = el('summary', null, COPY.importToggle);
    importDetails.appendChild(importSummary);
    importDetails.appendChild(el('p', 'setup-hint', COPY.importHint));
    var encImportLabel = el('label', 'setup-label', 'Encryption private key (PEM or JWK)');
    encImportLabel.setAttribute('for', 'setup-import-enc');
    importDetails.appendChild(encImportLabel);
    var encImport = el('textarea', 'setup-input');
    encImport.id = 'setup-import-enc';
    encImport.rows = 4;
    encImport.setAttribute('autocomplete', 'off');
    encImport.setAttribute('spellcheck', 'false');
    importDetails.appendChild(encImport);
    var sigImportLabel = el('label', 'setup-label', 'Signing private key (PEM or JWK)');
    sigImportLabel.setAttribute('for', 'setup-import-sig');
    importDetails.appendChild(sigImportLabel);
    var sigImport = el('textarea', 'setup-input');
    sigImport.id = 'setup-import-sig';
    sigImport.rows = 4;
    sigImport.setAttribute('autocomplete', 'off');
    sigImport.setAttribute('spellcheck', 'false');
    importDetails.appendChild(sigImport);
    var importBtn = el('button', 'setup-secondary', COPY.importButton);
    importBtn.type = 'button';
    importBtn.id = 'setup-import-button';
    importDetails.appendChild(importBtn);
    var importStatus = el('p', 'setup-status', '');
    importStatus.setAttribute('role', 'status');
    importDetails.appendChild(importStatus);
    step1.appendChild(importDetails);
    rootEl.appendChild(step1);

    // Step 2 — check-code (hero) + full fingerprints (collapsed, so
    // the owner compares the short code, not the long hex, by eye).
    var step2 = el('div', 'setup-step');
    step2.id = 'setup-step-fingerprints';
    step2.hidden = true;
    step2.appendChild(el('h2', null, 'Step 2 of 4 — Check your code'));
    var fpDetails = el('details', 'setup-fingerprints-details');
    fpDetails.appendChild(el('summary', null, COPY.fingerprintsToggle));
    fpDetails.appendChild(el('p', 'setup-hint', COPY.fingerprintsExplain));
    var fpBox = el('div', 'setup-fingerprints');
    fpDetails.appendChild(fpBox);
    step2.appendChild(fpDetails);
    var checkBox = el('div', 'setup-checkcode');
    checkBox.appendChild(el('div', 'setup-fingerprint-label', COPY.checkCodeLabel));
    var checkCodeEl = el('code', 'setup-checkcode-value', '');
    checkBox.appendChild(checkCodeEl);
    var checkCopyWrap = el('span', 'setup-checkcode-copy');
    checkBox.appendChild(checkCopyWrap);
    step2.appendChild(checkBox);
    step2.appendChild(el('p', 'setup-hint', COPY.checkCodeHint));
    rootEl.appendChild(step2);

    // Step 2 (continued) — verify Jarvis (BLOCKING, automatic).
    var step3 = el('div', 'setup-step');
    step3.id = 'setup-step-jarvis';
    step3.hidden = true;
    step3.appendChild(el('h2', null, COPY.jarvisTitle));
    var jarvisStatus = el('p', 'setup-status', COPY.jarvisChecking);
    jarvisStatus.setAttribute('role', 'status');
    step3.appendChild(jarvisStatus);
    var jarvisBox = el('div', 'setup-jarvis');
    step3.appendChild(jarvisBox);
    var jarvisRetry = el('button', 'setup-secondary', COPY.retryCheckButton);
    jarvisRetry.type = 'button';
    jarvisRetry.id = 'setup-jarvis-retry';
    jarvisRetry.hidden = true;
    step3.appendChild(jarvisRetry);
    rootEl.appendChild(step3);

    // Step 2 (continued) — publish public key. The button only stays
    // when a publish endpoint is configured; otherwise publish is
    // auto-recorded as pending (P7) and the button is hidden.
    var step4 = el('div', 'setup-step');
    step4.id = 'setup-step-publish';
    step4.hidden = true;
    step4.appendChild(el('h2', null, COPY.publishTitle));
    var pubBtn = el('button', 'setup-primary', COPY.publishButton);
    pubBtn.type = 'button';
    pubBtn.id = 'setup-publish';
    step4.appendChild(pubBtn);
    var pubStatus = el('p', 'setup-status', '');
    pubStatus.setAttribute('role', 'status');
    step4.appendChild(pubStatus);
    rootEl.appendChild(step4);

    // Step 3 — backup gate
    var step5 = el('div', 'setup-step');
    step5.id = 'setup-step-backup';
    step5.hidden = true;
    step5.appendChild(el('h2', null, 'Step 3 of 4 — Save your backup'));
    step5.appendChild(el('p', 'setup-hint', COPY.backupHint));
    var phraseLabel = el('label', 'setup-label', COPY.backupPhraseLabel);
    phraseLabel.setAttribute('for', 'setup-backup-phrase');
    step5.appendChild(phraseLabel);
    var phraseInput = el('input', 'setup-input');
    phraseInput.id = 'setup-backup-phrase';
    phraseInput.type = 'password';
    phraseInput.setAttribute('autocomplete', 'new-password');
    step5.appendChild(phraseInput);
    var backupBtn = el('button', 'setup-primary', COPY.backupButton);
    backupBtn.type = 'button';
    backupBtn.id = 'setup-backup';
    step5.appendChild(backupBtn);
    var backupStatus = el('p', 'setup-status', '');
    backupStatus.setAttribute('role', 'status');
    step5.appendChild(backupStatus);
    var skipBox = el('div', 'setup-skip');
    skipBox.appendChild(el('p', 'setup-hint', COPY.skipWarning));
    var skipBtn = el('button', 'setup-secondary', COPY.skipAccept);
    skipBtn.type = 'button';
    skipBtn.id = 'setup-skip-backup';
    skipBox.appendChild(skipBtn);
    var skipStatus = el('p', 'setup-status', '');
    skipBox.appendChild(skipStatus);
    step5.appendChild(skipBox);
    rootEl.appendChild(step5);

    // Step 4 — Join
    var joinBox = el('div', 'setup-step setup-join');
    joinBox.id = 'setup-step-join';
    joinBox.appendChild(el('h2', null, 'Step 4 of 4 — Join the chat'));
    var joinBtn = el('button', 'setup-primary setup-join-button', COPY.joinButton);
    joinBtn.type = 'button';
    joinBtn.id = 'setup-join';
    joinBtn.disabled = true;
    joinBox.appendChild(joinBtn);
    var joinStatus = el('p', 'setup-status', COPY.joinBlockedReason);
    joinStatus.setAttribute('role', 'status');
    joinBox.appendChild(joinStatus);
    rootEl.appendChild(joinBox);

    /* --- helpers --- */

    function refreshProgress() {
      var progress = setupProgress(state);
      progressList.textContent = '';
      COPY.progressSteps.forEach(function (label, i) {
        var isCurrent = progress.current === i + 1 && !progress.done[i];
        var li = el('li', 'setup-progress-step' +
          (progress.done[i] ? ' setup-progress-done' : '') +
          (isCurrent ? ' setup-progress-current' : ''));
        li.textContent = 'Step ' + (i + 1) + ' of 4 — ' + label +
          (progress.done[i] ? ' — done' : (isCurrent ? ' — current step' : ''));
        if (isCurrent) li.setAttribute('aria-current', 'step');
        progressList.appendChild(li);
      });
    }

    function refreshJoin() {
      var reason = joinBlockReason(state);
      joinBtn.disabled = reason !== null;
      joinStatus.textContent = state.joined ? COPY.joinDone : (reason || '');
      joinStatus.className = 'setup-status' + (reason ? ' setup-status-blocked' : ' setup-status-ok');
      refreshProgress();
    }

    function showFingerprints() {
      fpBox.textContent = '';
      fpBox.appendChild(fingerprintBlock(COPY.encFingerprintLabel, state.encFingerprint));
      fpBox.appendChild(fingerprintBlock(COPY.sigFingerprintLabel, state.sigFingerprint));
      checkCodeEl.textContent = state.checkCode || '';
      checkCopyWrap.textContent = '';
      if (state.checkCode) checkCopyWrap.appendChild(copyButton(state.checkCode, COPY.copyButton));
      step2.hidden = false;
    }

    async function storeKeys() {
      var cryptoMod = getCryptoModule();
      async function pubJwk(key) {
        if (cryptoMod && cryptoMod.exportPublicKeyJwk) return cryptoMod.exportPublicKeyJwk(key);
        return getSubtle().exportKey('jwk', key);
      }
      record = {
        id: OWNER_KEY_RECORD_ID,
        displayName: state.displayName,
        deviceLabel: state.deviceLabel,
        sigAlg: state.sigAlg,
        encPrivateKey: state.encKeypair.privateKey,
        sigPrivateKey: state.sigKeypair.privateKey,
        encPublicKey: state.encKeypair.publicKey,
        sigPublicKey: state.sigKeypair.publicKey,
        encPublicKeyJwk: await pubJwk(state.encKeypair.publicKey),
        sigPublicKeyJwk: await pubJwk(state.sigKeypair.publicKey),
        encFingerprint: state.encFingerprint,
        sigFingerprint: state.sigFingerprint,
        createdAt: new Date().toISOString()
      };
      // Keys-store only (C17). Never localStorage.
      await keysStore.saveOwnerKeys(record);
    }

    async function afterKeysReady() {
      state.keysReady = true;
      genStatus.textContent = COPY.keyReady + (state.sigAlg === 'ES256' ? ' (Signing uses P-256 on this browser — Ed25519 is not available here.)' : '');
      showFingerprints();
      refreshJoin();
      step3.hidden = false;
      await runJarvisCheck();
    }

    async function runJarvisCheck() {
      state.jarvisCheck = 'pending';
      jarvisStatus.textContent = COPY.jarvisChecking;
      jarvisBox.textContent = '';
      jarvisRetry.hidden = true;
      refreshJoin();
      var seen = await fetchJarvisFingerprint(cfg.keyDirectoryUrls, cfg.fetchFn);
      if (destroyed) return;
      state.jarvisSeenFingerprint = seen;
      state.jarvisCheck = verifyJarvisFingerprint(seen);
      jarvisBox.textContent = '';
      jarvisBox.appendChild(fingerprintBlock(COPY.jarvisExpectedLabel, JARVIS_ENC_FINGERPRINT));
      if (seen) jarvisBox.appendChild(fingerprintBlock(COPY.jarvisSeenLabel, seen));
      if (state.jarvisCheck === 'match') {
        jarvisStatus.textContent = COPY.jarvisMatch;
        jarvisStatus.className = 'setup-status setup-status-ok';
        step4.hidden = false;
        // P7: no publish endpoint exists in the FILE-MAP store design
        // (D2/D3 — the store is a git repo, no POST /keys), so a tap on
        // "Publish my public key" would only record the same
        // pending-no-endpoint state. Do it now instead — one fewer tap,
        // identical state. When an endpoint IS configured the button
        // stays and the tap publishes for real.
        if (!cfg.onPublishPublicKey) publishPublicKey();
      } else if (state.jarvisCheck === 'mismatch') {
        jarvisStatus.textContent = COPY.jarvisMismatch;
        jarvisStatus.className = 'setup-status setup-status-blocked';
        jarvisRetry.hidden = false;
      } else {
        jarvisStatus.textContent = COPY.jarvisUnavailable;
        jarvisStatus.className = 'setup-status setup-status-blocked';
        jarvisRetry.hidden = false;
      }
      refreshJoin();
    }

    async function publishPublicKey() {
      pubStatus.textContent = COPY.publishing;
      pubBtn.disabled = true;
      var publicRecord = {
        id: 'owner',
        display_name: state.displayName,
        device: state.deviceLabel,
        enc_pub_jwk: record ? record.encPublicKeyJwk : null,
        enc_fingerprint: state.encFingerprint,
        sig_pub_jwk: record ? record.sigPublicKeyJwk : null,
        sig_fingerprint: state.sigFingerprint,
        sig_alg: state.sigAlg,
        check_code: state.checkCode
      };
      // Public keys + fingerprints only. Private keys are never in this payload.
      try {
        if (cfg.onPublishPublicKey) {
          await cfg.onPublishPublicKey(publicRecord);
          state.publishState = 'done';
          pubStatus.textContent = COPY.publishDone;
        } else {
          // No publish endpoint configured (FILE-MAP D2/D3: the store is a
          // git repo; there is no POST /keys). Record as pending and say so.
          // Join is NOT blocked on this — the owner shares the check-code
          // with Jarvis in Muse chat and Jarvis publishes the key.
          state.publishState = 'pending-no-endpoint';
          pubStatus.textContent = COPY.publishPending;
        }
      } catch (e) {
        state.publishState = 'failed';
        pubStatus.textContent = COPY.publishFailed;
        pubBtn.disabled = false;
        pubBtn.hidden = false;
        pubBtn.textContent = COPY.retryPublishButton;
      }
      if (state.publishState !== 'failed') {
        step5.hidden = false;
        pubBtn.hidden = true; // nothing left to tap here
      }
      refreshJoin();
    }

    async function saveBackup() {
      var phrase = phraseInput.value || '';
      if (!backupPhraseIsStrong(phrase)) {
        backupStatus.textContent = COPY.backupPhraseWeak;
        backupStatus.className = 'setup-status setup-status-blocked';
        return;
      }
      backupStatus.textContent = COPY.backupSaving;
      backupBtn.disabled = true;
      try {
        var backupMod = getBackupModule();
        if (!backupMod || typeof backupMod.createBackup !== 'function') {
          // C11 did not load: fail closed. There is no fallback backup
          // writer in this file any more (P7 follow-up — the old one
          // wrote the superseded OWNER-JOIN §2 layout, which C11
          // restore cannot read). No backup is saved; Join stays
          // blocked on this step unless the owner explicitly accepts
          // the skip warning. Reloading the page reloads C11.
          backupStatus.textContent = COPY.backupUnavailable;
          backupStatus.className = 'setup-status setup-status-blocked';
          backupBtn.disabled = false;
          refreshJoin();
          return;
        }
        var backupText;
        var filename;
        // Real C11 API: createBackup(keys, device, passphrase, options)
        // with keys = [{ purpose, privateKey, publicKey, fingerprint }];
        // it returns { fileText, filename, verified } and runs the
        // mandatory test-restore inside the call (verified:true means
        // decrypt + re-derive + fingerprint-compare already passed).
        // The file it writes is the G2 layout (owner/backup-format.md:
        // header line + one single-line JSON object, 13 fields, field
        // "nonce", plaintext exactly {"encryption","signing"} JWKs).
        var participant = String(state.displayName || '').replace(/[^A-Za-z0-9_-]/g, '') || 'koalstin';
        var out = await backupMod.createBackup([
          { purpose: 'encryption', privateKey: record.encPrivateKey, publicKey: record.encPublicKey, fingerprint: state.encFingerprint },
          { purpose: 'signing', privateKey: record.sigPrivateKey, publicKey: record.sigPublicKey, fingerprint: state.sigFingerprint }
        ], state.deviceLabel, phrase, { owner: participant });
        backupText = out.fileText;
        filename = out.filename;
        if (!out.verified) throw new Error('backup-test-restore-failed');
        if (typeof backupMod.downloadBackup === 'function') {
          backupMod.downloadBackup(backupText, filename);
        } else {
          downloadText(filename, backupText);
        }
        // Clear the phrase from the field immediately; it is never stored.
        phraseInput.value = '';
        state.backupSaved = true;
        backupStatus.textContent = COPY.backupDone;
        backupStatus.className = 'setup-status setup-status-ok';
      } catch (e) {
        state.backupSaved = false;
        backupStatus.textContent = e && e.message === 'backup-test-restore-failed' ? COPY.backupTestFailed : COPY.backupFailed;
        backupStatus.className = 'setup-status setup-status-blocked';
        backupBtn.disabled = false;
      }
      refreshJoin();
    }

    async function doJoin() {
      var reason = joinBlockReason(state);
      if (reason) {
        joinStatus.textContent = reason;
        return false;
      }
      state.joined = true;
      refreshJoin();
      // "You are in", unmistakable: show the confirmation in place and
      // hold it briefly before routing away, so the user actually sees
      // it instead of the view vanishing under the tap.
      joinBtn.disabled = true;
      joinBtn.textContent = COPY.joinDoneButton;
      await new Promise(function (resolve) { setTimeout(resolve, 900); });
      if (destroyed) return true;
      if (typeof options.onComplete === 'function') options.onComplete(state);
      if (typeof options.onJoin === 'function') options.onJoin(state);
      return true;
    }

    /* --- events --- */

    nameInput.addEventListener('input', function () {
      state.displayName = nameInput.value.trim() || cfg.displayNameDefault;
      if (record) { record.displayName = state.displayName; }
    });
    devSelect.addEventListener('change', function () {
      state.deviceLabel = devSelect.value;
      if (record) { record.deviceLabel = state.deviceLabel; }
    });

    genBtn.addEventListener('click', async function () {
      genBtn.disabled = true;
      genStatus.textContent = COPY.generating;
      genStatus.className = 'setup-status';
      // Deck waiting line first; the slow line after 10 s if the
      // key is still being made (J1 setup.make_key.slow).
      if (genTimer) clearTimeout(genTimer);
      genTimer = setTimeout(function () {
        if (!state.keysReady) genStatus.textContent = COPY.generatingSlow;
      }, 10000);
      try {
        state.encKeypair = await generateEncryptionKeypair();
        var sig = await generateSigningKeypair();
        state.sigKeypair = sig.keypair;
        state.sigAlg = sig.sigAlg;
        state.encFingerprint = await fingerprintOf(state.encKeypair.publicKey);
        state.sigFingerprint = await fingerprintOf(state.sigKeypair.publicKey);
        state.checkCode = checkCodeFromFingerprint(state.encFingerprint);
        await storeKeys();
        await afterKeysReady();
      } catch (e) {
        genStatus.textContent = COPY.generateFailed;
        genStatus.className = 'setup-status setup-status-blocked';
        genBtn.disabled = false;
      }
      if (genTimer) { clearTimeout(genTimer); genTimer = null; }
      refreshJoin();
    });

    importBtn.addEventListener('click', async function () {
      importStatus.textContent = '';
      try {
        var encPriv = await importPrivateKeyText(encImport.value, 'enc');
        var sigPriv = await importPrivateKeyText(sigImport.value, 'sig', null);
        // Derive the public halves from the imported private keys: export
        // each private key as JWK, keep only the public fields, and
        // re-import as a public key so fingerprints can be computed.
        var subtle = getSubtle();
        var encJwk = await subtle.exportKey('jwk', encPriv);
        var sigJwk = await subtle.exportKey('jwk', sigPriv);
        function publicJwk(jwk) {
          var pub = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, n: jwk.n, e: jwk.e };
          Object.keys(pub).forEach(function (k) { if (pub[k] === undefined) delete pub[k]; });
          return pub;
        }
        var encPubJwk = publicJwk(encJwk);
        var sigPubJwk = publicJwk(sigJwk);
        var encPub, sigPub;
        var cryptoMod = getCryptoModule();
        if (cryptoMod && cryptoMod.importEncryptionPublicKeyJwk) {
          encPub = await cryptoMod.importEncryptionPublicKeyJwk(encPubJwk);
        } else {
          encPub = await subtle.importKey('jwk', encPubJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
        }
        if (cryptoMod && cryptoMod.importSigningPublicKeyJwk) {
          sigPub = await cryptoMod.importSigningPublicKeyJwk(sigPubJwk);
        } else if (sigJwk.crv === 'P-256') {
          sigPub = await subtle.importKey('jwk', sigPubJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
        } else {
          sigPub = await subtle.importKey('jwk', sigPubJwk, { name: 'Ed25519' }, true, ['verify']);
        }
        state.encKeypair = { publicKey: encPub, privateKey: encPriv };
        state.sigKeypair = { publicKey: sigPub, privateKey: sigPriv };
        state.sigAlg = sigJwk.crv === 'P-256' ? 'ES256' : 'Ed25519';
        state.encFingerprint = await fingerprintOf(encPub);
        state.sigFingerprint = await fingerprintOf(sigPub);
        state.checkCode = checkCodeFromFingerprint(state.encFingerprint);
        await storeKeys();
        importStatus.textContent = COPY.importDone;
        importStatus.className = 'setup-status setup-status-ok';
        await afterKeysReady();
      } catch (e) {
        importStatus.textContent = COPY.importFailed;
        importStatus.className = 'setup-status setup-status-blocked';
      }
      refreshJoin();
    });

    jarvisRetry.addEventListener('click', function () { runJarvisCheck(); });
    pubBtn.addEventListener('click', function () { publishPublicKey(); });
    backupBtn.addEventListener('click', function () { saveBackup(); });
    skipBtn.addEventListener('click', function () {
      state.skipBackupAccepted = true;
      skipStatus.textContent = COPY.skipAccepted;
      skipStatus.className = 'setup-status setup-status-ok';
      refreshJoin();
    });
    joinBtn.addEventListener('click', function () { doJoin(); });

    // Returning visitor who already has a key and lands on #setup
    // directly: say so plainly and offer one tap back into the chat,
    // instead of presenting "Make my key" as if no key existed.
    keysStore.hasOwnerKeys().then(function (has) {
      if (destroyed || !has) return;
      var notice = el('div', 'setup-already');
      notice.appendChild(el('p', 'setup-status', COPY.alreadyHaveKey));
      var enterBtn = el('button', 'setup-secondary', COPY.enterChatButton);
      enterBtn.type = 'button';
      enterBtn.addEventListener('click', function () {
        if (typeof options.onComplete === 'function') options.onComplete({ restored: true });
        if (typeof options.onJoin === 'function') options.onJoin({ restored: true });
      });
      notice.appendChild(enterBtn);
      rootEl.insertBefore(notice, step0);
    }).catch(function () { /* no keys / store unreadable: normal first run */ });

    refreshJoin();

    return {
      state: state,
      canJoin: function () { return canJoin(state); },
      joinBlockReason: function () { return joinBlockReason(state); },
      verifyJarvis: runJarvisCheck,
      publish: publishPublicKey,
      join: doJoin,
      destroy: function () { destroyed = true; }
    };
  }

  /* ------------------------------------------------------------------ */
  /* Exports                                                             */
  /* ------------------------------------------------------------------ */

  return {
    mount: mount,
    initSetupView: mount,
    JARVIS_ENC_FINGERPRINT: JARVIS_ENC_FINGERPRINT,
    BACKUP_FORMAT: BACKUP_FORMAT,
    COPY: COPY,
    // Pure helpers (unit-testable without a browser):
    isHex64: isHex64,
    groupFingerprint: groupFingerprint,
    checkCodeFromFingerprint: checkCodeFromFingerprint,
    fingerprintsEqual: fingerprintsEqual,
    verifyJarvisFingerprint: verifyJarvisFingerprint,
    joinBlockReason: joinBlockReason,
    canJoin: canJoin,
    setupProgress: setupProgress,
    backupPhraseIsStrong: backupPhraseIsStrong,
    generateEncryptionKeypair: generateEncryptionKeypair,
    generateSigningKeypair: generateSigningKeypair,
    fingerprintOf: fingerprintOf,
    fetchJarvisFingerprint: fetchJarvisFingerprint
    // NOTE: no fallbackBackup export any more. The old fallback backup
    // writer was removed (P7 follow-up, 2026-11-16): it wrote the
    // superseded OWNER-JOIN §2 layout, which C11 (G2 layout) cannot
    // read. Backups go through window.GhostChatBackup only; when C11
    // is absent, saveBackup() fails closed (COPY.backupUnavailable).
  };
});
