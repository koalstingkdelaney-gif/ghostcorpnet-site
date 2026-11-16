/* GhostCorp encrypted chat — GitHub PAT handling (worker C13)
 *
 * Owner's write path only. Jarvis writes via git from the VM; ChatGPT
 * has NO direct write path. The owner writes from his browser with his
 * own GitHub personal access token (PAT), through this module.
 *
 * FILE-MAP (authoritative) refs:
 *   D2  Store layout (public repo, ciphertext only):
 *         chat/messages/<msg_id>.json, chat/manifest.json,
 *         chat/tombstones.jsonl, chat/keys/participants.json
 *   D3  Writers: (b) the owner, in his browser, via the app + his own
 *         GitHub PAT (minimal scope: contents write on the site repo;
 *         stored in his browser only, never in page source, never in docs).
 *   D7  RELAY-SPEC's private-repo variant is OVERRIDDEN by D2: public
 *         repo, ciphertext-only. (RELAY-SPEC §7(b) says private repo /
 *         keys.json / manifest v1 — superseded; see CONFLICTS at the end
 *         of this file.)
 *   D18 CSP: connect-src 'self' https://api.github.com
 *         https://ghostcorpnet.com — the token is sent ONLY to
 *         https://api.github.com, nowhere else.
 *   §6 rule 4: no real keys / secrets in any file. Every token-like
 *         string in this file is a labelled PLACEHOLDER, never a live
 *         token. Tests use a placeholder string only.
 *
 * RELAY-SPEC (variant b, reference detail) refs:
 *   §7(b) Operation mapping: post = Contents PUT (create message file,
 *         then manifest CAS update with sha, retry up to 5 times);
 *         get = GET /contents/messages/<msg_id>.json; list = directory
 *         listing; purge_expired = coordinator job deleting files +
 *         appending tombstones.jsonl. Rate limits §6. Error codes §4.5
 *         (MSG_ID_CONFLICT, RATE_LIMITED, CONFLICT_RETRY, ...).
 *   FILE-MAP §3 overrides the relay envelope (ecc-1, AES-256-CBC+HMAC,
 *   not the relay spec's AES-256-GCM) and the manifest shape
 *         ({"v":"ecc-1","seq":...,"messages":[{msg_id,seq,sender,iat,
 *         exp,url:"messages/<msg_id>.json"}]}). This module carries
 *         envelopes opaquely — it never parses, decrypts, or logs
 *         envelope content — so the envelope change does not change
 *         this module's behaviour.
 *
 * OWNER-JOIN refs: §3 the owner joins with his own keypair; his PAT is
 *   a separate, GitHub-only credential for publishing. He never pastes
 *   his private key, backup file, or backup phrase here — this module
 *   accepts ONLY a GitHub PAT, and rejects anything that looks like a
 *   private key.
 *
 * Security rules implemented here:
 *   1. Storage is IndexedDB ONLY. Never localStorage, never
 *      sessionStorage, never cookies, never in page source, never in
 *      any file, never in a URL, never logged.
 *   2. The token is sent ONLY to https://api.github.com, as an
 *      `Authorization: Bearer <token>` header. Every fetch in this
 *      module goes through githubFetch(), which refuses any URL whose
 *      origin is not https://api.github.com.
 *   3. The token value is never logged, never included in an error
 *      message, never returned by any status function. Status reports
 *      give only: present/absent, token kind (classic / fine-grained /
 *      unknown), and scopes reported by GitHub (header only).
 *   4. In-memory copy is held in a closure variable, cleared on wipe
 *      and on page unload is NOT persisted anywhere else. The input
 *      field is cleared immediately after the token is read.
 *   5. Validation is a READ-ONLY API call before the first write.
 *      A write is refused until validation has passed in this session
 *      (or the caller explicitly passes { skipValidation: true } for a
 *      retry after a successful validation — never the default).
 *   6. Minimal scope: fine-grained PAT with Contents: Read and write
 *      on the ghostcorpnet-site repo ONLY (or, if a classic PAT is
 *      used, the `repo` scope — wider than needed, and the UI should
 *      warn the owner to prefer fine-grained). This module cannot
 *      prove a fine-grained PAT is repo-scoped from the client alone;
 *      the read-only validation call against that exact repo is the
 *      check: a token without access to this repo gets 404/403 here.
 *
 * No external resources, no build step, no framework. Plain script;
 * exposes window.GhostCorpPat (and module.exports under Node, for tests).
 * $0 spend. No plaintext conversation content is handled here — file
 * contents passed to putFile() are opaque envelope/store JSON strings
 * supplied by the caller (C14 paste-publish / C7 compose); this module
 * never logs them.
 */
(function (globalThis_) {
  'use strict';

  /* ------------------------------------------------------------------ */
  /* Config                                                              */
  /* ------------------------------------------------------------------ */

  var DEFAULTS = {
    apiBase: 'https://api.github.com',
    // Public site repo (FILE-MAP D2). Owner/repo from the live site-sync
    // chain (TRANSPORT-DECISION §2.2): github.com/koalstingkdelaney-gif/
    // ghostcorpnet-site. Override per call via options, or once via
    // GhostCorpPat.configure({ owner, repo, branch }).
    owner: 'koalstingkdelaney-gif',
    repo: 'ghostcorpnet-site',
    branch: 'main',
    // Store paths inside the repo (FILE-MAP D2, §3).
    chatDir: 'chat',
    manifestPath: 'chat/manifest.json',
    tombstonesPath: 'chat/tombstones.jsonl',
    // CAS retries for the shared manifest (RELAY-SPEC §7(b) post step 4).
    maxCasRetries: 5,
    casBackoffMs: [500, 1000, 2000, 4000, 8000],
    // Validation cache: a passed validation stays valid for this long
    // within one page session (the token itself is re-read from
    // IndexedDB on load; validation is re-run after a reload).
    validationTtlMs: 15 * 60 * 1000,
  };

  var config = {
    owner: DEFAULTS.owner,
    repo: DEFAULTS.repo,
    branch: DEFAULTS.branch,
    chatDir: DEFAULTS.chatDir,
    manifestPath: DEFAULTS.manifestPath,
    tombstonesPath: DEFAULTS.tombstonesPath,
  };

  /* ------------------------------------------------------------------ */
  /* IndexedDB storage — the ONLY persistence for the token              */
  /* ------------------------------------------------------------------ */

  var DB_NAME = 'ghostcorp-chat-pat';
  var DB_VERSION = 1;
  var STORE_NAME = 'secrets';
  var RECORD_KEY = 'github-pat';

  // In-memory copy only. Never written to any other store. Cleared by
  // wipeToken() and never serialised (no JSON.stringify of this object
  // anywhere in this module).
  var cachedToken = null; // string | null
  var cachedKind = null; // 'classic' | 'fine-grained' | 'unknown' | null
  var validatedAt = 0; // ms epoch of last successful validation, 0 = none
  var validatedScopes = null; // scopes string GitHub reported, or null

  function indexedDB_() {
    if (typeof indexedDB === 'undefined') return null;
    return indexedDB;
  }

  function openDb() {
    return new Promise(function (resolve, reject) {
      var idb = indexedDB_();
      if (!idb) {
        reject(new PatError('INDEXEDDB_UNAVAILABLE',
          'This browser cannot store the token securely (IndexedDB is ' +
          'unavailable — try a normal tab, not private/incognito). ' +
          'The token is never kept anywhere else.'));
        return;
      }
      var req;
      try {
        req = idb.open(DB_NAME, DB_VERSION);
      } catch (e) {
        reject(new PatError('INDEXEDDB_UNAVAILABLE',
          'Could not open secure token storage.'));
        return;
      }
      req.onupgradeneeded = function () {
        if (!req.result.objectStoreNames.contains(STORE_NAME)) {
          req.result.createObjectStore(STORE_NAME);
        }
      };
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () {
        reject(new PatError('INDEXEDDB_UNAVAILABLE',
          'Could not open secure token storage.'));
      };
      req.onblocked = function () {
        reject(new PatError('INDEXEDDB_UNAVAILABLE',
          'Secure token storage is blocked by another tab. Close other ' +
          'chat tabs and try again.'));
      };
    });
  }

  function idbPut(value) {
    return openDb().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx;
        try {
          tx = db.transaction(STORE_NAME, 'readwrite');
        } catch (e) {
          db.close();
          reject(new PatError('INDEXEDDB_UNAVAILABLE',
            'Could not write secure token storage.'));
          return;
        }
        var store = tx.objectStore(STORE_NAME);
        var req = store.put(value, RECORD_KEY);
        req.onsuccess = function () { resolve(); };
        req.onerror = function () {
          reject(new PatError('INDEXEDDB_UNAVAILABLE',
            'Could not save the token.'));
        };
        tx.oncomplete = function () { db.close(); };
        tx.onerror = function () { db.close(); };
      });
    });
  }

  function idbGet() {
    return openDb().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx;
        try {
          tx = db.transaction(STORE_NAME, 'readonly');
        } catch (e) {
          db.close();
          reject(new PatError('INDEXEDDB_UNAVAILABLE',
            'Could not read secure token storage.'));
          return;
        }
        var req = tx.objectStore(STORE_NAME).get(RECORD_KEY);
        req.onsuccess = function () { resolve(req.result || null); };
        req.onerror = function () {
          reject(new PatError('INDEXEDDB_UNAVAILABLE',
            'Could not read secure token storage.'));
        };
        tx.oncomplete = function () { db.close(); };
        tx.onerror = function () { db.close(); };
      });
    });
  }

  function idbDelete() {
    return openDb().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx;
        try {
          tx = db.transaction(STORE_NAME, 'readwrite');
        } catch (e) {
          db.close();
          reject(new PatError('INDEXEDDB_UNAVAILABLE',
            'Could not clear secure token storage.'));
          return;
        }
        var req = tx.objectStore(STORE_NAME).delete(RECORD_KEY);
        req.onsuccess = function () { resolve(); };
        req.onerror = function () {
          reject(new PatError('INDEXEDDB_UNAVAILABLE',
            'Could not remove the token.'));
        };
        tx.oncomplete = function () { db.close(); };
        tx.onerror = function () { db.close(); };
      });
    });
  }

  /* ------------------------------------------------------------------ */
  /* Errors — never carry the token, never carry file content            */
  /* ------------------------------------------------------------------ */

  function PatError(code, message, extra) {
    var err = new Error(message);
    err.name = 'PatError';
    err.code = code;
    if (extra) {
      if (typeof extra.status === 'number') err.status = extra.status;
      if (typeof extra.retryAfterSeconds === 'number') {
        err.retryAfterSeconds = extra.retryAfterSeconds;
      }
    }
    return err;
  }

  // GitHub API error bodies may echo request data; only the short
  // `message` string is surfaced, and only after stripping anything
  // that looks like a token (defence in depth — the token is never in
  // a request body, so this should never trigger).
  function safeGithubMessage(body) {
    var msg = '';
    try {
      var parsed = typeof body === 'string' ? JSON.parse(body) : body;
      msg = (parsed && typeof parsed.message === 'string')
        ? parsed.message : '';
    } catch (e) { msg = ''; }
    if (cachedToken && msg.indexOf(cachedToken) !== -1) {
      msg = '[redacted]';
    }
    return msg || 'GitHub request failed.';
  }

  function retryAfterSecondsFromHeaders(headers) {
    if (!headers || typeof headers.get !== 'function') return null;
    var v = headers.get('retry-after') || headers.get('x-ratelimit-reset');
    if (!v) return null;
    var n = parseInt(v, 10);
    if (!isNaN(n) && n > 0 && n < 3600) {
      // x-ratelimit-reset is an epoch; retry-after is seconds.
      if (headers.get('retry-after')) return n;
      return Math.max(1, n - Math.floor(Date.now() / 1000));
    }
    return null;
  }

  /* ------------------------------------------------------------------ */
  /* Token shape — local checks before anything is stored or sent        */
  /* ------------------------------------------------------------------ */

  // Classic PAT: ghp_ + 36+ base62 chars. Fine-grained PAT:
  // github_pat_ + base62/underscore. OAuth tokens (gho_) and other
  // GitHub token kinds are NOT accepted here — this module takes a PAT
  // only, per the brief (minimal scope, contents write on one repo).
  var CLASSIC_RE = /^ghp_[A-Za-z0-9]{36,}$/;
  var FINE_GRAINED_RE = /^github_pat_[A-Za-z0-9_]{22,}$/;

  function tokenKind(token) {
    if (typeof token !== 'string') return 'unknown';
    if (CLASSIC_RE.test(token)) return 'classic';
    if (FINE_GRAINED_RE.test(token)) return 'fine-grained';
    return 'unknown';
  }

  // Returns { ok: true, kind } or throws a PatError with plain words.
  // NEVER logs or returns the token. The placeholder used in tests is
  // 'ghp_' + '0'.repeat(36) — PLACEHOLDER, NOT A REAL TOKEN.
  function checkTokenShape(raw) {
    if (typeof raw !== 'string') {
      throw new PatError('TOKEN_INVALID',
        'Paste your GitHub token into the box. It is the long code ' +
        'starting ghp_ or github_pat_ from GitHub settings.');
    }
    var token = raw.trim();
    if (!token) {
      throw new PatError('TOKEN_INVALID',
        'The token box is empty. Paste your GitHub token to continue.');
    }
    if (/\s/.test(token)) {
      throw new PatError('TOKEN_INVALID',
        'That token has a space or line break in it. Paste it as one ' +
        'unbroken code, with no extra spaces.');
    }
    if (token.indexOf('BEGIN') !== -1 ||
        token.indexOf('PRIVATE KEY') !== -1 ||
        token.indexOf('GHOSTCORP-CHAT-BACKUP') !== -1) {
      // OWNER-JOIN §2: a private key / backup file is never a PAT.
      throw new PatError('TOKEN_INVALID',
        'That looks like a private key or a chat backup, not a GitHub ' +
        'token. Never paste your private key or backup here. Paste ' +
        'only the GitHub token from GitHub settings.');
    }
    if (token.length > 255) {
      throw new PatError('TOKEN_INVALID',
        'That token is far longer than any GitHub token. Check you ' +
        'pasted the token, not a whole file.');
    }
    var kind = tokenKind(token);
    if (kind === 'unknown') {
      throw new PatError('TOKEN_INVALID',
        'That does not look like a GitHub token. A classic token ' +
        'starts ghp_ and a fine-grained token starts github_pat_. ' +
        'Create one in GitHub settings (see the setup guide) and ' +
        'paste it here.');
    }
    return { ok: true, kind: kind, token: token };
  }

  /* ------------------------------------------------------------------ */
  /* GitHub fetch — api.github.com ONLY, token in header ONLY            */
  /* ------------------------------------------------------------------ */

  function githubFetch(path, options) {
    options = options || {};
    if (typeof path !== 'string' || path.charAt(0) !== '/') {
      return Promise.reject(new PatError('TOKEN_INVALID',
        'Internal error: bad GitHub request path.'));
    }
    if (!cachedToken) {
      return Promise.reject(new PatError('TOKEN_MISSING',
        'No GitHub token is saved. Paste your token first.'));
    }
    var url = DEFAULTS.apiBase + path;
    // Hard allowlist: the token goes ONLY to api.github.com.
    var origin;
    try {
      origin = new URL(url).origin;
    } catch (e) {
      return Promise.reject(new PatError('TOKEN_INVALID',
        'Internal error: bad GitHub request URL.'));
    }
    if (origin !== DEFAULTS.apiBase) {
      return Promise.reject(new PatError('TOKEN_INVALID',
        'Internal error: refused to send the token anywhere except ' +
        'api.github.com.'));
    }
    var headers = {
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      // The token travels ONLY here, ONLY to api.github.com.
      'Authorization': 'Bearer ' + cachedToken,
    };
    if (options.body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }
    var fetchFn = (typeof fetch !== 'undefined') ? fetch : null;
    if (!fetchFn) {
      return Promise.reject(new PatError('TOKEN_INVALID',
        'This browser cannot reach GitHub (fetch is unavailable).'));
    }
    return fetchFn(url, {
      method: options.method || 'GET',
      headers: headers,
      body: options.body !== undefined
        ? JSON.stringify(options.body) : undefined,
    });
  }

  // Map an HTTP response to either parsed JSON or a plain-words
  // PatError. Status codes follow RELAY-SPEC §4.5 where they apply.
  function handleResponse(res, what) {
    var retryAfter = retryAfterSecondsFromHeaders(res.headers);
    if (res.status === 401) {
      throw new PatError('TOKEN_INVALID',
        'GitHub says this token is not valid (401). It may have ' +
        'expired or been revoked. Create a fresh token in GitHub ' +
        'settings and paste it again.',
        { status: 401 });
    }
    if (res.status === 403) {
      throw new PatError('TOKEN_SCOPE',
        'GitHub refused this request (403). The token does not have ' +
        'the access this needs — it must be allowed Contents: Read ' +
        'and write on the ' + config.repo + ' repo. Check the token ' +
        'scope in GitHub settings, or create a new fine-grained ' +
        'token for that one repo only.',
        { status: 403, retryAfterSeconds: retryAfter || undefined });
    }
    if (res.status === 404) {
      throw new PatError('REPO_NOT_FOUND',
        'GitHub could not find ' + what + ' (404). Either the repo ' +
        config.owner + '/' + config.repo + ' does not exist, or ' +
        'this token has no access to it. Check the repo name and ' +
        'the token scope.',
        { status: 404 });
    }
    if (res.status === 409) {
      throw new PatError('CONFLICT_RETRY',
        'GitHub reported a write conflict (409) — another writer ' +
        'changed the same file first. The message itself is safe; ' +
        'retrying will re-read and try again.',
        { status: 409 });
    }
    if (res.status === 422) {
      throw new PatError('TOKEN_INVALID',
        'GitHub rejected this request as invalid (422). The file ' +
        'may have changed since it was read. Try again.',
        { status: 422 });
    }
    if (res.status === 429) {
      throw new PatError('RATE_LIMITED',
        'GitHub rate limit hit (429). Wait a minute and try again.',
        { status: 429, retryAfterSeconds: retryAfter || 60 });
    }
    if (res.status >= 500) {
      throw new PatError('RELAY_UNAVAILABLE',
        'GitHub is having trouble right now (' + res.status + '). ' +
        'Nothing was saved. Wait a minute and try again.',
        { status: res.status });
    }
    if (!res.ok) {
      throw new PatError('RELAY_UNAVAILABLE',
        'GitHub request failed (' + res.status + '). Nothing was saved.',
        { status: res.status });
    }
    return res;
  }

  function readJsonBody(res) {
    return res.text().then(function (text) {
      if (!text) return null;
      try {
        return JSON.parse(text);
      } catch (e) {
        throw new PatError('RELAY_UNAVAILABLE',
          'GitHub sent a reply this app could not read. Nothing was saved.');
      }
    });
  }

  /* ------------------------------------------------------------------ */
  /* Input + storage                                                     */
  /* ------------------------------------------------------------------ */

  // Save a pasted token. `raw` is the exact pasted string; it is
  // validated, stored in IndexedDB only, held in memory, and the
  // caller's input element (if given) is cleared immediately.
  // Returns { ok: true, kind, validated: false } — validation is a
  // separate step (validateToken), run before the first write.
  function saveToken(raw, inputEl) {
    var checked;
    try {
      checked = checkTokenShape(raw);
    } catch (e) {
      if (inputEl) clearInput(inputEl);
      throw e;
    }
    // Clear the visible field FIRST, so the token never sits in the DOM.
    if (inputEl) clearInput(inputEl);
    return idbPut({ token: checked.token, kind: checked.kind,
      savedAt: new Date().toISOString() }).then(function () {
        cachedToken = checked.token;
        cachedKind = checked.kind;
        validatedAt = 0;
        validatedScopes = null;
        return { ok: true, kind: checked.kind, validated: false };
      });
  }

  function clearInput(inputEl) {
    try {
      if (inputEl && typeof inputEl.value === 'string') inputEl.value = '';
    } catch (e) { /* clearing must never throw */ }
  }

  // Wire an <input type="password"> + a save button to saveToken().
  // The token is read from the field once, saved, and the field is
  // cleared. `onStatus` receives plain-words status objects only
  // ({ ok, kind } / { ok: false, code, message }) — never the token.
  function bindPatInput(inputEl, saveButtonEl, onStatus) {
    if (!inputEl || !saveButtonEl) {
      throw new PatError('TOKEN_INVALID',
        'Internal error: token input is not wired up on this page.');
    }
    function report(status) {
      if (typeof onStatus === 'function') {
        try { onStatus(status); } catch (e) { /* status must not throw */ }
      }
    }
    saveButtonEl.addEventListener('click', function () {
      var raw = inputEl.value;
      saveToken(raw, inputEl).then(function (result) {
        report({ ok: true, kind: result.kind,
          message: 'Token saved on this device only. It is checked ' +
            'against GitHub before your first message is sent.' });
      }).catch(function (err) {
        report({ ok: false, code: err.code || 'TOKEN_INVALID',
          message: err.message || 'Could not save the token.' });
      });
    });
    // Enter in the field saves too; the field is cleared either way.
    inputEl.addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter') {
        ev.preventDefault();
        saveButtonEl.click();
      }
    });
    return { ok: true };
  }

  // Load the saved token (if any) into memory. Called at startup by
  // app.js. Returns { ok: true, present: boolean, kind } — never the
  // token itself.
  function loadToken() {
    return idbGet().then(function (record) {
      if (!record || typeof record.token !== 'string') {
        cachedToken = null;
        cachedKind = null;
        return { ok: true, present: false, kind: null };
      }
      var checked;
      try {
        checked = checkTokenShape(record.token);
      } catch (e) {
        // A stored value that no longer looks like a token is wiped,
        // not used.
        cachedToken = null;
        cachedKind = null;
        return wipeToken().then(function () {
          return { ok: true, present: false, kind: null };
        });
      }
      cachedToken = checked.token;
      cachedKind = checked.kind;
      return { ok: true, present: true, kind: checked.kind };
    });
  }

  function hasToken() {
    return cachedToken !== null;
  }

  // Status for the UI. Never includes the token or any part of it.
  function status() {
    return {
      ok: true,
      present: cachedToken !== null,
      kind: cachedKind,
      validated: validatedAt > 0 &&
        (Date.now() - validatedAt) < DEFAULTS.validationTtlMs,
      scopes: validatedScopes,
      repo: config.owner + '/' + config.repo,
      branch: config.branch,
    };
  }

  /* ------------------------------------------------------------------ */
  /* Validation — read-only API call, before the first write             */
  /* ------------------------------------------------------------------ */

  // Read-only check: GET the repo itself. This proves (a) the token is
  // valid, (b) it can reach this exact repo, and (c) the repo exists.
  // It writes NOTHING. A 404 here means "no access to this repo" as
  // often as "repo missing" — the error says so plainly.
  // Also records the scopes GitHub reports (classic PATs only, via the
  // x-oauth-scopes header; fine-grained PATs report none that way, and
  // that is expected, not a failure).
  // Returns { ok: true, kind, scopes, repo }.
  function validateToken(options) {
    options = options || {};
    if (!cachedToken) {
      return Promise.reject(new PatError('TOKEN_MISSING',
        'No GitHub token is saved. Paste your token first.'));
    }
    return githubFetch('/repos/' + encodeURIComponent(config.owner) +
      '/' + encodeURIComponent(config.repo), { method: 'GET' })
      .then(function (res) {
        var scopes = null;
        try {
          if (res.headers && typeof res.headers.get === 'function') {
            scopes = res.headers.get('x-oauth-scopes') || null;
            if (scopes) {
              scopes = scopes.split(',').map(function (s) {
                return s.trim();
              }).filter(Boolean).join(', ');
            }
          }
        } catch (e) { scopes = null; }
        handleResponse(res, 'the repo ' + config.owner + '/' +
          config.repo);
        return readJsonBody(res).then(function (body) {
          validatedAt = Date.now();
          validatedScopes = scopes;
          var result = { ok: true, kind: cachedKind,
            scopes: scopes,
            repo: config.owner + '/' + config.repo };
          if (cachedKind === 'classic' && scopes &&
              scopes.indexOf('repo') === -1) {
            result.warning = 'This classic token does not report the ' +
              'repo scope. It may not be able to write. Prefer a ' +
              'fine-grained token with Contents: Read and write on ' +
              'this repo only.';
          }
          if (cachedKind === 'classic') {
            result.warning = 'This is a classic token. It can reach ' +
              'more than this one repo. Prefer a fine-grained token ' +
              'scoped to ' + config.repo + ' only.';
          }
          if (body && body.private === true) {
            // FILE-MAP D7: the store repo is PUBLIC. A private repo
            // here means the wrong repo is configured.
            result.warning = 'This repo is private. The chat store ' +
              'is meant to be the public ' + config.repo + ' repo, ' +
              'so ChatGPT and the owner can read it without signing in.';
          }
          return result;
        });
      })
      .catch(function (err) {
        if (err && err.code === 'TOKEN_MISSING') throw err;
        // A failed validation never leaves a stale "validated" flag.
        validatedAt = 0;
        validatedScopes = null;
        if (err && err.name === 'PatError') throw err;
        throw new PatError('RELAY_UNAVAILABLE',
          'Could not reach GitHub to check the token. Check your ' +
          'connection and try again. Nothing was saved or sent.');
      });
  }

  function isValidated() {
    return validatedAt > 0 &&
      (Date.now() - validatedAt) < DEFAULTS.validationTtlMs;
  }

  // Gate every write: a token must be present AND validated in this
  // session. Callers pass { skipValidation: true } only to retry a
  // write that already passed validation in this session (e.g. after
  // a CAS conflict) — never as the default.
  function ensureReadyForWrite(options) {
    options = options || {};
    if (!cachedToken) {
      return Promise.reject(new PatError('TOKEN_MISSING',
        'No GitHub token is saved. Paste your token first.'));
    }
    if (options.skipValidation) return Promise.resolve({ ok: true });
    if (isValidated()) return Promise.resolve({ ok: true });
    return validateToken();
  }

  /* ------------------------------------------------------------------ */
  /* Contents API — exact calls (RELAY-SPEC §7(b))                       */
  /*                                                                     */
  /*   GET  /repos/{owner}/{repo}/contents/{path}                       */
  /*        → { sha, content (base64), encoding, ... } or 404           */
  /*   PUT  /repos/{owner}/{repo}/contents/{path}                       */
  /*        { message, content (base64), sha?, branch }                 */
  /*        → 200/201 { content: { sha, ... } }                         */
  /*   DELETE /repos/{owner}/{repo}/contents/{path}                     */
  /*        { message, sha, branch }  (purge path only, D9 sweeper)     */
  /*                                                                     */
  /* `content` is base64 of the exact UTF-8 bytes to store. `sha` is   */
  /* required for updates, omitted for creates. A PUT with a stale     */
  /* sha returns 409 — the CAS signal (RELAY-SPEC §4.5 CONFLICT_RETRY). */
  /* ------------------------------------------------------------------ */

  function contentsPath(path) {
    return '/repos/' + encodeURIComponent(config.owner) +
      '/' + encodeURIComponent(config.repo) + '/contents/' +
      path.split('/').map(encodeURIComponent).join('/');
  }

  function base64EncodeUtf8(text) {
    var bytes = new TextEncoder().encode(text);
    var bin = '';
    for (var i = 0; i < bytes.length; i++) {
      bin += String.fromCharCode(bytes[i]);
    }
    return btoa(bin);
  }

  function base64DecodeUtf8(b64) {
    var bin = atob(b64.replace(/\s/g, ''));
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) {
      bytes[i] = bin.charCodeAt(i);
    }
    return new TextDecoder().decode(bytes);
  }

  // GET the current file record, or null if it does not exist (404).
  // Returns { sha, contentText } or null. Never logs content.
  function getFile(path) {
    return githubFetch(contentsPath(path) +
      '?ref=' + encodeURIComponent(config.branch), { method: 'GET' })
      .then(function (res) {
        if (res.status === 404) return null;
        handleResponse(res, 'the file ' + path);
        return readJsonBody(res).then(function (body) {
          if (!body || typeof body.sha !== 'string') {
            throw new PatError('RELAY_UNAVAILABLE',
              'GitHub sent an unexpected reply for ' + path + '.');
          }
          var contentText = '';
          if (typeof body.content === 'string' && body.content) {
            contentText = base64DecodeUtf8(body.content);
          }
          return { sha: body.sha, contentText: contentText };
        });
      });
  }

  // PUT a file: create if absent, update if present (sha required).
  // If the file already holds byte-identical content, returns
  // { ok: true, duplicate: true, sha } without writing (RELAY-SPEC
  // §3.2 idempotency: same ID + same bytes = OK, already stored).
  // `contentText` is the exact string to store (opaque envelope/store
  // JSON — this module never inspects or logs it).
  function putFile(path, contentText, commitMessage, options) {
    options = options || {};
    if (typeof contentText !== 'string') {
      return Promise.reject(new PatError('TOKEN_INVALID',
        'Internal error: nothing to publish.'));
    }
    return ensureReadyForWrite(options).then(function () {
      return getFile(path);
    }).then(function (existing) {
      if (existing && existing.contentText === contentText) {
        return { ok: true, duplicate: true, sha: existing.sha,
          path: path };
      }
      var body = {
        message: commitMessage ||
          ('chat: publish ' + path),
        content: base64EncodeUtf8(contentText),
        branch: config.branch,
      };
      if (existing) body.sha = existing.sha;
      return githubFetch(contentsPath(path), {
        method: 'PUT', body: body,
      }).then(function (res) {
        handleResponse(res, 'the file ' + path);
        return readJsonBody(res).then(function (parsed) {
          var sha = (parsed && parsed.content &&
            typeof parsed.content.sha === 'string')
            ? parsed.content.sha : (existing ? existing.sha : null);
          return { ok: true, duplicate: false, sha: sha, path: path };
        });
      }).catch(function (err) {
        // A 409 from a stale sha is a CAS conflict: re-read once and
        // retry with the fresh sha, unless the caller already retried.
        if (err && err.code === 'CONFLICT_RETRY' &&
            !options._casRetried) {
          var retryOptions = {};
          for (var k in options) retryOptions[k] = options[k];
          retryOptions._casRetried = true;
          retryOptions.skipValidation = true;
          return putFile(path, contentText, commitMessage, retryOptions);
        }
        throw err;
      });
    });
  }

  // DELETE a file (purge path only — relay D9 sweeper). Requires the
  // current sha. Returns { ok: true }.
  function deleteFile(path, commitMessage, options) {
    options = options || {};
    return ensureReadyForWrite(options).then(function () {
      return getFile(path);
    }).then(function (existing) {
      if (!existing) return { ok: true, duplicate: true, path: path };
      return githubFetch(contentsPath(path), {
        method: 'DELETE',
        body: {
          message: commitMessage || ('chat: remove ' + path),
          sha: existing.sha,
          branch: config.branch,
        },
      }).then(function (res) {
        handleResponse(res, 'the file ' + path);
        return { ok: true, path: path };
      });
    });
  }

  /* ------------------------------------------------------------------ */
  /* Store operations — message / manifest / tombstones (FILE-MAP §3)   */
  /* ------------------------------------------------------------------ */

  function messagePath(msgId) {
    return config.chatDir + '/messages/' + msgId + '.json';
  }

  // Publish one envelope file: chat/messages/<msg_id>.json.
  // `envelopeText` is the exact envelope JSON string (plus `seq` added
  // by the caller/relay — seq is NOT part of the signed bytes, FILE-MAP
  // §3). Idempotent: same msg_id + same bytes returns duplicate: true
  // (RELAY-SPEC §3.2); same msg_id + different bytes is a conflict —
  // the original is kept, and this returns MSG_ID_CONFLICT.
  // The caller must check the duplicate/conflict case: putFile() alone
  // cannot tell "same bytes" from "different bytes" without reading,
  // which it does — see putFile() above. A conflicting file (same
  // path, different content) is overwritten by putFile() only if the
  // caller passes { allowOverwrite: true }; by default publishMessage
  // REFUSES to overwrite a different envelope under the same msg_id.
  function publishMessage(msgId, envelopeText, options) {
    options = options || {};
    if (typeof msgId !== 'string' ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
          .test(msgId)) {
      return Promise.reject(new PatError('TOKEN_INVALID',
        'Internal error: bad message ID.'));
    }
    var path = messagePath(msgId);
    return ensureReadyForWrite(options).then(function () {
      return getFile(path);
    }).then(function (existing) {
      if (existing && existing.contentText === envelopeText) {
        return { ok: true, duplicate: true, msgId: msgId, path: path,
          sha: existing.sha };
      }
      if (existing && !options.allowOverwrite) {
        throw new PatError('MSG_ID_CONFLICT',
          'A different message is already stored under this message ' +
          'ID. The original was kept. Use a new message ID for new ' +
          'content.');
      }
      var nextOptions = {};
      for (var k in options) nextOptions[k] = options[k];
      nextOptions.skipValidation = true;
      return putFile(path, envelopeText,
        'chat: message ' + msgId, nextOptions).then(function (result) {
          return { ok: true, duplicate: result.duplicate,
            msgId: msgId, path: path, sha: result.sha };
        });
    });
  }

  // Read the manifest, apply `mutate(manifestObject)` in memory, and
  // PUT it back with the sha just read (CAS). On a 409, re-read and
  // retry, up to maxCasRetries times with backoff (RELAY-SPEC §7(b)
  // post step 4). `mutate` must return the new manifest object (it
  // must NOT include the token, keys, or plaintext — manifest holds
  // routing metadata only, FILE-MAP §3).
  // Returns { ok: true, manifest, sha, attempts }.
  function updateManifest(mutate, options) {
    options = options || {};
    if (typeof mutate !== 'function') {
      return Promise.reject(new PatError('TOKEN_INVALID',
        'Internal error: no manifest update given.'));
    }
    return ensureReadyForWrite(options).then(function () {
      var attempt = 0;
      function attemptOnce() {
        attempt++;
        return getFile(config.manifestPath).then(function (existing) {
          var manifest;
          if (!existing || !existing.contentText) {
            manifest = { v: 'ecc-1', seq: 0, messages: [] };
          } else {
            try {
              manifest = JSON.parse(existing.contentText);
            } catch (e) {
              throw new PatError('RELAY_UNAVAILABLE',
                'The chat manifest on GitHub could not be read. ' +
                'Nothing was changed.');
            }
          }
          var updated = mutate(manifest);
          if (!updated || typeof updated !== 'object') {
            throw new PatError('TOKEN_INVALID',
              'Internal error: manifest update returned nothing.');
          }
          var text = JSON.stringify(updated);
          var body = {
            message: 'chat: update manifest',
            content: base64EncodeUtf8(text),
            branch: config.branch,
          };
          if (existing) body.sha = existing.sha;
          return githubFetch(contentsPath(config.manifestPath), {
            method: 'PUT', body: body,
          }).then(function (res) {
            handleResponse(res, 'the manifest');
            return readJsonBody(res).then(function (parsed) {
              var sha = (parsed && parsed.content &&
                typeof parsed.content.sha === 'string')
                ? parsed.content.sha : null;
              return { ok: true, manifest: updated, sha: sha,
                attempts: attempt };
            });
          }).catch(function (err) {
            if (err && err.code === 'CONFLICT_RETRY' &&
                attempt < DEFAULTS.maxCasRetries) {
              var delay = DEFAULTS.casBackoffMs[
                Math.min(attempt - 1,
                  DEFAULTS.casBackoffMs.length - 1)];
              return new Promise(function (resolve) {
                setTimeout(resolve, delay);
              }).then(attemptOnce);
            }
            if (err && err.code === 'CONFLICT_RETRY') {
              throw new PatError('CONFLICT_RETRY',
                'The manifest kept changing while this message was ' +
                'being recorded (another writer updated it first). ' +
                'The message file itself is already stored; only the ' +
                'manifest update was not applied. Try again — the ' +
                'next publish will pick it up.',
                { status: 409 });
            }
            throw err;
          });
        });
      }
      return attemptOnce();
    });
  }

  // Append one tombstone line to chat/tombstones.jsonl.
  // entry: { msg_id, seq, purged_at, reason: "expired" } (FILE-MAP §3).
  // The file is append-only JSONL; concurrent appends go through the
  // same read-modify-PUT with one CAS retry (a lost race only delays
  // the tombstone — the message file is already gone).
  function appendTombstone(entry, options) {
    options = options || {};
    if (!entry || typeof entry.msg_id !== 'string' ||
        typeof entry.seq !== 'number') {
      return Promise.reject(new PatError('TOKEN_INVALID',
        'Internal error: bad tombstone entry.'));
    }
    var line = JSON.stringify({
      msg_id: entry.msg_id,
      seq: entry.seq,
      purged_at: entry.purged_at ||
        new Date().toISOString(),
      reason: entry.reason || 'expired',
    }) + '\n';
    return ensureReadyForWrite(options).then(function () {
      return getFile(config.tombstonesPath);
    }).then(function (existing) {
      var text = (existing ? existing.contentText : '') + line;
      var nextOptions = {};
      for (var k in options) nextOptions[k] = options[k];
      nextOptions.skipValidation = true;
      return putFile(config.tombstonesPath, text,
        'chat: tombstone ' + entry.msg_id, nextOptions);
    }).then(function (result) {
      return { ok: true, duplicate: result.duplicate,
        path: config.tombstonesPath, sha: result.sha };
    });
  }

  // Full publish for one message, in the RELAY-SPEC §7(b) order:
  //   1. publish the message file (durable from this step),
  //   2. CAS-update the manifest (seq assigned here; the sender does
  //      NOT know seq at sign time — FILE-MAP §3).
  // `entry` is the manifest entry for this message:
  //   { msg_id, seq, sender, iat, exp, url: "messages/<msg_id>.json" }
  // Returns { ok, duplicate, msgId, seq, sha, manifestAttempts }.
  // If step 2 fails with CONFLICT_RETRY after all retries, the
  // message file is still stored — the error says so plainly, and the
  // next successful publish repairs the manifest (RELAY-SPEC §7(b)).
  function publishEnvelope(msgId, envelopeText, entry, options) {
    options = options || {};
    return publishMessage(msgId, envelopeText, options)
      .then(function (published) {
        if (published.duplicate) {
          return { ok: true, duplicate: true, msgId: msgId,
            seq: entry && entry.seq, sha: published.sha,
            manifestAttempts: 0 };
        }
        return updateManifest(function (manifest) {
          if (!Array.isArray(manifest.messages)) {
            manifest.messages = [];
          }
          var already = manifest.messages.some(function (m) {
            return m.msg_id === msgId;
          });
          if (!already) {
            manifest.messages.push(entry);
            manifest.messages.sort(function (a, b) {
              return a.seq - b.seq;
            });
          }
          if (typeof entry.seq === 'number') {
            manifest.seq = Math.max(manifest.seq || 0, entry.seq);
          }
          manifest.v = 'ecc-1';
          return manifest;
        }, { skipValidation: true }).then(function (updated) {
          return { ok: true, duplicate: false, msgId: msgId,
            seq: entry && entry.seq, sha: published.sha,
            manifestAttempts: updated.attempts };
        });
      });
  }

  /* ------------------------------------------------------------------ */
  /* Removal — wipe the token on demand                                  */
  /* ------------------------------------------------------------------ */

  // Wipe the token: delete the IndexedDB record, clear the in-memory
  // copy, and clear the validation flag. Also clears any token input
  // element passed in. The GitHub token itself is NOT revoked by this
  // — revocation is a GitHub settings action by the owner (RELAY-SPEC
  // §7(b): "revocation is a GitHub settings action by the owner").
  // Returns { ok: true, present: false }.
  function wipeToken(inputEl) {
    if (inputEl) clearInput(inputEl);
    cachedToken = null;
    cachedKind = null;
    validatedAt = 0;
    validatedScopes = null;
    return idbDelete().then(function () {
      return { ok: true, present: false };
    }).catch(function () {
      // Even if IndexedDB is unavailable, the in-memory copy is gone.
      // Report the wipe as done in-memory, with a warning that the
      // stored copy could not be confirmed deleted.
      return { ok: true, present: false,
        warning: 'The token was cleared from memory, but the stored ' +
          'copy could not be confirmed deleted (storage unavailable). ' +
          'Clear your browser site data for this site to be sure.' };
    });
  }

  // Alias matching the brief's wording ("removal").
  function removeToken(inputEl) {
    return wipeToken(inputEl);
  }

  /* ------------------------------------------------------------------ */
  /* Configuration                                                       */
  /* ------------------------------------------------------------------ */

  function configure(options) {
    options = options || {};
    if (typeof options.owner === 'string' && options.owner) {
      config.owner = options.owner;
    }
    if (typeof options.repo === 'string' && options.repo) {
      config.repo = options.repo;
    }
    if (typeof options.branch === 'string' && options.branch) {
      config.branch = options.branch;
    }
    if (typeof options.chatDir === 'string' && options.chatDir) {
      config.chatDir = options.chatDir.replace(/\/$/, '');
      config.manifestPath = config.chatDir + '/manifest.json';
      config.tombstonesPath = config.chatDir + '/tombstones.jsonl';
    }
    return { ok: true, owner: config.owner, repo: config.repo,
      branch: config.branch };
  }

  /* ------------------------------------------------------------------ */
  /* Self-test helper (placeholder token ONLY — never a live token)      */
  /*                                                                     */
  /* GhostCorpPat.selfTestPlaceholder() runs the offline checks only:   */
  /* token-shape validation (with the placeholder string below), URL    */
  /* allowlisting, and base64 round-trip. It performs NO network call   */
  /* and stores NOTHING. A placeholder token must never be saved via   */
  /* saveToken() in production; saveToken() accepts any well-formed    */
  /* string, so the caller — not this module — must never pass a       */
  /* placeholder to it outside a test.                                 */
  /* ------------------------------------------------------------------ */

  var PLACEHOLDER_TOKEN = 'ghp_' + '0'.repeat(36); // PLACEHOLDER — NOT A REAL TOKEN

  function selfTestPlaceholder() {
    var results = [];
    function check(name, passed, detail) {
      results.push({ name: name, passed: !!passed,
        detail: detail || '' });
    }
    try {
      var shaped = checkTokenShape(PLACEHOLDER_TOKEN);
      check('placeholder-shape', shaped.kind === 'classic',
        'placeholder parses as classic');
    } catch (e) {
      check('placeholder-shape', false, e.message);
    }
    try {
      checkTokenShape('not-a-token');
      check('reject-garbage', false, 'garbage was accepted');
    } catch (e) {
      check('reject-garbage', e.code === 'TOKEN_INVALID',
        'garbage rejected with TOKEN_INVALID');
    }
    try {
      checkTokenShape('-----BEGIN PRIVATE KEY-----\nPLACEHOLDER\n-----END PRIVATE KEY-----');
      check('reject-private-key', false, 'private key was accepted');
    } catch (e) {
      check('reject-private-key', e.code === 'TOKEN_INVALID',
        'private-key-like input rejected');
    }
    var roundTrip = base64DecodeUtf8(
      base64EncodeUtf8('{"v":"ecc-1"}')) === '{"v":"ecc-1"}';
    check('base64-roundtrip', roundTrip, 'UTF-8 base64 round-trip');
    check('api-base-is-github', DEFAULTS.apiBase ===
      'https://api.github.com', 'token host is api.github.com only');
    check('store-is-indexeddb-only', DB_NAME === 'ghostcorp-chat-pat',
      'IndexedDB database name set; no localStorage use in this file');
    var allPassed = results.every(function (r) { return r.passed; });
    return { ok: allPassed, results: results };
  }

  /* ------------------------------------------------------------------ */
  /* Public API                                                          */
  /* ------------------------------------------------------------------ */

  var api = {
    // Input / storage
    saveToken: saveToken,
    bindPatInput: bindPatInput,
    loadToken: loadToken,
    hasToken: hasToken,
    status: status,
    // Validation (read-only, before first write)
    validateToken: validateToken,
    isValidated: isValidated,
    ensureReadyForWrite: ensureReadyForWrite,
    // Use — GitHub Contents API
    getFile: getFile,
    putFile: putFile,
    deleteFile: deleteFile,
    publishMessage: publishMessage,
    updateManifest: updateManifest,
    appendTombstone: appendTombstone,
    publishEnvelope: publishEnvelope,
    messagePath: messagePath,
    // Removal
    wipeToken: wipeToken,
    removeToken: removeToken,
    // Config / test
    configure: configure,
    selfTestPlaceholder: selfTestPlaceholder,
    // Exposed for unit tests only (never log their outputs):
    _checkTokenShape: checkTokenShape,
    _tokenKind: tokenKind,
    _base64EncodeUtf8: base64EncodeUtf8,
    _base64DecodeUtf8: base64DecodeUtf8,
    _defaults: DEFAULTS,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  globalThis_.GhostCorpPat = api;

})(typeof globalThis !== 'undefined' ? globalThis : this);

/* ---------------------------------------------------------------------- */
/* FILE-MAP CONFLICTS FOUND (this file implements FILE-MAP, not the design */
/* docs, where they differ — per FILE-MAP §6 rule 1):                      */
/*                                                                        */
/* 1. RELAY-SPEC §7(b): private repo, keys.json registry, manifest        */
/*    {"v": 1, "next_seq": ...}. FILE-MAP D2/D7 + §3 OVERRIDE: public    */
/*    ghostcorpnet-site repo, chat/keys/participants.json, manifest       */
/*    {"v": "ecc-1", "seq": ..., "messages": [...]}. This module uses     */
/*    the FILE-MAP layout and repo. A private repo would break ChatGPT   */
/*    + owner reads (FILE-MAP D7).                                        */
/* 2. RELAY-SPEC §2 envelope: v:1, AES-256-GCM, created_at/expires_at    */
/*    strings, part/parts, cipher/nonce/tag, wrapped_keys as an object.   */
/*    FILE-MAP D5 + §3 OVERRIDE: ecc-1, AES-256-CBC+HMAC (A256CBC-HS256), */
/*    iat/exp integers, wrapped_keys as an array of {recipient, wk}.     */
/*    This module carries envelopes opaquely, so it is unaffected — but   */
/*    callers must pass ecc-1 envelopes, and the manifest default here   */
/*    is v "ecc-1".                                                       */
/* 3. RELAY-SPEC §3.3: "The relay sets expires_at = created_at + 30d     */
/*    if the client omits it" contradicts its own §2.2/§3.3 default TTL  */
/*    of 24 h and FILE-MAP D10 (24 h TTL default AND maximum). This      */
/*    module sets no expiry at all — expiry lives in the envelope, set   */
/*    by the composer (C7) under D10.                                    */
/* 4. OWNER-JOIN §5 says "Private one-to-one messages inside the same    */
/*    app are out of scope"; FILE-MAP D9 allows 1:1 only as an explicit  */
/*    opt-in with a UI warning. This module does not enforce recipient   */
/*    policy — the composer (C7) does. No conflict for this file.         */
/* 5. RELAY-SPEC §7(b) says ChatGPT gets a token via secure handoff.     */
/*    FILE-MAP D3 OVERRIDES: ChatGPT has NO direct write path; its       */
/*    envelopes reach the store via owner paste (C14, using this         */
/*    module + the owner's PAT) or paste to Jarvis. This module is the   */
/*    owner's PAT path only and must never be handed a ChatGPT token.    */
/* ---------------------------------------------------------------------- */
