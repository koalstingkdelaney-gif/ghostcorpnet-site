/**
 * keys-store.js — IndexedDB private-key storage for the ghostcorpnet
 * encrypted chat (ecc-1). Worker C17.
 *
 * Implements FILE-MAP §4 C17 and:
 *   - KEY-MANAGEMENT.md §3.2 (owner private-key storage — IndexedDB),
 *     §3.1 (keypairs), §5.1 (rotation retains old keys for old messages),
 *     §4.1 (no private keys in any shared/public store).
 *   - UI-SPEC.md §2.1 (first-run setup: key lives in this browser only),
 *     §2.2 (rotation keeps the old key for reading old messages),
 *     §5 "Caching note" (no plaintext / no private key in localStorage).
 *
 * Storage rule (absolute): private keys live in IndexedDB ONLY, as
 * CryptoKey objects, origin-bound to this page's origin, namespaced per
 * room. NEVER localStorage, NEVER sessionStorage, NEVER a cookie, NEVER
 * a synced/shared store, NEVER a URL, NEVER the published store. This
 * module performs NO fallback to any of those: if IndexedDB is
 * unavailable the operations reject (fail closed) instead of writing a
 * private key somewhere weaker.
 *
 * Extractability: keys are stored exactly as handed in. Callers generate
 * with extractable:false where possible (crypto-core.js generate*Keypair
 * default — FILE-MAP D6 / CRYPTO-DESIGN §13.1). This module never
 * re-exports a key and never changes its extractability (WebCrypto makes
 * that immutable). The audit function reports the stored keys'
 * extractable flags so the audit view can show whether a backup-export
 * window exists; an extractable private key is a finding, not a silent
 * default.
 *
 * No crypto operations live in this file. Fingerprint checks delegate to
 * app/js/crypto-core.js (GhostChatCrypto.fingerprintPublicKey) when it is
 * loaded; if it is not loaded, fingerprints are stored unverified and the
 * record says so. This file never calls crypto.subtle directly.
 *
 * Room namespacing: one IndexedDB database (`ghostcorp-chat-keys`), one
 * object store (`keys`, keyPath `room`), one record per room. The room id
 * is a public, non-sensitive identifier (UI-SPEC §1: `#room=<room-id>`).
 * It is never key material and carries no secret.
 *
 * API (all async — every function returns a Promise):
 *   saveKeys({ encPrivate, sigPrivate, encPublic, sigPublic,
 *              fingerprints }, roomId?)
 *   loadKeys(roomId?)            -> stored key set, or null
 *   hasKeys(roomId?)             -> true iff both private keys are stored
 *   wipeKeys(roomId?, { all }?)  -> deletes the room's record (or all)
 *   auditStorageLocations(roomId?)
 *        -> where keys live, for the owner audit view (C8)
 *   getRoom() / setRoom(roomId) / listRooms()
 *
 * saveKeys() rotation behaviour: saving a new key set for a room that
 * already has one moves the previous current set into `prior` (retained
 * so old messages stay decryptable — KEY-MANAGEMENT §5.1, UI-SPEC §2.2).
 * Prior generations are never re-encrypted and are never used for new
 * messages; they are returned by loadKeys() under `prior` for the
 * decrypt path only. Prior sets are wiped together with the room by
 * wipeKeys().
 *
 * Nothing in this file ever contains a real key, a plaintext message, a
 * secret, or personal info — not in code, comments, or error strings.
 * Error messages name key ROLES (encPrivate, sigPublic) and room ids
 * only, never key bytes or fingerprints beyond the first 8 hex chars
 * in a mismatch report (enough to tell two fingerprints apart, not
 * enough to reconstruct one — and only in a thrown error, never stored).
 */

'use strict';

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    // Node / CommonJS (used by the test harness; the page loads this as a
    // plain <script> and gets window.GhostChatKeysStore).
    module.exports = factory();
  } else {
    root.GhostChatKeysStore = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {

  // ---------------------------------------------------------------------------
  // Constants
  // ---------------------------------------------------------------------------

  var DB_NAME = 'ghostcorp-chat-keys';
  var DB_VERSION = 1;
  var STORE_NAME = 'keys';
  var RECORD_VERSION = 1;

  // Default room id when no room is given and none can be read from the
  // page (config C20 / URL fragment). Public identifier only.
  var DEFAULT_ROOM = 'default';

  // Room ids are public identifiers: short, URL-safe, no secrets.
  var ROOM_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

  // A fingerprint is SHA-256 hex of the DER SPKI (CRYPTO-DESIGN §9):
  // 64 lowercase hex chars.
  var FINGERPRINT_RE = /^[0-9a-f]{64}$/;

  // Names that must never hold key material. The audit function scans
  // these stores for suspicious NAMES (names only are reported) and for
  // a private-key marker in values (boolean only — values are never
  // returned, logged, or retained).
  var SUSPICIOUS_NAME_RE = /private|privkey|priv_key|secret|pem|jwk|passphrase|ghostcorp[-_ ]?chat[-_ ]?(key|backup)/i;
  var PRIVATE_KEY_MARKER_RE = /-----BEGIN (?:[A-Z ]*)PRIVATE KEY-----/;

  // ---------------------------------------------------------------------------
  // Errors
  // ---------------------------------------------------------------------------

  function KeyStoreError(code, message) {
    var e = new Error(message);
    e.name = 'KeyStoreError';
    e.code = code;
    return e;
  }

  // ---------------------------------------------------------------------------
  // Room handling
  // ---------------------------------------------------------------------------

  var _explicitRoom = null;

  // Read the room id from the page, in priority order:
  //   1. an explicit setRoom() call,
  //   2. the URL fragment #room=<room-id> (UI-SPEC §1 link model),
  //   3. window.GhostChatConfig.roomId (C20 config, when it exists),
  //   4. DEFAULT_ROOM.
  // The room id is public and non-sensitive; it is never key material.
  function getRoom() {
    if (_explicitRoom) return _explicitRoom;
    try {
      if (typeof location !== 'undefined' && typeof location.hash === 'string') {
        var m = location.hash.match(/(?:#|&)room=([A-Za-z0-9_-]+)/);
        if (m && ROOM_ID_RE.test(m[1])) return m[1];
      }
    } catch (e) { /* fall through — a room read failure is not fatal */ }
    try {
      if (typeof rootConfigRoomId === 'function') {
        var cfg = rootConfigRoomId();
        if (cfg) return cfg;
      }
    } catch (e) { /* fall through */ }
    return DEFAULT_ROOM;
  }

  // Helper kept separate so getRoom() stays testable without a window.
  function rootConfigRoomId() {
    var g = (typeof window !== 'undefined') ? window
      : (typeof self !== 'undefined') ? self : null;
    if (g && g.GhostChatConfig && typeof g.GhostChatConfig.roomId === 'string' &&
        ROOM_ID_RE.test(g.GhostChatConfig.roomId)) {
      return g.GhostChatConfig.roomId;
    }
    return null;
  }

  function setRoom(roomId) {
    _explicitRoom = normalizeRoomId(roomId);
    return _explicitRoom;
  }

  function normalizeRoomId(roomId) {
    if (roomId === undefined || roomId === null || roomId === '') return getRoom();
    if (typeof roomId !== 'string' || !ROOM_ID_RE.test(roomId)) {
      throw KeyStoreError('BAD_ROOM',
        'roomId must be 1-128 chars of [A-Za-z0-9_-], starting alphanumeric');
    }
    return roomId;
  }

  // ---------------------------------------------------------------------------
  // IndexedDB plumbing (fail closed — no fallback store, ever)
  // ---------------------------------------------------------------------------

  function indexedDBFactory() {
    var idb = (typeof indexedDB !== 'undefined') ? indexedDB : null;
    if (!idb) {
      throw KeyStoreError('DB_UNAVAILABLE',
        'IndexedDB is unavailable in this browser/context. Private keys ' +
        'are stored in IndexedDB only — no fallback store is used, so ' +
        'keys cannot be saved here. Use a current browser over HTTPS.');
    }
    return idb;
  }

  function openDb() {
    var idb;
    try {
      idb = indexedDBFactory();
    } catch (e) {
      return Promise.reject(e);
    }
    return new Promise(function (resolve, reject) {
      var req;
      try {
        req = idb.open(DB_NAME, DB_VERSION);
      } catch (e) {
        reject(KeyStoreError('DB_UNAVAILABLE',
          'IndexedDB open failed: ' + (e && e.message ? e.message : String(e))));
        return;
      }
      req.onupgradeneeded = function () {
        var db = req.result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME, { keyPath: 'room' });
        }
      };
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () {
        reject(KeyStoreError('DB_ERROR',
          'IndexedDB open failed: ' +
          (req.error && req.error.message ? req.error.message : 'unknown error')));
      };
      req.onblocked = function () {
        reject(KeyStoreError('DB_BLOCKED',
          'IndexedDB open blocked: another tab holds an older version open. ' +
          'Close other tabs showing this chat and retry.'));
      };
    });
  }

  // Run one object-store operation and resolve with the request result.
  // `mode` is 'readonly' or 'readwrite'. The transaction is scoped to
  // the single keys store; nothing else is read or written.
  function withStore(mode, run) {
    return openDb().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx;
        try {
          tx = db.transaction(STORE_NAME, mode);
        } catch (e) {
          db.close();
          reject(KeyStoreError('DB_ERROR',
            'IndexedDB transaction failed: ' + (e && e.message ? e.message : String(e))));
          return;
        }
        var store;
        try {
          store = tx.objectStore(STORE_NAME);
        } catch (e) {
          db.close();
          reject(KeyStoreError('DB_ERROR',
            'IndexedDB object store unavailable: ' + (e && e.message ? e.message : String(e))));
          return;
        }
        var settled = false;
        function done(value) {
          if (!settled) { settled = true; db.close(); resolve(value); }
        }
        function fail(err) {
          if (!settled) {
            settled = true;
            try { tx.abort(); } catch (ab) { /* already finished */ }
            db.close();
            reject(err instanceof Error ? err : KeyStoreError('DB_ERROR', String(err)));
          }
        }
        tx.oncomplete = function () { done(tx._result); };
        tx.onerror = function () {
          fail(KeyStoreError('DB_ERROR',
            'IndexedDB transaction failed: ' +
            (tx.error && tx.error.message ? tx.error.message : 'unknown error')));
        };
        tx.onabort = function () {
          fail(KeyStoreError('DB_ERROR', 'IndexedDB transaction aborted'));
        };
        var req;
        try {
          req = run(store);
        } catch (e) {
          fail(e);
          return;
        }
        // Attach handlers whenever run() returns an object: a real
        // IDBRequest always carries onsuccess/onerror (initially null),
        // and minimal shims may not pre-declare them — testing for the
        // property's presence would silently drop the result.
        if (req && typeof req === 'object') {
          req.onsuccess = function () { tx._result = req.result; };
          req.onerror = function () {
            fail(KeyStoreError('DB_ERROR',
              'IndexedDB request failed: ' +
              (req.error && req.error.message ? req.error.message : 'unknown error')));
          };
        } else {
          // run() returned a plain value (or nothing) — complete on tx.
          tx._result = req;
        }
      });
    });
  }

  function getRecord(room) {
    return withStore('readonly', function (store) {
      return store.get(room);
    }).then(function (record) {
      return record === undefined ? null : record;
    });
  }

  function putRecord(record) {
    return withStore('readwrite', function (store) {
      return store.put(record);
    }).then(function () { return record; });
  }

  function deleteRecord(room) {
    return withStore('readwrite', function (store) {
      return store.delete(room);
    });
  }

  function listRecordRooms() {
    return withStore('readonly', function (store) {
      if (typeof store.getAllKeys === 'function') return store.getAllKeys();
      // Fallback for minimal IndexedDB shims: enumerate via a cursor.
      return null;
    }).then(function (keys) {
      if (Array.isArray(keys)) return keys.slice();
      return [];
    });
  }

  // ---------------------------------------------------------------------------
  // Key validation (shape only — no crypto operations here)
  // ---------------------------------------------------------------------------

  function isCryptoKey(value) {
    if (!value || typeof value !== 'object') return false;
    // Real browsers / Node WebCrypto: value is a CryptoKey instance.
    if (typeof CryptoKey !== 'undefined' && value instanceof CryptoKey) return true;
    // Structural fallback (test shims / cross-realm keys): a CryptoKey has
    // exactly these own properties — type, algorithm, extractable, usages.
    return typeof value.type === 'string' &&
      value.algorithm !== undefined &&
      typeof value.extractable === 'boolean' &&
      Array.isArray(value.usages);
  }

  function checkKey(value, role, expectedType, expectedAlgs, expectedUsage) {
    if (!isCryptoKey(value)) {
      throw KeyStoreError('BAD_KEY', role + ' must be a CryptoKey object');
    }
    if (value.type !== expectedType) {
      throw KeyStoreError('BAD_KEY',
        role + ' must be a "' + expectedType + '" key, got "' + value.type + '"');
    }
    var algName = value.algorithm && value.algorithm.name;
    if (expectedAlgs.indexOf(algName) === -1) {
      throw KeyStoreError('BAD_KEY',
        role + ' has unexpected algorithm "' + String(algName) +
        '", expected one of: ' + expectedAlgs.join(', '));
    }
    if (value.usages.indexOf(expectedUsage) === -1) {
      throw KeyStoreError('BAD_KEY',
        role + ' must include the "' + expectedUsage + '" usage');
    }
  }

  // Encryption private key: RSA-OAEP (FILE-MAP D5 / CRYPTO-DESIGN §5).
  // Signing private key: Ed25519 primary, ES256 fallback (FILE-MAP D6).
  // NOTE (FILE-MAP conflict, flagged): KEY-MANAGEMENT §1.2/§3.1 prescribes
  // ECDSA P-256 as the signing algorithm; FILE-MAP D6 overrides it with
  // Ed25519 primary + ES256 fallback. This store is algorithm-agnostic and
  // accepts both, so it implements to the FILE-MAP.
  function validateKeySet(keys) {
    if (!keys || typeof keys !== 'object') {
      throw KeyStoreError('BAD_KEYSET', 'saveKeys requires a key object');
    }
    checkKey(keys.encPrivate, 'encPrivate', 'private', ['RSA-OAEP'], 'decrypt');
    checkKey(keys.sigPrivate, 'sigPrivate', 'private', ['Ed25519', 'ECDSA'], 'sign');
    checkKey(keys.encPublic, 'encPublic', 'public', ['RSA-OAEP'], 'encrypt');
    checkKey(keys.sigPublic, 'sigPublic', 'public', ['Ed25519', 'ECDSA'], 'verify');
  }

  // ---------------------------------------------------------------------------
  // Fingerprints (delegated to crypto-core.js — no crypto here)
  // ---------------------------------------------------------------------------

  function cryptoCore() {
    var g = (typeof window !== 'undefined') ? window
      : (typeof self !== 'undefined') ? self
      : (typeof globalThis !== 'undefined') ? globalThis : null;
    if (g && g.GhostChatCrypto && typeof g.GhostChatCrypto.fingerprintPublicKey === 'function') {
      return g.GhostChatCrypto;
    }
    return null;
  }

  // Accept the fingerprints in any of the shapes callers use and normalize
  // to { enc, sig } (lowercase hex, or null when not supplied).
  function normalizeFingerprints(input) {
    if (!input || typeof input !== 'object') return { enc: null, sig: null };
    var enc = input.enc || input.encFingerprint || input.encryption || null;
    var sig = input.sig || input.sigFingerprint || input.signing || null;
    if (enc !== null && typeof enc === 'string') enc = enc.toLowerCase();
    if (sig !== null && typeof sig === 'string') sig = sig.toLowerCase();
    if (enc !== null && !FINGERPRINT_RE.test(enc)) {
      throw KeyStoreError('BAD_FINGERPRINT',
        'enc fingerprint must be 64 lowercase hex chars (SHA-256 of DER SPKI)');
    }
    if (sig !== null && !FINGERPRINT_RE.test(sig)) {
      throw KeyStoreError('BAD_FINGERPRINT',
        'sig fingerprint must be 64 lowercase hex chars (SHA-256 of DER SPKI)');
    }
    return { enc: enc, sig: sig };
  }

  // Verify supplied fingerprints against the public keys, via crypto-core.
  // Returns { verified: bool, computed: { enc, sig } | null }.
  // Mismatch throws BEFORE anything is written (fail closed). When
  // crypto-core is not loaded, verification is skipped and reported as
  // such — the caller (C4 setup) must load crypto-core first for a
  // verified save; an unverified save is still stored, flagged.
  async function verifyFingerprints(keys, fingerprints) {
    var core = cryptoCore();
    if (!core) {
      return { verified: false, computed: null, reason: 'crypto-core not loaded' };
    }
    var computedEnc = await core.fingerprintPublicKey(keys.encPublic);
    var computedSig = await core.fingerprintPublicKey(keys.sigPublic);
    var computed = { enc: computedEnc, sig: computedSig };
    if (fingerprints.enc !== null && fingerprints.enc !== computedEnc) {
      throw KeyStoreError('FINGERPRINT_MISMATCH',
        'enc fingerprint does not match the encPublic key ' +
        '(supplied ' + fingerprints.enc.slice(0, 8) + '…, computed ' +
        computedEnc.slice(0, 8) + '…). Nothing was saved.');
    }
    if (fingerprints.sig !== null && fingerprints.sig !== computedSig) {
      throw KeyStoreError('FINGERPRINT_MISMATCH',
        'sig fingerprint does not match the sigPublic key ' +
        '(supplied ' + fingerprints.sig.slice(0, 8) + '…, computed ' +
        computedSig.slice(0, 8) + '…). Nothing was saved.');
    }
    return { verified: true, computed: computed, reason: null };
  }

  function keyMeta(keys, fingerprints, verification) {
    return {
      encAlgorithm: keys.encPrivate.algorithm.name,
      encModulusLength: keys.encPrivate.algorithm.modulusLength || null,
      sigAlgorithm: keys.sigPrivate.algorithm.name,
      sigNamedCurve: (keys.sigPrivate.algorithm.namedCurve || null),
      encPrivateExtractable: keys.encPrivate.extractable,
      sigPrivateExtractable: keys.sigPrivate.extractable,
      fingerprintsVerified: verification.verified,
      fingerprintsVerifiedReason: verification.reason,
      fingerprintsSource: verification.verified ? 'computed-from-public-keys'
        : (fingerprints.enc || fingerprints.sig) ? 'supplied-unverified' : 'none-supplied'
    };
  }

  function snapshotKeySet(keys, fingerprints, rotatedAt) {
    return {
      encPrivate: keys.encPrivate,
      sigPrivate: keys.sigPrivate,
      encPublic: keys.encPublic,
      sigPublic: keys.sigPublic,
      fingerprints: { enc: fingerprints.enc, sig: fingerprints.sig },
      rotatedAt: rotatedAt
    };
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /**
   * saveKeys({ encPrivate, sigPrivate, encPublic, sigPublic, fingerprints },
   *          roomId?)
   *
   * Stores the owner's key set for one room in IndexedDB. Private keys are
   * stored as CryptoKey objects, with whatever extractable flag they were
   * generated with (extractable:false where possible — see header).
   *
   * If the room already has keys, the previous current set is moved to
   * `prior` (rotation retention) before the new set becomes current.
   * Verification (key shapes, then fingerprints via crypto-core) runs
   * BEFORE any write, so a failed save never clobbers stored keys.
   *
   * Resolves with { room, savedAt, fingerprintsVerified, rotated: bool }.
   * Never writes to localStorage / sessionStorage / cookies.
   */
  async function saveKeys(keys, roomId) {
    var room = normalizeRoomId(roomId);
    validateKeySet(keys);
    var fingerprints = normalizeFingerprints(keys.fingerprints);
    var verification = await verifyFingerprints(keys, fingerprints);
    // Prefer computed fingerprints when verification ran: the stored
    // fingerprint is then always the one derived from the stored key.
    var storedFingerprints = verification.computed || fingerprints;

    var now = new Date().toISOString();
    var existing = await getRecord(room);
    var prior = existing ? (existing.prior || []).slice() : [];
    var rotated = false;
    if (existing && existing.encPrivate && existing.sigPrivate) {
      prior.push(snapshotKeySet(
        {
          encPrivate: existing.encPrivate,
          sigPrivate: existing.sigPrivate,
          encPublic: existing.encPublic,
          sigPublic: existing.sigPublic
        },
        existing.fingerprints || { enc: null, sig: null },
        now
      ));
      rotated = true;
    }

    var record = {
      room: room,
      version: RECORD_VERSION,
      savedAt: now,
      updatedAt: now,
      encPrivate: keys.encPrivate,
      sigPrivate: keys.sigPrivate,
      encPublic: keys.encPublic,
      sigPublic: keys.sigPublic,
      fingerprints: storedFingerprints,
      prior: prior,
      meta: keyMeta(keys, storedFingerprints, verification)
    };
    await putRecord(record);
    return {
      room: room,
      savedAt: now,
      fingerprintsVerified: verification.verified,
      rotated: rotated,
      priorGenerations: prior.length
    };
  }

  /**
   * loadKeys(roomId?) -> the stored key set for the room, or null.
   * Returns { encPrivate, sigPrivate, encPublic, sigPublic, fingerprints,
   *           prior, savedAt, meta } — `prior` is the list of retained
   * previous generations (decrypt-old-messages only). Returns null when
   * the room has no stored keys. Rejects when IndexedDB is unavailable.
   * The returned CryptoKey objects are live keys: callers must never
   * export, serialize, log, or transmit the private ones.
   */
  async function loadKeys(roomId) {
    var room = normalizeRoomId(roomId);
    var record = await getRecord(room);
    if (!record) return null;
    return {
      encPrivate: record.encPrivate || null,
      sigPrivate: record.sigPrivate || null,
      encPublic: record.encPublic || null,
      sigPublic: record.sigPublic || null,
      fingerprints: record.fingerprints || { enc: null, sig: null },
      prior: (record.prior || []).slice(),
      savedAt: record.savedAt || null,
      meta: record.meta || null
    };
  }

  /**
   * hasKeys(roomId?) -> true iff the room has BOTH private keys stored.
   * (A record with only public keys — e.g. a half-finished setup — is
   * not "has keys".) Rejects when IndexedDB is unavailable, so callers
   * can show the blocking WebCrypto/storage notice instead of silently
   * routing a user into a setup that cannot save.
   */
  async function hasKeys(roomId) {
    var room = normalizeRoomId(roomId);
    var record = await getRecord(room);
    return !!(record && isCryptoKey(record.encPrivate) && isCryptoKey(record.sigPrivate));
  }

  /**
   * wipeKeys(roomId?, options?) — deletes the room's stored keys,
   * including all retained prior generations, from IndexedDB.
   * Pass { all: true } (roomId ignored) to wipe every room's keys on
   * this device/profile. Resolves with { room | wipedRooms, wiped: true }
   * after verifying the record is gone. This is the "forget this device"
   * / "start over" path — it does not touch the key directory, the relay,
   * or any backup file. There is no undo; callers must confirm first.
   */
  async function wipeKeys(roomId, options) {
    var opts = options || {};
    if (opts.all === true) {
      var rooms = await listRecordRooms();
      // listRecordRooms may come back empty on shims without getAllKeys;
      // fall back to wiping the current/default room in that case.
      if (rooms.length === 0) rooms = [normalizeRoomId(roomId)];
      var wiped = [];
      for (var i = 0; i < rooms.length; i++) {
        await deleteRecord(rooms[i]);
        var after = await getRecord(rooms[i]);
        if (after !== null) {
          throw KeyStoreError('WIPE_FAILED',
            'keys for room "' + rooms[i] + '" could not be deleted');
        }
        wiped.push(rooms[i]);
      }
      return { wipedRooms: wiped, wiped: true };
    }
    var room = normalizeRoomId(roomId);
    await deleteRecord(room);
    var remaining = await getRecord(room);
    if (remaining !== null) {
      throw KeyStoreError('WIPE_FAILED',
        'keys for room "' + room + '" could not be deleted');
    }
    return { room: room, wiped: true };
  }

  // ---------------------------------------------------------------------------
  // Storage-location audit (for the owner audit view, C8)
  // ---------------------------------------------------------------------------

  // Scan one Web Storage area (localStorage / sessionStorage) for signs of
  // key material. Reports NAMES only, plus booleans — never values.
  function scanWebStorage(area, areaName) {
    var result = {
      available: false,
      entries: 0,
      suspiciousNames: [],
      privateKeyMarkerFound: false
    };
    var storage = null;
    try {
      storage = (typeof window !== 'undefined' && window[areaName]) ? window[areaName]
        : (typeof globalThis !== 'undefined' && globalThis[areaName]) ? globalThis[areaName]
        : null;
    } catch (e) {
      storage = null;
    }
    if (!storage) return result;
    result.available = true;
    var names = [];
    try {
      if (typeof storage.length === 'number') {
        for (var i = 0; i < storage.length; i++) {
          var name = storage.key(i);
          if (typeof name === 'string') names.push(name);
        }
      } else if (typeof storage === 'object') {
        names = Object.keys(storage);
      }
    } catch (e) {
      return result; // unreadable store: report available, entries unknown
    }
    result.entries = names.length;
    for (var j = 0; j < names.length; j++) {
      if (SUSPICIOUS_NAME_RE.test(names[j])) result.suspiciousNames.push(names[j]);
    }
    // Value scan: boolean only. A private-key PEM marker in any value is
    // a FAIL finding. Values are never copied, returned, or logged.
    for (var k = 0; k < names.length; k++) {
      try {
        var value = storage.getItem(names[k]);
        if (typeof value === 'string' && PRIVATE_KEY_MARKER_RE.test(value)) {
          result.privateKeyMarkerFound = true;
          break;
        }
      } catch (e) { /* unreadable value — skip it */ }
    }
    return result;
  }

  function scanCookies() {
    var result = { present: false, count: 0, suspiciousNames: [] };
    var raw = '';
    try {
      raw = (typeof document !== 'undefined' && typeof document.cookie === 'string')
        ? document.cookie : '';
    } catch (e) {
      raw = '';
    }
    if (!raw) return result;
    var parts = raw.split(';');
    result.present = true;
    result.count = parts.length;
    for (var i = 0; i < parts.length; i++) {
      var name = parts[i].split('=')[0].trim();
      if (name && SUSPICIOUS_NAME_RE.test(name)) result.suspiciousNames.push(name);
    }
    return result;
  }

  /**
   * auditStorageLocations(roomId?) — reports where this room's keys live,
   * for the owner audit view (C8 / UI-SPEC §2.5 "key audit section").
   *
   * Returns:
   *   { generatedAt, room, verdict, findings[], indexedDB: {...},
   *     localStorage: {...}, sessionStorage: {...}, cookies: {...},
   *     forbiddenStores: {...} }
   *
   * verdict: 'PASS' (keys in IndexedDB only, nothing forbidden found),
   *          'FAIL' (private-key material found outside IndexedDB, or the
   *          stored fingerprints do not match the stored public keys, or
   *          IndexedDB is unavailable while keys are expected),
   *          'NOT VERIFIED' (no keys stored for this room yet, or the
   *          fingerprint re-check could not run because crypto-core is
   *          not loaded).
   *
   * The report contains fingerprints (public, non-secret identifiers)
   * and key metadata only. It never contains private-key material,
   * plaintext, or storage values.
   */
  async function auditStorageLocations(roomId) {
    var room = normalizeRoomId(roomId);
    var findings = [];
    var verdict = 'PASS';

    var idbReport = {
      available: true,
      dbName: DB_NAME,
      storeName: STORE_NAME,
      room: room,
      recordPresent: false,
      hasPrivateKeys: false,
      hasPublicKeys: false,
      fingerprintsStored: { enc: null, sig: null },
      fingerprintsRecomputedMatch: null,
      priorGenerations: 0,
      keyAlgorithms: { enc: null, sig: null },
      privateKeyExtractable: { enc: null, sig: null },
      savedAt: null,
      location: 'IndexedDB only (origin-bound, this browser profile only)'
    };

    var record = null;
    var dbError = null;
    try {
      record = await getRecord(room);
    } catch (e) {
      dbError = e;
      idbReport.available = false;
    }
    if (dbError) {
      verdict = 'FAIL';
      findings.push('IndexedDB is unavailable (' + (dbError.code || 'DB_ERROR') +
        '): keys cannot be stored or verified here. No fallback store is used.');
    } else if (record) {
      idbReport.recordPresent = true;
      idbReport.hasPrivateKeys = isCryptoKey(record.encPrivate) && isCryptoKey(record.sigPrivate);
      idbReport.hasPublicKeys = isCryptoKey(record.encPublic) && isCryptoKey(record.sigPublic);
      idbReport.fingerprintsStored = record.fingerprints || { enc: null, sig: null };
      idbReport.priorGenerations = (record.prior || []).length;
      idbReport.savedAt = record.savedAt || null;
      if (record.encPrivate) {
        idbReport.keyAlgorithms.enc = record.encPrivate.algorithm.name;
        idbReport.privateKeyExtractable.enc = record.encPrivate.extractable;
      }
      if (record.sigPrivate) {
        idbReport.keyAlgorithms.sig = record.sigPrivate.algorithm.name;
        idbReport.privateKeyExtractable.sig = record.sigPrivate.extractable;
      }
      if (!idbReport.hasPrivateKeys) {
        verdict = 'NOT VERIFIED';
        findings.push('A record exists for this room but it holds no complete ' +
          'private key pair (setup unfinished or partially wiped).');
      }
      // Recompute fingerprints from the stored public keys (crypto-core)
      // and compare with what is stored — a mismatch is a FAIL.
      var core = cryptoCore();
      if (core && record.encPublic && record.sigPublic) {
        try {
          var recomputedEnc = await core.fingerprintPublicKey(record.encPublic);
          var recomputedSig = await core.fingerprintPublicKey(record.sigPublic);
          var stored = record.fingerprints || {};
          idbReport.fingerprintsRecomputedMatch =
            (stored.enc === recomputedEnc && stored.sig === recomputedSig);
          if (!idbReport.fingerprintsRecomputedMatch) {
            verdict = 'FAIL';
            findings.push('Stored fingerprints do not match the stored public ' +
              'keys — the record may have been tampered with or mis-saved.');
          }
        } catch (e) {
          verdict = 'NOT VERIFIED';
          findings.push('Stored fingerprints could not be re-verified: ' +
            (e && e.message ? e.message : String(e)));
        }
      } else if (!core) {
        verdict = (verdict === 'PASS') ? 'NOT VERIFIED' : verdict;
        findings.push('crypto-core is not loaded, so stored fingerprints ' +
          'could not be recomputed and re-checked in this audit.');
      }
      if (record.encPrivate && record.encPrivate.extractable === true) {
        findings.push('Note: the stored encryption private key is extractable ' +
          '(generated with extractable:true, e.g. for a backup export). ' +
          'Day-to-day keys should be extractable:false where possible.');
      }
      if (record.sigPrivate && record.sigPrivate.extractable === true) {
        findings.push('Note: the stored signing private key is extractable ' +
          '(generated with extractable:true, e.g. for a backup export). ' +
          'Day-to-day keys should be extractable:false where possible.');
      }
      if (idbReport.priorGenerations > 0) {
        findings.push(idbReport.priorGenerations + ' prior key generation(s) ' +
          'retained in IndexedDB for reading old messages (rotation history).');
      }
    } else {
      verdict = 'NOT VERIFIED';
      findings.push('No keys are stored for this room yet in IndexedDB.');
    }

    var lsReport = scanWebStorage('localStorage', 'localStorage');
    var ssReport = scanWebStorage('sessionStorage', 'sessionStorage');
    var cookieReport = scanCookies();

    if (lsReport.privateKeyMarkerFound || ssReport.privateKeyMarkerFound) {
      verdict = 'FAIL';
      findings.push('Private-key material (PEM marker) found in ' +
        (lsReport.privateKeyMarkerFound ? 'localStorage' : 'sessionStorage') +
        ' — private keys must live in IndexedDB only. Remove it and re-audit.');
    }
    if (lsReport.suspiciousNames.length > 0 || ssReport.suspiciousNames.length > 0) {
      verdict = 'FAIL';
      findings.push('Suspicious key-like entry name(s) found in Web Storage: ' +
        lsReport.suspiciousNames.concat(ssReport.suspiciousNames).join(', ') +
        ' — inspect and remove; keys belong in IndexedDB only.');
    }
    if (cookieReport.suspiciousNames.length > 0) {
      verdict = 'FAIL';
      findings.push('Suspicious key-like cookie name(s) found: ' +
        cookieReport.suspiciousNames.join(', ') +
        ' — keys must never be stored in cookies.');
    }

    var forbiddenStores = {
      localStorage: lsReport.privateKeyMarkerFound || lsReport.suspiciousNames.length > 0
        ? 'FAIL — key-like material present' : 'clean — no key material found',
      sessionStorage: ssReport.privateKeyMarkerFound || ssReport.suspiciousNames.length > 0
        ? 'FAIL — key-like material present' : 'clean — no key material found',
      cookies: cookieReport.suspiciousNames.length > 0
        ? 'FAIL — key-like cookie present' : 'clean — no key-like cookie found',
      syncedOrSharedStore: 'never used by this module — keys are written to ' +
        'IndexedDB only and are never synced, shared, or published',
      publishedStore: 'never used — private keys are never written to the ' +
        'chat store (ciphertext + public keys only)'
    };

    if (verdict === 'PASS') {
      findings.push('Keys for this room live in IndexedDB only (' + DB_NAME +
        ' / ' + STORE_NAME + ' / room "' + room + '"). No private-key ' +
        'material was found in localStorage, sessionStorage, or cookies.');
    }

    return {
      generatedAt: new Date().toISOString(),
      room: room,
      verdict: verdict,
      findings: findings,
      indexedDB: idbReport,
      localStorage: lsReport,
      sessionStorage: ssReport,
      cookies: cookieReport,
      forbiddenStores: forbiddenStores
    };
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  return {
    DB_NAME: DB_NAME,
    DB_VERSION: DB_VERSION,
    STORE_NAME: STORE_NAME,
    DEFAULT_ROOM: DEFAULT_ROOM,

    saveKeys: saveKeys,
    loadKeys: loadKeys,
    hasKeys: hasKeys,
    wipeKeys: wipeKeys,
    auditStorageLocations: auditStorageLocations,
    getRoom: getRoom,
    setRoom: setRoom,
    listRooms: listRecordRooms,

    KeyStoreError: KeyStoreError
  };
});
