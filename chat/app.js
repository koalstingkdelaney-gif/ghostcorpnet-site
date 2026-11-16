/* Encrypted chat — app/app.js (worker C3)
 *
 * Bootstrap + shared state + view routing for the static single-page app.
 *
 * Spec: ~/workspace/encrypted-chat/FILE-MAP.md (authoritative) §4 C3,
 *   D4 (inline log), D9 (all-three recipients default), D10 (24 h TTL),
 *   D11 (polling cadence — owned by poll.js, held here as config only),
 *   D18 (page constraints — owned by C1/C2; this file makes no external
 *   requests and fetches only config URLs).
 * Reference detail: design/UI-SPEC.md §2 (views), §5 (states),
 *   §6 (polling/ordering/dedup), §7 (mobile layout, bottom tab bar).
 *
 * What this file does:
 *   - bootstrap: config -> WebCrypto availability gate -> key check
 *     (via keys-store.js) -> key-directory fetch (via config URL) ->
 *     inline-log seed (ciphertext only) -> route -> start poller/outbox
 *   - shared state: current participant ("owner" in the browser),
 *     key directory, message list (envelopes only, never plaintext),
 *     outbox mirror, relay sequence cursor, view + connectivity
 *   - view routing: setup / thread / keys / compose / audit, hash-synced,
 *     bottom tab bar (thread / keys / compose / audit)
 *
 * What this file does NOT do (other workers own it — never duplicated here):
 *   - no crypto of any kind (A1/A2 crypto-core.js, crypto-p256.js) — the only
 *     WebCrypto touch is the *availability* check (crypto.subtle exists?),
 *     which gates the blocking "browser can't do encryption" notice
 *     (UI-SPEC §2.1d). No key generation, encryption, signing or decryption.
 *   - no key storage (C17 keys-store.js: loadKeys() / hasKeys())
 *   - no polling/fetch loop (C9 poll.js owns intervals, backoff, seq cursor)
 *   - no outbox persistence/retry (C12 outbox.js — the instance is created
 *     by the compose view with its publish function; app.js only attaches
 *     to it via attachOutbox() and mirrors its list into shared state)
 *   - no view rendering (C4 view-setup, C5 view-keys, C6 view-thread,
 *     C7 view-compose, C8 view-audit) — this file mounts them through
 *     per-view adapters (see §3) and shows a placeholder if one has not
 *     loaded yet; it never renders message content itself
 *   - no badge computation (C10 badges.js), no fingerprint check
 *     (C16 fingerprint-check.js), no notifications (C18), no error copy
 *     (C19 errors.js — this file records error objects, views render them)
 *
 * NAMESPACE NOTE (integration conflict found 2026-11-16, resolved here):
 *   the C3 brief assumed globals named ChatKeysStore / ChatPoll /
 *   ChatOutbox / CHAT_CONFIG / ChatViews. The sibling workers as landed
 *   use a different namespace: bare `CONFIG` (C20 config.js, a top-level
 *   const, loaded before app.js by C1's index.html), GhostChatKeysStore
 *   (C17), GhostChatPoll.createPoller() factory (C9), GhostChatOutbox.
 *   createOutbox() factory (C12), and one global per view — GhostChatSetup,
 *   GhostChatThread, GhostChatKeys, GhostChatCompose, GhostChatAuditView.
 *   This file binds to the LANDED names (with the brief's Chat* names kept
 *   only as fallbacks) and to each module's real entry point — e.g. the
 *   poller is a createPoller(options) factory whose onVerified callback
 *   delivers envelopes; it has no start(context) method. Wiring to the
 *   brief's assumed names would have silently done nothing (no keys found,
 *   no poller started, no views mounted). No sibling file was edited.
 *
 * No real keys, no private-key material, no plaintext conversation, no
 * secrets and no personal info in this file. $0 spend. No network calls
 * except through config URLs (key-directory fetch below; message fetching
 * is poll.js's job).
 */
'use strict';

(function () {
  /* ------------------------------------------------------------------ */
  /* 0. Globals helper — resolves a landed GhostChat* global, with the */
  /*    brief's Chat* name as a fallback. Never invents a module.      */
  /* ------------------------------------------------------------------ */

  function getGlobal(name) {
    if (typeof window !== 'undefined' && window[name]) { return window[name]; }
    if (typeof globalThis !== 'undefined' && globalThis[name]) { return globalThis[name]; }
    return null;
  }

  /* ------------------------------------------------------------------ */
  /* 1. Config — C20 config.js wins; defaults are FILE-MAP values.      */
  /*    config.js declares top-level `const CONFIG` (a lexical global,  */
  /*    NOT a window property) and freezes it, so it is read as a bare  */
  /*    identifier; window.CHAT_CONFIG (the brief's assumed name) is a  */
  /*    fallback only. The merged object is a fresh copy — the frozen   */
  /*    source is never mutated. C20 field names are honoured as-is    */
  /*    (roomId "ghostcorp-chat-1", absolute store URLs,                */
  /*    pollBackoffStartMs/pollBackoffMaxMs); pollBackoffMs is derived  */
  /*    from them when the array form is absent.                        */
  /* ------------------------------------------------------------------ */

  var DEFAULT_CONFIG = {
    roomId: 'ghostcorp-chat-1',
    roomTitle: 'Jarvis \u2194 ChatGPT \u2014 owner chat',
    // Published store layout (FILE-MAP D1/D2): page at /chat/, key
    // directory at chat/keys/participants.json, manifest at
    // chat/manifest.json. C20 supplies absolute
    // https://ghostcorpnet.com/chat/... URLs; the relative paths below
    // are only the fallback if config.js failed to load.
    storeBaseUrl: '/chat',
    keyDirectoryUrl: '/chat/keys/participants.json',
    manifestUrl: '/chat/manifest.json',
    messagesUrlPrefix: '/chat/messages/',
    tombstonesUrl: '/chat/tombstones.jsonl',
    pollIntervalMs: 15000, // FILE-MAP D11: 15 s while visible
    pollBackoffMs: [5000, 15000, 30000, 60000], // D11 / UI-SPEC §6
    pollBackoffStartMs: 5000,
    pollBackoffMaxMs: 60000,
    defaultTtlSeconds: 86400, // FILE-MAP D10: 24 h default AND maximum
    maxTtlSeconds: 86400,
    maxMessageChars: 4000, // UI-SPEC §2.4 step 4 (proposed)
    maxPlaintextBytes: 65536, // FILE-MAP §3 inner-plaintext max
    pageSize: 50, // UI-SPEC §2.3: most recent 50 first
    participants: ['jarvis', 'chatgpt', 'owner'],
    defaultRecipients: ['jarvis', 'chatgpt', 'owner'] // FILE-MAP D9
  };

  function readConfig() {
    var sources = [];
    var g = getGlobal('GhostChatConfig');
    if (g && typeof g === 'object') { sources.push(g); }
    // Bare CONFIG: C20's top-level const. typeof-guard keeps this safe
    // when config.js did not load.
    try {
      if (typeof CONFIG !== 'undefined' && CONFIG && typeof CONFIG === 'object') {
        sources.push(CONFIG);
      }
    } catch (e) { /* config.js absent — defaults apply */ }
    var legacy = getGlobal('CHAT_CONFIG');
    if (legacy && typeof legacy === 'object') { sources.push(legacy); }

    var cfg = {};
    var k, i;
    for (k in DEFAULT_CONFIG) {
      if (Object.prototype.hasOwnProperty.call(DEFAULT_CONFIG, k)) {
        cfg[k] = DEFAULT_CONFIG[k];
      }
    }
    for (i = 0; i < sources.length; i++) {
      for (k in sources[i]) {
        if (Object.prototype.hasOwnProperty.call(sources[i], k) &&
            sources[i][k] !== undefined && sources[i][k] !== null) {
          cfg[k] = sources[i][k];
        }
      }
    }
    if (!Array.isArray(cfg.pollBackoffMs) || !cfg.pollBackoffMs.length) {
      cfg.pollBackoffMs = [
        cfg.pollBackoffStartMs || 5000, 15000, 30000, cfg.pollBackoffMaxMs || 60000
      ];
    }
    return cfg;
  }

  /* ------------------------------------------------------------------ */
  /* 2. Shared state. messages hold ENVELOPES ONLY (ciphertext +        */
  /*    metadata). Decrypted plaintext lives in the view modules'       */
  /*    memory for the current session only (UI-SPEC §5 caching note)   */
  /*    and is never stored here, never cached to disk by this file.    */
  /* ------------------------------------------------------------------ */

  var config = readConfig();

  var state = {
    ready: false, // bootstrap finished (successfully or fail-closed)
    booted: false, // bootstrap attempted
    me: 'owner', // current participant id in THIS browser (task brief)
    hasKeys: false, // a keypair exists in this browser (keys-store.js)
    keys: null, // opaque handle from keys-store loadKeys(); never inspected
    keysError: null, // set when keys-store is missing or loadKeys() fails
    keyDirectory: {
      status: 'not-loaded', // not-loaded | loading | loaded | error
      participants: [], // normalised entries, public keys only (see §5)
      loadedAt: null,
      error: null
    },
    messages: [], // envelopes, ordered by relay seq (see addMessages)
    lastSeq: null, // relay sequence cursor (poll.js advances it)
    seenIds: {}, // msg_id -> true (dedup; UI-SPEC §6)
    outbox: [], // mirror of C12 outbox entries (pending envelopes)
    outboxAttached: false, // true once a real outbox instance is attached
    view: 'thread', // setup | thread | keys | compose | audit
    returnView: 'thread', // view to land on after setup completes
    online: (typeof navigator !== 'undefined' ? navigator.onLine : true),
    polling: 'not-started', // not-started | running | unavailable | error
    cryptoAvailable: false,
    errors: [] // { code, message, at } — copy rendered by C19 errors.js
  };

  /* ------------------------------------------------------------------ */
  /* 3. Views + routing.                                                 */
  /*    FILE-MAP C4–C8 are the view modules; UI-SPEC §2 lists five      */
  /*    views (setup, thread, keys, compose, audit). The bottom tab     */
  /*    bar carries the four everyday tabs (thread / keys / compose /   */
  /*    audit); setup is the first-run gate, not a tab — it is shown    */
  /*    automatically when no keys exist and is reachable later via     */
  /*    #setup (UI-SPEC §2.1: "reachable later from Settings").         */
  /*    Hash names: #thread (UI-SPEC §2 also uses #chat — accepted as   */
  /*    an alias), #keys, #compose, #audit, #setup.                     */
  /*                                                                     */
  /*    MOUNT CONTRACTS (as landed — each view module exposes its own   */
  /*    entry point; there is no uniform ChatViews.mount):              */
  /*      setup   GhostChatSetup.mount(container, options)               */
  /*               -> handle { destroy }; options.onComplete/onJoin     */
  /*               fire when the user finishes setup (C4).              */
  /*      thread  GhostChatThread.createThreadRenderer(container, opts)  */
  /*               -> { setMessages, addMessages, getMessages, ... }    */
  /*      keys    GhostChatKeys.renderKeysInto(container, entries, opts) */
  /*               -> view handle.                                       */
  /*      compose GhostChatCompose.mountCompose(container, options)      */
  /*               -> { view, root, elements, refresh }.                 */
  /*      audit   GhostChatAuditView.mountAuditView(container, inputs,   */
  /*               options) — async -> { audit, rendered }.              */
  /*    Unmounting tries handle.destroy / handle.view.destroy /          */
  /*    handle.teardown, then clears the container. A module that has   */
  /*    not loaded yet yields a placeholder, never a crash.              */
  /* ------------------------------------------------------------------ */

  var VIEWS = ['setup', 'thread', 'keys', 'compose', 'audit'];
  var TABS = ['thread', 'keys', 'compose', 'audit'];
  var TAB_LABELS = { thread: 'Chat', keys: 'Keys', compose: 'Compose', audit: 'Audit' };
  var HASH_TO_VIEW = {
    thread: 'thread', chat: 'thread', // UI-SPEC §2 hash alias
    keys: 'keys', compose: 'compose', audit: 'audit', setup: 'setup'
  };
  var VIEW_GLOBALS = {
    setup: 'GhostChatSetup',
    thread: 'GhostChatThread',
    keys: 'GhostChatKeys',
    compose: 'GhostChatCompose',
    audit: 'GhostChatAuditView'
  };

  var viewEls = {}; // view name -> <section> element
  var tabEls = {}; // view name -> <button> element
  var tabBarEl = null;
  var mountedView = null; // view currently mounted
  var mountedHandle = null; // handle returned by the view's mount call
  var listeners = {}; // event name -> [fn]

  function on(event, fn) {
    if (!listeners[event]) { listeners[event] = []; }
    listeners[event].push(fn);
    return function off() {
      var i = listeners[event].indexOf(fn);
      if (i !== -1) { listeners[event].splice(i, 1); }
    };
  }

  function emit(event, payload) {
    var fns = listeners[event] || [];
    for (var i = 0; i < fns.length; i++) {
      try { fns[i](payload); } catch (e) { recordError('listener-failed', String(e && e.message || e)); }
    }
    refreshMounted(event, payload);
  }

  function recordError(code, message) {
    var err = { code: code, message: String(message || code), at: new Date().toISOString() };
    state.errors.push(err);
    if (state.errors.length > 50) { state.errors.shift(); }
    emit('error', err);
    return err;
  }

  function ensureViewElements() {
    var root = document.getElementById('app') || document.body;
    VIEWS.forEach(function (name) {
      var el = document.getElementById('view-' + name);
      if (!el) {
        el = document.createElement('section');
        el.id = 'view-' + name;
        el.setAttribute('data-view', name);
        el.setAttribute('aria-label', name + ' view');
        root.appendChild(el);
      }
      el.hidden = true;
      el.classList.remove('view-active');
      viewEls[name] = el;
    });
  }

  function ensureTabBar() {
    tabBarEl = document.getElementById('tab-bar');
    if (!tabBarEl) {
      tabBarEl = document.createElement('nav');
      tabBarEl.id = 'tab-bar';
      tabBarEl.setAttribute('aria-label', 'Chat views');
      document.body.appendChild(tabBarEl);
    }
    // (Re)build tabs from TABS so labels/attributes are always exact,
    // even if C1's shell shipped different markup.
    tabBarEl.innerHTML = '';
    TABS.forEach(function (name) {
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'tab';
      btn.setAttribute('data-view', name);
      btn.setAttribute('aria-current', 'false');
      btn.textContent = TAB_LABELS[name];
      btn.addEventListener('click', function () { navigate(name); });
      tabBarEl.appendChild(btn);
      tabEls[name] = btn;
    });
  }

  function renderPlaceholder(name) {
    var el = viewEls[name];
    if (!el) { return; }
    el.innerHTML = '';
    var p = document.createElement('p');
    p.className = 'view-placeholder';
    p.textContent = 'This view is still loading. If it stays like this, reload the page.';
    el.appendChild(p);
  }

  function showView(name) {
    VIEWS.forEach(function (v) {
      var el = viewEls[v];
      if (!el) { return; }
      var active = (v === name);
      el.hidden = !active;
      el.classList.toggle('view-active', active);
    });
    TABS.forEach(function (t) {
      var btn = tabEls[t];
      if (btn) { btn.setAttribute('aria-current', String(t === name)); }
    });
    // Setup is not a tab; hide the tab bar there so first-run
    // onboarding is a single centred column (UI-SPEC §2.1 layout).
    if (tabBarEl) { tabBarEl.hidden = (name === 'setup'); }
    document.body.setAttribute('data-view', name);
  }

  /* Per-view mount adapters — each calls the module's real entry point
   * with (container, options/inputs) and returns its handle. */
  var VIEW_MOUNTS = {
    setup: function (mod, el) {
      return mod.mount(el, {
        config: config,
        onComplete: completeSetup,
        onJoin: completeSetup
      });
    },
    thread: function (mod, el) {
      var renderer = mod.createThreadRenderer(el, viewContext());
      renderer.setMessages(state.messages);
      return renderer;
    },
    keys: function (mod, el) {
      return mod.renderKeysInto(el, state.keyDirectory.participants, viewContext());
    },
    compose: function (mod, el) {
      return mod.mountCompose(el, viewContext());
    },
    audit: function (mod, el) {
      var inputs = {
        messages: state.messages,
        participants: state.keyDirectory.participants,
        keyDirectory: state.keyDirectory.participants,
        nowSec: Math.floor(Date.now() / 1000)
      };
      var p = mod.mountAuditView(el, inputs, viewContext());
      if (p && typeof p.catch === 'function') {
        p.catch(function (e) {
          recordError('view-mount-failed', String(e && e.message || e));
          renderPlaceholder('audit');
        });
      }
      return { promise: p, destroy: function () { /* container cleared by unmountView */ } };
    }
  };

  function unmountView() {
    if (!mountedView) { return; }
    var name = mountedView;
    var h = mountedHandle;
    mountedView = null;
    mountedHandle = null;
    if (h) {
      try {
        if (typeof h.destroy === 'function') { h.destroy(); }
        else if (h.view && typeof h.view.destroy === 'function') { h.view.destroy(); }
        else if (typeof h.teardown === 'function') { h.teardown(); }
      } catch (e) { recordError('view-unmount-failed', String(e && e.message || e)); }
    }
    var el = viewEls[name];
    if (el) { el.innerHTML = ''; }
  }

  function mountView(name) {
    unmountView();
    mountedView = name;
    var mod = getGlobal(VIEW_GLOBALS[name]);
    var el = viewEls[name];
    if (!mod) { renderPlaceholder(name); return; }
    var mount = VIEW_MOUNTS[name];
    if (!mount) { renderPlaceholder(name); return; }
    try {
      mountedHandle = mount(mod, el);
    } catch (e) {
      recordError('view-mount-failed', String(e && e.message || e));
      mountedHandle = null;
      renderPlaceholder(name);
    }
  }

  /* Keep the mounted view in sync with shared state. The thread
   * renderer owns its own dedup/replay map, so a full setMessages on
   * each poll is safe; keys/audit re-render when their inputs change;
   * compose refreshes its lock line when the key directory changes. */
  function refreshMounted(event, payload) {
    if (!mountedView || !mountedHandle) { return; }
    try {
      if (mountedView === 'thread' && event === 'messages' &&
          typeof mountedHandle.setMessages === 'function') {
        mountedHandle.setMessages(state.messages);
      } else if (mountedView === 'keys' && event === 'key-directory' &&
          payload && (payload.status === 'loaded' || payload.status === 'error')) {
        // Re-render only once the directory settles (not on the
        // intermediate 'loading' emit — the initial mount already
        // shows the empty state).
        mountView('keys');
      } else if (mountedView === 'audit' &&
          (event === 'messages' ||
            (event === 'key-directory' && payload &&
              (payload.status === 'loaded' || payload.status === 'error')))) {
        mountView('audit');
      } else if (mountedView === 'thread' && event === 'key-directory' &&
          payload && payload.status === 'loaded') {
        // Re-mount with the fresh participants: the thread view
        // resolves recipient enc keys from viewContext at mount time,
        // and the directory loads after the first mount. Messages are
        // restored from state.messages on mount; the container's
        // last-read-seq watermark survives (it lives on the element).
        mountView('thread');
      } else if (mountedView === 'compose' && event === 'key-directory' &&
          typeof mountedHandle.refresh === 'function') {
        // Push fresh participants into the live compose view WITHOUT
        // remounting (a remount would drop the draft in progress),
        // then refresh the lock line / send availability.
        if (mountedHandle.view && typeof mountedHandle.view.setParticipants === 'function') {
          try { mountedHandle.view.setParticipants(getKeyDirectoryParticipants()); } catch (e) { /* refresh below still runs */ }
        }
        mountedHandle.refresh();
      }
    } catch (e) { recordError('view-refresh-failed', String(e && e.message || e)); }
  }

  function viewContext() {
    return {
      state: state,
      config: config,
      roomId: config.roomId,
      // Presence-send options (P5/P6, wired here in Phase 3b assembly
      // — see §4b): the thread + compose views need these to publish
      // typing signals and read markers live. getSigningKey and the
      // publish function are live references (no staleness); the
      // participants snapshot is refreshed when the key directory
      // settles (refreshMounted, below) because the directory loads
      // after the first mount.
      currentUserId: state.me,
      senderId: state.me,
      getSigningKey: getSigningKey,
      participants: getKeyDirectoryParticipants(),
      keyDirectory: getKeyDirectoryParticipants(),
      recipients: (config.defaultRecipients || ['jarvis', 'chatgpt', 'owner']).slice(),
      publishEnvelope: publishPresenceEnvelope,
      publish: publishPresenceEnvelope,
      threadId: presenceThreadId,
      navigate: navigate,
      subscribe: on,
      addMessages: addMessages,
      confirmSent: confirmSent,
      getMessage: getMessage,
      refreshKeyDirectory: refreshKeyDirectory,
      onKeysReady: onKeysReady,
      completeSetup: completeSetup,
      queueOutbox: queueOutbox,
      removeOutbox: removeOutbox,
      refreshOutbox: refreshOutbox,
      attachOutbox: attachOutbox,
      getOutboxInstance: getOutboxInstance
    };
  }

  /* Route to a view. The setup gate is fail-closed: with no keys in
   * this browser the app always lands on setup, whatever the hash says
   * (UI-SPEC §2.1: setup appears automatically on first visit). */
  function navigate(name) {
    var target = HASH_TO_VIEW[name] || name;
    if (VIEWS.indexOf(target) === -1) { target = state.hasKeys ? 'thread' : 'setup'; }
    if (!state.hasKeys && target !== 'setup') {
      state.returnView = target;
      target = 'setup';
    }
    var changed = (target !== state.view);
    state.view = target;
    showView(target);
    mountView(target);
    var hash = '#' + target;
    if (window.location.hash !== hash) {
      // replaceState keeps tab-switching out of the back-button history
      // while still letting a refresh land on the same view (UI-SPEC §2).
      try {
        window.history.replaceState(null, '', hash);
      } catch (e) {
        window.location.hash = hash;
      }
    }
    if (changed) { emit('view', { view: target }); }
    return target;
  }

  function viewFromHash() {
    var raw = (window.location.hash || '').replace(/^#/, '').split('?')[0];
    return HASH_TO_VIEW[raw] || null;
  }

  /* Called by view-setup.js (C4) after key generation/import succeeds
   * (via options.onComplete/onJoin). Re-checks the store rather than
   * trusting the setup view's state shape, then routes onward.
   * P7: the setup view shows its "You're in" confirmation and holds it
   * briefly (~1 s) before calling here, so the user sees the
   * confirmation before the view changes. */
  function completeSetup() {
    return checkKeys().then(function () {
      emit('keys', { hasKeys: state.hasKeys });
      var next = (state.returnView && state.returnView !== 'setup')
        ? state.returnView : 'thread';
      navigate(state.hasKeys ? next : 'setup');
      // P7: setup finished. Views can subscribe to 'setup-complete'
      // for a one-time post-join hook (e.g. a welcome note); routing
      // itself is done above.
      emit('setup-complete', { hasKeys: state.hasKeys, view: state.view });
      return state.hasKeys;
    });
  }

  /* Back-compat entry point: a caller that already holds a key set
   * (e.g. an older setup flow) can hand it in directly. */
  function onKeysReady(keys) {
    if (keys) {
      state.keys = keys;
      state.hasKeys = true;
      state.keysError = null;
      emit('keys', { hasKeys: true });
      var next = (state.returnView && state.returnView !== 'setup')
        ? state.returnView : 'thread';
      navigate(next);
      return Promise.resolve(true);
    }
    return completeSetup();
  }

  /* ------------------------------------------------------------------ */
  /* 4. Keys — via C17 keys-store.js ONLY (GhostChatKeysStore:           */
  /*    loadKeys(roomId?) / hasKeys(roomId?), both async). This file     */
  /*    never touches IndexedDB or key material directly. The room id   */
  /*    is passed explicitly (C20 roomId, "ghostcorp-chat-1").          */
  /* ------------------------------------------------------------------ */

  function keysStore() {
    return getGlobal('GhostChatKeysStore') || getGlobal('ChatKeysStore');
  }

  function checkKeys() {
    var store = keysStore();
    if (!store || typeof store.hasKeys !== 'function' ||
        typeof store.loadKeys !== 'function') {
      // Fail closed: without the store we cannot prove a key exists,
      // so route to setup (C4 surfaces the storage problem).
      state.hasKeys = false;
      state.keys = null;
      state.keysError = 'key-store-unavailable';
      recordError('key-store-unavailable',
        'Key storage (keys-store.js) is not loaded yet.');
      return Promise.resolve(false);
    }
    return Promise.resolve()
      .then(function () { return store.hasKeys(config.roomId); })
      .then(function (has) {
        state.hasKeys = !!has;
        if (!state.hasKeys) { state.keys = null; return false; }
        return Promise.resolve(store.loadKeys(config.roomId)).then(function (keys) {
          state.keys = keys || null;
          state.hasKeys = !!state.keys;
          return state.hasKeys;
        });
      })
      .catch(function (e) {
        state.hasKeys = false;
        state.keys = null;
        state.keysError = 'key-load-failed';
        recordError('key-load-failed', String(e && e.message || e));
        return false;
      });
  }

  /* ------------------------------------------------------------------ */
  /* 4b. Presence-send wiring (assembly, Phase 3b — STATE-OF-THE-ART-  */
  /*     BAR P5/P6). The thread + compose views send typing signals    */
  /*     and read markers through window.GhostChatPresence, which      */
  /*     needs sender + signing key + recipient enc keys + a publish   */
  /*     function + a UUIDv4 threadId. app.js is the only place that   */
  /*     holds all five, so viewContext() (below) carries them into    */
  /*     both views. Every resolver here fails CLOSED (null / reject)  */
  /*     when its input is missing — the views then skip the send,     */
  /*     never publish an unsigned or unwrapped envelope.              */
  /*     Side effect, intended: the same participants + getSigningKey  */
  /*     options are what compose's send engine reads (C7), so this    */
  /*     wiring also unblocks ordinary sends, which previously had no  */
  /*     signing key or recipient keys from app.js at all.             */
  /* ------------------------------------------------------------------ */

  function uuidV4() {
    var bytes = new Uint8Array(16);
    try {
      if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
        crypto.getRandomValues(bytes);
      } else { throw new Error('no getRandomValues'); }
    } catch (e) {
      for (var i = 0; i < 16; i++) { bytes[i] = Math.floor(Math.random() * 256); }
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10
    function hex(n) { return (n < 16 ? '0' : '') + n.toString(16); }
    return hex(bytes[0]) + hex(bytes[1]) + hex(bytes[2]) + hex(bytes[3]) + '-' +
      hex(bytes[4]) + hex(bytes[5]) + '-' + hex(bytes[6]) + hex(bytes[7]) + '-' +
      hex(bytes[8]) + hex(bytes[9]) + '-' + hex(bytes[10]) + hex(bytes[11]) +
      hex(bytes[12]) + hex(bytes[13]) + hex(bytes[14]) + hex(bytes[15]);
  }

  // One UUIDv4 per page load: the thread id for typing signals and
  // read markers (presence.js requires UUIDv4; a marker without one
  // is a root of its own thread). The chat is a single room, so one
  // session thread id threads all presence in this load.
  var presenceThreadId = uuidV4();

  // Signing key for this browser's participant, in the
  // { privateKey, sigAlg } shape the views expect (keys-store C17
  // contract). sigAlg comes from the stored key's own metadata
  // (Ed25519, or ES256 when the browser fell back to P-256 at setup);
  // null when no keys are stored — the caller then fails closed.
  function getSigningKey() {
    var store = keysStore();
    if (!store || typeof store.loadKeys !== 'function') {
      return Promise.resolve(null);
    }
    return Promise.resolve(store.loadKeys(config.roomId)).then(function (keys) {
      if (!keys || !keys.sigPrivate) { return null; }
      var sigAlg = 'Ed25519';
      var meta = keys.meta || {};
      if (meta.sigAlgorithm === 'ECDSA' && meta.sigNamedCurve === 'P-256') {
        sigAlg = 'ES256';
      } else if (meta.sigAlgorithm === 'Ed25519') {
        sigAlg = 'Ed25519';
      }
      return { privateKey: keys.sigPrivate, sigAlg: sigAlg };
    }).catch(function () { return null; });
  }

  // Raw key-directory entries (array form), with enc_pub_pem intact:
  // the views import recipient enc keys from these PEMs (via
  // GhostChatCrypto) for presence envelopes and for wrapping message
  // keys. Falls back to the normalised state entries (fingerprints
  // only — recipient resolution then finds no keys and skips the
  // send, fail-closed) when the raw payload has not loaded yet.
  function getKeyDirectoryParticipants() {
    var raw = keyDirectoryRaw;
    if (Array.isArray(raw)) { return raw.slice(); }
    if (raw && Array.isArray(raw.participants)) { return raw.participants.slice(); }
    return state.keyDirectory.participants.slice();
  }

  // Publish function for presence envelopes: the paste-publish
  // module's publishEnvelope (C14), which writes the envelope file +
  // manifest via the owner's GitHub PAT (C13) and is idempotent
  // (same ID + same bytes = no-op). Rejects when the module has not
  // loaded — the views then skip the send.
  function publishPresenceEnvelope(envelope) {
    var mod = getGlobal('GhostChatPastePublish');
    if (!mod || typeof mod.publishEnvelope !== 'function') {
      return Promise.reject(new Error('publish module (paste-publish.js) is not loaded'));
    }
    return mod.publishEnvelope(envelope);
  }

  /* ------------------------------------------------------------------ */
  /* 5. Key directory — the ONE fetch this file makes, through the      */
  /*    config URL (FILE-MAP D8: chat/keys/participants.json, public    */
  /*    keys only, schema per CRYPTO-DESIGN §9). Loads in parallel     */
  /*    with the thread; the thread never waits for it (UI-SPEC §5).    */
  /*    Defense: any private-key-looking field in the payload is       */
  /*    dropped and recorded — a directory must never carry it.         */
  /* ------------------------------------------------------------------ */

  var PRIVATE_FIELD_RE = /private|secret|password|passphrase|seed|mnemonic/i;
  var VALID_KEY_STATUSES = ['unpinned', 'pinned', 'revoked'];

  function normaliseParticipant(raw) {
    if (!raw || typeof raw !== 'object') { return null; }
    var id = typeof raw.id === 'string' ? raw.id : null;
    if (!id) { return null; }
    var entry = {
      id: id,
      display_name: typeof raw.display_name === 'string' ? raw.display_name : id,
      enc_fingerprint: typeof raw.enc_fingerprint === 'string' ? raw.enc_fingerprint : null,
      sig_fingerprint: typeof raw.sig_fingerprint === 'string' ? raw.sig_fingerprint : null,
      sig_alg: typeof raw.sig_alg === 'string' ? raw.sig_alg : null,
      status: VALID_KEY_STATUSES.indexOf(raw.status) !== -1 ? raw.status : 'unknown',
      pinned_at: typeof raw.pinned_at === 'string' ? raw.pinned_at : null,
      pinned_by: typeof raw.pinned_by === 'string' ? raw.pinned_by : null,
      rotated_from: typeof raw.rotated_from === 'string' ? raw.rotated_from : null
    };
    // Public-key PEMs are large; keep only the fingerprint + algorithm
    // in shared state. Views that need a PEM fetch it from the directory
    // payload via getKeyDirectoryEntry (below) — never from this file's
    // state. Any private-looking field is dropped, never stored.
    var dropped = [];
    Object.keys(raw).forEach(function (k) {
      if (PRIVATE_FIELD_RE.test(k)) { dropped.push(k); }
    });
    if (dropped.length) {
      recordError('key-directory-private-field',
        'Key directory contained private-looking field(s): ' + dropped.join(', ') + ' — dropped.');
    }
    return entry;
  }

  // Raw (public-key) directory payload, kept for views that need PEMs.
  // Still public-keys-only: the same private-field sweep applies.
  var keyDirectoryRaw = null;

  function refreshKeyDirectory() {
    state.keyDirectory.status = 'loading';
    state.keyDirectory.error = null;
    emit('key-directory', { status: 'loading' });
    return fetch(config.keyDirectoryUrl, { cache: 'no-store' })
      .then(function (res) {
        if (!res.ok) {
          throw new Error('key directory HTTP ' + res.status);
        }
        return res.json();
      })
      .then(function (data) {
        var list = Array.isArray(data) ? data
          : (data && Array.isArray(data.participants) ? data.participants : null);
        if (!list) { throw new Error('key directory has no participants list'); }
        keyDirectoryRaw = data;
        var entries = [];
        list.forEach(function (raw) {
          var e = normaliseParticipant(raw);
          if (e) { entries.push(e); }
        });
        state.keyDirectory.participants = entries;
        state.keyDirectory.status = 'loaded';
        state.keyDirectory.loadedAt = new Date().toISOString();
        emit('key-directory', { status: 'loaded', count: entries.length });
        return entries;
      })
      .catch(function (e) {
        state.keyDirectory.status = 'error';
        state.keyDirectory.error = String(e && e.message || e);
        recordError('key-directory-failed', state.keyDirectory.error);
        emit('key-directory', { status: 'error', error: state.keyDirectory.error });
        return [];
      });
  }

  function getKeyDirectoryEntry(id) {
    var found = null;
    state.keyDirectory.participants.forEach(function (p) {
      if (p.id === id) { found = p; }
    });
    return found;
  }

  /* ------------------------------------------------------------------ */
  /* 6. Messages — envelopes only. addMessages is the single entry     */
  /*    point for poll.js (C9), the inline-log seed (§7) and the        */
  /*    outbox send path (C12/C7). Dedup by msg_id (UI-SPEC §6): an    */
  /*    identical re-delivery is ignored silently; the same msg_id     */
  /*    with DIFFERENT bytes is kept as a second entry flagged         */
  /*    replaySuspect — never silently merged (UI-SPEC §2.3/§6).       */
  /*    Ordering is by relay seq (FILE-MAP §3 manifest), NOT sender    */
  /*    clock; entries without a seq sort after sequenced ones, by     */
  /*    iat, then msg_id for stability.                                */
  /* ------------------------------------------------------------------ */

  // Byte comparison for dedup/replay detection. App-private fields
  // (_source, _pending, replaySuspect) are stripped first, and keys
  // are sorted, so an identical re-delivery compares equal to the
  // stored copy even though the stored copy carries app metadata.
  function envelopeBytes(env) {
    try {
      var clean = {};
      Object.keys(env).sort().forEach(function (k) {
        if (k.charAt(0) === '_' || k === 'replaySuspect') { return; }
        clean[k] = env[k];
      });
      return JSON.stringify(clean);
    } catch (e) { return null; }
  }

  function compareMessages(a, b) {
    var aSeq = (typeof a.seq === 'number') ? a.seq : null;
    var bSeq = (typeof b.seq === 'number') ? b.seq : null;
    if (aSeq !== null && bSeq !== null) { return aSeq - bSeq; }
    if (aSeq !== null) { return -1; }
    if (bSeq !== null) { return 1; }
    var aIat = (typeof a.iat === 'number') ? a.iat : 0;
    var bIat = (typeof b.iat === 'number') ? b.iat : 0;
    if (aIat !== bIat) { return aIat - bIat; }
    return String(a.msg_id || '') < String(b.msg_id || '') ? -1 : 1;
  }

  function addMessages(envelopes, source) {
    if (!Array.isArray(envelopes)) { return { added: 0, duplicates: 0, replay: 0 }; }
    var added = 0, duplicates = 0, replay = 0;
    var changed = false;
    envelopes.forEach(function (env) {
      if (!env || typeof env !== 'object' ||
          typeof env.msg_id !== 'string' || !env.msg_id) {
        return; // malformed: not our message to display; poller logs it
      }
      var bytes = envelopeBytes(env);
      var existing = null;
      for (var i = 0; i < state.messages.length; i++) {
        if (state.messages[i].msg_id === env.msg_id) { existing = state.messages[i]; break; }
      }
      if (existing) {
        if (bytes !== null && envelopeBytes(existing) === bytes) {
          duplicates++;
          return; // identical re-delivery: ignore silently (UI-SPEC §6)
        }
        // Same ID, different bytes: replay suspect — keep as a second
        // entry, flagged for badges.js (C10); never merge (UI-SPEC §6).
        var suspect = {};
        Object.keys(env).forEach(function (k) { suspect[k] = env[k]; });
        suspect.replaySuspect = true;
        suspect._source = source || 'poll';
        state.messages.push(suspect);
        replay++;
        changed = true;
        return;
      }
      var copy = {};
      Object.keys(env).forEach(function (k) { copy[k] = env[k]; });
      copy._source = source || 'poll';
      state.messages.push(copy);
      state.seenIds[env.msg_id] = true;
      if (typeof env.seq === 'number' &&
          (state.lastSeq === null || env.seq > state.lastSeq)) {
        state.lastSeq = env.seq;
      }
      added++;
      changed = true;
    });
    if (changed) {
      state.messages.sort(compareMessages);
      emit('messages', { added: added, duplicates: duplicates, replay: replay, source: source || 'poll' });
    }
    return { added: added, duplicates: duplicates, replay: replay };
  }

  /* Pending -> sent replacement (UI-SPEC §6): when the poll returns the
   * relay-accepted copy of a message we sent, it replaces the pending
   * bubble in place, matched by msg_id — never by text content. The
   * outbox mirror drops the entry at the same time. */
  function confirmSent(msgId, acceptedEnvelope) {
    var idx = -1;
    for (var i = 0; i < state.messages.length; i++) {
      if (state.messages[i].msg_id === msgId) { idx = i; break; }
    }
    if (idx === -1) {
      return addMessages([acceptedEnvelope], 'poll');
    }
    var merged = {};
    Object.keys(state.messages[idx]).forEach(function (k) { merged[k] = state.messages[idx][k]; });
    Object.keys(acceptedEnvelope || {}).forEach(function (k) { merged[k] = acceptedEnvelope[k]; });
    delete merged._pending;
    state.messages[idx] = merged;
    state.messages.sort(compareMessages);
    removeOutbox(msgId, true);
    emit('messages', { added: 0, duplicates: 0, replay: 0, source: 'confirm-sent' });
    return { added: 0, duplicates: 0, replay: 0 };
  }

  function getMessage(msgId) {
    for (var i = 0; i < state.messages.length; i++) {
      if (state.messages[i].msg_id === msgId) { return state.messages[i]; }
    }
    return null;
  }

  /* ------------------------------------------------------------------ */
  /* 7. Inline-log seed (FILE-MAP D4). C1 embeds the current message   */
  /*    log as ciphertext in <script type="application/json"            */
  /*    id="chat-log"> so a fetch without JS still sees the log. The   */
  /*    app seeds its message list from it at bootstrap, then polling  */
  /*    (C9) takes over. A bad block never blocks boot.                */
  /* ------------------------------------------------------------------ */

  function seedFromInlineLog() {
    var el = document.getElementById('chat-log');
    if (!el) { return { added: 0, duplicates: 0, replay: 0 }; }
    var data;
    try {
      data = JSON.parse(el.textContent || '');
    } catch (e) {
      recordError('inline-log-unparseable', String(e && e.message || e));
      return { added: 0, duplicates: 0, replay: 0 };
    }
    var list = Array.isArray(data) ? data
      : (data && Array.isArray(data.messages) ? data.messages : null);
    if (!list) {
      recordError('inline-log-no-messages', 'Inline chat log has no messages list.');
      return { added: 0, duplicates: 0, replay: 0 };
    }
    return addMessages(list, 'inline-log');
  }

  /* ------------------------------------------------------------------ */
  /* 8. Outbox mirror — C12 outbox.js owns persistence + retry. The    */
  /*    outbox instance is created by the compose view (C7), which     */
  /*    supplies its publish function (createOutbox requires one —     */
  /*    app.js must not invent a publish path); whoever creates it     */
  /*    registers it here via attachOutbox(). This file only mirrors   */
  /*    its list into shared state so the thread and compose views     */
  /*    render pending/queued bubbles from one place. If no instance   */
  /*    is attached yet, entries live in memory only for this session  */
  /*    (flagged degraded — they will not survive reload).             */
  /* ------------------------------------------------------------------ */

  var outboxInstance = null;
  var outboxUnsubscribe = null;

  function getOutboxInstance() { return outboxInstance; }

  function attachOutbox(instance) {
    if (outboxUnsubscribe) {
      try { outboxUnsubscribe(); } catch (e) { /* ignore */ }
      outboxUnsubscribe = null;
    }
    outboxInstance = instance || null;
    state.outboxAttached = !!outboxInstance;
    if (outboxInstance && typeof outboxInstance.subscribe === 'function') {
      try {
        outboxUnsubscribe = outboxInstance.subscribe(function () { refreshOutbox(); });
      } catch (e) { recordError('outbox-subscribe-failed', String(e && e.message || e)); }
    }
    emit('outbox-attached', { attached: state.outboxAttached });
    return refreshOutbox();
  }

  function refreshOutbox() {
    if (!outboxInstance || typeof outboxInstance.list !== 'function') {
      return Promise.resolve(state.outbox);
    }
    return Promise.resolve(outboxInstance.list())
      .then(function (list) {
        state.outbox = Array.isArray(list) ? list : [];
        emit('outbox', { count: state.outbox.length });
        return state.outbox;
      })
      .catch(function (e) {
        recordError('outbox-list-failed', String(e && e.message || e));
        return state.outbox;
      });
  }

  function queueOutbox(entry) {
    if (outboxInstance && typeof outboxInstance.enqueue === 'function') {
      // The outbox validates the envelope (signed + encrypted) itself
      // and throws otherwise — app.js never bypasses that check.
      return Promise.resolve(outboxInstance.enqueue(entry)).then(function () {
        return refreshOutbox();
      });
    }
    // Degraded in-memory path (no outbox instance attached yet): keep
    // the entry for this session only and say so — never pretend it
    // persisted.
    state.outbox.push(entry);
    recordError('outbox-degraded',
      'Outbox instance not attached — queued message kept in memory only and will not survive reload.');
    emit('outbox', { count: state.outbox.length, degraded: true });
    return Promise.resolve(state.outbox);
  }

  function removeOutbox(msgId, silent) {
    if (outboxInstance) {
      var fn = null;
      if (typeof outboxInstance.discard === 'function') {
        fn = outboxInstance.discard.bind(outboxInstance);
      } else if (typeof outboxInstance.remove === 'function') {
        fn = outboxInstance.remove.bind(outboxInstance);
      }
      if (fn) {
        return Promise.resolve(fn(msgId)).then(function () {
          return refreshOutbox();
        });
      }
    }
    state.outbox = state.outbox.filter(function (e) { return e.msg_id !== msgId; });
    if (!silent) { emit('outbox', { count: state.outbox.length }); }
    return Promise.resolve(state.outbox);
  }

  /* ------------------------------------------------------------------ */
  /* 9. Poller hookup — C9 poll.js owns the loop (15 s visible,        */
  /*    backoff 5 s -> 60 s, seq cursor, dedup). app.js only creates   */
  /*    the poller through the landed GhostChatPoll.createPoller        */
  /*    factory, wires onVerified -> addMessages, seeds the poller's   */
  /*    seen-set from the inline log, and starts it.                   */
  /* ------------------------------------------------------------------ */

  var poller = null;

  function startPoller() {
    var factory = getGlobal('GhostChatPoll') || getGlobal('ChatPoll');
    if (!factory || typeof factory.createPoller !== 'function') {
      state.polling = 'unavailable';
      recordError('poll-unavailable',
        'Polling module (poll.js) is not loaded — new messages will not arrive until it loads.');
      return false;
    }
    if (poller) {
      try { poller.stop(); } catch (e) { /* ignore */ }
      poller = null;
    }
    try {
      var prefix = config.messagesUrlPrefix ||
        (String(config.storeBaseUrl || '/chat').replace(/\/$/, '') + '/messages/');
      poller = factory.createPoller({
        manifestUrl: config.manifestUrl,
        messageUrlFor: function (msgId) { return prefix + msgId + '.json'; },
        pollIntervalMs: config.pollIntervalMs,
        backoffMs: config.pollBackoffMs,
        initialLastSeq: state.lastSeq || 0,
        onVerified: function (envelope) {
          if (envelope) { addMessages([envelope], 'poll'); }
        },
        onProblem: function (problem) {
          var detail = problem && (problem.message || problem.code ||
            (function () { try { return JSON.stringify(problem); } catch (e) { return String(problem); } })());
          recordError('poll-problem', detail || 'poll problem');
        },
        onStatus: function (status) {
          var s = (status && typeof status === 'object')
            ? (status.status || status.state) : status;
          if (s) { state.polling = String(s); }
          emit('polling', { status: state.polling });
        }
      });
      // Seed the poller's seen-set from the inline log so it does not
      // re-deliver messages the page already holds.
      if (typeof poller.seedSeen === 'function') {
        try { poller.seedSeen(state.messages); } catch (e) { /* non-fatal */ }
      }
      poller.start();
      state.polling = 'running';
      emit('polling', { status: 'running' });
      return true;
    } catch (e) {
      state.polling = 'error';
      recordError('poll-start-failed', String(e && e.message || e));
      return false;
    }
  }

  function stopPoller() {
    if (poller) {
      try {
        if (typeof poller.stop === 'function') { poller.stop(); }
        else if (typeof poller.destroy === 'function') { poller.destroy(); }
      } catch (e) { recordError('poll-stop-failed', String(e && e.message || e)); }
      poller = null;
    }
    state.polling = 'not-started';
  }

  /* ------------------------------------------------------------------ */
  /* 10. Bootstrap. Order (UI-SPEC §5 Loading: thread does not wait    */
  /*     for the key directory):                                         */
  /*     crypto gate -> key check -> shell (views + tab bar) -> route   */
  /*     -> inline-log seed -> key directory (parallel) -> outbox      */
  /*     mirror -> poller create + start (seeded from the inline log). */
  /*     A failure at any step fails closed to a usable state (setup   */
  /*     view / empty thread + recorded error), never to a half-        */
  /*     rendered page or a silent dead end.                           */
  /* ------------------------------------------------------------------ */

  function cryptoAvailable() {
    try {
      return !!(typeof window !== 'undefined' && window.crypto &&
        window.crypto.subtle &&
        typeof window.crypto.subtle.generateKey === 'function');
    } catch (e) {
      return false;
    }
  }

  function showCryptoBlocked() {
    ensureViewElements();
    var el = viewEls.setup;
    if (!el) { return; }
    el.innerHTML = '';
    var h = document.createElement('h1');
    h.textContent = 'This browser can\u2019t do the encryption this chat needs.';
    var p = document.createElement('p');
    p.textContent = 'Use a current browser over HTTPS. There is no weaker way to join this chat.';
    el.appendChild(h);
    el.appendChild(p);
    showView('setup');
    if (tabBarEl) { tabBarEl.hidden = true; }
  }

  function bindConnectivity() {
    window.addEventListener('online', function () {
      state.online = true;
      emit('online', { online: true });
    });
    window.addEventListener('offline', function () {
      state.online = false;
      emit('offline', { online: false });
    });
    document.addEventListener('visibilitychange', function () {
      emit('visibility', { visible: !document.hidden });
    });
  }

  function bindHash() {
    window.addEventListener('hashchange', function () {
      var view = viewFromHash();
      if (view) { navigate(view); }
    });
  }

  function bootstrap() {
    if (state.booted) { return Promise.resolve(state); }
    state.booted = true;

    state.cryptoAvailable = cryptoAvailable();
    if (!state.cryptoAvailable) {
      recordError('webcrypto-unavailable',
        'WebCrypto is unavailable (old browser or non-secure context).');
      ensureTabBar();
      showCryptoBlocked();
      state.ready = true;
      emit('ready', { cryptoAvailable: false });
      return Promise.resolve(state);
    }

    ensureViewElements();
    ensureTabBar();
    bindConnectivity();
    bindHash();

    return checkKeys()
      .then(function () {
        // Route first so the user sees a view immediately; the
        // key directory and poller fill in behind it (UI-SPEC §5).
        var requested = viewFromHash();
        if (requested) { state.returnView = requested; }
        navigate(requested || (state.hasKeys ? 'thread' : 'setup'));
        seedFromInlineLog();
        refreshKeyDirectory(); // parallel, non-blocking
        refreshOutbox(); // parallel, non-blocking (no-op until attached)
        startPoller(); // seeded from the inline log above
        state.ready = true;
        emit('ready', { cryptoAvailable: true, hasKeys: state.hasKeys, view: state.view });
        return state;
      })
      .catch(function (e) {
        // checkKeys already records its own errors; this is the
        // last-resort guard so boot never rejects unhandled.
        recordError('bootstrap-failed', String(e && e.message || e));
        navigate('setup');
        state.ready = true;
        emit('ready', { cryptoAvailable: true, hasKeys: false, view: 'setup' });
        return state;
      });
  }

  /* ------------------------------------------------------------------ */
  /* 11. Public interface for the view modules (C4–C8), poll.js (C9),  */
  /*     outbox.js (C12) and the publish-time embedder (C15). Nothing  */
  /*     here exposes keys, plaintext, or any secret.                   */
  /* ------------------------------------------------------------------ */

  var ChatApp = {
    config: config,
    state: state,
    views: VIEWS,
    tabs: TABS,
    bootstrap: bootstrap,
    navigate: navigate,
    on: on,
    emit: emit,
    getState: function () { return state; },
    getConfig: function () { return config; },
    addMessages: addMessages,
    confirmSent: confirmSent,
    getMessage: getMessage,
    refreshKeyDirectory: refreshKeyDirectory,
    getKeyDirectoryEntry: getKeyDirectoryEntry,
    onKeysReady: onKeysReady,
    completeSetup: completeSetup,
    queueOutbox: queueOutbox,
    removeOutbox: removeOutbox,
    refreshOutbox: refreshOutbox,
    attachOutbox: attachOutbox,
    getOutboxInstance: getOutboxInstance,
    startPoller: startPoller,
    stopPoller: stopPoller,
    seedFromInlineLog: seedFromInlineLog
  };

  if (typeof window !== 'undefined') {
    window.ChatApp = ChatApp;
  }

  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', function () { bootstrap(); });
    } else {
      bootstrap();
    }
  }

  /* Node / test harness escape hatch: module.exports when present so
   * unit tests can load this file without a browser. Not used in the
   * shipped page (no build step, no bundler — D18). */
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = ChatApp;
  }
})();
