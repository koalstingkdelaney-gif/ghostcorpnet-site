// notify.js — lock-screen-safe notifications for the ghostcorpnet encrypted chat.
//
// Worker C18. Normative refs:
//   - FILE-MAP.md §4 C18: "lock-screen-safe notifications: 'New message in
//     the locked chat' only, no preview text."
//   - design/OWNER-JOIN.md §5 "Notifications": notification text is
//     "New message in the locked chat" — nothing more. A lock-screen preview
//     would leak the message to anyone who sees the phone.
//   - design/UI-SPEC.md §6: polling pauses while the tab is hidden and a
//     single fetch fires on visibility return; this module is the hook the
//     poller calls when that fetch finds new VERIFIED messages.
//
// Lock-screen safety, by construction:
//   - The notification has a fixed title and NO body, NO icon, NO image,
//     NO tag data, NO actions. There is no parameter anywhere in this module
//     that can carry message content, a sender name, or a preview —
//     notifyNewMessage() takes only a boolean (verified or not). Content
//     cannot leak through this module because it is never handed any.
//   - Notifications fire ONLY while the page is in the background
//     (document.hidden). While the page is visible the thread itself shows
//     the message and no notification is raised.
//   - Permission is requested ONLY after the owner joins, exactly once per
//     page session, via initAfterJoin(). A denial is respected silently:
//     no prompt is ever repeated, no error is shown, no state is recorded
//     anywhere except the browser's own permission setting.
//   - No analytics, no network calls, no external services, no storage
//     writes (the "already asked" flag is in-memory only; the browser's own
//     Notification.permission is the durable record).
//   - No service worker, no push. A notification can only fire while the
//     chat tab is open (even if backgrounded). If the tab is closed, no
//     notification fires — that is a known limitation, not a bug (see the
//     open item at the bottom of this file).
//
// Wiring (other workers — this module calls nothing outside itself):
//   - app.js / view-setup.js call GhostChatNotify.initAfterJoin() once,
//     after the owner completes joining (after "Join the chat" succeeds).
//   - poll.js (C9) calls GhostChatNotify.notifyNewMessage(verified) when a
//     poll/visibility-return fetch finds a new message that local
//     verification (envelope.js + badges.js) has already accepted as
//     verified. Pass `true` only for verified messages; anything else
//     (false, undefined, unverified, tampered, replay) is ignored.
//   - The test hook GhostChatNotify.testNotification() fires the fixed safe
//     notification on demand (manual QA only). It never prompts for
//     permission: it shows only if permission is already granted.
//
// Runs in any browser with the Notification API (secure context). In
// environments without Notification support (or non-browser runtimes) every
// function is a silent no-op returning false.

'use strict';

(function (global) {
  // The ONLY text this module ever shows. Fixed string literal — never
  // built from, concatenated with, or substituted from message data.
  var NOTIFICATION_TEXT = 'New message in the locked chat';

  // In-memory session state only. Nothing is persisted by this module.
  var joined = false;           // true once initAfterJoin() has run
  var permissionAsked = false;  // true once requestPermission ran this session

  function isSupported() {
    return (
      typeof global !== 'undefined' &&
      typeof global.Notification !== 'undefined' &&
      typeof global.Notification.requestPermission === 'function'
    );
  }

  function currentPermission() {
    if (!isSupported()) {
      return 'unsupported';
    }
    // 'granted' | 'denied' | 'default' (browser-maintained, durable).
    return global.Notification.permission;
  }

  // Show the fixed safe notification. The title IS the whole notification:
  // no body, no icon, no image, no data payload — there is nothing in it
  // that could carry conversation content, by design.
  // Returns true if a notification object was created, false otherwise.
  function showSafeNotification() {
    if (!isSupported()) {
      return false;
    }
    if (global.Notification.permission !== 'granted') {
      return false;
    }
    try {
      var note = new global.Notification(NOTIFICATION_TEXT);
      // Tapping the notification brings the chat tab forward. No content
      // is involved: the click handler only focuses the window.
      try {
        note.onclick = function () {
          try {
            if (typeof global.focus === 'function') {
              global.focus();
            }
          } catch (e) {
            // Focusing is best-effort; a failure changes nothing.
          }
          try {
            note.close();
          } catch (e2) {
            // Already closed; nothing to do.
          }
        };
      } catch (e3) {
        // onclick assignment is best-effort; the notification stands.
      }
      return true;
    } catch (e4) {
      // Notification construction failed (e.g. blocked by the browser).
      // Silent: a notification is never worth an error surface.
      return false;
    }
  }

  // Returns true when the page is in the background. Missing document
  // (non-browser runtime) counts as "not background" — no notification.
  function isBackgrounded() {
    return (
      typeof global.document !== 'undefined' &&
      global.document &&
      global.document.hidden === true
    );
  }

  var api = {
    // The fixed notification text, exposed read-only so tests and the
    // app can assert on it without duplicating the string.
    NOTIFICATION_TEXT: NOTIFICATION_TEXT,

    // Whether the Notification API exists in this environment.
    isSupported: isSupported,

    // Current browser permission state: 'granted' | 'denied' | 'default'
    // | 'unsupported'. Read-only view of the browser's own setting.
    permission: currentPermission,

    // Whether the owner has joined (initAfterJoin has run) this session.
    hasJoined: function () {
      return joined;
    },

    // Diagnostic snapshot. Contains only permission/join state — never
    // message content, sender names, or counts of messages.
    getState: function () {
      return {
        supported: isSupported(),
        permission: currentPermission(),
        joined: joined,
        permissionAskedThisSession: permissionAsked
      };
    },

    // Call exactly once, after the owner joins the chat (after "Join the
    // chat" succeeds). Requests notification permission once, and only
    // then. Safe to call repeatedly: after the first call it is a no-op.
    //   - permission already 'granted' or 'denied' -> no prompt, no-op.
    //   - permission 'default' -> one prompt, this session only.
    //   - denial is respected silently: no retry, no message, no error.
    // Returns a Promise resolving to the resulting permission state.
    initAfterJoin: function () {
      joined = true;
      if (!isSupported()) {
        return Promise.resolve('unsupported');
      }
      var perm = global.Notification.permission;
      if (perm === 'granted' || perm === 'denied') {
        return Promise.resolve(perm);
      }
      if (permissionAsked) {
        // Already asked once this session; never repeat the prompt.
        return Promise.resolve(perm);
      }
      permissionAsked = true;
      try {
        var result = global.Notification.requestPermission();
        // Modern browsers return a Promise; older ones use a callback.
        // Normalise both to a Promise of the permission string.
        if (result && typeof result.then === 'function') {
          return result.then(
            function (p) {
              return p;
            },
            function () {
              return global.Notification.permission;
            }
          );
        }
        return Promise.resolve(global.Notification.permission);
      } catch (e) {
        // Prompt failed (e.g. not allowed in this context). Silent.
        return Promise.resolve(global.Notification.permission);
      }
    },

    // Notify about a new VERIFIED message that arrived while the page is
    // in the background. `verified` must be exactly `true` — the caller
    // (poll.js, C9) passes the result of local verification (envelope.js
    // + badges.js). Anything else is ignored: unverified, tampered,
    // replay-suspect, expired, or undecryptable messages never notify.
    // While the page is visible, no notification is raised (the thread
    // itself shows the message). Takes no message content of any kind.
    // Returns true if a notification was shown, false otherwise.
    notifyNewMessage: function (verified) {
      if (verified !== true) {
        return false;
      }
      if (!isBackgrounded()) {
        return false;
      }
      return showSafeNotification();
    },

    // Test hook (manual QA only). Fires the fixed safe notification with
    // the exact text a real arrival would show. Works regardless of
    // background state so it can be exercised from a visible tab.
    // It NEVER requests permission: it shows only if permission is
    // already 'granted', and silently returns false otherwise — so a
    // test can never trigger a permission prompt before the owner joins.
    // Returns true if a notification was shown, false otherwise.
    testNotification: function () {
      return showSafeNotification();
    }
  };

  // Export: browser global (no build step, no modules per FILE-MAP D18).
  // Under Node (tests) the same global is used.
  global.GhostChatNotify = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);

// OPEN ITEMS (for wave-3 assembly, not blockers for this module):
//   1. No notification fires while the chat tab is fully closed: this
//      module uses the page Notification API only (no service worker, no
//      push subscription — $0, no external services). If closed-tab
//      notifications are ever wanted, that is a new decision (service
//      worker + push endpoint) for the owner, not a change to this file.
//   2. Polling pauses while hidden (UI-SPEC §6), so a "background
//      arrival" is in practice detected by poll.js on the visibility-
//      return fetch; this module notifies at that point if the page is
//      still backgrounded when the fetch resolves.
//   3. On Android Chrome, a page Notification requires the tab to be
//      alive; behaviour while the tab is backgrounded-but-alive is
//      covered by the live-app check (TEST-PLAN T-*) in wave 3.
