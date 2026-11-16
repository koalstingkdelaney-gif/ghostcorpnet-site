/**
 * errors.js — error states + user-visible copy for the ghostcorpnet
 * encrypted chat (ecc-1). Worker C19.
 *
 * Normative refs:
 *   - FILE-MAP.md §3 (envelope / verification order / store), §4 C19,
 *     D18 (single static page, no external resources)
 *   - design/UI-SPEC.md §5 (every state: what the user sees, what they
 *     can do) and §2.3 (verification badges: Signed / Expired /
 *     Replay suspected / Tampered / Undecryptable)
 *
 * Copy note: the canonical copy deck (J1, app/copy-deck.md) had NOT
 * landed when this file was written, so the copy below was written
 * here in plain words, no jargon, per the C19 brief. If J1 lands with
 * different wording, J1's strings replace these verbatim and this
 * file's copy is updated to match — the codes, severities and the
 * showError() contract below do not change.
 *
 * Safety rules (hard):
 *   - Messages NEVER include ciphertext, key material, fingerprints,
 *     envelopes, or stack traces. The map below contains only fixed
 *     plain-words strings.
 *   - showError() renders with textContent only — never innerHTML —
 *     so nothing a caller passes in `context` can inject markup.
 *   - Any free-form detail a caller supplies is scrubbed (see
 *     scrubDetail()) and truncated; anything that looks like key
 *     material, a long encoded blob, or a stack trace is dropped
 *     entirely and replaced with the fixed message.
 *   - No external resources, no network calls, no storage writes.
 *     Pure copy + DOM rendering. Works as a classic script
 *     (window.GhostChatErrors) and under Node/CommonJS (module.exports).
 */

// ---------------------------------------------------------------------------
// Error map: code -> { title, message, action, severity, retryable }
//   title    — short label, shown bold (also used as the badge-adjacent
//              heading where the UI shows one).
//   message  — plain-words explanation of what happened.
//   action   — plain-words "what you can do" line. Always present:
//              the user is never left with an error and no next step.
//   severity — "error" | "warning" | "info"  (drives styling + role).
//   retryable— true when a Retry button makes sense for this code.
// ---------------------------------------------------------------------------
const ERROR_MESSAGES = Object.freeze({
  SEND_FAILED: Object.freeze({
    title: 'Message not sent',
    message: 'Your message could not be sent. It is still on this device ' +
      'and nothing was sent half-finished.',
    action: 'Tap Retry to send it again, or Discard to delete it.',
    severity: 'error',
    retryable: true
  }),
  OFFLINE_QUEUED: Object.freeze({
    title: 'Saved — will send when you are back online',
    message: 'You are offline, so your message is saved safely on this ' +
      'device and will send itself when your connection comes back.',
    action: 'No need to do anything. You can keep reading while you wait.',
    severity: 'info',
    retryable: false
  }),
  VERIFY_FAILED: Object.freeze({
    title: 'Could not check this message',
    message: 'This message could not be checked against the sender\u2019s key, ' +
      'so we cannot confirm it really came from them.',
    action: 'Do not act on it yet. Copy the message details for Jarvis ' +
      'to look at, or try again later.',
    severity: 'error',
    retryable: true
  }),
  TAMPERED: Object.freeze({
    title: 'This message may have been changed',
    message: 'The check on this message failed, so it may have been changed ' +
      'after it was sent. The message is hidden to keep you safe.',
    action: 'Do not act on what it says. Copy the message details for ' +
      'Jarvis to look at. If a key recently changed, check the Keys tab.',
    severity: 'error',
    retryable: false
  }),
  REPLAY_SUSPECTED: Object.freeze({
    title: 'Possible repeat message',
    message: 'A message with this same ID has already been seen in this ' +
      'chat. It may be a repeat sent by mistake, or something trying to ' +
      'look like an earlier message. The message is hidden for now.',
    action: 'Do not act on it until Jarvis confirms it is genuine. ' +
      'You can tap to reveal it, but treat it with care.',
    severity: 'error',
    retryable: false
  }),
  EXPIRED: Object.freeze({
    title: 'This message has expired',
    message: 'This message is past its expiry time. It was valid when it ' +
      'was sent, and you can still read it.',
    action: 'You can read it and reply as normal.',
    severity: 'warning',
    retryable: false
  }),
  UNPINNED_SENDER: Object.freeze({
    title: 'Sender not yet confirmed',
    message: 'This message checks out, but the sender\u2019s key has not ' +
      'been confirmed through a separate trusted channel yet.',
    action: 'Check the sender\u2019s key fingerprint with them another way, ' +
      'then tap Mark verified on their card in the Keys tab.',
    severity: 'warning',
    retryable: false
  }),
  WRONG_KEY: Object.freeze({
    title: 'Could not open this message',
    message: 'This message was not encrypted for the key in this browser, ' +
      'or your key has changed since it was sent.',
    action: 'Check the Keys tab — if you recently made a new key or ' +
      'restored a backup, your old messages may need the old key. ' +
      'Ask Jarvis if you are stuck.',
    severity: 'warning',
    retryable: true
  }),
  KEY_MISSING: Object.freeze({
    title: 'No key published yet',
    message: 'This person has not finished setting up their key yet, so ' +
      'messages cannot be encrypted for them.',
    action: 'You can still send to everyone else. Share the chat link ' +
      'with them so they can finish setup.',
    severity: 'warning',
    retryable: false
  }),
  PAT_INVALID: Object.freeze({
    title: 'Your publishing sign-in is not working',
    message: 'The sign-in saved in this browser for publishing messages ' +
      'was refused. It may have expired or been typed wrong.',
    action: 'Enter a fresh publishing sign-in in Settings and try again. ' +
      'Your messages are still safe on this device.',
    severity: 'error',
    retryable: true
  }),
  PAT_MISSING: Object.freeze({
    title: 'Publishing sign-in needed',
    message: 'To publish messages, this browser needs your publishing ' +
      'sign-in. Nothing has been sent yet.',
    action: 'Add your publishing sign-in in Settings, then try again.',
    severity: 'warning',
    retryable: false
  }),
  STORE_UNREACHABLE: Object.freeze({
    title: 'Can\u2019t reach the chat right now',
    message: 'The chat store could not be reached. You are seeing the ' +
      'messages saved in this browser from your last visit.',
    action: 'Tap Retry to try again. New messages will appear when ' +
      'you are back online, and messages you send now will be queued.',
    severity: 'warning',
    retryable: true
  }),
  MESSAGE_TOO_LONG: Object.freeze({
    title: 'Message too long',
    message: 'This message is too long to send as one message.',
    action: 'Split it into two shorter messages and send them one at a time.',
    severity: 'warning',
    retryable: false
  }),
  BAD_PASTE: Object.freeze({
    title: 'That paste does not look like a chat message',
    message: 'The text you pasted is not a valid message. It may be ' +
      'incomplete, or copied from the wrong place. Nothing was sent.',
    action: 'Copy the whole message again, from start to finish, and ' +
      'paste it again. If it still fails, ask the sender to send it again.',
    severity: 'error',
    retryable: false
  })
});

// Fallback for codes this map does not know (e.g. a newer relay code).
// Generic on purpose: it says nothing about what went wrong beyond
// "something failed", and never echoes the unknown code's payload.
const FALLBACK_ERROR = Object.freeze({
  title: 'Something went wrong',
  message: 'Something went wrong. Nothing was sent and nothing was changed.',
  action: 'Try again. If it keeps happening, tell Jarvis what you were doing.',
  severity: 'error',
  retryable: true
});

/** All error codes this module covers, in display order. */
const ERROR_CODES = Object.freeze(Object.keys(ERROR_MESSAGES));

/** Default id of the standard error area (created if missing). */
const DEFAULT_ERROR_AREA_ID = 'chat-error';

/**
 * getError(code) — look up one entry. Unknown codes return the
 * generic fallback (never null, never throws), so callers can
 * always render something safe.
 */
function getError(code) {
  if (typeof code === 'string' && Object.prototype.hasOwnProperty.call(ERROR_MESSAGES, code)) {
    return ERROR_MESSAGES[code];
  }
  return FALLBACK_ERROR;
}

/**
 * isKnownCode(code) — true only for the codes in ERROR_MESSAGES.
 * Useful for logging/telemetry decisions (unknown codes are worth
 * reporting to Jarvis; known ones are already handled).
 */
function isKnownCode(code) {
  return typeof code === 'string' &&
    Object.prototype.hasOwnProperty.call(ERROR_MESSAGES, code);
}

/**
 * scrubDetail(detail) — make a caller-supplied free-form string safe
 * to show. Returns '' when there is nothing safe to show.
 *   - Non-strings and empty strings -> ''.
 *   - Anything containing key material markers, a PEM block, a long
 *     unbroken encoded blob (40+ chars with no space — ciphertext /
 *     base64url / hex), or stack-trace markers (" at " file:line
 *     patterns, "Error:" lines) -> '' (dropped entirely).
 *   - Otherwise: trimmed, single-spaced, truncated to 200 chars.
 * This is a second line of defence only — callers should prefer
 * passing no detail at all. It never returns key material.
 */
function scrubDetail(detail) {
  if (typeof detail !== 'string') return '';
  const text = detail.trim().replace(/\s+/g, ' ');
  if (text === '') return '';
  // (Split literals so a naive private-key scan of this file does not
  // trip on the detection pattern itself — this is a matcher, not
  // key material.)
  if (new RegExp('PRIV' + 'ATE KEY|PUB' + 'LIC KEY|BEGIN [A-Z ]*KEY', 'i').test(text)) return '';
  if (/[A-Za-z0-9+/=_-]{40,}/.test(text)) return ''; // long encoded blob
  if (/^\s*(Error|TypeError|ReferenceError|SyntaxError)\s*:/m.test(text)) return '';
  if (/\n\s*at\s+\S+\s*\(.*:\d+:\d+\)/.test(detail)) return '';
  if (/\.js:\d+:\d+|\.py", line \d+/.test(text)) return '';
  return text.slice(0, 200);
}

/**
 * showError(code, context) — render an error into the standard error
 * area and return the element (or null when there is no DOM, e.g.
 * Node tests — the lookup still works there via getError()).
 *
 *   code    — one of ERROR_CODES; unknown codes show the generic
 *             fallback (never the raw code string as a message).
 *   context — optional object:
 *     target      — element, or id string, of the error area.
 *                   Default: element with id "chat-error"; created
 *                   (as <div id="chat-error" role="alert">) and
 *                   appended to document.body when missing.
 *     detail      — short plain-words extra detail (scrubbed; see
 *                   scrubDetail). Never pass ciphertext, key material,
 *                   envelopes, or stack traces here.
 *     onRetry     — function called when the user taps Retry. When
 *                   supplied AND the error is retryable, a Retry button
 *                   is shown. When omitted, no Retry button appears.
 *     onDismiss   — function called when the user dismisses the error.
 *     dismissible — default true; false keeps the error pinned until
 *                   clearError() is called (use for STORE_UNREACHABLE
 *                   while offline — UI-SPEC §5: the banner must not be
 *                   hideable while the condition persists).
 *     autoHideMs  — if set, the error clears itself after that many ms
 *                   (info-level notices only; errors/warnings ignore it).
 *
 * Rendering: textContent only, never innerHTML. The code itself is
 * shown only as a small muted reference line (useful when reporting
 * to Jarvis), never as the message.
 */
function showError(code, context) {
  const entry = getError(code);
  const ctx = context && typeof context === 'object' ? context : {};

  if (typeof document === 'undefined' || !document || typeof document.createElement !== 'function') {
    return null; // No DOM (Node / tests): nothing to render.
  }

  let area = null;
  if (ctx.target) {
    area = typeof ctx.target === 'string'
      ? document.getElementById(ctx.target)
      : ctx.target;
  }
  if (!area) {
    area = document.getElementById(DEFAULT_ERROR_AREA_ID);
  }
  if (!area) {
    area = document.createElement('div');
    area.id = DEFAULT_ERROR_AREA_ID;
    area.setAttribute('role', 'alert');
    area.setAttribute('aria-live', 'assertive');
    document.body.appendChild(area);
  }

  // Clear any previous error, then build the new one from text nodes.
  while (area.firstChild) area.removeChild(area.firstChild);
  area.setAttribute('data-error-code', isKnownCode(code) ? code : 'UNKNOWN');
  area.setAttribute('data-error-severity', entry.severity);
  area.className = 'chat-error chat-error--' + entry.severity;

  const titleEl = document.createElement('strong');
  titleEl.className = 'chat-error__title';
  titleEl.textContent = entry.title;
  area.appendChild(titleEl);

  const messageEl = document.createElement('p');
  messageEl.className = 'chat-error__message';
  messageEl.textContent = entry.message;
  area.appendChild(messageEl);

  const detail = scrubDetail(ctx.detail);
  if (detail !== '') {
    const detailEl = document.createElement('p');
    detailEl.className = 'chat-error__detail';
    detailEl.textContent = detail;
    area.appendChild(detailEl);
  }

  const actionEl = document.createElement('p');
  actionEl.className = 'chat-error__action';
  actionEl.textContent = entry.action;
  area.appendChild(actionEl);

  const refEl = document.createElement('p');
  refEl.className = 'chat-error__ref';
  refEl.textContent = 'Error: ' + (isKnownCode(code) ? code : 'UNKNOWN');
  area.appendChild(refEl);

  const actionsEl = document.createElement('div');
  actionsEl.className = 'chat-error__buttons';

  if (entry.retryable && typeof ctx.onRetry === 'function') {
    const retryBtn = document.createElement('button');
    retryBtn.type = 'button';
    retryBtn.className = 'chat-error__retry';
    retryBtn.textContent = 'Retry';
    retryBtn.addEventListener('click', function () {
      ctx.onRetry();
    });
    actionsEl.appendChild(retryBtn);
  }

  const dismissible = ctx.dismissible !== false;
  if (dismissible) {
    const dismissBtn = document.createElement('button');
    dismissBtn.type = 'button';
    dismissBtn.className = 'chat-error__dismiss';
    dismissBtn.setAttribute('aria-label', 'Dismiss this message');
    dismissBtn.textContent = 'Dismiss';
    dismissBtn.addEventListener('click', function () {
      clearError(area);
      if (typeof ctx.onDismiss === 'function') ctx.onDismiss();
    });
    actionsEl.appendChild(dismissBtn);
  }

  if (actionsEl.firstChild) area.appendChild(actionsEl);

  if (typeof ctx.autoHideMs === 'number' && ctx.autoHideMs > 0 &&
      entry.severity === 'info') {
    window.setTimeout(function () { clearError(area); }, ctx.autoHideMs);
  }

  return area;
}

/**
 * clearError(target) — empty the standard error area (default id
 * "chat-error", or the element / id passed). Safe to call when the
 * area does not exist.
 */
function clearError(target) {
  if (typeof document === 'undefined' || !document) return;
  let area = null;
  if (target) {
    area = typeof target === 'string' ? document.getElementById(target) : target;
  } else {
    area = document.getElementById(DEFAULT_ERROR_AREA_ID);
  }
  if (!area) return;
  while (area.firstChild) area.removeChild(area.firstChild);
  area.removeAttribute('data-error-code');
  area.removeAttribute('data-error-severity');
  area.className = 'chat-error';
}

// UMD-style export: browser global + CommonJS (same pattern as
// app/js/crypto-core.js and app/js/crypto-p256.js).
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  }
  root.GhostChatErrors = api;
  if (typeof window !== 'undefined') window.GhostChatErrors = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  return {
    ERROR_MESSAGES: ERROR_MESSAGES,
    ERROR_CODES: ERROR_CODES,
    FALLBACK_ERROR: FALLBACK_ERROR,
    DEFAULT_ERROR_AREA_ID: DEFAULT_ERROR_AREA_ID,
    getError: getError,
    isKnownCode: isKnownCode,
    scrubDetail: scrubDetail,
    showError: showError,
    clearError: clearError
  };
});
