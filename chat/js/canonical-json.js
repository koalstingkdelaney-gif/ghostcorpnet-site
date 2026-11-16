// canonical-json.js — canonical JSON (RFC 8785 JCS subset) for ecc-1.
//
// Normative refs:
//   - FILE-MAP.md §3 "Canonical JSON (what is signed)"
//   - design/CRYPTO-DESIGN.md §6.2 (canonical form, what is signed)
//   - design/CRYPTO-TEST-VECTORS.md §1.4 (run-2 canonical payload, 813 bytes,
//     the byte-exact reference this module is verified against)
//
// Rules implemented:
//   - Object keys sorted lexicographically by UTF-8 byte order, recursively
//     (nested objects and objects inside arrays), at every depth.
//   - Separators "," and ":" — no whitespace anywhere.
//   - Strings as raw UTF-8: no \u escaping except the JSON-mandatory escapes
//     for '"' , '\', and control characters (U+0000–U+001F). Non-ASCII
//     characters (e.g. café, ☃, 𝄞) are emitted raw and encoded as UTF-8 by
//     canonicalJSONBytes().
//   - Integers as plain decimal; `null` as `null`; booleans as `true`/`false`.
//   - Byte-identical to Python:
//       json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
//       .encode("utf-8")
//
// Implementation notes (why not "sort keys, then JSON.stringify"):
//   - Plain JSON.stringify preserves insertion order for string keys, but the
//     engine reorders integer-like keys ("2" before "10") regardless of
//     insertion order. Python sort_keys=True sorts them lexicographically
//     ("10" before "2"). This module therefore serializes by hand, writing
//     keys in the computed UTF-8-byte order, instead of building a sorted
//     object and calling JSON.stringify on it. Output is still byte-identical
//     to the Python form for every input in the supported domain.
//   - Key order is by UTF-8 bytes, not UTF-16 code units: JS's default
//     string comparison differs from UTF-8 byte order for characters outside
//     the BMP (e.g. U+FFFF vs U+10000). UTF-8 byte order equals Unicode code
//     point order, which is what Python's sort_keys produces.
//   - String escaping is delegated to JSON.stringify for a single string
//     value only. That escapes exactly '"' , '\', and control characters
//     (\b \f \n \r \t, other controls as \u00xx), leaves all other characters
//     — including non-ASCII — raw, and escapes lone surrogates as \udXXX
//     (RFC 8785 requires lone surrogates to be escaped; a lone surrogate has
//     no valid UTF-8 encoding, so Python's ensure_ascii=False form cannot
//     encode it either).
//
// Supported domain (fail-closed outside it — a silent mismatch would break a
// signature, so anything that cannot be represented exactly throws):
//   - null, booleans, strings, arrays, plain objects (prototype
//     Object.prototype or null).
//   - Integers only, within Number.MAX_SAFE_INTEGER. Non-integer numbers,
//     NaN, and +/-Infinity throw: Python renders 1.0 as "1.0" while JS renders
//     it as "1", so floats cannot be byte-identical in general.
//   - undefined, functions, symbols, bigints, Dates, Maps, Sets, class
//     instances, sparse arrays, and objects with a toJSON method throw.
//     (JSON.stringify would silently drop/convert these; here that is an
//     error, never a quiet rewrite.)
//   - Input objects are never mutated; sorting produces a new serialization.
//
// No keys, no plaintext conversation content, no secrets, no personal info
// belong in this file or in any value passed through it in tests — use the
// published test-vector envelope / throwaway fixtures only.
//
// Usage (browser, no build step — loaded via a plain <script> tag):
//   const bytes = GhostCorpCanonicalJSON.canonicalSignedBytes(envelope);
//   // `bytes` is a Uint8Array of the UTF-8 canonical JSON of the envelope
//   // WITHOUT `sig` (and WITHOUT `seq`, which the relay adds after signing
//   // and which is never part of the signed bytes — FILE-MAP.md §3).
// Also usable as a CommonJS module (Node tests) via module.exports.

(function (globalThis) {
  'use strict';

  var textEncoder = new TextEncoder();

  // Compare two strings by their UTF-8 byte sequences, lexicographically.
  // Shorter sequence sorts first when it is a prefix of the longer one.
  function compareUTF8(a, b) {
    var ab = textEncoder.encode(a);
    var bb = textEncoder.encode(b);
    var n = Math.min(ab.length, bb.length);
    for (var i = 0; i < n; i++) {
      if (ab[i] !== bb[i]) return ab[i] - bb[i];
    }
    return ab.length - bb.length;
  }

  function isPlainObject(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      return false;
    }
    var proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
  }

  // Recursive serializer. Returns the canonical JSON string for `value`.
  function serialize(value) {
    if (value === null) return 'null';

    switch (typeof value) {
      case 'boolean':
        return value ? 'true' : 'false';

      case 'number': {
        if (!Number.isFinite(value)) {
          throw new TypeError('canonicalJSON: non-finite numbers are not representable');
        }
        if (!Number.isInteger(value)) {
          throw new TypeError(
            'canonicalJSON: only integers are supported (floats are not byte-identical to Python json.dumps)'
          );
        }
        if (!Number.isSafeInteger(value)) {
          throw new RangeError('canonicalJSON: integer outside the safe-integer range');
        }
        // JSON.stringify(-0) === "0", matching Python json.dumps(-0) === "0".
        return JSON.stringify(value);
      }

      case 'string':
        // JSON.stringify escapes exactly the JSON-mandatory characters and
        // leaves every other character — including non-ASCII — raw.
        return JSON.stringify(value);

      case 'object': {
        if (Array.isArray(value)) {
          var parts = new Array(value.length);
          for (var i = 0; i < value.length; i++) {
            if (!(i in value)) {
              throw new TypeError('canonicalJSON: sparse arrays are not supported');
            }
            parts[i] = serialize(value[i]);
          }
          return '[' + parts.join(',') + ']';
        }
        if (!isPlainObject(value)) {
          throw new TypeError(
            'canonicalJSON: only plain objects are supported (got ' +
              Object.prototype.toString.call(value) + ')'
          );
        }
        if (Object.prototype.hasOwnProperty.call(value, 'toJSON')) {
          throw new TypeError('canonicalJSON: objects with a toJSON method are not supported');
        }
        var keys = Object.keys(value).sort(compareUTF8);
        var out = new Array(keys.length);
        for (var j = 0; j < keys.length; j++) {
          out[j] = JSON.stringify(keys[j]) + ':' + serialize(value[keys[j]]);
        }
        return '{' + out.join(',') + '}';
      }

      // undefined, function, symbol, bigint: JSON.stringify would silently
      // drop or convert these — here they are always an error.
      default:
        throw new TypeError('canonicalJSON: unsupported value of type ' + typeof value);
    }
  }

  // Canonical JSON string for any supported value.
  function canonicalJSON(value) {
    return serialize(value);
  }

  // Canonical JSON as UTF-8 bytes (what Ed25519 signs directly, and what
  // ES256 hashes with SHA-256 — CRYPTO-DESIGN.md §6.2).
  function canonicalJSONBytes(value) {
    return textEncoder.encode(serialize(value));
  }

  // Canonical JSON of an object with the named top-level keys omitted.
  // Does not mutate the input.
  function canonicalJSONWithoutKeys(value, keysToOmit) {
    if (!isPlainObject(value)) {
      throw new TypeError('canonicalJSONWithoutKeys: value must be a plain object');
    }
    var omit = new Set(keysToOmit);
    var copy = {};
    var keys = Object.keys(value);
    for (var i = 0; i < keys.length; i++) {
      if (!omit.has(keys[i])) copy[keys[i]] = value[keys[i]];
    }
    return serialize(copy);
  }

  // Canonical JSON of an ecc-1 envelope as signed: the envelope WITHOUT
  // `sig` (FILE-MAP.md §3, CRYPTO-DESIGN.md §6.2) and WITHOUT `seq` (the
  // relay-assigned sequence number, added after signing — FILE-MAP.md §3
  // "Store / manifest": receivers verify over the envelope minus `sig` AND
  // minus `seq`). Omitting an absent key is a no-op.
  function canonicalSignedJSON(envelope) {
    return canonicalJSONWithoutKeys(envelope, ['sig', 'seq']);
  }

  // UTF-8 bytes of the signed canonical JSON.
  function canonicalSignedBytes(envelope) {
    return textEncoder.encode(canonicalSignedJSON(envelope));
  }

  var api = {
    canonicalJSON: canonicalJSON,
    canonicalJSONBytes: canonicalJSONBytes,
    canonicalJSONWithoutKeys: canonicalJSONWithoutKeys,
    canonicalSignedJSON: canonicalSignedJSON,
    canonicalSignedBytes: canonicalSignedBytes,
    // Exported for tests: the UTF-8-byte key comparator.
    compareUTF8Keys: compareUTF8,
  };

  // Browser global (static page, no build step, no framework).
  globalThis.GhostCorpCanonicalJSON = api;
  // Node / CommonJS (unit tests, e.g. tests/test-canonical-json.py's JS side).
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
