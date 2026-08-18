/**
 * Lone UTF-16 surrogate detection for signed bodies.
 *
 * A JSON string can only carry a surrogate code point as a `\uXXXX` escape,
 * because UTF-8 cannot encode one as raw bytes. Parsers disagree on what such
 * an escape means: Go's `encoding/json` rewrites a lone surrogate to U+FFFD at
 * parse time while ECMAScript preserves it, so the two would canonicalize the
 * same signed body to different bytes. The witness therefore refuses a lone
 * surrogate at two points: on the raw request text before parsing, and on any
 * value handed to canonicalization.
 *
 * The rules here are pinned against the INK protocol by
 * `test/ink-parity.test.ts`, which asserts a fixed accept/reject table rather
 * than trusting this comment.
 */

const QUOTE = 0x22;
const BACKSLASH = 0x5c;
const LOWER_U = 0x75;
const HIGH_MIN = 0xd800;
const HIGH_MAX = 0xdbff;
const LOW_MIN = 0xdc00;
const LOW_MAX = 0xdfff;

/** Read exactly four hex digits at `idx`, or null if they are not all hex. */
function hex4(raw: string, idx: number): number | null {
  if (idx + 4 > raw.length) return null;
  let value = 0;
  for (let k = 0; k < 4; k++) {
    const code = raw.charCodeAt(idx + k);
    let digit: number;
    if (code >= 0x30 && code <= 0x39) digit = code - 0x30;
    else if (code >= 0x61 && code <= 0x66) digit = code - 0x61 + 10;
    else if (code >= 0x41 && code <= 0x46) digit = code - 0x41 + 10;
    else return null;
    value = value * 16 + digit;
  }
  return value;
}

/**
 * Whether raw JSON text contains a `\uXXXX` escape for an unpaired surrogate
 * inside a string. Works on the raw text, before parsing, because a parsed
 * value has already lost whatever the runtime chose to do with the escape.
 * A doubled backslash escapes itself, so `\\uD800` is text, not an escape.
 */
export function containsLoneSurrogateEscape(raw: string): boolean {
  let inString = false;
  let i = 0;
  while (i < raw.length) {
    const code = raw.charCodeAt(i);
    if (!inString) {
      if (code === QUOTE) inString = true;
      i++;
      continue;
    }
    if (code === QUOTE) {
      inString = false;
      i++;
      continue;
    }
    if (code !== BACKSLASH) {
      i++;
      continue;
    }
    // Truncated trailing backslash: the JSON parser rejects it on its own.
    if (i + 1 >= raw.length) return false;
    if (raw.charCodeAt(i + 1) !== LOWER_U) {
      i += 2; // \", \\, \n, ...
      continue;
    }
    const first = hex4(raw, i + 2);
    if (first === null) {
      i += 2; // malformed \u escape; the parser rejects it
      continue;
    }
    if (first >= LOW_MIN && first <= LOW_MAX) return true; // lone low
    if (first >= HIGH_MIN && first <= HIGH_MAX) {
      const next = i + 6;
      if (
        next + 1 < raw.length &&
        raw.charCodeAt(next) === BACKSLASH &&
        raw.charCodeAt(next + 1) === LOWER_U
      ) {
        const second = hex4(raw, next + 2);
        if (second !== null && second >= LOW_MIN && second <= LOW_MAX) {
          i = next + 6; // a well-formed pair
          continue;
        }
      }
      return true; // a high with no low behind it
    }
    i += 6;
  }
  return false;
}

/** Whether a JS string carries an unpaired surrogate code unit. */
function stringHasUnpairedSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code >= HIGH_MIN && code <= HIGH_MAX) {
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (next >= LOW_MIN && next <= LOW_MAX) {
        i++;
        continue;
      }
      return true;
    }
    if (code >= LOW_MIN && code <= LOW_MAX) return true;
  }
  return false;
}

/**
 * Whether a parsed value carries an unpaired surrogate in any string value or
 * object key. Used on values the witness is about to canonicalize, where the
 * raw text is no longer available.
 */
export function hasUnpairedSurrogate(value: unknown): boolean {
  if (typeof value === "string") return stringHasUnpairedSurrogate(value);
  if (Array.isArray(value)) return value.some(hasUnpairedSurrogate);
  if (value !== null && typeof value === "object") {
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      if (stringHasUnpairedSurrogate(key)) return true;
      if (hasUnpairedSurrogate(val)) return true;
    }
  }
  return false;
}
