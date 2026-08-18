/**
 * Out-of-range JSON number literal detection for signed bodies.
 *
 * A literal whose magnitude exceeds the IEEE-754 double range (`1e309`) is not
 * portable: ECMAScript `JSON.parse` decodes it to `Infinity` and hands the
 * document back, while Go's `encoding/json` refuses the whole document. A
 * value-level number check cannot see the difference, because JSON member
 * semantics are last-wins and a later duplicate member can shadow the literal
 * entirely: `{"a":1e309,"a":1}` canonicalizes cleanly under one parser and is
 * refused outright by the other. The check therefore belongs on the raw text,
 * before parsing.
 *
 * A run of number characters outside any string is read as one token. A run
 * that is not a valid number at all (`1e`) is left alone: the JSON parser
 * rejects it anyway, and this scanner must never reject something a parser
 * would accept. A token that underflows to zero (`1e-400`) is in range, since
 * every IEEE-754 parser decodes it to `0`.
 *
 * The accept/reject table is pinned against the INK protocol by
 * `test/ink-parity.test.ts`.
 */

const QUOTE = 0x22;
const BACKSLASH = 0x5c;

/** A character that may appear inside a JSON number token. */
function isNumberChar(code: number): boolean {
  if (code >= 0x30 && code <= 0x39) return true; // 0-9
  return (
    code === 0x2d || // -
    code === 0x2b || // +
    code === 0x2e || // .
    code === 0x65 || // e
    code === 0x45 //    E
  );
}

/** A character that may start a JSON number token. */
function isNumberStart(code: number): boolean {
  return (code >= 0x30 && code <= 0x39) || code === 0x2d;
}

/**
 * Whether raw JSON text contains a number literal outside the IEEE-754 double
 * range.
 */
export function containsOutOfRangeNumberLiteral(raw: string): boolean {
  let inString = false;
  let i = 0;
  while (i < raw.length) {
    const code = raw.charCodeAt(i);
    if (inString) {
      // A backslash escapes the next character, so an escaped quote does not
      // close the string and digits inside one are never a token.
      if (code === BACKSLASH) {
        i += 2;
        continue;
      }
      if (code === QUOTE) inString = false;
      i++;
      continue;
    }
    if (code === QUOTE) {
      inString = true;
      i++;
      continue;
    }
    if (!isNumberStart(code)) {
      i++;
      continue;
    }
    let end = i + 1;
    while (end < raw.length && isNumberChar(raw.charCodeAt(end))) end++;
    const value = Number(raw.slice(i, end));
    // NaN means the run was not a number at all; leave it to the parser.
    if (!Number.isNaN(value) && !Number.isFinite(value)) return true;
    i = end;
  }
  return false;
}
