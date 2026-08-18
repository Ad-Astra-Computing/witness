/**
 * Byte-level gate for a raw signed request body.
 *
 * An INK transport signature covers the raw bytes of the request body, so a
 * receiver that decodes those bytes leniently can canonicalize something other
 * than what the sender signed. Four hazards live below the JSON layer:
 *
 * - Invalid UTF-8. A non-fatal decoder substitutes U+FFFD, so the receiver
 *   signs over bytes the sender never sent, and different runtimes substitute
 *   at different boundaries.
 * - A lone UTF-16 surrogate escape, which survives a valid UTF-8 decode but
 *   which some parsers rewrite to U+FFFD.
 * - A number literal outside the IEEE-754 double range, which one parser
 *   decodes to `Infinity` and another refuses outright.
 * - An object member name written with an escape sequence, which V8 can decode
 *   to an entirely different string (see `member-name.ts`). This one is not a
 *   theoretical concern here: the witness runs on workerd, where the defect
 *   reproduces unconditionally and the corrupted transition persists across
 *   requests within an isolate.
 *
 * The first three are invisible once the body is a JS string, and the fourth is
 * invisible once the body is parsed, so the gate must run on the bytes. The witness runs it before parsing on every signature-bearing
 * endpoint.
 */

import { containsLoneSurrogateEscape } from "./surrogate.js";
import { containsOutOfRangeNumberLiteral } from "./number-literal.js";
import { containsEscapedMemberName } from "./member-name.js";

// ignoreBOM keeps a leading BOM as U+FEFF instead of stripping it, so the
// decoded text stays faithful to the bytes the signature covers.
const fatalUtf8Decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** Which gate rejected the body. Callers discriminate on this, not on prose. */
export type SignedBodyRejection =
  | "utf8"
  | "surrogate"
  | "number-range"
  | "member-name-escape";

/** Thrown when the byte gate rejects a raw body. */
export class SignedBodyError extends Error {
  readonly reason: SignedBodyRejection;

  constructor(reason: SignedBodyRejection, message: string) {
    super(message);
    this.name = "SignedBodyError";
    this.reason = reason;
  }
}

/**
 * Decode raw body bytes with a fatal UTF-8 decoder and run the three text-level
 * scans. Returns the decoded text; the caller parses it. Throws
 * `SignedBodyError` for the four byte-level failures.
 */
export function decodeSignedBodyBytes(bytes: Uint8Array): string {
  let text: string;
  try {
    text = fatalUtf8Decoder.decode(bytes);
  } catch {
    throw new SignedBodyError("utf8", "signed body is not valid UTF-8");
  }
  if (containsLoneSurrogateEscape(text)) {
    throw new SignedBodyError("surrogate", "signed body contains an unpaired UTF-16 surrogate");
  }
  if (containsOutOfRangeNumberLiteral(text)) {
    throw new SignedBodyError(
      "number-range",
      "signed body contains a number literal outside the IEEE-754 double range",
    );
  }
  if (containsEscapedMemberName(text)) {
    throw new SignedBodyError(
      "member-name-escape",
      "signed body contains an object member name written with an escape sequence",
    );
  }
  return text;
}

/**
 * Decode, gate, and parse raw body bytes. Throws `SignedBodyError` for the
 * four byte-level failures and the native `SyntaxError` for malformed JSON.
 */
export function parseSignedBodyBytes(bytes: Uint8Array): unknown {
  return JSON.parse(decodeSignedBodyBytes(bytes));
}
