/**
 * Pinned conformance vectors for the rules the witness shares with the INK
 * protocol.
 *
 * Every other test in this repository builds a value, runs it through the
 * witness, and checks the witness agrees with itself. That is why the number
 * profile drifted a whole protocol revision behind INK without a single test
 * failing: a self-referential round trip cannot notice that the rule itself
 * moved. The expectations below are fixed constants — accept/reject verdicts
 * and literal hash digests — so they fail when the witness changes, whether or
 * not the change is internally consistent.
 *
 * These are the rules where disagreement is not cosmetic: a body the witness
 * accepts and an INK verifier refuses to hash is an inclusion receipt nobody
 * can check.
 */

import { describe, it, expect } from "vitest";
import {
  isJcsSafeNumber,
  isWithinCanonicalizeBounds,
  computeEventHash,
  computeAgentChainHash,
} from "../src/shared/crypto.js";
import {
  decodeSignedBodyBytes,
  parseSignedBodyBytes,
  SignedBodyError,
} from "../src/shared/parse-signed-body.js";
import { containsLoneSurrogateEscape, hasUnpairedSurrogate } from "../src/shared/surrogate.js";
import { containsOutOfRangeNumberLiteral } from "../src/shared/number-literal.js";
import { containsEscapedMemberName, hasUnsafeObjectKey } from "../src/shared/member-name.js";
import { parseTimestampMs, isValidTimestamp } from "../src/shared/timestamp.js";
import { parseCheckpoint, isValidCheckpointOrigin } from "../src/shared/checkpoint.js";

/** Build a well-formed audit event around a `data` payload. */
function eventWithData(data: unknown): Record<string, unknown> {
  return {
    id: "e2",
    version: "ink-audit/1",
    agentId: "tulpa:zTestAgent",
    sequence: 1,
    previousEventHash: null,
    eventType: "message.sent",
    timestamp: "2026-01-01T00:00:00.000Z",
    data,
  };
}

describe("signed-body number profile", () => {
  // The safe-integer profile, stated as a table rather than derived from the
  // implementation. Each entry is a value and whether a signed body may carry
  // it. INK restricts numbers to safe integers because those are the only
  // values ECMAScript and Go serialize to identical bytes.
  const vectors: Array<[unknown, boolean, string]> = [
    [0, true, "zero"],
    [1, true, "one"],
    [-1, true, "negative one"],
    [9007199254740991, true, "2^53 - 1, the largest safe integer"],
    [-9007199254740991, true, "the smallest safe integer"],
    [100, true, "a value written as 1e2 decodes to a safe integer"],
    [0.95, false, "a fraction: serializers disagree on the shortest form"],
    [0.1, false, "a fraction"],
    [-0.5, false, "a negative fraction"],
    [9007199254740993, false, "2^53 + 1 does not round-trip through a double"],
    [1e20, false, "beyond the safe-integer range"],
    [1e21, false, "serializes in exponential notation"],
    [-0, false, "negative zero serializes as 0, losing the sign"],
    [Infinity, false, "not finite"],
    [-Infinity, false, "not finite"],
    [NaN, false, "not a number"],
  ];

  for (const [value, accepted, why] of vectors) {
    it(`${accepted ? "accepts" : "rejects"} ${String(value)} (${why})`, () => {
      expect(isJcsSafeNumber(value as number)).toBe(accepted);
      // The same verdict must hold through the walk that guards
      // canonicalization, and through the leaf-hash path that commits a value
      // to the Merkle tree.
      expect(isWithinCanonicalizeBounds({ n: value })).toBe(accepted);
    });
  }

  it("refuses to hash a leaf carrying a fractional value", async () => {
    // This is the shape that produced the divergence: `data` is an open record,
    // so a score reached the tree, got a signed inclusion receipt, and could not
    // be verified by anything else.
    await expect(computeEventHash(eventWithData({ score: 0.95 }))).rejects.toThrow();
    await expect(computeAgentChainHash(eventWithData({ score: 0.95 }))).rejects.toThrow();
  });

  it("refuses to hash a leaf carrying an unsafe integer", async () => {
    await expect(computeEventHash(eventWithData({ n: 9007199254740993 }))).rejects.toThrow();
    await expect(computeEventHash(eventWithData({ n: 1e20 }))).rejects.toThrow();
  });
});

describe("canonicalization bounds", () => {
  /** Build `depth` levels of nesting around a scalar. */
  function nest(depth: number): unknown {
    let v: unknown = 1;
    for (let i = 0; i < depth; i++) v = { a: v };
    return v;
  }

  it("accepts nesting at the cap", () => {
    expect(isWithinCanonicalizeBounds(nest(32))).toBe(true);
  });

  it("rejects nesting past the cap", () => {
    expect(isWithinCanonicalizeBounds(nest(33))).toBe(false);
    expect(isWithinCanonicalizeBounds(nest(40))).toBe(false);
    expect(isWithinCanonicalizeBounds(nest(64))).toBe(false);
  });

  it("rejects a value with too many nodes", () => {
    const wide: Record<string, number> = {};
    for (let i = 0; i < 6000; i++) wide[`k${i}`] = i;
    // Each key costs a node and each value costs a node, so 6000 keys is past
    // the 10,000-node cap.
    expect(isWithinCanonicalizeBounds(wide)).toBe(false);
  });

  it("rejects a single string past the aggregate character cap", () => {
    expect(isWithinCanonicalizeBounds({ s: "x".repeat(1_200_001) })).toBe(false);
  });

  it("rejects a lone surrogate in a value being canonicalized", async () => {
    expect(hasUnpairedSurrogate({ note: "\ud800" })).toBe(true);
    expect(hasUnpairedSurrogate({ note: "😀" })).toBe(false);
    await expect(computeEventHash(eventWithData({ note: "\ud800" }))).rejects.toThrow();
  });
});

describe("pinned leaf hashes", () => {
  // Literal digests for fixed events. If canonicalization, the domain prefix,
  // or the field-exclusion rule changes, these fail — including a change that
  // is perfectly self-consistent. Recomputing them to make a test pass is
  // always a protocol-breaking act and should be treated as one.
  const event: Record<string, unknown> = {
    id: "evt-pinned-1",
    version: "ink-audit/1",
    agentId: "tulpa:zPinnedAgent",
    agentSignature: "AAAA",
    sequence: 1,
    previousEventHash: null,
    eventType: "message.sent",
    timestamp: "2026-01-01T00:00:00.000Z",
    messageId: "msg-1",
    data: { disposition: "accepted", keySetVersion: 3 },
  };

  it("computes the pinned Merkle leaf hash (0x00-prefixed)", async () => {
    expect(await computeEventHash(event)).toBe(
      "6e09cb333c32f0bc31cd2c0c23c1278fa2247827c382e7aca749e53b64ea4527",
    );
  });

  it("computes the pinned chain-linkage hash (unprefixed)", async () => {
    expect(await computeAgentChainHash(event)).toBe(
      "ca20f478757bfce1b12df0a0975f75c53874098d80afaec2e61caa5df2b8c646",
    );
  });
});

describe("raw signed-body gate", () => {
  const encode = (s: string) => new TextEncoder().encode(s);

  it("rejects invalid UTF-8 rather than substituting U+FFFD", () => {
    // 0xff is not a valid UTF-8 start byte. A non-fatal decode turns it into
    // U+FFFD, so the receiver canonicalizes bytes the sender never signed.
    const bytes = new Uint8Array([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]);
    expect(() => decodeSignedBodyBytes(bytes)).toThrow(SignedBodyError);
    try {
      decodeSignedBodyBytes(bytes);
    } catch (e) {
      expect((e as SignedBodyError).reason).toBe("utf8");
    }
  });

  it("rejects a lone surrogate escape", () => {
    const raw = '{"note":"\\ud800"}';
    expect(containsLoneSurrogateEscape(raw)).toBe(true);
    try {
      parseSignedBodyBytes(encode(raw));
      throw new Error("expected a rejection");
    } catch (e) {
      expect(e).toBeInstanceOf(SignedBodyError);
      expect((e as SignedBodyError).reason).toBe("surrogate");
    }
  });

  it("accepts a well-formed surrogate pair", () => {
    const raw = '{"note":"\\ud83d\\ude00"}';
    expect(containsLoneSurrogateEscape(raw)).toBe(false);
    expect(parseSignedBodyBytes(encode(raw))).toEqual({ note: "\u{1f600}" });
  });

  it("does not read an escaped backslash as the start of a \\u escape", () => {
    expect(containsLoneSurrogateEscape('{"a":"\\\\ud800"}')).toBe(false);
  });

  it("rejects an out-of-range number literal even when a duplicate member shadows it", () => {
    // JSON member semantics are last-wins, so the parsed value never carries
    // the literal: only a raw-text scan can see it. One implementation
    // canonicalizes this cleanly, another refuses the document outright.
    const raw = '{"a":1e309,"a":1}';
    expect(containsOutOfRangeNumberLiteral(raw)).toBe(true);
    try {
      parseSignedBodyBytes(encode(raw));
      throw new Error("expected a rejection");
    } catch (e) {
      expect(e).toBeInstanceOf(SignedBodyError);
      expect((e as SignedBodyError).reason).toBe("number-range");
    }
  });

  it("leaves in-range and underflowing literals alone", () => {
    expect(containsOutOfRangeNumberLiteral('{"a":1e308}')).toBe(false);
    // Every IEEE-754 parser decodes this to 0, so implementations agree.
    expect(containsOutOfRangeNumberLiteral('{"a":1e-400}')).toBe(false);
    // Number-like text inside a string is not a token.
    expect(containsOutOfRangeNumberLiteral('{"a":"1e309"}')).toBe(false);
    // A malformed run is the parser's problem, not the scanner's: the scanner
    // must never reject something a parser would accept.
    expect(containsOutOfRangeNumberLiteral('{"a":1e}')).toBe(false);
  });

  it("preserves a leading BOM instead of stripping it", () => {
    // The signature covers the raw bytes, so the decoder must not silently
    // drop a code point.
    const bytes = new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d]);
    expect(decodeSignedBodyBytes(bytes)).toBe("﻿{}");
  });
});

describe("strict RFC 3339 timestamps", () => {
  const accepted: Array<[string, number]> = [
    ["2026-01-01T00:00:00Z", Date.UTC(2026, 0, 1, 0, 0, 0)],
    ["2026-01-01T00:00:00.000Z", Date.UTC(2026, 0, 1, 0, 0, 0)],
    ["2026-01-01T00:00:00.5Z", Date.UTC(2026, 0, 1, 0, 0, 0) + 500],
    // Sub-millisecond digits floor into the containing millisecond.
    ["2026-01-01T00:00:00.123456Z", Date.UTC(2026, 0, 1, 0, 0, 0) + 123],
    ["2026-01-01T01:00:00+01:00", Date.UTC(2026, 0, 1, 0, 0, 0)],
    ["2024-02-29T00:00:00Z", Date.UTC(2024, 1, 29, 0, 0, 0)],
  ];

  for (const [value, ms] of accepted) {
    it(`accepts ${value}`, () => {
      expect(parseTimestampMs(value)).toBe(ms);
    });
  }

  const rejected: Array<[string, string]> = [
    ["2026-01-01", "date only"],
    ["2026-01-01T00:00:00", "no zone"],
    ["2026-01-01 00:00:00Z", "space instead of T"],
    ["2026-01-01t00:00:00Z", "lowercase t"],
    ["2026-02-29T00:00:00Z", "2026 is not a leap year; Date rolls this to March 1"],
    ["2026-13-01T00:00:00Z", "month 13"],
    ["2026-01-32T00:00:00Z", "day 32"],
    ["2026-01-01T24:00:00Z", "hour 24"],
    ["2026-01-01T00:60:00Z", "minute 60"],
    ["2026-01-01T00:00:00,000Z", "comma fraction separator"],
    ["2026-01-01T00:00:00+24:00", "offset hour 24"],
    ["", "empty"],
    ["Jan 1 2026", "not RFC 3339 at all"],
  ];

  for (const [value, why] of rejected) {
    it(`rejects ${JSON.stringify(value)} (${why})`, () => {
      expect(parseTimestampMs(value)).toBeNull();
      expect(isValidTimestamp(value)).toBe(false);
    });
  }

  it("rejects a timestamp past the length cap before parsing", () => {
    expect(parseTimestampMs("2026-01-01T00:00:00.".padEnd(200, "0") + "Z")).toBeNull();
  });

  it("does not accept non-string values", () => {
    expect(parseTimestampMs(0)).toBeNull();
    expect(parseTimestampMs(null)).toBeNull();
    expect(parseTimestampMs(undefined)).toBeNull();
  });
});

describe("checkpoint parsing bounds", () => {
  const hash = "a".repeat(64);

  it("accepts a well-formed checkpoint", () => {
    expect(parseCheckpoint(`witness.example.com\n20\n${hash}\n`)).toEqual({
      origin: "witness.example.com",
      treeSize: 20,
      rootHash: hash,
    });
  });

  it("rejects a body past the 1024-character cap before splitting it", () => {
    const origin = "w".repeat(1100);
    expect(parseCheckpoint(`${origin}\n20\n${hash}\n`)).toBeNull();
  });

  it("rejects a line past the 256-character cap", () => {
    const origin = "w".repeat(300);
    expect(parseCheckpoint(`${origin}\n20\n${hash}\n`)).toBeNull();
  });

  it("rejects an origin containing a space", () => {
    // A verifier splits the `-- <origin> <signature>` line at its first space,
    // so this origin yields a checkpoint no verifier can accept.
    expect(parseCheckpoint(`witness example.com\n20\n${hash}\n`)).toBeNull();
    expect(isValidCheckpointOrigin("witness example.com")).toBe(false);
  });

  it("rejects an origin containing a control character or non-ASCII text", () => {
    expect(isValidCheckpointOrigin("witness\texample.com")).toBe(false);
    expect(isValidCheckpointOrigin("witness .com")).toBe(false);
    expect(isValidCheckpointOrigin("wítness.example.com")).toBe(false);
    expect(isValidCheckpointOrigin("")).toBe(false);
    expect(isValidCheckpointOrigin("w".repeat(257))).toBe(false);
  });

  it("accepts an ordinary origin", () => {
    expect(isValidCheckpointOrigin("witness.tulpa.network")).toBe(true);
    expect(isValidCheckpointOrigin("w".repeat(256))).toBe(true);
  });
});

describe("escaped member names", () => {
  // INK bans an escaped object member name in a signed body because V8 can
  // decode one to a different string. The witness runs on workerd, where that
  // defect reproduces unconditionally, so a leaf committed over such a body
  // would be a leaf no verifier reproduces. Stated as a table rather than
  // derived from the implementation, for the same reason as the number profile
  // above: a self-referential round trip cannot notice the rule moving.
  const raw: Array<[string, boolean, string]> = [
    [`{"note":1}`, true, "a plain member name"],
    [`{"\u00e9":1}`, true, "a raw non-ASCII member name"],
    [`{"":1}`, true, "the empty member name"],
    [`{"note":"line\\nbreak"}`, true, "an escape in a string value"],
    [`{"a":["\\n","\\\\"]}`, true, "an escape in an array element"],
    [`{"a":"b:c"}`, true, "a colon inside a string value"],
    [`{"\\n":1}`, false, "an escaped newline member name"],
    [`{"\\\\":1}`, false, "an escaped backslash member name"],
    [`{"\\u0041":1}`, false, "a \\uXXXX member name decoding to an ordinary character"],
    [`{"a\\nb":1}`, false, "an escape in the middle of a member name"],
    [`{"a":{"\\n":1}}`, false, "an escaped member name nested in an object"],
    [`{"x":{"\\\\":1},"y":{"\\n":2}}`, false, "the measured V8 corruption vector"],
  ];

  for (const [text, accepted, label] of raw) {
    it(`${accepted ? "accepts" : "rejects"} ${label}`, () => {
      expect(containsEscapedMemberName(text)).toBe(!accepted);
    });
  }

  const keys: Array<[string, boolean, string]> = [
    ["note", true, "a plain key"],
    ["\u00e9", true, "a non-ASCII key"],
    ["", true, "the empty key"],
    ["a.b-c_d/e", true, "punctuation JCS does not escape"],
    ["\u007f", true, "U+007F, which JCS does not escape"],
    ['a"b', false, "a key containing a quote"],
    ["a\\b", false, "a key containing a backslash"],
    ["a\nb", false, "a key containing a newline"],
    ["\u0000", false, "a key containing NUL"],
    ["\u001f", false, "a key containing U+001F"],
  ];

  for (const [key, accepted, label] of keys) {
    it(`${accepted ? "signs" : "refuses to sign"} ${label}`, () => {
      expect(hasUnsafeObjectKey({ [key]: 1 })).toBe(!accepted);
    });
  }

  it("keeps the two halves consistent: a signable key never needs an escape", () => {
    for (const [key, accepted] of keys) {
      if (!accepted) continue;
      expect(containsEscapedMemberName(JSON.stringify({ [key]: 1 }))).toBe(false);
    }
  });

  it("rejects an event whose data carries an unsignable key", async () => {
    await expect(computeEventHash(eventWithData({ "a\\b": 1 }))).rejects.toThrow();
  });
});
