/**
 * Witness security regression tests — round 11.
 *
 * Findings:
 *  1. shared/crypto.ts decodeBase58 had no input-length cap before the
 *     BigInt accumulation loop — same O(n^2) DoS as INK's keys.ts.
 *  2. shared/checkpoint.ts parseCheckpoint accepted bodies with more than
 *     4 lines, silently ignoring trailing junk (parser differential).
 *  3. shared/schemas.ts previousEventHash regex was `[0-9a-f]{0,128}` —
 *     allowed empty string as a non-null sentinel. Tighten to exactly 64
 *     hex chars (SHA-256 output) or null.
 *  4. merkle.ts sha256sync wrote only the low 32 bits of the bit-length
 *     field. Add an explicit input-size guard so the function never
 *     silently produces a wrong hash for >= 512 MB inputs.
 *  5. witness-log.ts checkpoint body was signed with raw signData (no
 *     domain-separation prefix). Add a checkpoint-specific prefix so the
 *     signature cannot be substituted for any other signed bytes from the
 *     same key.
 */
import { describe, it, expect } from "vitest";
import { decodeBase58 } from "../src/shared/crypto.js";
import { parseCheckpoint } from "../src/shared/checkpoint.js";
import { InkAuditEventSchema } from "../src/shared/schemas.js";

// ── Finding 1: decodeBase58 input cap ──

describe("witness shared decodeBase58: cap input length before BigInt loop", () => {
  it("throws on input above the cap", () => {
    expect(() => decodeBase58("1".repeat(10_000))).toThrow();
  });

  it("accepts realistic multibase-key-length input", () => {
    expect(() => decodeBase58("1".repeat(47))).not.toThrow();
  });
});

// ── Finding 2: parseCheckpoint strict line count ──

describe("witness parseCheckpoint: rejects bodies with extra trailing content", () => {
  it("accepts canonical 4-line split", () => {
    const body = "origin\n5\n" + "a".repeat(64) + "\n";
    expect(parseCheckpoint(body)).not.toBeNull();
  });

  it("rejects extra trailing content", () => {
    const body = "origin\n5\n" + "a".repeat(64) + "\nGARBAGE";
    expect(parseCheckpoint(body)).toBeNull();
  });

  it("rejects extra trailing newline", () => {
    const body = "origin\n5\n" + "a".repeat(64) + "\n\n";
    expect(parseCheckpoint(body)).toBeNull();
  });
});

// ── Finding 3: previousEventHash exact-length or null ──

describe("InkAuditEventSchema: previousEventHash must be 64 hex or null", () => {
  const baseEvent = {
    id: "evt-1",
    version: "ink-audit/1" as const,
    agentId: "tulpa:zAlice",
    agentSignature: "sig",
    sequence: 1,
    eventType: "message.sent" as const,
    timestamp: "2026-05-24T00:00:00.000Z",
  };

  it("accepts null previousEventHash (genesis event)", () => {
    const out = InkAuditEventSchema.safeParse({ ...baseEvent, previousEventHash: null });
    expect(out.success).toBe(true);
  });

  it("accepts 64-char hex previousEventHash", () => {
    const out = InkAuditEventSchema.safeParse({ ...baseEvent, previousEventHash: "a".repeat(64) });
    expect(out.success).toBe(true);
  });

  it("rejects empty string previousEventHash", () => {
    const out = InkAuditEventSchema.safeParse({ ...baseEvent, previousEventHash: "" });
    expect(out.success).toBe(false);
  });

  it("rejects short hex previousEventHash", () => {
    const out = InkAuditEventSchema.safeParse({ ...baseEvent, previousEventHash: "abc" });
    expect(out.success).toBe(false);
  });

  it("rejects 128-char previousEventHash (only 64 hex valid)", () => {
    const out = InkAuditEventSchema.safeParse({ ...baseEvent, previousEventHash: "a".repeat(128) });
    expect(out.success).toBe(false);
  });
});
