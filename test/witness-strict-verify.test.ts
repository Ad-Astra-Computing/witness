import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import canonicalize from "canonicalize";
import { verifyAuditEventSignature, computeEventHash, base64urlEncode } from "../src/shared/crypto.js";

async function signEvent(event: Record<string, unknown>, privateKey: Uint8Array): Promise<string> {
  const { agentSignature: _drop, ...unsigned } = event;
  const bytes = new TextEncoder().encode(`ink/audit-event\n${canonicalize(unsigned)}`);
  return base64urlEncode(await ed.signAsync(bytes, privateKey));
}

describe("witness strict Ed25519 verification", () => {
  it("rejects a small-order public key that ZIP-215 would accept", async () => {
    // A = identity (small-order); signature (R = basepoint, S = 1) satisfies the
    // cofactored ZIP-215 equation for any message but is rejected by RFC 8032.
    const pub = ed.Point.ZERO.toBytes();
    const R = ed.Point.BASE.toBytes();
    const S = new Uint8Array(32);
    S[0] = 1;
    const sig = new Uint8Array(64);
    sig.set(R, 0);
    sig.set(S, 32);
    const event = { id: "e1", foo: "bar", agentSignature: base64urlEncode(sig) };

    // The vector really is accepted by noble's default ZIP-215 mode:
    const bytes = new TextEncoder().encode(`ink/audit-event\n${canonicalize({ id: "e1", foo: "bar" })}`);
    expect(await ed.verifyAsync(sig, bytes, pub, { zip215: true })).toBe(true);
    // The witness verifier (strict) rejects it:
    expect(await verifyAuditEventSignature(event, pub)).toBe(false);
  });

  it("verifies a legitimately signed event (no regression)", async () => {
    const { secretKey, publicKey } = await ed.keygenAsync();
    const event: Record<string, unknown> = { id: "e2", eventType: "message.sent", seq: 1 };
    event.agentSignature = await signEvent(event, secretKey);
    expect(await verifyAuditEventSignature(event, publicKey)).toBe(true);
  });
});

describe("witness JCS number guard", () => {
  it("rejects an event carrying a JCS-unsafe number", async () => {
    const { secretKey, publicKey } = await ed.keygenAsync();
    const event: Record<string, unknown> = { id: "e3", count: 1e21 };
    event.agentSignature = await signEvent(event, secretKey);
    // Even with a structurally valid signature attempt, the unsafe number makes
    // the canonical bytes ambiguous, so verification refuses it.
    expect(await verifyAuditEventSignature(event, publicKey)).toBe(false);
  });

  it("computeEventHash refuses a JCS-unsafe number", async () => {
    await expect(computeEventHash({ id: "e4", x: 1e21 })).rejects.toThrow();
    await expect(computeEventHash({ id: "e5", x: -0 })).rejects.toThrow();
  });

  it("computeEventHash accepts ordinary integers", async () => {
    const h = await computeEventHash({ id: "e6", seq: 42, ratio: 1.5 });
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });
});
