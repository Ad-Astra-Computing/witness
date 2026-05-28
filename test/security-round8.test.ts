/**
 * Security regression tests — witness round 8.
 *
 * Finding:
 *  1. verifyAuditEventSignature in shared/crypto.ts lacks try/catch around
 *     base64urlDecode and ed.verifyAsync. Malformed signatures (wrong byte
 *     length, invalid base64url chars) throw instead of returning false,
 *     causing unhandled exceptions in the audit submit path.
 */
import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { verifyAuditEventSignature } from "../src/shared/crypto.js";

function base64urlEncode(bytes: Uint8Array): string {
  const binString = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  return btoa(binString).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ── Finding 1: verifyAuditEventSignature must return false instead of throwing ──

describe("verifyAuditEventSignature: malformed input returns false", () => {
  it("returns false for a non-base64url agentSignature (does not throw)", async () => {
    const { secretKey: kp, publicKey: pub } = await ed.keygenAsync();

    const event = {
      id: "e1",
      agentId: "tulpa:z123",
      agentSignature: "!!!not-base64url!!!",
      eventType: "message.sent",
    };

    const result = await verifyAuditEventSignature(event, pub);
    expect(result).toBe(false);
  });

  it("returns false for a wrong-length signature (does not throw)", async () => {
    const { secretKey: kp, publicKey: pub } = await ed.keygenAsync();

    // 10 bytes — not 64 (Ed25519 sig length), should cause noble/ed25519 to throw
    const shortSig = base64urlEncode(new Uint8Array(10));

    const event = {
      id: "e1",
      agentId: "tulpa:z123",
      agentSignature: shortSig,
      eventType: "message.sent",
    };

    const result = await verifyAuditEventSignature(event, pub);
    expect(result).toBe(false);
  });

  it("returns false for an empty signature string", async () => {
    const { secretKey: kp, publicKey: pub } = await ed.keygenAsync();

    const event = {
      id: "e1",
      agentId: "tulpa:z123",
      agentSignature: "",
      eventType: "message.sent",
    };

    const result = await verifyAuditEventSignature(event, pub);
    expect(result).toBe(false);
  });

  it("returns false for a valid-length but wrong signature", async () => {
    const { secretKey: kp, publicKey: pub } = await ed.keygenAsync();

    // 64 bytes of zeros — correct length but wrong signature
    const wrongSig = base64urlEncode(new Uint8Array(64));

    const event = {
      id: "e1",
      agentId: "tulpa:z123",
      agentSignature: wrongSig,
      eventType: "message.sent",
    };

    const result = await verifyAuditEventSignature(event, pub);
    expect(result).toBe(false);
  });

  it("returns true for a correctly signed event", async () => {
    const { secretKey: kp, publicKey: pub } = await ed.keygenAsync();

    const event: Record<string, unknown> = {
      id: "e1",
      agentId: "tulpa:z123",
      eventType: "message.sent",
    };

    // Sign manually using the same domain separation as signAuditEvent
    const { agentSignature: _omit, ...eventWithoutSig } = event;
    // JCS: sort keys for canonical representation
    const canonical = JSON.stringify(
      Object.fromEntries(Object.keys(eventWithoutSig).sort().map((k) => [k, eventWithoutSig[k]])),
    );
    const prefixed = `ink/audit-event\n${canonical}`;
    const sigBytes = await ed.signAsync(new TextEncoder().encode(prefixed), kp);
    const sig = base64urlEncode(sigBytes);

    const signedEvent = { ...event, agentSignature: sig };
    const result = await verifyAuditEventSignature(signedEvent, pub);
    expect(result).toBe(true);
  });
});
