/**
 * Witness security regression tests — round 3.
 *
 * Findings (Codex pass 2):
 *  1. resolveKeySetFromCard returned null for both "card unavailable" and
 *     "card present with empty signing keys", letting callers fall back to
 *     bootstrap key for the latter — equivalent to the INK empty-key-set
 *     issue. Fix: return [] when card has empty signing array, and update
 *     callers to treat [] as authoritative reject.
 *  2. verifyInkTransportAuth had no 256-char senderDid cap — oversized
 *     attacker-supplied DIDs could drive expensive card-fetch and base58
 *     decode work.
 */
import { describe, it, expect } from "vitest";

describe("Witness: senderDid length cap in transport auth", () => {
  it("rejects body.from longer than 256 chars before any key resolution", async () => {
    const { verifyInkTransportAuth } = await import("../src/shared/crypto.js");
    const result = await verifyInkTransportAuth({
      authHeader: "INK-Ed25519 " + "A".repeat(86),
      method: "POST",
      path: "/ink/v1/audit/submit",
      recipientDid: "did:web:witness.example.com",
      body: {
        from: "tulpa:z" + "A".repeat(300),
        timestamp: new Date().toISOString(),
      },
    });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toBe("missing_sender");
    }
  });
});

describe("Witness: empty-key-set semantics", () => {
  it("verifyInkTransportAuth rejects when callback returns empty key set (no bootstrap fallback)", async () => {
    const { verifyInkTransportAuth } = await import("../src/shared/crypto.js");

    // Empty key set means hasKeySet=true, which short-circuits the bootstrap
    // path regardless of signature validity. Use any well-formed-looking auth
    // header and from value — the test is about flow control, not signature
    // correctness.
    const result = await verifyInkTransportAuth({
      authHeader: "INK-Ed25519 " + "A".repeat(86),
      method: "POST",
      path: "/ink/v1/audit/submit",
      recipientDid: "did:web:witness.example.com",
      body: {
        from: "tulpa:zAgent",
        timestamp: new Date().toISOString(),
      },
      // empty array = key set exists but no usable keys → must reject
      resolveKeySet: () => [],
    });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      // Must NOT be unresolvable_sender_key (which would mean bootstrap was tried).
      // invalid_signature means the empty key set short-circuited to authoritative reject.
      expect(result.error).toBe("invalid_signature");
    }
  });
});

describe("Witness: malformed key entry does not collapse to bootstrap", () => {
  it("resolveKeySetFromCard returns [] (not null) when all signing entries are malformed", async () => {
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = async () => new Response(JSON.stringify({
        protocol: "ink/0.1",
        agentId: "tulpa:zVictim",
        keys: {
          signing: [
            { keyId: "k1", publicKeyMultibase: "not-valid-multibase", status: "active" },
            { keyId: "k2", publicKeyMultibase: "z!!!garbage", status: "active" },
          ],
        },
      }), { status: 200 });
      const { resolveKeySetFromCard } = await import("../src/shared/crypto.js");
      const result = await resolveKeySetFromCard("tulpa:zVictim", { fetch: globalThis.fetch });
      // Must be [] — key set was observed, all entries unparseable.
      // Returning null here would let callers bootstrap-fall-back to a key
      // the agent might have rotated away from.
      expect(result).toEqual([]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("resolveKeySetFromCard skips malformed entries but keeps valid ones", async () => {
    const originalFetch = globalThis.fetch;
    try {
      // One bad entry + one good entry (a base58btc multibase Ed25519 public key)
      // Use a real valid multibase from a freshly generated key.
      const ed = await import("@noble/ed25519");
      const pub = (await ed.keygenAsync()).publicKey;
      const { encodePublicKeyMultibase } = await import("../src/shared/crypto.js");
      const validMb = encodePublicKeyMultibase(pub);

      globalThis.fetch = async () => new Response(JSON.stringify({
        protocol: "ink/0.1",
        agentId: "tulpa:zMixed",
        keys: {
          signing: [
            { keyId: "bad", publicKeyMultibase: "not-valid", status: "active" },
            { keyId: "good", publicKeyMultibase: validMb, status: "active" },
          ],
        },
      }), { status: 200 });
      const { resolveKeySetFromCard } = await import("../src/shared/crypto.js");
      const result = await resolveKeySetFromCard("tulpa:zMixed", { fetch: globalThis.fetch });
      expect(result).not.toBeNull();
      expect(result?.length).toBe(1);
      expect(result?.[0]?.keyId).toBe("good");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
