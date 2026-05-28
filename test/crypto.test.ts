import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  encodeBase58,
  encodePublicKeyMultibase,
  resolveKeySetFromCard,
} from "../src/shared/crypto.js";

describe("encodeBase58", () => {
  it("encodes empty bytes to empty string", () => {
    expect(encodeBase58(new Uint8Array(0))).toBe("");
  });

  it("encodes leading zero bytes as '1' characters", () => {
    expect(encodeBase58(new Uint8Array([0, 0, 1]))).toBe("112");
  });

  it("roundtrips with decodeBase58", async () => {
    const { decodeBase58 } = await import("../src/shared/crypto.js");
    const original = new Uint8Array([0xed, 0x01, 0xaa, 0xbb, 0xcc]);
    const encoded = encodeBase58(original);
    const decoded = decodeBase58(encoded);
    expect(decoded).toEqual(original);
  });
});

describe("encodePublicKeyMultibase", () => {
  it("returns z-prefixed string", () => {
    const key = new Uint8Array(32).fill(0x42);
    const result = encodePublicKeyMultibase(key);
    expect(result.startsWith("z")).toBe(true);
  });

  it("roundtrips with decodePublicKeyMultibase", async () => {
    const { extractPublicKeyFromAgentId } = await import("../src/shared/crypto.js");
    // Generate a known 32-byte key
    const key = new Uint8Array(32);
    for (let i = 0; i < 32; i++) key[i] = i;

    const multibase = encodePublicKeyMultibase(key);

    // Decode manually: strip 'z', base58 decode, strip 0xed01 prefix
    const { decodeBase58 } = await import("../src/shared/crypto.js");
    const decoded = decodeBase58(multibase.slice(1));
    // Check multicodec prefix
    expect(decoded[0]).toBe(0xed);
    expect(decoded[1]).toBe(0x01);
    // Check raw key
    expect(decoded.slice(2)).toEqual(key);
  });

  it("produces output compatible with decodePublicKeyMultibase used by extractPublicKeyFromAgentId", async () => {
    const { extractPublicKeyFromAgentId } = await import("../src/shared/crypto.js");
    const key = new Uint8Array(32);
    for (let i = 0; i < 32; i++) key[i] = i + 10;

    const multibase = encodePublicKeyMultibase(key);
    const agentId = `tulpa:${multibase}`;
    const extracted = extractPublicKeyFromAgentId(agentId);
    expect(extracted).toEqual(key);
  });
});

describe("resolveKeySetFromCard caching", () => {
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    // Clear the cache between tests by resetting the module
  });

  it("caches resolved key sets and skips fetch on second call", async () => {
    const agentIdForTest = "tulpa:test-agent-1";
    const cardResponse = {
      protocol: "ink/0.1",
      agentId: agentIdForTest,  // Must match requested agentId (identity binding)
      keys: {
        signing: [
          {
            keyId: "key-1",
            publicKeyMultibase: (() => {
              // Build a valid multibase key
              const key = new Uint8Array(32).fill(0x01);
              const prefixed = new Uint8Array(34);
              prefixed[0] = 0xed;
              prefixed[1] = 0x01;
              prefixed.set(key, 2);
              return "z" + encodeBase58(prefixed);
            })(),
            status: "active" as const,
          },
        ],
      },
    };

    fetchSpy.mockImplementation(() => Promise.resolve(new Response(JSON.stringify(cardResponse), { status: 200, headers: { "Content-Type": "application/json" } })));

    const agentId = agentIdForTest;
    const result1 = await resolveKeySetFromCard(agentId, { fetch: globalThis.fetch });
    expect(result1).not.toBeNull();
    expect(result1!.length).toBe(1);
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    // Second call should use cache, no additional fetch
    const result2 = await resolveKeySetFromCard(agentId, { fetch: globalThis.fetch });
    expect(result2).not.toBeNull();
    expect(result2!.length).toBe(1);
    expect(fetchSpy).toHaveBeenCalledTimes(1); // Still 1 — cached
  });

  it("fetches again after TTL expires", async () => {
    const agentIdForTtl = "tulpa:test-agent-ttl";
    const cardResponse = {
      protocol: "ink/0.1",
      agentId: agentIdForTtl,  // Must match requested agentId (identity binding)
      keys: {
        signing: [
          {
            keyId: "key-1",
            publicKeyMultibase: (() => {
              const key = new Uint8Array(32).fill(0x02);
              const prefixed = new Uint8Array(34);
              prefixed[0] = 0xed;
              prefixed[1] = 0x01;
              prefixed.set(key, 2);
              return "z" + encodeBase58(prefixed);
            })(),
            status: "active" as const,
          },
        ],
      },
    };

    fetchSpy.mockImplementation(() => Promise.resolve(new Response(JSON.stringify(cardResponse), { status: 200, headers: { "Content-Type": "application/json" } })));

    vi.useFakeTimers();

    const agentId = agentIdForTtl;
    await resolveKeySetFromCard(agentId, { fetch: globalThis.fetch });
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    // Advance past TTL (5 minutes)
    vi.advanceTimersByTime(5 * 60 * 1000 + 1);

    await resolveKeySetFromCard(agentId, { fetch: globalThis.fetch });
    expect(fetchSpy).toHaveBeenCalledTimes(2);

    vi.useRealTimers();
  });
});
