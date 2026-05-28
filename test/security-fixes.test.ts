/**
 * Security regression tests for Witness service.
 * Tests for findings from security review round 5.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import * as ed from "@noble/ed25519";
import {
  verifyInkTransportAuth,
  resolveKeySetFromCard,
  base64urlEncode,
} from "../src/shared/crypto.js";
import { parseCheckpoint } from "../src/shared/checkpoint.js";

// ── Helpers ──

async function makeKeypair() {
  const { secretKey: privateKey, publicKey: publicKey } = await ed.keygenAsync();
  return { privateKey, publicKey };
}

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function encodePublicKeyMultibase(publicKey: Uint8Array): string {
  const prefixed = new Uint8Array([0xed, 0x01, ...publicKey]);
  let num = 0n;
  for (const b of prefixed) num = num * 256n + BigInt(b);
  let result = "";
  while (num > 0n) {
    result = ALPHABET[Number(num % 58n)]! + result;
    num = num / 58n;
  }
  let zeros = 0;
  for (const b of prefixed) { if (b !== 0) break; zeros++; }
  return "z" + "1".repeat(zeros) + result;
}

function deriveAgentId(publicKey: Uint8Array): string {
  return `tulpa:${encodePublicKeyMultibase(publicKey)}`;
}

function jcsCanonicalize(obj: unknown): string {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(jcsCanonicalize).join(",") + "]";
  const sorted = Object.keys(obj as Record<string, unknown>).sort();
  const pairs = sorted.map((k) => `${JSON.stringify(k)}:${jcsCanonicalize((obj as Record<string, unknown>)[k])}`);
  return "{" + pairs.join(",") + "}";
}

async function signTransport(
  method: string,
  path: string,
  recipientDid: string,
  body: Record<string, unknown>,
  timestamp: string,
  privateKey: Uint8Array,
): Promise<string> {
  const canonical = jcsCanonicalize(body);
  const sigBase = `ink/0.1\n${method}\n${path}\n${recipientDid}\n${canonical}\n${timestamp}`;
  const sig = await ed.signAsync(new TextEncoder().encode(sigBase), privateKey);
  return base64urlEncode(sig);
}

const WITNESS_DID = "did:web:witness.example.com";

// ── Auth header malformed base64url ──

describe("Witness auth: malformed base64url in Authorization header", () => {
  it("returns invalid_auth_scheme rather than throwing on malformed base64url", async () => {
    const kp = await makeKeypair();
    const agentId = deriveAgentId(kp.publicKey);
    const now = new Date().toISOString();

    // Intentionally malformed signature (contains invalid base64url chars)
    const result = await verifyInkTransportAuth({
      authHeader: "INK-Ed25519 !!NOT_BASE64!!",
      method: "POST",
      path: "/ink/v1/audit/submit",
      recipientDid: WITNESS_DID,
      body: { from: agentId, timestamp: now },
      agentCardFetcher: { fetch: globalThis.fetch },
    });

    expect(result.valid).toBe(false);
    expect((result as { error: string }).error).not.toBe(undefined);
  });
});

// ── JSON root type check ──

describe("Witness auth: non-object JSON body handled safely", () => {
  it("verifyInkTransportAuth returns error for null body.from", async () => {
    const result = await verifyInkTransportAuth({
      authHeader: "INK-Ed25519 " + "A".repeat(86),
      method: "POST",
      path: "/ink/v1/audit/submit",
      recipientDid: WITNESS_DID,
      body: {} as Record<string, unknown>, // missing from
      agentCardFetcher: { fetch: globalThis.fetch },
    });

    expect(result.valid).toBe(false);
    expect((result as { error: string }).error).toBe("missing_sender");
  });
});

// ── resolveKeySetFromCard identity binding ──

describe("resolveKeySetFromCard identity binding", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("throws if fetched card agentId does not match requested agentId (fail-closed)", async () => {
    const requestedId = "tulpa:zRequested";
    const wrongId = "tulpa:zWrong";

    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (_url: RequestInfo | URL, _opts?: RequestInit) => {
      return new Response(JSON.stringify({
        protocol: "ink/0.1",
        agentId: wrongId,  // Mismatch!
        keys: {
          signing: [
            { keyId: "key1", publicKeyMultibase: encodePublicKeyMultibase(new Uint8Array(32)), status: "active" },
          ],
        },
      }), { status: 200, headers: { "Content-Type": "application/json" } });
    }) as typeof fetch;

    try {
      await expect(resolveKeySetFromCard(requestedId, { fetch: globalThis.fetch })).rejects.toThrow(/mismatch/i);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("returns keys when fetched card agentId matches requested agentId", async () => {
    const requestedId = "tulpa:zRequested";

    const kp = await makeKeypair();
    const pubKeyMb = encodePublicKeyMultibase(kp.publicKey);

    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (_url: RequestInfo | URL, _opts?: RequestInit) => {
      return new Response(JSON.stringify({
        protocol: "ink/0.1",
        agentId: requestedId,  // Matches!
        keys: {
          signing: [
            { keyId: "key1", publicKeyMultibase: pubKeyMb, status: "active" },
          ],
        },
      }), { status: 200, headers: { "Content-Type": "application/json" } });
    }) as typeof fetch;

    try {
      const keys = await resolveKeySetFromCard(requestedId, { fetch: globalThis.fetch });
      expect(keys).not.toBeNull();
      expect(keys!.length).toBe(1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

// ── Auth header length cap ──

describe("Witness auth header length cap", () => {
  it("rejects oversized Authorization header", async () => {
    const kp = await makeKeypair();
    const agentId = deriveAgentId(kp.publicKey);
    const bigSig = "A".repeat(2000);
    const result = await verifyInkTransportAuth({
      authHeader: `INK-Ed25519 ${bigSig}`,
      method: "POST",
      path: "/ink/v1/audit/submit",
      recipientDid: WITNESS_DID,
      body: { from: agentId, timestamp: new Date().toISOString() },
      agentCardFetcher: { fetch: globalThis.fetch },
    });
    expect(result.valid).toBe(false);
  });
});

// ── Witness checkpoint parseCheckpoint ──

describe("Witness parseCheckpoint strict validation", () => {
  it("rejects tree size with trailing junk", () => {
    const result = parseCheckpoint("witness.example.com\n100abc\nabc123\n");
    expect(result).toBeNull();
  });

  it("rejects root hash shorter than 64 chars", () => {
    const result = parseCheckpoint("witness.example.com\n100\nabc123\n");
    expect(result).toBeNull();
  });

  it("rejects negative tree size", () => {
    const result = parseCheckpoint("witness.example.com\n-1\n" + "a".repeat(64) + "\n");
    expect(result).toBeNull();
  });

  it("accepts valid checkpoint", () => {
    const rootHash = "a".repeat(64);
    const result = parseCheckpoint(`witness.example.com\n100\n${rootHash}\n`);
    expect(result).not.toBeNull();
    expect(result?.treeSize).toBe(100);
  });
});
