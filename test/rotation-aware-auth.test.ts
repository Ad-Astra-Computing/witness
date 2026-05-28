import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as ed from "@noble/ed25519";
import {
  verifyInkTransportAuth,
  base64urlEncode,
  type WitnessCandidateKey,
} from "../src/shared/crypto.js";

// ── Helpers (duplicated from endpoints.test.ts) ──

async function generateKeypair() {
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

async function signInkTransport(
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
  return `INK-Ed25519 ${base64urlEncode(sig)}`;
}

function makeBody(agentId: string) {
  return {
    protocol: "ink/0.1",
    type: "network.tulpa.audit_submit",
    from: agentId,
    to: "did:web:witness.example.com",
    timestamp: new Date().toISOString(),
    nonce: "abc123",
  };
}

/** Build a mock agent card JSON response with signing keys */
function makeAgentCardJson(agentId: string, signingKeys: Array<{
  keyId: string;
  publicKey: Uint8Array;
  status: "active" | "retired" | "revoked";
}>) {
  return {
    protocol: "ink/0.1",
    agentId,
    publicKeyMultibase: encodePublicKeyMultibase(signingKeys[0]!.publicKey),
    handle: "test.example.com",
    displayName: "Test Agent",
    endpoint: "https://api.example.com",
    capabilities: { intentsAccepted: [], intentsSent: [] },
    availability: { timezone: "UTC" },
    keys: {
      signing: signingKeys.map((k) => ({
        keyId: k.keyId,
        algorithm: "Ed25519",
        publicKeyMultibase: encodePublicKeyMultibase(k.publicKey),
        status: k.status,
        validFrom: "2025-01-01T00:00:00Z",
      })),
      encryption: [],
    },
  };
}

// ── Tests ──

const WITNESS_DID = "did:web:witness.example.com";
const METHOD = "POST";
const PATH = "/ink/v1/audit/submit";

describe("Rotation-aware witness auth", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("verifies with current signing key after rotation", async () => {
    // Bootstrap key (old)
    const bootstrapKp = await generateKeypair();
    const agentId = deriveAgentId(bootstrapKp.publicKey);

    // Rotated key (current signing key)
    const rotatedKp = await generateKeypair();

    // Mock fetch to return agent card with rotated key
    const card = makeAgentCardJson(agentId, [
      { keyId: "key-2", publicKey: rotatedKp.publicKey, status: "active" },
      { keyId: "key-1", publicKey: bootstrapKp.publicKey, status: "retired" },
    ]);
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(card), { status: 200, headers: { "Content-Type": "application/json" } }),
    );

    // Sign with the rotated key
    const body = makeBody(agentId);
    const auth = await signInkTransport(METHOD, PATH, WITNESS_DID, body, body.timestamp, rotatedKp.privateKey);

    const result = await verifyInkTransportAuth({
      authHeader: auth,
      method: METHOD,
      path: PATH,
      recipientDid: WITNESS_DID,
      body,
      agentCardFetcher: { fetch: globalThis.fetch },
      agentCardBaseUrl: "https://api.example.com",
    });

    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.senderAgentId).toBe(agentId);
    }
  });

  it("rejects bootstrap key when agent has rotated keys", async () => {
    // Bootstrap key
    const bootstrapKp = await generateKeypair();
    const agentId = deriveAgentId(bootstrapKp.publicKey);

    // Rotated key (current signing key)
    const rotatedKp = await generateKeypair();

    // Mock fetch to return agent card with rotated key (bootstrap is revoked)
    const card = makeAgentCardJson(agentId, [
      { keyId: "key-2", publicKey: rotatedKp.publicKey, status: "active" },
    ]);
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(card), { status: 200, headers: { "Content-Type": "application/json" } }),
    );

    // Sign with the bootstrap key (should be rejected)
    const body = makeBody(agentId);
    const auth = await signInkTransport(METHOD, PATH, WITNESS_DID, body, body.timestamp, bootstrapKp.privateKey);

    const result = await verifyInkTransportAuth({
      authHeader: auth,
      method: METHOD,
      path: PATH,
      recipientDid: WITNESS_DID,
      body,
      agentCardFetcher: { fetch: globalThis.fetch },
      agentCardBaseUrl: "https://api.example.com",
    });

    expect(result.valid).toBe(false);
  });

  it("falls back to bootstrap key when agent has no key rotation", async () => {
    // Agent that never rotated keys — no agent card
    const bootstrapKp = await generateKeypair();
    const agentId = deriveAgentId(bootstrapKp.publicKey);

    // Mock fetch to return 404 (no agent card)
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response("Not Found", { status: 404 }),
    );

    // Sign with bootstrap key
    const body = makeBody(agentId);
    const auth = await signInkTransport(METHOD, PATH, WITNESS_DID, body, body.timestamp, bootstrapKp.privateKey);

    const result = await verifyInkTransportAuth({
      authHeader: auth,
      method: METHOD,
      path: PATH,
      recipientDid: WITNESS_DID,
      body,
      agentCardFetcher: { fetch: globalThis.fetch },
      agentCardBaseUrl: "https://api.example.com",
    });

    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.senderAgentId).toBe(agentId);
    }
  });

  it("fails closed when card fetch fails (does NOT fall through to bootstrap)", async () => {
    // Security invariant: a transient agent-card fetch failure must not
    // be silently treated as "no key set published" — that would let a
    // compromised bootstrap key authenticate any time the upstream is
    // unavailable. The verifier must reject with unresolvable_sender_key.
    const bootstrapKp = await generateKeypair();
    const agentId = deriveAgentId(bootstrapKp.publicKey);

    globalThis.fetch = vi.fn().mockRejectedValue(new Error("network error"));

    const body = makeBody(agentId);
    const auth = await signInkTransport(METHOD, PATH, WITNESS_DID, body, body.timestamp, bootstrapKp.privateKey);

    const result = await verifyInkTransportAuth({
      authHeader: auth,
      method: METHOD,
      path: PATH,
      recipientDid: WITNESS_DID,
      body,
      agentCardFetcher: { fetch: globalThis.fetch },
      agentCardBaseUrl: "https://api.example.com",
    });

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toBe("unresolvable_sender_key");
    }
  });

  it("falls back to bootstrap only when upstream returns 404 (no key set published)", async () => {
    const bootstrapKp = await generateKeypair();
    const agentId = deriveAgentId(bootstrapKp.publicKey);

    globalThis.fetch = vi.fn().mockResolvedValue(new Response("", { status: 404 }));

    const body = makeBody(agentId);
    const auth = await signInkTransport(METHOD, PATH, WITNESS_DID, body, body.timestamp, bootstrapKp.privateKey);

    const result = await verifyInkTransportAuth({
      authHeader: auth,
      method: METHOD,
      path: PATH,
      recipientDid: WITNESS_DID,
      body,
      agentCardFetcher: { fetch: globalThis.fetch },
      agentCardBaseUrl: "https://api.example.com",
    });

    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.senderAgentId).toBe(agentId);
    }
  });

  it("verifies with retired key from agent card", async () => {
    const bootstrapKp = await generateKeypair();
    const agentId = deriveAgentId(bootstrapKp.publicKey);
    const retiredKp = await generateKeypair();
    const activeKp = await generateKeypair();

    const card = makeAgentCardJson(agentId, [
      { keyId: "key-3", publicKey: activeKp.publicKey, status: "active" },
      { keyId: "key-2", publicKey: retiredKp.publicKey, status: "retired" },
    ]);
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(card), { status: 200, headers: { "Content-Type": "application/json" } }),
    );

    // Sign with retired key — should still verify
    const body = makeBody(agentId);
    const auth = await signInkTransport(METHOD, PATH, WITNESS_DID, body, body.timestamp, retiredKp.privateKey);

    const result = await verifyInkTransportAuth({
      authHeader: auth,
      method: METHOD,
      path: PATH,
      recipientDid: WITNESS_DID,
      body,
      agentCardFetcher: { fetch: globalThis.fetch },
      agentCardBaseUrl: "https://api.example.com",
    });

    expect(result.valid).toBe(true);
  });

  it("rejects revoked key from agent card", async () => {
    const bootstrapKp = await generateKeypair();
    const agentId = deriveAgentId(bootstrapKp.publicKey);
    const revokedKp = await generateKeypair();
    const activeKp = await generateKeypair();

    const card = makeAgentCardJson(agentId, [
      { keyId: "key-2", publicKey: activeKp.publicKey, status: "active" },
      { keyId: "key-1", publicKey: revokedKp.publicKey, status: "revoked" },
    ]);
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(card), { status: 200, headers: { "Content-Type": "application/json" } }),
    );

    // Sign with revoked key — should be rejected
    const body = makeBody(agentId);
    const auth = await signInkTransport(METHOD, PATH, WITNESS_DID, body, body.timestamp, revokedKp.privateKey);

    const result = await verifyInkTransportAuth({
      authHeader: auth,
      method: METHOD,
      path: PATH,
      recipientDid: WITNESS_DID,
      body,
      agentCardFetcher: { fetch: globalThis.fetch },
      agentCardBaseUrl: "https://api.example.com",
    });

    expect(result.valid).toBe(false);
  });
});
