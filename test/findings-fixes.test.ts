/**
 * Tests for INK protocol security findings (witness-side).
 *
 * Finding 1: Witness must verify audit event signatures with rotation-aware
 *   key resolution, not just bootstrap key.
 * Finding 4: Witness transport auth must accept keyId in Authorization header.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as ed from "@noble/ed25519";
import {
  verifyInkTransportAuth,
  verifyAuditEventSignature,
  resolveKeySetFromCard,
  base64urlEncode,
  type WitnessCandidateKey,
} from "../src/shared/crypto.js";

// ── Helpers ──

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

async function signAuditEvent(
  event: Record<string, unknown>,
  privateKey: Uint8Array,
): Promise<string> {
  const { agentSignature: _, ...eventWithoutSig } = event;
  const canonical = jcsCanonicalize(eventWithoutSig);
  const prefixed = `ink/audit-event\n${canonical}`;
  const bytes = new TextEncoder().encode(prefixed);
  const sig = await ed.signAsync(bytes, privateKey);
  return base64urlEncode(sig);
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
  return base64urlEncode(sig);
}

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

const WITNESS_DID = "did:web:witness.example.com";

// ── Finding 1: Audit event signature with rotated keys ──

describe("Finding 1: Witness audit event verification with rotated keys", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("verifyAuditEventSignature works with rotated (non-bootstrap) key", async () => {
    const bootstrapKp = await generateKeypair();
    const rotatedKp = await generateKeypair();

    const event: Record<string, unknown> = {
      id: "evt-001",
      version: "ink-audit/1",
      agentId: deriveAgentId(bootstrapKp.publicKey),
      sequence: 1,
      previousEventHash: null,
      eventType: "message.sent",
      timestamp: new Date().toISOString(),
      signingKeyId: "sig-v2",
    };

    const sig = await signAuditEvent(event, rotatedKp.privateKey);
    const signed = { ...event, agentSignature: sig };

    // Must verify with rotated key
    expect(await verifyAuditEventSignature(signed, rotatedKp.publicKey)).toBe(true);
    // Must NOT verify with bootstrap key
    expect(await verifyAuditEventSignature(signed, bootstrapKp.publicKey)).toBe(false);
  });

  it("resolveKeySetFromCard returns candidate keys for verification", async () => {
    const bootstrapKp = await generateKeypair();
    const rotatedKp = await generateKeypair();
    const agentId = deriveAgentId(bootstrapKp.publicKey);

    const card = makeAgentCardJson(agentId, [
      { keyId: "sig-v2", publicKey: rotatedKp.publicKey, status: "active" },
      { keyId: "sig-v1", publicKey: bootstrapKp.publicKey, status: "retired" },
    ]);

    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(card), { status: 200 }),
    );

    const keys = await resolveKeySetFromCard(agentId, { fetch: globalThis.fetch });
    expect(keys).not.toBeNull();
    expect(keys!.length).toBe(2);
    expect(keys!.some((k) => k.keyId === "sig-v2" && k.status === "active")).toBe(true);
  });
});

// ── Finding 4: Witness auth parser keyId support ──

describe("Finding 4: Witness transport auth accepts keyId", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("accepts Authorization header with keyId suffix", async () => {
    const kp = await generateKeypair();
    const agentId = deriveAgentId(kp.publicKey);

    // No agent card — will fall back to bootstrap key
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response("Not Found", { status: 404 }),
    );

    const body = {
      protocol: "ink/0.1",
      type: "network.tulpa.audit_submit",
      from: agentId,
      to: WITNESS_DID,
      timestamp: new Date().toISOString(),
      nonce: "test-nonce-123",
    };

    const sig = await signInkTransport(
      "POST", "/ink/v1/audit/submit", WITNESS_DID, body, body.timestamp, kp.privateKey,
    );

    // Add keyId to the header (this was previously rejected)
    const authHeader = `INK-Ed25519 ${sig} keyId=sig-v1`;

    const result = await verifyInkTransportAuth({
      authHeader,
      method: "POST",
      path: "/ink/v1/audit/submit",
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

  it("still works without keyId suffix", async () => {
    const kp = await generateKeypair();
    const agentId = deriveAgentId(kp.publicKey);

    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response("Not Found", { status: 404 }),
    );

    const body = {
      protocol: "ink/0.1",
      type: "network.tulpa.audit_submit",
      from: agentId,
      to: WITNESS_DID,
      timestamp: new Date().toISOString(),
      nonce: "test-nonce-456",
    };

    const sig = await signInkTransport(
      "POST", "/ink/v1/audit/submit", WITNESS_DID, body, body.timestamp, kp.privateKey,
    );

    const authHeader = `INK-Ed25519 ${sig}`;

    const result = await verifyInkTransportAuth({
      authHeader,
      method: "POST",
      path: "/ink/v1/audit/submit",
      recipientDid: WITNESS_DID,
      body,
      agentCardFetcher: { fetch: globalThis.fetch },
      agentCardBaseUrl: "https://api.example.com",
    });

    expect(result.valid).toBe(true);
  });

  it("uses hinted keyId for faster key set verification", async () => {
    const bootstrapKp = await generateKeypair();
    const rotatedKp = await generateKeypair();
    const agentId = deriveAgentId(bootstrapKp.publicKey);

    const card = makeAgentCardJson(agentId, [
      { keyId: "sig-v2", publicKey: rotatedKp.publicKey, status: "active" },
      { keyId: "sig-v1", publicKey: bootstrapKp.publicKey, status: "retired" },
    ]);
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(card), { status: 200 }),
    );

    const body = {
      protocol: "ink/0.1",
      type: "network.tulpa.audit_submit",
      from: agentId,
      to: WITNESS_DID,
      timestamp: new Date().toISOString(),
      nonce: "test-nonce-789",
    };

    const sig = await signInkTransport(
      "POST", "/ink/v1/audit/submit", WITNESS_DID, body, body.timestamp, rotatedKp.privateKey,
    );

    // keyId hint tells the verifier which key to try first
    const authHeader = `INK-Ed25519 ${sig} keyId=sig-v2`;

    const result = await verifyInkTransportAuth({
      authHeader,
      method: "POST",
      path: "/ink/v1/audit/submit",
      recipientDid: WITNESS_DID,
      body,
      agentCardFetcher: { fetch: globalThis.fetch },
      agentCardBaseUrl: "https://api.example.com",
    });

    expect(result.valid).toBe(true);
  });
});

describe("Witness per-agent audit chain continuity", () => {
  it("persists sequence and event hash for per-agent chain validation", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const schema = fs.readFileSync(
      path.join(__dirname, "..", "src", "schema.ts"),
      "utf-8",
    );
    const log = fs.readFileSync(
      path.join(__dirname, "..", "src", "witness-log.ts"),
      "utf-8",
    );

    expect(schema).toContain("sequence INTEGER");
    expect(schema).toContain("event_hash TEXT");
    expect(schema).toContain("idx_audit_events_agent_sequence");
    // Witness now derives the per-agent chain hash from the previous
    // event's canonical JSON (UNPREFIXED SHA-256) rather than comparing
    // against the Merkle leaf hash. computeAgentChainHash is the
    // matching primitive in shared/crypto.ts.
    expect(log).toContain("computeAgentChainHash(previousEvent");
    expect(log).toContain("event.previousEventHash !== expectedChainHash");
    expect(log).toContain("event.sequence !== expectedSequence");
  });
});
