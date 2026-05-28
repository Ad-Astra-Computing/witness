/**
 * Security regression tests — witness round 7.
 *
 * Findings:
 *  1. /ink/v1/audit/query: `body.nonce` type not validated — non-string truthy values
 *     (e.g. numbers) bypass the length checks, allowing numeric nonces to reach
 *     the nonce store without format validation
 *  2. /ink/v1/audit/query: `body.messageId` type not validated and has no max-length
 *     cap — allows non-strings and unbounded strings to be forwarded to the DO
 *  3. witness shared/schemas.ts: InkAuditSubmitSchema `from`/`to` fields have no
 *     .max() cap, enabling storage-DoS via oversized field values
 */
import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import * as ed from "@noble/ed25519";
import { createApp } from "../src/app.js";
import type { Env } from "../src/types.js";
import { InkAuditSubmitSchema } from "../src/shared/schemas.js";

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

function base64urlEncode(bytes: Uint8Array): string {
  const binString = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  return btoa(binString).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
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

function createMockEnv(): Env {
  return {
    WITNESS_LOG: {
      idFromName: () => ({ toString: () => "global" }),
      get: () => ({
        async fetch(request: Request): Promise<Response> {
          const url = new URL(request.url);
          if (url.pathname === "/nonce-check") {
            return Response.json({ ok: true });
          }
          if (url.pathname === "/query") {
            return Response.json({ events: [] });
          }
          return new Response("Not Found", { status: 404 });
        },
      }),
    } as unknown as DurableObjectNamespace,
    WITNESS_KEY_SECRET: "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1",
    WITNESS_DID: "did:web:witness.example.com",
    WITNESS_ORIGIN: "witness.example.com",
    AGENT_CARD_BASE_URL: "https://api.example.com",
    AGENT_DIRECTORY: {
      fetch: async () => new Response("", { status: 404 }),
    } as unknown as Fetcher,
  };
}

// ── Finding 1 & 2: query endpoint body.nonce and body.messageId type validation ──

describe("/ink/v1/audit/query: body field type validation", () => {
  let app: ReturnType<typeof createApp>;
  let env: Env;
  const WITNESS_DID = "did:web:witness.example.com";

  beforeEach(() => {
    env = createMockEnv();
    app = createApp();
  });

  it("rejects query with numeric nonce (type bypass)", async () => {
    const kp = await generateKeypair();
    const agentId = deriveAgentId(kp.publicKey);
    const now = new Date().toISOString();

    // nonce is a number, not a string — should be rejected
    const body = {
      protocol: "ink/0.1",
      from: agentId,
      to: WITNESS_DID,
      messageId: "msg-001",
      nonce: 12345 as unknown as string,  // numeric nonce (type bypass attempt)
      timestamp: now,
    };

    const auth = await signInkTransport(
      "POST", "/ink/v1/audit/query", WITNESS_DID,
      body as unknown as Record<string, unknown>, now, kp.privateKey,
    );

    const res = await app.request("/ink/v1/audit/query", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: auth },
      body: JSON.stringify(body),
    }, env);

    expect(res.status).toBe(400);
  });

  it("rejects query with oversized messageId", async () => {
    const kp = await generateKeypair();
    const agentId = deriveAgentId(kp.publicKey);
    const now = new Date().toISOString();
    const validNonce = "a".repeat(16);

    const body = {
      protocol: "ink/0.1",
      from: agentId,
      to: WITNESS_DID,
      messageId: "x".repeat(300),  // oversized messageId
      nonce: validNonce,
      timestamp: now,
    };

    const auth = await signInkTransport(
      "POST", "/ink/v1/audit/query", WITNESS_DID,
      body as unknown as Record<string, unknown>, now, kp.privateKey,
    );

    const res = await app.request("/ink/v1/audit/query", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: auth },
      body: JSON.stringify(body),
    }, env);

    expect(res.status).toBe(400);
  });

  it("rejects query with non-string messageId (numeric)", async () => {
    const kp = await generateKeypair();
    const agentId = deriveAgentId(kp.publicKey);
    const now = new Date().toISOString();
    const validNonce = "a".repeat(16);

    const body = {
      protocol: "ink/0.1",
      from: agentId,
      to: WITNESS_DID,
      messageId: 99999 as unknown as string,  // numeric messageId
      nonce: validNonce,
      timestamp: now,
    };

    const auth = await signInkTransport(
      "POST", "/ink/v1/audit/query", WITNESS_DID,
      body as unknown as Record<string, unknown>, now, kp.privateKey,
    );

    const res = await app.request("/ink/v1/audit/query", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: auth },
      body: JSON.stringify(body),
    }, env);

    expect(res.status).toBe(400);
  });

  it("accepts query with valid string nonce and messageId", async () => {
    const kp = await generateKeypair();
    const agentId = deriveAgentId(kp.publicKey);
    const now = new Date().toISOString();
    const validNonce = "a".repeat(16);

    const body = {
      protocol: "ink/0.1",
      from: agentId,
      to: WITNESS_DID,
      messageId: "msg-12345",
      nonce: validNonce,
      timestamp: now,
    };

    const auth = await signInkTransport(
      "POST", "/ink/v1/audit/query", WITNESS_DID,
      body as unknown as Record<string, unknown>, now, kp.privateKey,
    );

    const res = await app.request("/ink/v1/audit/query", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: auth },
      body: JSON.stringify(body),
    }, env);

    expect(res.status).toBe(200);
  });
});

// ── Finding 3: InkAuditSubmitSchema from/to length caps ──

describe("InkAuditSubmitSchema: from/to field length caps", () => {
  const validBase = {
    protocol: "ink/0.1" as const,
    type: "network.tulpa.audit_submit" as const,
    from: "tulpa:zABCDEF0123456",
    to: "did:web:witness.example.com",
    event: {
      id: "evt-001",
      version: "ink-audit/1" as const,
      agentId: "tulpa:zABCDEF0123456",
      agentSignature: "dGVzdA",
      sequence: 1,
      previousEventHash: null,
      eventType: "message.sent" as const,
      timestamp: new Date().toISOString(),
    },
    nonce: "testnonce1234567890",
    timestamp: new Date().toISOString(),
  };

  it("rejects submit body with oversized from field", () => {
    const oversized = { ...validBase, from: "tulpa:z" + "A".repeat(300) };
    const result = InkAuditSubmitSchema.safeParse(oversized);
    expect(result.success).toBe(false);
  });

  it("rejects submit body with oversized to field", () => {
    const oversized = { ...validBase, to: "did:web:" + "b".repeat(300) };
    const result = InkAuditSubmitSchema.safeParse(oversized);
    expect(result.success).toBe(false);
  });

  it("accepts submit body with valid from/to fields", () => {
    const result = InkAuditSubmitSchema.safeParse(validBase);
    expect(result.success).toBe(true);
  });
});
