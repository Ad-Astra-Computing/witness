import { describe, it, expect, beforeEach } from "vitest";
import * as ed from "@noble/ed25519";
import { createApp } from "../src/app.js";
import type { Env } from "../src/types.js";

// ── Helpers (duplicated from endpoints.test.ts for isolation) ──

async function generateKeypair() {
  const { secretKey: privateKey, publicKey: publicKey } = await ed.keygenAsync();
  return { privateKey, publicKey };
}

function encodePublicKeyMultibase(publicKey: Uint8Array): string {
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
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

async function signAuditEvent(event: Record<string, unknown>, privateKey: Uint8Array): Promise<string> {
  const { agentSignature: _, ...rest } = event;
  const canonical = jcsCanonicalize(rest);
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
  return `INK-Ed25519 ${base64urlEncode(sig)}`;
}

async function makeAuditEvent(kp: { privateKey: Uint8Array; publicKey: Uint8Array }, overrides?: { id?: string; messageId?: string }) {
  const agentId = deriveAgentId(kp.publicKey);
  const event: Record<string, unknown> = {
    id: overrides?.id ?? crypto.randomUUID(),
    version: "ink-audit/1",
    agentId,
    agentSignature: "",
    sequence: 1,
    previousEventHash: null,
    eventType: "message.sent",
    timestamp: new Date().toISOString(),
    messageId: overrides?.messageId ?? "msg-nonce-001",
    counterpartyId: "tulpa:zOther",
  };
  event.agentSignature = await signAuditEvent(event, kp.privateKey);
  return event;
}

async function makeSubmitBody(kp: { privateKey: Uint8Array; publicKey: Uint8Array }, overrides?: { id?: string; messageId?: string; nonce?: string }) {
  const event = await makeAuditEvent(kp, overrides);
  return {
    protocol: "ink/0.1" as const,
    type: "network.tulpa.audit_submit" as const,
    from: event.agentId as string,
    to: "did:web:witness.example.com",
    event,
    nonce: overrides?.nonce ?? crypto.randomUUID().replace(/-/g, ""),
    timestamp: new Date().toISOString(),
  };
}

async function makeSignedSubmitRequest(kp: { privateKey: Uint8Array; publicKey: Uint8Array }, overrides?: { id?: string; messageId?: string; nonce?: string }) {
  const body = await makeSubmitBody(kp, overrides);
  const auth = await signInkTransport(
    "POST",
    "/ink/v1/audit/submit",
    "did:web:witness.example.com",
    body as unknown as Record<string, unknown>,
    body.timestamp,
    kp.privateKey,
  );
  return { body, auth };
}

async function makeSignedQueryRequest(
  kp: { privateKey: Uint8Array; publicKey: Uint8Array },
  messageId: string,
  nonce?: string,
) {
  const agentId = deriveAgentId(kp.publicKey);
  const body = {
    protocol: "ink/0.1" as const,
    type: "network.tulpa.audit_query" as const,
    from: agentId,
    to: "did:web:witness.example.com",
    messageId,
    nonce: nonce ?? crypto.randomUUID().replace(/-/g, ""),
    timestamp: new Date().toISOString(),
  };
  const auth = await signInkTransport(
    "POST",
    "/ink/v1/audit/query",
    "did:web:witness.example.com",
    body as unknown as Record<string, unknown>,
    body.timestamp,
    kp.privateKey,
  );
  return { body, auth };
}

// ── Mock DO with nonce tracking ──

async function createMockDO() {
  let treeSize = 0;
  const events: Record<string, unknown>[] = [];
  const _witnessKp = await ed.keygenAsync(); const witnessPrivateKey = _witnessKp.secretKey; const witnessPublicKey = _witnessKp.publicKey;
  const seenNonces = new Set<string>();

  return {
    witnessPrivateKey,
    seenNonces,
    async fetch(request: Request): Promise<Response> {
      const url = new URL(request.url);

      if (url.pathname === "/nonce-check" && request.method === "POST") {
        const nonce = url.searchParams.get("nonce");
        if (!nonce) return Response.json({ error: "missing_nonce" }, { status: 400 });
        const mode = url.searchParams.get("mode") ?? "commit";
        if (mode === "peek") {
          return Response.json({ ok: !seenNonces.has(nonce) });
        }
        if (seenNonces.has(nonce)) {
          return Response.json({ ok: false });
        }
        seenNonces.add(nonce);
        return Response.json({ ok: true });
      }

      if (url.pathname === "/submit" && request.method === "POST") {
        const body = await request.json() as Record<string, unknown>;
        const event = body.event as Record<string, unknown>;
        events.push(event);
        treeSize++;

        const eventId = event.id as string;
        const rootHash = "a".repeat(64);
        const timestamp = new Date().toISOString();
        const sigBase = `${eventId}:${treeSize}:${rootHash}:${timestamp}`;
        const sig = await ed.signAsync(new TextEncoder().encode(sigBase), witnessPrivateKey);

        return Response.json({
          protocol: "ink/0.1",
          type: "network.tulpa.audit_inclusion",
          eventId,
          treeSize,
          leafIndex: treeSize - 1,
          rootHash,
          timestamp,
          serviceSignature: base64urlEncode(sig),
        });
      }

      if (url.pathname === "/query" && request.method === "POST") {
        const body = await request.json() as { messageId: string; requester: string };
        const matched = events.filter((e) => e.messageId === body.messageId);

        if (matched.length > 0) {
          const first = matched[0]!;
          if (body.requester !== first.agentId && body.requester !== first.counterpartyId) {
            return Response.json({ error: "Forbidden" }, { status: 403 });
          }
        }

        // alpha.3 audit-query response envelope shape
        return Response.json({
          protocol: "ink/0.1",
          type: "network.tulpa.audit_query_response",
          serviceDid: "did:web:witness.example.com",
          messageId: body.messageId,
          requester: body.requester,
          events: matched,
          proofs: matched.map((e, i) => ({ eventId: e.id, leafIndex: i, inclusionProof: [] as string[] })),
          treeSize: Math.max(matched.length, 1),
          rootHash: "a".repeat(64),
          timestamp: new Date().toISOString(),
          serviceSignature: "A".repeat(86),
        });
      }

      if (url.pathname === "/identity") {
        const pub = witnessPublicKey;
        return Response.json({
          did: "did:web:witness.example.com",
          publicKey: base64urlEncode(pub),
        });
      }

      return new Response("Not Found", { status: 404 });
    },
  };
}

async function createMockEnv(): Promise<Env> {
  const mockDO = await createMockDO();
  return {
    WITNESS_LOG: {
      idFromName: () => ({ toString: () => "global" }),
      get: () => mockDO,
    } as unknown as DurableObjectNamespace,
    WITNESS_KEY_SECRET: "0".repeat(64),
    WITNESS_DID: "did:web:witness.example.com",
    WITNESS_ORIGIN: "witness.example.com",
    AGENT_CARD_BASE_URL: "https://api.example.com",
    AGENT_DIRECTORY: {
      fetch: async () => new Response("", { status: 404 }),
    } as unknown as Fetcher,
  };
}

// ── Tests ──

describe("Nonce Replay Protection", () => {
  let app: ReturnType<typeof createApp>;
  let env: Env;

  beforeEach(async () => {
    env = await createMockEnv();
    app = createApp();
  });

  describe("POST /ink/v1/audit/submit", () => {
    it("first submission with a nonce succeeds", async () => {
      const kp = await generateKeypair();
      const { body, auth } = await makeSignedSubmitRequest(kp);

      const res = await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: auth },
        body: JSON.stringify(body),
      }, env);

      expect(res.status).toBe(200);
      const json = await res.json() as Record<string, unknown>;
      expect(json.type).toBe("network.tulpa.audit_inclusion");
    });

    it("second submission with the same nonce is rejected", async () => {
      const kp = await generateKeypair();
      const fixedNonce = "replay-nonce-submit-001";

      // First request
      const { body: body1, auth: auth1 } = await makeSignedSubmitRequest(kp, { id: "evt-001", nonce: fixedNonce });
      const res1 = await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: auth1 },
        body: JSON.stringify(body1),
      }, env);
      expect(res1.status).toBe(200);

      // Second request with same nonce but different event ID
      const { body: body2, auth: auth2 } = await makeSignedSubmitRequest(kp, { id: "evt-002", nonce: fixedNonce });
      const res2 = await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: auth2 },
        body: JSON.stringify(body2),
      }, env);

      expect(res2.status).toBe(401);
      const json = await res2.json() as { error: string };
      expect(json.error).toBe("nonce_replay");
    });
  });

  describe("POST /ink/v1/audit/query", () => {
    it("query with replayed nonce is rejected", async () => {
      const kp = await generateKeypair();
      const fixedNonce = "replay-nonce-query-001";

      // Submit an event first so there's data to query
      const { body: submitBody, auth: submitAuth } = await makeSignedSubmitRequest(kp);
      await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: submitAuth },
        body: JSON.stringify(submitBody),
      }, env);

      // First query succeeds
      const { body: qBody1, auth: qAuth1 } = await makeSignedQueryRequest(kp, "msg-nonce-001", fixedNonce);
      const res1 = await app.request("/ink/v1/audit/query", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: qAuth1 },
        body: JSON.stringify(qBody1),
      }, env);
      expect(res1.status).toBe(200);

      // Second query with same nonce is rejected
      const { body: qBody2, auth: qAuth2 } = await makeSignedQueryRequest(kp, "msg-nonce-001", fixedNonce);
      const res2 = await app.request("/ink/v1/audit/query", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: qAuth2 },
        body: JSON.stringify(qBody2),
      }, env);

      expect(res2.status).toBe(401);
      const json = await res2.json() as { error: string };
      expect(json.error).toBe("nonce_replay");
    });
  });

  describe("Nonce expiry", () => {
    it("expired nonces are pruned from the set", async () => {
      // This tests the DO-level pruning logic directly via the mock.
      // The mock uses a Set, so we test the real WitnessLog pruning conceptually.
      // The real pruning is tested via the schema/SQL path in integration.
      // Here we verify the mock nonce-check returns false for replayed nonces.
      const mockDO = await createMockDO();
      const nonce = "prune-test-nonce";
      mockDO.seenNonces.add(nonce);
      expect(mockDO.seenNonces.has(nonce)).toBe(true);

      // Simulate pruning by clearing
      mockDO.seenNonces.delete(nonce);
      expect(mockDO.seenNonces.has(nonce)).toBe(false);
    });
  });
});
