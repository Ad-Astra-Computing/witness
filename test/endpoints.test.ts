import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { createApp } from "../src/app.js";
import type { Env } from "../src/types.js";

// ── Helpers ──

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
  // Domain separation prefix must match verifyAuditEventSignature
  const prefixed = `ink/audit-event\n${canonical}`;
  const bytes = new TextEncoder().encode(prefixed);
  const sig = await ed.signAsync(bytes, privateKey);
  return base64urlEncode(sig);
}

/** Sign an INK transport request per §3.3 */
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

async function makeAuditEvent(kp: { privateKey: Uint8Array; publicKey: Uint8Array }, overrides?: { id?: string; messageId?: string; counterpartyId?: string }) {
  const agentId = deriveAgentId(kp.publicKey);
  const event: Record<string, unknown> = {
    id: overrides?.id ?? "01JEST0001",
    version: "ink-audit/1",
    agentId,
    agentSignature: "",
    sequence: 1,
    previousEventHash: null,
    eventType: "message.sent",
    timestamp: new Date().toISOString(),
    messageId: overrides?.messageId ?? "msg-001",
    counterpartyId: overrides?.counterpartyId ?? "tulpa:zOther",
  };
  event.agentSignature = await signAuditEvent(event, kp.privateKey);
  return event;
}

async function makeSubmitBody(kp: { privateKey: Uint8Array; publicKey: Uint8Array }, overrides?: { id?: string; messageId?: string; counterpartyId?: string }) {
  const event = await makeAuditEvent(kp, overrides);
  return {
    protocol: "ink/0.1" as const,
    type: "network.tulpa.audit_submit" as const,
    from: event.agentId as string,
    to: "did:web:witness.example.com",
    event,
    nonce: crypto.randomUUID().replace(/-/g, ""),
    timestamp: new Date().toISOString(),
  };
}

/** Build a signed submit request (body + Authorization header) */
async function makeSignedSubmitRequest(kp: { privateKey: Uint8Array; publicKey: Uint8Array }, overrides?: { id?: string; messageId?: string; counterpartyId?: string }) {
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

/** Freeze the wall clock for a rate-limit test. The limiter counts requests in
 *  fixed one-minute windows keyed on Math.floor(now / 60_000). Across the tens
 *  to hundreds of sequential signed submits these tests make, the real clock can
 *  cross a window boundary, resetting the count so the request that should be
 *  the (cap + 1)th lands in a fresh window and returns 200 instead of 429. That
 *  is a pure test-timing flake, not a limiter bug. Freezing the clock puts every
 *  request in one window so the assertion is deterministic. Only Date is faked;
 *  setTimeout and friends stay real so async I/O still settles. The frozen
 *  instant is the real now, so the signed event timestamps and the witness
 *  freshness check stay mutually consistent. afterEach restores the real clock. */
function freezeRateLimitClock(): void {
  const now = Date.now();
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(now);
}

/** Build a signed query request body + Authorization header */
async function makeSignedQueryRequest(
  kp: { privateKey: Uint8Array; publicKey: Uint8Array },
  messageId: string,
) {
  const agentId = deriveAgentId(kp.publicKey);
  const body = {
    protocol: "ink/0.1" as const,
    type: "network.tulpa.audit_query" as const,
    from: agentId,
    to: "did:web:witness.example.com",
    messageId,
    nonce: crypto.randomUUID().replace(/-/g, ""),
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

// ── Mock DO ──

async function createMockDO() {
  let treeSize = 0;
  const events: Record<string, unknown>[] = [];
  const _witnessKp = await ed.keygenAsync(); const witnessPrivateKey = _witnessKp.secretKey; const witnessPublicKey = _witnessKp.publicKey;
  const seenNonces = new Set<string>();
  // In-memory fake of the DO's rate_limit_buckets table.
  const rateLimitBuckets = new Map<string, Map<number, number>>();

  return {
    witnessPrivateKey,
    seenNonces,
    rateLimitBuckets,
    async fetch(request: Request): Promise<Response> {
      const url = new URL(request.url);

      if (url.pathname === "/ratelimit-check" && request.method === "POST") {
        const body = await request.json() as { now?: number; buckets: Array<{ key: string; maxPerMinute: number }> };
        const nowMs = typeof body.now === "number" ? body.now : Date.now();
        const windowStart = Math.floor(nowMs / 60_000) * 60_000;
        for (const b of body.buckets) {
          const inner = rateLimitBuckets.get(b.key) ?? new Map();
          const count = inner.get(windowStart) ?? 0;
          if (count >= b.maxPerMinute) {
            return Response.json({ ok: false, exceeded: b.key, limit: b.maxPerMinute, count, windowStart });
          }
        }
        for (const b of body.buckets) {
          const inner = rateLimitBuckets.get(b.key) ?? new Map();
          inner.set(windowStart, (inner.get(windowStart) ?? 0) + 1);
          rateLimitBuckets.set(b.key, inner);
        }
        return Response.json({ ok: true, windowStart });
      }

      if (url.pathname === "/nonce-check" && request.method === "POST") {
        const nonce = url.searchParams.get("nonce");
        if (!nonce) return Response.json({ error: "missing_nonce" }, { status: 400 });
        const mode = url.searchParams.get("mode") ?? "commit";
        // Peek = read-only check (no commit). Commit = atomic check + store.
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
          inclusionProof: ["deadbeef".repeat(8)],
          timestamp,
          serviceSignature: base64urlEncode(sig),
        });
      }

      if (url.pathname === "/query" && request.method === "POST") {
        const body = await request.json() as { messageId: string; requester: string };
        const matched = events.filter((e) => e.messageId === body.messageId);

        // Filter to events where requester is a party
        const visible = matched.filter(
          (e) => e.agentId === body.requester || e.counterpartyId === body.requester,
        );

        // Mirror production handleQuery's alpha.3 envelope shape so worker
        // and integration tests assert against the real wire contract.
        const queryPayload = {
          protocol: "ink/0.1" as const,
          type: "network.tulpa.audit_query_response" as const,
          serviceDid: "did:web:witness.example.com",
          messageId: body.messageId,
          requester: body.requester,
          events: visible,
          proofs: visible.map((e, i) => ({ eventId: e.id, leafIndex: i, inclusionProof: [] as string[] })),
          treeSize: Math.max(visible.length, 1),
          rootHash: "a".repeat(64),
          timestamp: new Date().toISOString(),
        };
        const queryCanonical = `ink/audit-query-response/v1\n${JSON.stringify(queryPayload)}`;
        const querySig = await ed.signAsync(new TextEncoder().encode(queryCanonical), witnessPrivateKey);
        return Response.json({ ...queryPayload, serviceSignature: base64urlEncode(querySig) });
      }

      if (url.pathname === "/checkpoint") {
        const checkpointBody = `witness.example.com\n${treeSize}\n${"a".repeat(64)}`;
        const cpSig = await ed.signAsync(new TextEncoder().encode(checkpointBody), witnessPrivateKey);
        const signedCheckpoint = `${checkpointBody}\n\n\u2014 witness.example.com ${base64urlEncode(cpSig)}\n`;
        return new Response(
          signedCheckpoint,
          { headers: { "Content-Type": "text/plain" } },
        );
      }

      if (url.pathname === "/identity") {
        const pub = witnessPublicKey;
        return Response.json({
          did: "did:web:witness.example.com",
          publicKeyMultibase: encodePublicKeyMultibase(pub),
        });
      }

      if (url.pathname === "/agent-summary" && request.method === "POST") {
        const body = await request.json() as { agentId?: string };
        const agentId = body.agentId;
        if (typeof agentId !== "string" || !/^[A-Za-z0-9_:.\-]+$/.test(agentId) || agentId.length > 256) {
          return Response.json({ error: "invalid_agent_id" }, { status: 400 });
        }
        const HIGH_RISK = new Set([
          "message.rejected", "signature.failed", "signature.revoked_rejected",
          "replay.detected", "transport_scope_violation",
          "handshake_rate_limited", "handshake_budget_exhausted",
        ]);
        const ACCEPTED = new Set(["message.delivered", "message.acted", "message.received"]);
        let highRiskCount = 0;
        let acceptedCount = 0;
        let totalEvents = 0;
        let knownSince: string | null = null;
        for (const e of events) {
          if (e.agentId !== agentId && e.counterpartyId !== agentId) continue;
          totalEvents++;
          if (HIGH_RISK.has(e.eventType as string)) highRiskCount++;
          else if (ACCEPTED.has(e.eventType as string)) acceptedCount++;
          const ts = e.timestamp as string | undefined;
          if (typeof ts === "string" && (knownSince === null || ts < knownSince)) {
            knownSince = ts;
          }
        }
        return Response.json({
          schemaVersion: "ink.witness.agent-summary.v1",
          agentId,
          highRiskCount,
          acceptedCount,
          totalEvents,
          knownSince,
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
    // Mock the AGENT_DIRECTORY service binding: return 404 so the witness treats
    // every agent as "no key set published" and falls back to bootstrap
    // key verification (which the tests sign with).
    AGENT_DIRECTORY: {
      fetch: async () => new Response("", { status: 404 }),
    } as unknown as Fetcher,
  };
}

// ── Tests ──

describe("Witness Endpoints", () => {
  let app: ReturnType<typeof createApp>;
  let env: Env;

  beforeEach(async () => {
    env = await createMockEnv();
    app = createApp();
  });

  // A few tests freeze the clock (see freezeRateLimitClock); always restore the
  // real clock afterwards so the freeze cannot leak into an unrelated test.
  afterEach(() => {
    vi.useRealTimers();
  });

  describe("POST /ink/v1/audit/submit", () => {
    it("returns InkAuditInclusion with inclusionProof for valid signed request", async () => {
      const kp = await generateKeypair();
      const { body, auth } = await makeSignedSubmitRequest(kp);

      const res = await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: auth },
        body: JSON.stringify(body),
      }, env);

      expect(res.status).toBe(200);
      const json = await res.json() as Record<string, unknown>;
      expect(json.protocol).toBe("ink/0.1");
      expect(json.type).toBe("network.tulpa.audit_inclusion");
      expect(json.eventId).toBe("01JEST0001");
      expect(json.treeSize).toBeGreaterThan(0);
      expect(json.leafIndex).toBeGreaterThanOrEqual(0);
      expect(json.rootHash).toBeTruthy();
      expect(json.serviceSignature).toBeTruthy();
      // M3: inclusionProof must be present
      expect(json.inclusionProof).toBeDefined();
      expect(Array.isArray(json.inclusionProof)).toBe(true);
    });

    it("rejects request without Authorization header", async () => {
      const kp = await generateKeypair();
      const body = await makeSubmitBody(kp);

      const res = await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }, env);

      expect(res.status).toBe(401);
      const json = await res.json() as { error: string };
      expect(json.error).toContain("authorization");
    });

    it("rejects request with invalid transport signature", async () => {
      const kp = await generateKeypair();
      const body = await makeSubmitBody(kp);

      const res = await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `INK-Ed25519 ${base64urlEncode(new Uint8Array(64))}`,
        },
        body: JSON.stringify(body),
      }, env);

      expect(res.status).toBe(401);
      const json = await res.json() as { error: string };
      expect(json.error).toContain("signature");
    });

    it("rejects request with expired timestamp", async () => {
      const kp = await generateKeypair();
      const body = await makeSubmitBody(kp);
      body.timestamp = new Date(Date.now() - 10 * 60_000).toISOString();
      const auth = await signInkTransport(
        "POST", "/ink/v1/audit/submit", "did:web:witness.example.com",
        body as unknown as Record<string, unknown>, body.timestamp, kp.privateKey,
      );

      const res = await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: auth },
        body: JSON.stringify(body),
      }, env);

      expect(res.status).toBe(401);
      const json = await res.json() as { error: string };
      expect(json.error).toContain("timestamp");
    });

    it("rejects request with future timestamp", async () => {
      const kp = await generateKeypair();
      const body = await makeSubmitBody(kp);
      body.timestamp = new Date(Date.now() + 2 * 60_000).toISOString();
      const auth = await signInkTransport(
        "POST", "/ink/v1/audit/submit", "did:web:witness.example.com",
        body as unknown as Record<string, unknown>, body.timestamp, kp.privateKey,
      );

      const res = await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: auth },
        body: JSON.stringify(body),
      }, env);

      expect(res.status).toBe(401);
      const json = await res.json() as { error: string };
      expect(json.error).toContain("timestamp");
    });

    it("rejects request signed by different key than from field", async () => {
      const kpSender = await generateKeypair();
      const kpOther = await generateKeypair();
      const body = await makeSubmitBody(kpSender);
      const auth = await signInkTransport(
        "POST", "/ink/v1/audit/submit", "did:web:witness.example.com",
        body as unknown as Record<string, unknown>, body.timestamp, kpOther.privateKey,
      );

      const res = await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: auth },
        body: JSON.stringify(body),
      }, env);

      expect(res.status).toBe(401);
    });

    it("rejects invalid agent signature with 400 (even with valid transport auth)", async () => {
      const kp = await generateKeypair();
      const body = await makeSubmitBody(kp);
      (body.event as Record<string, unknown>).agentSignature = base64urlEncode(new Uint8Array(64));
      const auth = await signInkTransport(
        "POST", "/ink/v1/audit/submit", "did:web:witness.example.com",
        body as unknown as Record<string, unknown>, body.timestamp, kp.privateKey,
      );

      const res = await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: auth },
        body: JSON.stringify(body),
      }, env);

      expect(res.status).toBe(400);
    });

    it("rejects request where body.from does not match event.agentId", async () => {
      const kpSender = await generateKeypair();
      const kpOther = await generateKeypair();
      // Build event with kpOther's agentId but submit body with kpSender's from
      const event = await makeAuditEvent(kpOther);
      const body = {
        protocol: "ink/0.1" as const,
        type: "network.tulpa.audit_submit" as const,
        from: deriveAgentId(kpSender.publicKey),
        to: "did:web:witness.example.com",
        event,
        nonce: crypto.randomUUID().replace(/-/g, ""),
        timestamp: new Date().toISOString(),
      };
      // Sign transport with kpSender (matches body.from)
      const auth = await signInkTransport(
        "POST", "/ink/v1/audit/submit", "did:web:witness.example.com",
        body as unknown as Record<string, unknown>, body.timestamp, kpSender.privateKey,
      );

      const res = await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: auth },
        body: JSON.stringify(body),
      }, env);

      expect(res.status).toBe(400);
      const json = await res.json() as { error: string };
      expect(json.error).toContain("agentId");
    });

    it("rate limits after 30 events per minute from same agent", { timeout: 30_000 }, async () => {
      freezeRateLimitClock();
      const kp = await generateKeypair();

      // Send 30 events — all should succeed
      for (let i = 0; i < 30; i++) {
        const { body, auth } = await makeSignedSubmitRequest(kp, { id: `rate-${i}` });
        const res = await app.request("/ink/v1/audit/submit", {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: auth },
          body: JSON.stringify(body),
        }, env);
        expect(res.status).toBe(200);
      }

      // 31st should be rate limited
      const { body, auth } = await makeSignedSubmitRequest(kp, { id: "rate-30" });
      const res = await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: auth },
        body: JSON.stringify(body),
      }, env);

      expect(res.status).toBe(429);
      const json = await res.json() as { error: string };
      expect(json.error).toContain("rate");
    });

    it("rate limit is per-agent (different agents are independent)", { timeout: 30_000 }, async () => {
      freezeRateLimitClock();
      const kpA = await generateKeypair();
      const kpB = await generateKeypair();

      // Send 30 events from agent A
      for (let i = 0; i < 30; i++) {
        const { body, auth } = await makeSignedSubmitRequest(kpA, { id: `a-${i}` });
        const res = await app.request("/ink/v1/audit/submit", {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: auth },
          body: JSON.stringify(body),
        }, env);
        expect(res.status).toBe(200);
      }

      // Agent B should still be able to submit
      const { body, auth } = await makeSignedSubmitRequest(kpB, { id: "b-0" });
      const res = await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: auth },
        body: JSON.stringify(body),
      }, env);

      expect(res.status).toBe(200);
    });

    it("rate limits by IP across distinct fresh keypairs", { timeout: 30_000 }, async () => {
      freezeRateLimitClock();
      const sharedIp = "203.0.113.42";
      for (let i = 0; i < 60; i++) {
        const kp = await generateKeypair();
        const { body, auth } = await makeSignedSubmitRequest(kp, { id: `ip-${i}` });
        const res = await app.request("/ink/v1/audit/submit", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: auth,
            "CF-Connecting-IP": sharedIp,
          },
          body: JSON.stringify(body),
        }, env);
        expect(res.status).toBe(200);
      }
      const kp = await generateKeypair();
      const { body, auth } = await makeSignedSubmitRequest(kp, { id: "ip-overflow" });
      const res = await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: auth,
          "CF-Connecting-IP": sharedIp,
        },
        body: JSON.stringify(body),
      }, env);
      expect(res.status).toBe(429);
      const json = await res.json() as { exceeded?: string };
      expect(json.exceeded).toMatch(/^ip:/);
    });

    it("rate limits by /24 CIDR across distinct IPs in the same prefix", { timeout: 30_000 }, async () => {
      freezeRateLimitClock();
      const ips = ["203.0.113.10", "203.0.113.20", "203.0.113.30", "203.0.113.40", "203.0.113.50", "203.0.113.60"];
      for (let i = 0; i < 300; i++) {
        const kp = await generateKeypair();
        const { body, auth } = await makeSignedSubmitRequest(kp, { id: `cidr-${i}` });
        const res = await app.request("/ink/v1/audit/submit", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: auth,
            "CF-Connecting-IP": ips[i % ips.length]!,
          },
          body: JSON.stringify(body),
        }, env);
        expect(res.status).toBe(200);
      }
      const kp = await generateKeypair();
      const { body, auth } = await makeSignedSubmitRequest(kp, { id: "cidr-overflow" });
      const res = await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: auth,
          "CF-Connecting-IP": "203.0.113.99",
        },
        body: JSON.stringify(body),
      }, env);
      expect(res.status).toBe(429);
      const json = await res.json() as { exceeded?: string };
      expect(json.exceeded).toMatch(/^cidr:/);
    });

    it("IP-bucket isolation: a different /24 is not throttled by another /24's traffic", { timeout: 30_000 }, async () => {
      const cidrA = ["203.0.113.10", "203.0.113.20", "203.0.113.30"];
      for (let i = 0; i < 300; i++) {
        const kp = await generateKeypair();
        const { body, auth } = await makeSignedSubmitRequest(kp, { id: `a-${i}` });
        await app.request("/ink/v1/audit/submit", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: auth,
            "CF-Connecting-IP": cidrA[i % cidrA.length]!,
          },
          body: JSON.stringify(body),
        }, env);
      }
      const kp = await generateKeypair();
      const { body, auth } = await makeSignedSubmitRequest(kp, { id: "different-cidr" });
      const res = await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: auth,
          "CF-Connecting-IP": "198.51.100.5",
        },
        body: JSON.stringify(body),
      }, env);
      expect(res.status).toBe(200);
    });

    it("canonicalizes CF-Connecting-IP variants into the same bucket", { timeout: 30_000 }, async () => {
      const variants = [
        "203.0.113.77",
        "  203.0.113.77  ",
        "203.0.113.77, 10.0.0.1",
        "::ffff:203.0.113.77",
        "0000:0000:0000:0000:0000:ffff:cb00:714d",
      ];
      for (const v of variants) {
        for (let i = 0; i < 12; i++) {
          const kp = await generateKeypair();
          const { body, auth } = await makeSignedSubmitRequest(kp, { id: `canon-${v.replace(/\W/g, "")}-${i}` });
          const res = await app.request("/ink/v1/audit/submit", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: auth,
              "CF-Connecting-IP": v,
            },
            body: JSON.stringify(body),
          }, env);
          expect(res.status).toBe(200);
        }
      }
      const kp = await generateKeypair();
      const { body, auth } = await makeSignedSubmitRequest(kp, { id: "canon-overflow" });
      const res = await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: auth,
          "CF-Connecting-IP": "::ffff:203.0.113.77",
        },
        body: JSON.stringify(body),
      }, env);
      expect(res.status).toBe(429);
      const json = await res.json() as { exceeded?: string };
      expect(json.exceeded).toMatch(/^ip:/);
    });

    it("malformed CF-Connecting-IP falls back to skipping IP/CIDR (no header-set rate-limit)", { timeout: 30_000 }, async () => {
      const kp = await generateKeypair();
      for (let i = 0; i < 30; i++) {
        const { body, auth } = await makeSignedSubmitRequest(kp, { id: `malformed-${i}` });
        const res = await app.request("/ink/v1/audit/submit", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: auth,
            "CF-Connecting-IP": "999.999.999.999",
          },
          body: JSON.stringify(body),
        }, env);
        expect(res.status).toBe(200);
      }
      const { body, auth } = await makeSignedSubmitRequest(kp, { id: "malformed-overflow" });
      const res = await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: auth,
          "CF-Connecting-IP": "garbage-not-an-ip",
        },
        body: JSON.stringify(body),
      }, env);
      expect(res.status).toBe(429);
      const json = await res.json() as { exceeded?: string };
      expect(json.exceeded).toMatch(/^agent:/);
    });
  });

  describe("POST /ink/v1/audit/query (signed)", () => {
    it("returns events for authenticated requester", async () => {
      const kp = await generateKeypair();

      const { body: submitBody, auth: submitAuth } = await makeSignedSubmitRequest(kp);
      await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: submitAuth },
        body: JSON.stringify(submitBody),
      }, env);

      const { body: queryBody, auth: queryAuth } = await makeSignedQueryRequest(kp, "msg-001");
      const res = await app.request("/ink/v1/audit/query", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: queryAuth },
        body: JSON.stringify(queryBody),
      }, env);

      expect(res.status).toBe(200);
      const json = await res.json() as { events: unknown[] };
      expect(json.events.length).toBeGreaterThan(0);
    });

    it("rejects query without Authorization header", async () => {
      const kp = await generateKeypair();
      const agentId = deriveAgentId(kp.publicKey);
      const body = {
        protocol: "ink/0.1",
        type: "network.tulpa.audit_query",
        from: agentId,
        to: "did:web:witness.example.com",
        messageId: "msg-001",
        nonce: crypto.randomUUID().replace(/-/g, ""),
        timestamp: new Date().toISOString(),
      };

      const res = await app.request("/ink/v1/audit/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }, env);

      expect(res.status).toBe(401);
    });

    it("returns empty events for authenticated but unauthorized requester", async () => {
      const kpSender = await generateKeypair();
      const kpUnrelated = await generateKeypair();

      const { body: submitBody, auth: submitAuth } = await makeSignedSubmitRequest(kpSender);
      await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: submitAuth },
        body: JSON.stringify(submitBody),
      }, env);

      const { body: queryBody, auth: queryAuth } = await makeSignedQueryRequest(kpUnrelated, "msg-001");
      const res = await app.request("/ink/v1/audit/query", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: queryAuth },
        body: JSON.stringify(queryBody),
      }, env);

      expect(res.status).toBe(200);
      const json = await res.json() as { events: unknown[] };
      expect(json.events).toEqual([]);
    });

    it("rejects query signed by different key than from field", async () => {
      const kpClaimed = await generateKeypair();
      const kpActual = await generateKeypair();
      const agentId = deriveAgentId(kpClaimed.publicKey);
      const body = {
        protocol: "ink/0.1",
        type: "network.tulpa.audit_query",
        from: agentId,
        to: "did:web:witness.example.com",
        messageId: "msg-001",
        nonce: crypto.randomUUID().replace(/-/g, ""),
        timestamp: new Date().toISOString(),
      };
      const auth = await signInkTransport(
        "POST", "/ink/v1/audit/query", "did:web:witness.example.com",
        body as unknown as Record<string, unknown>, body.timestamp, kpActual.privateKey,
      );

      const res = await app.request("/ink/v1/audit/query", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: auth },
        body: JSON.stringify(body),
      }, env);

      expect(res.status).toBe(401);
    });

    it("old GET query endpoint returns 404", async () => {
      const res = await app.request(
        "/ink/v1/audit/query?messageId=msg-001&requester=tulpa:zFoo",
        { method: "GET" },
        env,
      );
      expect(res.status).toBe(404);
    });
  });

  describe("GET /ink/v1/checkpoint", () => {
    it("returns signed tlog-checkpoint format", async () => {
      const res = await app.request("/ink/v1/checkpoint", { method: "GET" }, env);
      expect(res.status).toBe(200);

      const text = await res.text();
      const lines = text.split("\n");
      expect(lines[0]).toBe("witness.example.com");
      expect(parseInt(lines[1]!, 10)).toBeGreaterThanOrEqual(0);
      expect(lines[2]!.length).toBe(64);
      // M2: checkpoint must be signed — blank line separating body from signature
      expect(lines[3]).toBe("");
      // Signature line with em dash
      expect(lines[4]).toMatch(/^\u2014 witness\.example\.com /);
      const sigPart = lines[4]!.replace(/^\u2014 witness\.example\.com /, "");
      expect(sigPart.length).toBeGreaterThan(0);
    });
  });

  describe("GET /.well-known/did.json", () => {
    it("returns a valid DID document", async () => {
      const res = await app.request("/.well-known/did.json", { method: "GET" }, env);
      expect(res.status).toBe(200);

      const json = await res.json() as Record<string, unknown>;
      expect(json["@context"]).toContain("https://www.w3.org/ns/did/v1");
      expect(json.id).toBe("did:web:witness.example.com");
      expect(json.verificationMethod).toBeTruthy();
    });
  });

  describe("GET /health", () => {
    it("returns 200", async () => {
      const res = await app.request("/health", { method: "GET" }, env);
      expect(res.status).toBe(200);
    });
  });

  describe("POST /ink/v1/audit/submit — security checks", () => {
    it("rejects non-object JSON body (null)", async () => {
      const kp = await generateKeypair();
      const agentId = deriveAgentId(kp.publicKey);
      const now = new Date().toISOString();
      const nullBody = "null";
      // Use a valid-looking auth header (will fail at body parse stage)
      const res = await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `INK-Ed25519 ${base64urlEncode(new Uint8Array(64))}`,
        },
        body: nullBody,
      }, env);
      expect(res.status).toBe(400);
    });

    it("rejects non-object JSON body (array)", async () => {
      const res = await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `INK-Ed25519 ${base64urlEncode(new Uint8Array(64))}`,
        },
        body: "[1, 2, 3]",
      }, env);
      expect(res.status).toBe(400);
    });

    it("rejects oversized Authorization header", async () => {
      const kp = await generateKeypair();
      const body = await makeSubmitBody(kp);
      const bigHeader = `INK-Ed25519 ${"A".repeat(2000)}`;
      const res = await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: bigHeader },
        body: JSON.stringify(body),
      }, env);
      expect(res.status).toBe(401);
    });

    it("rejects submission addressed to wrong recipient", async () => {
      const kp = await generateKeypair();
      const body = await makeSubmitBody(kp);
      // Change the 'to' field to a different DID
      (body as Record<string, unknown>).to = "did:web:other.witness.example.com";
      const auth = await signInkTransport(
        "POST", "/ink/v1/audit/submit", "did:web:witness.example.com",
        body as unknown as Record<string, unknown>, body.timestamp, kp.privateKey,
      );
      const res = await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: auth },
        body: JSON.stringify(body),
      }, env);
      // Should be rejected because to != WITNESS_DID
      expect(res.status).toBeGreaterThanOrEqual(400);
    });

    it("rejects event with extreme future timestamp", async () => {
      const kp = await generateKeypair();
      const agentId = deriveAgentId(kp.publicKey);
      const farFuture = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour future
      const event: Record<string, unknown> = {
        id: "future-event-1",
        version: "ink-audit/1",
        agentId,
        agentSignature: "",
        sequence: 1,
        previousEventHash: null,
        eventType: "message.sent",
        timestamp: farFuture,  // extreme future
        messageId: "msg-future",
      };
      event.agentSignature = await (async () => {
        const { agentSignature: _, ...rest } = event;
        const canonical = jcsCanonicalize(rest);
        const prefixed = `ink/audit-event\n${canonical}`;
        const sig = await ed.signAsync(new TextEncoder().encode(prefixed), kp.privateKey);
        return base64urlEncode(sig);
      })();
      const now = new Date().toISOString();
      const body = {
        protocol: "ink/0.1" as const,
        type: "network.tulpa.audit_submit" as const,
        from: agentId,
        to: "did:web:witness.example.com",
        event,
        nonce: crypto.randomUUID().replace(/-/g, ""),
        timestamp: now,
      };
      const auth = await signInkTransport(
        "POST", "/ink/v1/audit/submit", "did:web:witness.example.com",
        body as unknown as Record<string, unknown>, body.timestamp, kp.privateKey,
      );
      const res = await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: auth },
        body: JSON.stringify(body),
      }, env);
      expect(res.status).toBe(400);
      const json = await res.json() as { error: string };
      expect(json.error).toContain("future");
    });
  });

  describe("GET /ink/v1/agents/:agentId/audit-summary", () => {
    it("returns the schema-versioned shape with the requested agentId", async () => {
      const kp = await generateKeypair();
      const agentId = deriveAgentId(kp.publicKey);
      // Submit one event so totalEvents has a known value.
      const { body, auth } = await makeSignedSubmitRequest(kp);
      const submitRes = await app.request("/ink/v1/audit/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: auth },
        body: JSON.stringify(body),
      }, env);
      expect(submitRes.status).toBe(200);

      const res = await app.request(`/ink/v1/agents/${encodeURIComponent(agentId)}/audit-summary`, { method: "GET" }, env);
      expect(res.status).toBe(200);
      const json = await res.json() as Record<string, unknown>;
      expect(json.schemaVersion).toBe("ink.witness.agent-summary.v1");
      expect(json.agentId).toBe(agentId);
      expect(typeof json.totalEvents).toBe("number");
      expect(json.totalEvents).toBeGreaterThanOrEqual(1);
      expect(typeof json.highRiskCount).toBe("number");
      expect(typeof json.acceptedCount).toBe("number");
    });

    it("returns zero counts for an unknown agent", async () => {
      const res = await app.request("/ink/v1/agents/tulpa%3Aunknown-agent/audit-summary", { method: "GET" }, env);
      expect(res.status).toBe(200);
      const json = await res.json() as Record<string, unknown>;
      expect(json.highRiskCount).toBe(0);
      expect(json.acceptedCount).toBe(0);
      expect(json.totalEvents).toBe(0);
      expect(json.knownSince).toBeNull();
    });

    it("rejects an agent id with invalid characters", async () => {
      const res = await app.request("/ink/v1/agents/bad%20agent%20id/audit-summary", { method: "GET" }, env);
      expect(res.status).toBe(400);
    });

    it("rejects an empty agent id", async () => {
      const res = await app.request("/ink/v1/agents//audit-summary", { method: "GET" }, env);
      // Empty param falls through to 404 since the route requires a non-empty segment.
      expect([400, 404]).toContain(res.status);
    });

    it("sets a short Cache-Control on successful responses", async () => {
      const res = await app.request("/ink/v1/agents/tulpa%3Asome-agent/audit-summary", { method: "GET" }, env);
      expect(res.status).toBe(200);
      expect(res.headers.get("Cache-Control")).toContain("max-age=60");
    });
  });

  describe("CORS for public read endpoints", () => {
    it("GET /ink/v1/checkpoint includes Access-Control-Allow-Origin", async () => {
      const res = await app.request("/ink/v1/checkpoint", { method: "GET" }, env);
      expect(res.status).toBe(200);
      expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    });

    it("GET /ink/v1/checkpoint does NOT emit Vary: Origin (ACAO is static *)", async () => {
      // With a static "*" we never echo the request Origin, so Vary: Origin
      // would only fragment the CDN cache without changing the response.
      const res = await app.request("/ink/v1/checkpoint", { method: "GET" }, env);
      const vary = res.headers.get("Vary")?.toLowerCase() ?? "";
      expect(vary).not.toContain("origin");
    });

    it("OPTIONS preflight on /ink/v1/checkpoint returns 204 with CORS headers", async () => {
      const res = await app.request("/ink/v1/checkpoint", { method: "OPTIONS" }, env);
      expect(res.status).toBe(204);
      expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
      expect(res.headers.get("Access-Control-Allow-Methods")?.toUpperCase()).toContain("GET");
    });

    it("GET /ink/v1/leaves includes Access-Control-Allow-Origin", async () => {
      // The middleware tags every response on a public-read path with CORS,
      // regardless of body status — assert the header alone, not the body.
      const res = await app.request("/ink/v1/leaves?start=0&count=10", { method: "GET" }, env);
      expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    });

    it("GET /ink/v1/consistency includes Access-Control-Allow-Origin", async () => {
      // Params may be missing/invalid (400), but CORS tags the response either way.
      const res = await app.request("/ink/v1/consistency?first=1&second=2", { method: "GET" }, env);
      expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    });

    it("GET /ink/v1/agents/:id/audit-summary includes Access-Control-Allow-Origin", async () => {
      // Response may be 200 or 404 depending on whether the agent has events;
      // CORS should be present either way.
      const res = await app.request("/ink/v1/agents/tulpa%3Asomecorsprobe/audit-summary", { method: "GET" }, env);
      expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    });

    it("auth-required POST /ink/v1/audit/submit does NOT include Access-Control-Allow-Origin", async () => {
      // Sending without auth fails before any handler — the absence of the
      // CORS header confirms the middleware is scoped to public reads only.
      const res = await app.request(
        "/ink/v1/audit/submit",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({}),
        },
        env,
      );
      expect(res.headers.get("Access-Control-Allow-Origin")).toBeNull();
    });

    it("auth-required POST /ink/v1/audit/query does NOT include Access-Control-Allow-Origin", async () => {
      const res = await app.request(
        "/ink/v1/audit/query",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({}),
        },
        env,
      );
      expect(res.headers.get("Access-Control-Allow-Origin")).toBeNull();
    });

    it("OPTIONS on auth endpoints is NOT short-circuited to a CORS 204", async () => {
      // The preflight handler is scoped to the public-read paths only, so an
      // OPTIONS to an auth endpoint must not return the 204 + ACAO preflight.
      for (const path of ["/ink/v1/audit/submit", "/ink/v1/audit/query"]) {
        const res = await app.request(path, { method: "OPTIONS" }, env);
        expect(res.headers.get("Access-Control-Allow-Origin")).toBeNull();
      }
    });
  });
});
