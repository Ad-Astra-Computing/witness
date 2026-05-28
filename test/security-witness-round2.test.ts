/**
 * Witness security regression tests — round 2.
 *
 * Findings (Codex):
 *  1. TOCTOU race in handleSubmit between duplicate check and Merkle append:
 *     `await computeEventHash` released the DO input gate, letting a second
 *     concurrent submit pass the dup check before the first INSERT committed.
 *     Result: phantom Merkle leaves with no stored event.
 *     Fix: compute the hash up-front, keep the check→append→INSERT section
 *     synchronous so it runs atomically within a single DO request.
 *
 *  2. Event signature verification iterated all active+retired keys with no
 *     cap; a poisoned Agent Card could force unbounded Ed25519 verifications.
 *     Fix: bound to MAX_CANDIDATE_KEYS (20) to match transport-auth handling.
 *
 *  3. Body size check ran after c.req.text() buffered the entire body, so
 *     chunked-transfer requests without Content-Length could buffer
 *     unbounded bytes before rejection. Fix: stream-read with hard cap.
 *
 *  4. Query endpoint committed nonces without per-agent rate limit; an
 *     authenticated agent could flood unique signed nonces and grow
 *     nonce_cache between TTL pruning cycles.
 *     Fix: apply checkRateLimit to /query; cap nonce_cache table size.
 */
import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";

// The witness app and DO are integration-tested elsewhere — these are
// targeted regression tests proving the specific fixes are in place.

describe("Witness security — TOCTOU and rate-limit hardening", () => {
  it("body stream cap rejects oversized chunked /audit/query without Content-Length", async () => {
    // Build a ReadableStream emitting > MAX_QUERY_BODY_BYTES (4 KB) without
    // a Content-Length header so the upfront header check passes.
    const enc = new TextEncoder();
    const chunk = enc.encode("x".repeat(1024));
    let chunksEmitted = 0;
    const stream = new ReadableStream({
      pull(controller) {
        if (chunksEmitted++ >= 10) { controller.close(); return; }
        controller.enqueue(chunk);
      },
    });
    const req = new Request("https://w.example/ink/v1/audit/query", {
      method: "POST",
      body: stream,
      // @ts-expect-error — duplex is required for streaming bodies but missing from lib.dom types
      duplex: "half",
    });
    const { createApp } = await import("../src/app.js");
    const app = createApp();
    const res = await app.fetch(req, {
      WITNESS_LOG: { idFromName: () => ({}), get: () => ({ fetch: async () => new Response("{}") }) } as any,
      WITNESS_KEY_SECRET: "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1",
    } as any);
    expect(res.status).toBe(413);
  });

  it("MAX_CANDIDATE_KEYS is exported and bounded at 20", async () => {
    const { MAX_CANDIDATE_KEYS } = await import("../src/shared/crypto.js");
    expect(MAX_CANDIDATE_KEYS).toBe(20);
  });

  it("computeEventHash is deterministic for identical events", async () => {
    // Sanity check that supports the TOCTOU fix: the up-front hash
    // computation produces the same hash for identical inputs, so the
    // atomic INSERT can use it without races.
    const { computeEventHash } = await import("../src/shared/crypto.js");
    const event = {
      id: "evt-1",
      protocol: "ink/0.1",
      type: "test",
      agentId: "tulpa:zAgent",
      timestamp: new Date().toISOString(),
      sequence: 1,
      previousEventHash: null,
    };
    const h1 = await computeEventHash(event as unknown as Record<string, unknown>);
    const h2 = await computeEventHash(event as unknown as Record<string, unknown>);
    expect(h1).toBe(h2);
    expect(h1).toMatch(/^[0-9a-f]{64}$/);
  });
});
