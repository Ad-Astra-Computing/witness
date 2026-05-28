/**
 * Regression tests for round-13 agent-card hardening:
 *   - resolveKeySetFromCard now stream-reads with a hard byte cap
 *   - card body parsed with runtime type guards on keys / signing /
 *     each entry, so malformed JSON cannot throw out of the function
 *     (which would surface as 500 / collapse to bootstrap fallback).
 */
import { describe, it, expect, vi } from "vitest";

// Each test uses a unique agentId so the LRU card cache from one test
// can't pollute another.
let testCounter = 0;
const nextVictim = () => `tulpa:zVictimAgent${++testCounter}`;

describe("resolveKeySetFromCard hardening", () => {
  it("rejects an oversized chunked card body without buffering it all", async () => {
    const victim = nextVictim();
    const origFetch = globalThis.fetch;
    try {
      // Stream emits ~256KB without Content-Length — cap is 64KB
      let emitted = 0;
      const stream = new ReadableStream({
        pull(controller) {
          if (emitted >= 256) { controller.close(); return; }
          controller.enqueue(new TextEncoder().encode("x".repeat(1024)));
          emitted++;
        },
      });
      globalThis.fetch = (async () => new Response(stream, { status: 200 })) as typeof fetch;
      const { resolveKeySetFromCard } = await import("../src/shared/crypto.js");
      await expect(resolveKeySetFromCard(victim, { fetch: globalThis.fetch })).rejects.toThrow(/oversized/i);
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  it("throws on a card where keys is not an object (fail-closed, no bootstrap fallback)", async () => {
    const victim = nextVictim();
    const orig = globalThis.fetch;
    try {
      globalThis.fetch = (async () => new Response(JSON.stringify({
        protocol: "ink/0.1",
        agentId: victim,
        keys: "not an object",
      }), { status: 200 })) as typeof fetch;
      const { resolveKeySetFromCard } = await import("../src/shared/crypto.js");
      await expect(resolveKeySetFromCard(victim, { fetch: globalThis.fetch })).rejects.toThrow();
    } finally {
      globalThis.fetch = orig;
    }
  });

  it("throws on a card where signing is not an array (fail-closed)", async () => {
    const victim = nextVictim();
    const orig = globalThis.fetch;
    try {
      globalThis.fetch = (async () => new Response(JSON.stringify({
        protocol: "ink/0.1",
        agentId: victim,
        keys: { signing: { keyId: "k1" } },
      }), { status: 200 })) as typeof fetch;
      const { resolveKeySetFromCard } = await import("../src/shared/crypto.js");
      await expect(resolveKeySetFromCard(victim, { fetch: globalThis.fetch })).rejects.toThrow();
    } finally {
      globalThis.fetch = orig;
    }
  });

  it("skips entries that are not plain objects without throwing", async () => {
    const victim = nextVictim();
    const orig = globalThis.fetch;
    try {
      globalThis.fetch = (async () => new Response(JSON.stringify({
        protocol: "ink/0.1",
        agentId: victim,
        keys: { signing: [null, 42, "string", [], { keyId: "ok", publicKeyMultibase: "bad", status: "active" }] },
      }), { status: 200 })) as typeof fetch;
      const { resolveKeySetFromCard } = await import("../src/shared/crypto.js");
      // Last entry has the right shape but bad multibase; decode throws and
      // is caught per-entry. Result is [] (key set observed, no usable keys)
      // not null (card unavailable) — bootstrap fallback must NOT fire.
      const result = await resolveKeySetFromCard(victim, { fetch: globalThis.fetch });
      expect(result).toEqual([]);
    } finally {
      globalThis.fetch = orig;
    }
  });

  it("skips entries with non-string keyId / publicKeyMultibase without throwing", async () => {
    const victim = nextVictim();
    const orig = globalThis.fetch;
    try {
      globalThis.fetch = (async () => new Response(JSON.stringify({
        protocol: "ink/0.1",
        agentId: victim,
        keys: { signing: [
          { keyId: 42, publicKeyMultibase: "z123", status: "active" },
          { keyId: "k1", publicKeyMultibase: 0, status: "active" },
          { keyId: "k2", publicKeyMultibase: "z123", status: "unknown-status" },
        ] },
      }), { status: 200 })) as typeof fetch;
      const { resolveKeySetFromCard } = await import("../src/shared/crypto.js");
      const result = await resolveKeySetFromCard(victim, { fetch: globalThis.fetch });
      expect(result).toEqual([]);
    } finally {
      globalThis.fetch = orig;
    }
  });

  it("top-level non-object card throws (fail-closed)", async () => {
    const victim = nextVictim();
    const orig = globalThis.fetch;
    try {
      globalThis.fetch = (async () => new Response(JSON.stringify(["not", "an", "object"]), { status: 200 })) as typeof fetch;
      const { resolveKeySetFromCard } = await import("../src/shared/crypto.js");
      await expect(resolveKeySetFromCard(victim, { fetch: globalThis.fetch })).rejects.toThrow();
    } finally {
      globalThis.fetch = orig;
    }
  });
});
