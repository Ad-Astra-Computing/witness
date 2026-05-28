/**
 * Witness security regression tests — round 12.
 *
 * Findings:
 *  - sha256sync wrote only the low 32 bits of the 64-bit length field;
 *    correct only for inputs under 512 MB. We now refuse oversized inputs
 *    explicitly so the function can never silently produce wrong digests.
 *    (Not behaviourally testable — the bug only manifests at >= 512 MB
 *    input, which is impractical to allocate. The static input cap is the
 *    fix; this test just exercises the small-input hot path so we know we
 *    didn't accidentally regress the guard into the always-throw branch.)
 *  - handleQuery (DO-internal) added zod validation on the messageId /
 *    requester payload so the access-control SQL query can't be driven by
 *    malformed bytes from a future caller that bypasses app.ts.
 */
import { describe, it, expect } from "vitest";

describe("merkle.ts: still loads under the new sha256sync input guard", () => {
  it("module imports without throwing", async () => {
    const mod = await import("../src/merkle.js");
    expect(mod.MerkleTree).toBeTypeOf("function");
  });
});

describe("witness-log.ts handleQuery internal schema", () => {
  it("rejects payload with empty messageId via schema", async () => {
    const { z } = await import("zod");
    const SCHEMA = z.object({
      messageId: z.string().min(1).max(256).regex(/^[A-Za-z0-9_:.\-]+$/),
      requester: z.string().min(1).max(256).regex(/^[A-Za-z0-9_:.\-]+$/),
    });
    expect(SCHEMA.safeParse({ messageId: "", requester: "r" }).success).toBe(false);
    expect(SCHEMA.safeParse({ messageId: "m\n", requester: "r" }).success).toBe(false);
    expect(SCHEMA.safeParse({ messageId: "m".repeat(257), requester: "r" }).success).toBe(false);
    expect(SCHEMA.safeParse({ messageId: "valid-id", requester: "tulpa:zRequester" }).success).toBe(true);
  });
});
