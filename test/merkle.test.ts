import { describe, it, expect, beforeEach } from "vitest";
import { MerkleTree } from "../src/merkle.js";

/** SHA-256 hex hash helper for test data */
async function sha256hex(data: string): Promise<string> {
  const bytes = new TextEncoder().encode(data);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * In-memory SQL storage mock that behaves like CF DO SQLite.
 * Stores merkle_nodes as a Map keyed by "level:idx".
 */
class MockSql {
  private nodes = new Map<string, string>();
  private meta = new Map<string, number | string>();
  selectCount = 0;

  resetSelectCount(): void {
    this.selectCount = 0;
  }

  exec(query: string, ...params: unknown[]): { toArray(): Record<string, unknown>[] } {
    const q = query.trim().toUpperCase();

    if (q.startsWith("INSERT") || q.startsWith("REPLACE")) {
      if (query.includes("merkle_nodes")) {
        const [level, idx, hash] = params as [number, number, string];
        this.nodes.set(`${level}:${idx}`, hash);
      } else if (query.includes("merkle_meta")) {
        // Distinguish 'tree_size' vs 'root_hash' INSERTs by literal key in
        // the query (matches what the production code emits).
        if (query.includes("'tree_size'")) {
          this.meta.set("tree_size", params[0] as number);
        } else if (query.includes("'root_hash'")) {
          this.meta.set("root_hash", params[0] as string);
        }
      }
      return { toArray: () => [] };
    }

    if (q.startsWith("SELECT") && query.includes("merkle_nodes")) {
      this.selectCount++;
      const [level, idx] = params as [number, number];
      const hash = this.nodes.get(`${level}:${idx}`);
      if (hash) return { toArray: () => [{ level, idx, hash }] };
      return { toArray: () => [] };
    }

    if (q.startsWith("SELECT") && query.includes("merkle_meta")) {
      const key = query.includes("'root_hash'") ? "root_hash" : "tree_size";
      const value = this.meta.get(key);
      if (value !== undefined) return { toArray: () => [{ value }] };
      return { toArray: () => [] };
    }

    if (q.startsWith("CREATE")) {
      return { toArray: () => [] };
    }

    return { toArray: () => [] };
  }
}

describe("MerkleTree", () => {
  let sql: MockSql;
  let tree: MerkleTree;

  beforeEach(() => {
    sql = new MockSql();
    tree = new MerkleTree(sql as unknown as SqlStorage);
  });

  it("appends a single leaf and returns root hash", async () => {
    const hash = await sha256hex("event-1");
    const result = tree.appendLeaf(hash);

    expect(result.leafIndex).toBe(0);
    expect(result.treeSize).toBe(1);
    expect(result.rootHash).toBe(hash);
  });

  it("root hash changes with each append", async () => {
    const h1 = await sha256hex("event-1");
    const h2 = await sha256hex("event-2");
    const h3 = await sha256hex("event-3");

    const r1 = tree.appendLeaf(h1);
    const r2 = tree.appendLeaf(h2);
    const r3 = tree.appendLeaf(h3);

    expect(r1.rootHash).not.toBe(r2.rootHash);
    expect(r2.rootHash).not.toBe(r3.rootHash);
    expect(r1.rootHash).not.toBe(r3.rootHash);
  });

  it("tracks tree size correctly", async () => {
    for (let i = 0; i < 5; i++) {
      const hash = await sha256hex(`event-${i}`);
      const result = tree.appendLeaf(hash);
      expect(result.treeSize).toBe(i + 1);
      expect(result.leafIndex).toBe(i);
    }
  });

  it("generates an inclusion proof for any leaf", async () => {
    const hashes: string[] = [];
    for (let i = 0; i < 8; i++) {
      hashes.push(await sha256hex(`event-${i}`));
      tree.appendLeaf(hashes[i]!);
    }

    // Get proof for leaf 3 in a tree of size 8
    const proof = tree.getInclusionProof(3, 8);
    expect(proof).not.toBeNull();
    expect(proof!.length).toBeGreaterThan(0);
    // For a perfect tree of 8 leaves, proof should have 3 sibling hashes (log2(8))
    expect(proof!.length).toBe(3);
  });

  it("verifies inclusion proof against known root", async () => {
    const hashes: string[] = [];
    let lastResult: { rootHash: string; treeSize: number } = { rootHash: "", treeSize: 0 };

    for (let i = 0; i < 4; i++) {
      hashes.push(await sha256hex(`event-${i}`));
      lastResult = tree.appendLeaf(hashes[i]!);
    }

    // Verify each leaf's proof
    for (let i = 0; i < 4; i++) {
      const proof = tree.getInclusionProof(i, lastResult.treeSize);
      expect(proof).not.toBeNull();

      const valid = await MerkleTree.verifyInclusionProof(
        hashes[i]!,
        proof!,
        i,
        lastResult.treeSize,
        lastResult.rootHash,
      );
      expect(valid).toBe(true);
    }
  });

  it("rejects tampered proof", async () => {
    const hashes: string[] = [];
    let lastResult: { rootHash: string; treeSize: number } = { rootHash: "", treeSize: 0 };

    for (let i = 0; i < 4; i++) {
      hashes.push(await sha256hex(`event-${i}`));
      lastResult = tree.appendLeaf(hashes[i]!);
    }

    const proof = tree.getInclusionProof(0, lastResult.treeSize)!;
    // Tamper with proof
    proof[0] = "0000000000000000000000000000000000000000000000000000000000000000";

    const valid = await MerkleTree.verifyInclusionProof(
      hashes[0]!,
      proof,
      0,
      lastResult.treeSize,
      lastResult.rootHash,
    );
    expect(valid).toBe(false);
  });

  it("rejects wrong leaf hash", async () => {
    const hashes: string[] = [];
    let lastResult: { rootHash: string; treeSize: number } = { rootHash: "", treeSize: 0 };

    for (let i = 0; i < 4; i++) {
      hashes.push(await sha256hex(`event-${i}`));
      lastResult = tree.appendLeaf(hashes[i]!);
    }

    const proof = tree.getInclusionProof(0, lastResult.treeSize)!;
    const wrongHash = await sha256hex("wrong-event");

    const valid = await MerkleTree.verifyInclusionProof(
      wrongHash,
      proof,
      0,
      lastResult.treeSize,
      lastResult.rootHash,
    );
    expect(valid).toBe(false);
  });

  it("handles non-power-of-two tree sizes", async () => {
    const hashes: string[] = [];
    let lastResult: { rootHash: string; treeSize: number } = { rootHash: "", treeSize: 0 };

    // 5 leaves — not a power of two
    for (let i = 0; i < 5; i++) {
      hashes.push(await sha256hex(`event-${i}`));
      lastResult = tree.appendLeaf(hashes[i]!);
    }

    expect(lastResult.treeSize).toBe(5);

    // Every leaf should have a valid proof
    for (let i = 0; i < 5; i++) {
      const proof = tree.getInclusionProof(i, lastResult.treeSize);
      expect(proof).not.toBeNull();

      const valid = await MerkleTree.verifyInclusionProof(
        hashes[i]!,
        proof!,
        i,
        lastResult.treeSize,
        lastResult.rootHash,
      );
      expect(valid).toBe(true);
    }
  });

  it("appendLeaf uses O(log n) SQL reads via subtree caching", async () => {
    // Build a tree of 64 leaves
    for (let i = 0; i < 64; i++) {
      const hash = await sha256hex(`event-${i}`);
      tree.appendLeaf(hash);
    }

    // Now append the 65th leaf and count SQL reads
    sql.resetSelectCount();
    const hash65 = await sha256hex("event-64");
    tree.appendLeaf(hash65);

    // Without caching: O(n) reads (recomputes all 65 leaves).
    // With caching: O(log n) reads — only the rightmost path needs recomputation.
    // For 65 leaves, log2(65) ~= 7, so we expect at most ~10 reads (generous bound).
    // Without caching it would be 65 reads.
    expect(sql.selectCount).toBeLessThanOrEqual(10);
  });

  it("cached subtree hashes produce correct roots", async () => {
    // Build tree incrementally and verify each root matches a fresh computation
    const hashes: string[] = [];
    const roots: string[] = [];

    for (let i = 0; i < 20; i++) {
      hashes.push(await sha256hex(`cached-event-${i}`));
      const result = tree.appendLeaf(hashes[i]!);
      roots.push(result.rootHash);
    }

    // Verify every leaf still has a valid inclusion proof against its root
    for (let treeSize = 1; treeSize <= 20; treeSize++) {
      for (let leafIdx = 0; leafIdx < treeSize; leafIdx++) {
        const proof = tree.getInclusionProof(leafIdx, treeSize);
        expect(proof).not.toBeNull();

        const valid = await MerkleTree.verifyInclusionProof(
          hashes[leafIdx]!,
          proof!,
          leafIdx,
          treeSize,
          roots[treeSize - 1]!,
        );
        expect(valid).toBe(true);
      }
    }
  });

  // ── Proof over-consumption / padding attack ──

  it("rejects proof with extra trailing elements (non-canonical proof)", async () => {
    const hashes: string[] = [];
    let lastResult: { rootHash: string; treeSize: number } = { rootHash: "", treeSize: 0 };

    for (let i = 0; i < 4; i++) {
      hashes.push(await sha256hex(`event-${i}`));
      lastResult = tree.appendLeaf(hashes[i]!);
    }

    const validProof = tree.getInclusionProof(0, lastResult.treeSize)!;
    // Append a garbage extra element — should be rejected
    const bloatedProof = [...validProof, "a".repeat(64)];

    const valid = await MerkleTree.verifyInclusionProof(
      hashes[0]!,
      bloatedProof,
      0,
      lastResult.treeSize,
      lastResult.rootHash,
    );
    expect(valid).toBe(false);
  });

  it("rejects proof containing a malformed hash element (not 64-char hex)", async () => {
    const hashes: string[] = [];
    let lastResult: { rootHash: string; treeSize: number } = { rootHash: "", treeSize: 0 };

    for (let i = 0; i < 4; i++) {
      hashes.push(await sha256hex(`event-${i}`));
      lastResult = tree.appendLeaf(hashes[i]!);
    }

    const validProof = tree.getInclusionProof(0, lastResult.treeSize)!;
    // Replace one element with a malformed hash
    const badProof = [...validProof];
    badProof[0] = "GGGGGG"; // uppercase / invalid hex

    const valid = await MerkleTree.verifyInclusionProof(
      hashes[0]!,
      badProof,
      0,
      lastResult.treeSize,
      lastResult.rootHash,
    );
    expect(valid).toBe(false);
  });

  it("rejects proof with too few elements (truncated proof)", async () => {
    const hashes: string[] = [];
    let lastResult: { rootHash: string; treeSize: number } = { rootHash: "", treeSize: 0 };

    // 4 leaves: valid proof should have 2 elements
    for (let i = 0; i < 4; i++) {
      hashes.push(await sha256hex(`event-${i}`));
      lastResult = tree.appendLeaf(hashes[i]!);
    }

    const validProof = tree.getInclusionProof(0, lastResult.treeSize)!;
    expect(validProof.length).toBe(2);
    // Remove the last element — truncated proof should be rejected
    const truncatedProof = validProof.slice(0, 1);

    const valid = await MerkleTree.verifyInclusionProof(
      hashes[0]!,
      truncatedProof,
      0,
      lastResult.treeSize,
      lastResult.rootHash,
    );
    expect(valid).toBe(false);
  });

  it("rejects out-of-range leafIndex even when leafHash equals rootHash", async () => {
    // Single-leaf tree: rootHash == leafHash. Without bounds validation
    // verifyInclusionProof would return true for ANY leafIndex.
    const hash = await sha256hex("only-leaf");
    const { rootHash, treeSize } = tree.appendLeaf(hash);
    expect(treeSize).toBe(1);

    // Real index (0) should verify
    expect(await MerkleTree.verifyInclusionProof(hash, [], 0, treeSize, rootHash)).toBe(true);
    // Out-of-range indices must be rejected
    expect(await MerkleTree.verifyInclusionProof(hash, [], 1, treeSize, rootHash)).toBe(false);
    expect(await MerkleTree.verifyInclusionProof(hash, [], 99, treeSize, rootHash)).toBe(false);
    expect(await MerkleTree.verifyInclusionProof(hash, [], -1, treeSize, rootHash)).toBe(false);
  });

  it("rejects malformed treeSize and non-integer values", async () => {
    const hash = await sha256hex("leaf");
    const { rootHash } = tree.appendLeaf(hash);
    expect(await MerkleTree.verifyInclusionProof(hash, [], 0, 0, rootHash)).toBe(false);
    expect(await MerkleTree.verifyInclusionProof(hash, [], 0, -1, rootHash)).toBe(false);
    expect(await MerkleTree.verifyInclusionProof(hash, [], 0.5, 1, rootHash)).toBe(false);
    expect(await MerkleTree.verifyInclusionProof(hash, [], 0, 1.5, rootHash)).toBe(false);
    expect(await MerkleTree.verifyInclusionProof(hash, [], 0, NaN, rootHash)).toBe(false);
  });

  it("rejects malformed leafHash and rootHash strings", async () => {
    const hash = await sha256hex("leaf");
    const { rootHash, treeSize } = tree.appendLeaf(hash);
    expect(await MerkleTree.verifyInclusionProof("notahash", [], 0, treeSize, rootHash)).toBe(false);
    expect(await MerkleTree.verifyInclusionProof(hash, [], 0, treeSize, "notahash")).toBe(false);
    expect(await MerkleTree.verifyInclusionProof(hash.toUpperCase(), [], 0, treeSize, rootHash)).toBe(false);
  });

  it("rejects non-array proof shapes from untrusted JSON without throwing", async () => {
    const hash = await sha256hex("leaf");
    const { rootHash, treeSize } = tree.appendLeaf(hash);
    expect(await MerkleTree.verifyInclusionProof(hash, null as unknown as string[], 0, treeSize, rootHash)).toBe(false);
    expect(await MerkleTree.verifyInclusionProof(hash, { length: 0 } as unknown as string[], 0, treeSize, rootHash)).toBe(false);
    expect(await MerkleTree.verifyInclusionProof(hash, "abc" as unknown as string[], 0, treeSize, rootHash)).toBe(false);
  });

  it("getInclusionProof returns null for non-integer / non-finite inputs", () => {
    const hash = "a".repeat(64);
    tree.appendLeaf(hash);
    expect(tree.getInclusionProof(0.5, 1)).toBeNull();
    expect(tree.getInclusionProof(0, 1.5)).toBeNull();
    expect(tree.getInclusionProof(NaN, 1)).toBeNull();
    expect(tree.getInclusionProof(0, NaN)).toBeNull();
    expect(tree.getInclusionProof(Infinity, 1)).toBeNull();
  });

  it("getState reads persisted root without walking the tree on cold start", async () => {
    // Populate a tree of 50 leaves via the live MerkleTree, then simulate a
    // cold start by constructing a fresh MerkleTree against the same MockSql.
    // The fresh instance starts with an empty subtree cache, so any cold-start
    // call to getState() that recomputes the root would read >= 50 nodes.
    for (let i = 0; i < 50; i++) {
      tree.appendLeaf(await sha256hex(`cold-${i}`));
    }
    const liveState = tree.getState();

    const fresh = new MerkleTree(sql as unknown as SqlStorage);
    sql.resetSelectCount();
    const coldState = fresh.getState();

    expect(coldState.treeSize).toBe(liveState.treeSize);
    expect(coldState.rootHash).toBe(liveState.rootHash);
    // The persisted root means getState() must not read any merkle_nodes
    // rows. Without the cache we would expect dozens of reads here.
    expect(sql.selectCount).toBe(0);
  });

  it("getState backfills root_hash for legacy trees missing the persisted value", async () => {
    // Simulate a tree that pre-dates the persisted-root upgrade: leaves and
    // tree_size are present, but root_hash is missing from merkle_meta.
    for (let i = 0; i < 8; i++) {
      tree.appendLeaf(await sha256hex(`legacy-${i}`));
    }
    const expected = tree.getState().rootHash;
    // Wipe just the cached root_hash to mimic a legacy DO.
    (sql as unknown as { meta: Map<string, unknown> }).meta.delete("root_hash");

    const legacy = new MerkleTree(sql as unknown as SqlStorage);
    const firstRead = legacy.getState();
    expect(firstRead.rootHash).toBe(expected);

    sql.resetSelectCount();
    const secondRead = legacy.getState();
    expect(secondRead.rootHash).toBe(expected);
    // Second read should hit the in-memory cache, not the tree.
    expect(sql.selectCount).toBe(0);
  });

  it("appendLeaf persists the updated root for the next reader", async () => {
    tree.appendLeaf(await sha256hex("persist-1"));
    tree.appendLeaf(await sha256hex("persist-2"));
    const live = tree.getState();

    const fresh = new MerkleTree(sql as unknown as SqlStorage);
    expect(fresh.getState().rootHash).toBe(live.rootHash);
  });

  it("restoreState rolls back the cached root after a transaction rollback", async () => {
    tree.appendLeaf(await sha256hex("snap-1"));
    const snapshot = tree.snapshotState();
    const rootBefore = tree.getState().rootHash;

    tree.appendLeaf(await sha256hex("snap-2"));
    expect(tree.getState().rootHash).not.toBe(rootBefore);

    tree.restoreState(snapshot);
    expect(tree.getState().rootHash).toBe(rootBefore);
  });
});
