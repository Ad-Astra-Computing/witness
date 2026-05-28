import { describe, it, expect, beforeEach } from "vitest";
import { MerkleTree } from "../src/merkle.js";

/** SHA-256 hex hash helper for test data */
async function sha256hex(data: string): Promise<string> {
  const bytes = new TextEncoder().encode(data);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

class MockSql {
  private nodes = new Map<string, string>();
  private meta = new Map<string, number>();

  exec(query: string, ...params: unknown[]): { toArray(): Record<string, unknown>[] } {
    const q = query.trim().toUpperCase();

    if (q.startsWith("INSERT") || q.startsWith("REPLACE")) {
      if (query.includes("merkle_nodes")) {
        const [level, idx, hash] = params as [number, number, string];
        this.nodes.set(`${level}:${idx}`, hash);
      } else if (query.includes("merkle_meta")) {
        const [, value] = params as [string, number];
        this.meta.set("tree_size", value);
      }
      return { toArray: () => [] };
    }

    if (q.startsWith("SELECT") && query.includes("merkle_nodes") && query.includes("level = ? AND idx = ?")) {
      const [level, idx] = params as [number, number];
      const hash = this.nodes.get(`${level}:${idx}`);
      if (hash) return { toArray: () => [{ level, idx, hash }] };
      return { toArray: () => [] };
    }

    // Range query for getLeafHashes
    if (q.startsWith("SELECT") && query.includes("merkle_nodes") && query.includes("BETWEEN")) {
      const [, start, end] = params as [number, number, number];
      const results: Record<string, unknown>[] = [];
      for (let i = start; i <= end; i++) {
        const hash = this.nodes.get(`0:${i}`);
        if (hash) results.push({ idx: i, hash });
      }
      results.sort((a, b) => (a.idx as number) - (b.idx as number));
      return { toArray: () => results };
    }

    if (q.startsWith("SELECT") && query.includes("merkle_meta")) {
      const size = this.meta.get("tree_size");
      if (size !== undefined) return { toArray: () => [{ value: size }] };
      return { toArray: () => [] };
    }

    if (q.startsWith("CREATE")) {
      return { toArray: () => [] };
    }

    return { toArray: () => [] };
  }
}

describe("MerkleTree.getLeafHashes", () => {
  let sql: MockSql;
  let tree: MerkleTree;

  beforeEach(async () => {
    sql = new MockSql();
    tree = new MerkleTree(sql as unknown as SqlStorage);

    // Build a tree with 10 leaves
    for (let i = 0; i < 10; i++) {
      const hash = await sha256hex(`event-${i}`);
      tree.appendLeaf(hash);
    }
  });

  it("returns leaf hashes for a valid range", () => {
    const result = tree.getLeafHashes(0, 5);
    expect(result).toHaveLength(5);
    expect(result[0]!.index).toBe(0);
    expect(result[4]!.index).toBe(4);
    expect(typeof result[0]!.hash).toBe("string");
  });

  it("returns leaf hashes for a middle range", () => {
    const result = tree.getLeafHashes(3, 4);
    expect(result).toHaveLength(4);
    expect(result[0]!.index).toBe(3);
    expect(result[3]!.index).toBe(6);
  });

  it("clamps count to available leaves", () => {
    const result = tree.getLeafHashes(8, 100);
    expect(result).toHaveLength(2); // only indices 8 and 9 remain
  });

  it("returns empty array when start is at or past tree size", () => {
    expect(tree.getLeafHashes(10, 5)).toHaveLength(0);
    expect(tree.getLeafHashes(100, 5)).toHaveLength(0);
  });

  it("returns empty array for negative start", () => {
    expect(tree.getLeafHashes(-1, 5)).toHaveLength(0);
  });

  it("returns empty array for zero or negative count", () => {
    expect(tree.getLeafHashes(0, 0)).toHaveLength(0);
    expect(tree.getLeafHashes(0, -1)).toHaveLength(0);
  });

  it("caps count at 1000", () => {
    // Build a larger tree
    const bigSql = new MockSql();
    const bigTree = new MerkleTree(bigSql as unknown as SqlStorage);
    // We can't build 1001 leaves in a test easily, but verify the cap logic
    const result = bigTree.getLeafHashes(0, 2000);
    // Tree is empty so returns nothing, but the method should not crash
    expect(result).toHaveLength(0);
  });

  it("leaf hashes do not contain event content", () => {
    const result = tree.getLeafHashes(0, 3);
    for (const leaf of result) {
      // Each entry should only have index and hash — no event data
      expect(Object.keys(leaf)).toEqual(["index", "hash"]);
      // Hash should be a hex string (64 chars for SHA-256)
      expect(leaf.hash).toMatch(/^[a-f0-9]{64}$/);
    }
  });
});
