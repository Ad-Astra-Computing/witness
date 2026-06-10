import { describe, it, expect } from "vitest";
import { MerkleTree } from "../src/merkle.js";
import { createApp } from "../src/app.js";

// In-memory SQL storage mock that behaves like CF DO SQLite (mirrors the one in
// merkle.test.ts). The MerkleTree only needs merkle_nodes/merkle_meta.
class MockSql {
  private nodes = new Map<string, string>();
  private meta = new Map<string, number | string>();
  exec(query: string, ...params: unknown[]): { toArray(): Record<string, unknown>[] } {
    const q = query.trim().toUpperCase();
    if (q.startsWith("INSERT") || q.startsWith("REPLACE")) {
      if (query.includes("merkle_nodes")) {
        const [level, idx, hash] = params as [number, number, string];
        this.nodes.set(`${level}:${idx}`, hash);
      } else if (query.includes("merkle_meta")) {
        if (query.includes("'tree_size'")) this.meta.set("tree_size", params[0] as number);
        else if (query.includes("'root_hash'")) this.meta.set("root_hash", params[0] as string);
      }
      return { toArray: () => [] };
    }
    if (q.startsWith("SELECT") && query.includes("merkle_nodes")) {
      const [level, idx] = params as [number, number];
      const hash = this.nodes.get(`${level}:${idx}`);
      return { toArray: () => (hash ? [{ level, idx, hash }] : []) };
    }
    if (q.startsWith("SELECT") && query.includes("merkle_meta")) {
      const key = query.includes("'root_hash'") ? "root_hash" : "tree_size";
      const value = this.meta.get(key);
      return { toArray: () => (value !== undefined ? [{ value }] : []) };
    }
    return { toArray: () => [] };
  }
}

const enc = new TextEncoder();
const EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}
function fromHex(s: string): Uint8Array {
  const a = new Uint8Array(s.length / 2);
  for (let i = 0; i < a.length; i++) a[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return a;
}
async function sha256(b: Uint8Array): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", b)));
}
async function leafHash(data: string): Promise<string> {
  const d = enc.encode(data);
  const buf = new Uint8Array(1 + d.length);
  buf[0] = 0x00;
  buf.set(d, 1);
  return sha256(buf);
}
async function nodeHash(l: string, r: string): Promise<string> {
  const buf = new Uint8Array(65);
  buf[0] = 0x01;
  buf.set(fromHex(l), 1);
  buf.set(fromHex(r), 33);
  return sha256(buf);
}

// Independent imperative RFC 6962 consistency verifier (mirrors the ink library
// verifyConsistencyProof). The witness implements the recursive GENERATOR; this
// is the unrelated VERIFIER, so agreement across the matrix rules out a shared
// off-by-one.
async function refVerify(first: number, firstRoot: string, second: number, secondRoot: string, proof: string[]): Promise<boolean> {
  if (first > second) return false;
  if (first === second) return proof.length === 0 && firstRoot === secondRoot;
  if (first === 0) return proof.length === 0 && firstRoot === EMPTY;
  let node = first - 1;
  let last = second - 1;
  while (node % 2 === 1) { node = Math.floor(node / 2); last = Math.floor(last / 2); }
  let i = 0;
  const take = (): string | null => (i < proof.length ? proof[i++]! : null);
  let oldHash: string;
  if (node > 0) { const h = take(); if (h === null) return false; oldHash = h; } else { oldHash = firstRoot; }
  let newHash = oldHash;
  while (node > 0) {
    if (node % 2 === 1) {
      const h = take(); if (h === null) return false;
      oldHash = await nodeHash(h, oldHash); newHash = await nodeHash(h, newHash);
    } else if (node < last) {
      const h = take(); if (h === null) return false;
      newHash = await nodeHash(newHash, h);
    }
    node = Math.floor(node / 2); last = Math.floor(last / 2);
  }
  while (last > 0) { const h = take(); if (h === null) return false; newHash = await nodeHash(newHash, h); last = Math.floor(last / 2); }
  if (i !== proof.length) return false;
  return oldHash === firstRoot && newHash === secondRoot;
}

async function buildTree(n: number): Promise<{ tree: MerkleTree; root: string }> {
  const tree = new MerkleTree(new MockSql() as unknown as SqlStorage);
  for (let i = 0; i < n; i++) tree.appendLeaf(await leafHash(`leaf-${i}`));
  return { tree, root: tree.getState().rootHash };
}

describe("witness getConsistencyProof — cross-repo literal anchor", () => {
  it("produces the exact 1 -> 2 proof and roots the ink library test pins", async () => {
    const { tree } = await buildTree(2);
    const proof = tree.getConsistencyProof(1, 2);
    expect(proof).toEqual(["3145c409f259b7c53e32036090ff76751025a2498ba9823ef718cac50b4e616f"]);
    const root1 = (await buildTree(1)).root;
    const root2 = tree.getState().rootHash;
    expect(root1).toBe("305df59f9590c3c9ac63d2b2743c388e3792449078cebf7fb3dbe6471643b2b7");
    expect(root2).toBe("60a53eed0de87a90c8e59427c59c46253c33a76a09502a51801300927b7e6bdc");
  });
});

describe("witness getConsistencyProof — verified by an independent verifier", () => {
  it("every 1 <= m <= n <= 24 proof verifies against both roots", async () => {
    const N = 24;
    const roots: string[] = [EMPTY];
    for (let s = 1; s <= N; s++) roots.push((await buildTree(s)).root);
    const big = await buildTree(N);
    for (let n = 1; n <= N; n++) {
      const treeN = (await buildTree(n)).tree;
      for (let m = 1; m <= n; m++) {
        const proof = treeN.getConsistencyProof(m, n);
        expect(proof, `${m} -> ${n} not null`).not.toBeNull();
        // Every proof element is a 64-char lowercase hex hash the verifier accepts.
        for (const node of proof!) expect(node).toMatch(/^[0-9a-f]{64}$/);
        expect(await refVerify(m, roots[m]!, n, roots[n]!, proof!), `${m} -> ${n}`).toBe(true);
      }
    }
    expect(big.root).toBe(roots[N]);
  });
});

describe("witness getConsistencyProof — range and trivial cases", () => {
  it("returns an empty proof for first === 0 and first === second", async () => {
    const { tree } = await buildTree(8);
    expect(tree.getConsistencyProof(0, 8)).toEqual([]);
    expect(tree.getConsistencyProof(8, 8)).toEqual([]);
    expect(tree.getConsistencyProof(0, 0)).toEqual([]);
  });

  it("returns null for out-of-range or non-integer sizes", async () => {
    const { tree } = await buildTree(8);
    expect(tree.getConsistencyProof(5, 4)).toBeNull(); // first > second
    expect(tree.getConsistencyProof(3, 9)).toBeNull(); // second > treeSize
    expect(tree.getConsistencyProof(-1, 8)).toBeNull();
    expect(tree.getConsistencyProof(2.5, 8)).toBeNull();
  });
});

describe("GET /ink/v1/consistency — request validation", () => {
  // The route validates query parameters before reaching the Durable Object, so
  // these rejections need no log binding.
  const app = createApp();
  const env = {} as unknown as Env;

  it("rejects missing or non-integer query parameters with 400", async () => {
    for (const qs of ["", "?first=1", "?second=2", "?first=abc&second=2", "?first=1&second=2.5", "?first=-1&second=2"]) {
      const res = await app.request(`/ink/v1/consistency${qs}`, {}, env);
      expect(res.status, qs).toBe(400);
    }
  });

  it("returns the proof on a valid request", async () => {
    // Back the log binding with a real Merkle tree so the route's proxy and
    // response passthrough are exercised end to end.
    const treeEnv = {
      WITNESS_LOG: {
        idFromName: () => ({ toString: () => "global" }),
        get: () => ({
          async fetch(req: Request): Promise<Response> {
            const url = new URL(req.url);
            if (url.pathname !== "/consistency") return new Response("Not Found", { status: 404 });
            const tree = new MerkleTree(new MockSql() as unknown as SqlStorage);
            for (let i = 0; i < 2; i++) tree.appendLeaf(await leafHash(`leaf-${i}`));
            const first = Number(url.searchParams.get("first"));
            const second = Number(url.searchParams.get("second"));
            const proof = tree.getConsistencyProof(first, second);
            if (proof === null) return Response.json({ error: "range" }, { status: 400 });
            return Response.json({ first, second, proof });
          },
        }),
      },
    } as unknown as Env;
    const res = await app.request("/ink/v1/consistency?first=1&second=2", {}, treeEnv);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { first: number; second: number; proof: string[] };
    expect(body.first).toBe(1);
    expect(body.second).toBe(2);
    expect(body.proof).toEqual(["3145c409f259b7c53e32036090ff76751025a2498ba9823ef718cac50b4e616f"]);
  });
});
