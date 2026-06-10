/**
 * Binary Merkle tree backed by SQLite.
 *
 * Leaves use domain-separated hashing per RFC 6962 Section 2.1:
 *   leaf hash   = SHA-256(0x00 || data)   (computed in shared/crypto.ts computeEventHash)
 *   node hash   = SHA-256(0x01 || left || right)
 * Level 0 = leaves. Level k = internal nodes 2^k apart.
 *
 * For non-power-of-two sizes, the tree uses the RFC 6962 approach:
 * recursively split at the largest power of 2 less than the tree size.
 *
 * BREAKING CHANGE (v0.2): Added RFC 6962 domain separation. Trees built
 * before this change produce different hashes and must be rebuilt.
 */

const EMPTY_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/** Hard upper bound on the subtree cache. For an append-only tree of N
 * leaves the cache can hold O(N) distinct subtree hashes; capping it
 * bounds RAM under sustained submit traffic and bounds the per-submit
 * cost of snapshotState() (which copies the cache to support rollback). */
const MAX_SUBTREE_CACHE_ENTRIES = 4096;

export class MerkleTree {
  private treeSize: number;
  /** Cache of computed subtree hashes keyed by "start:size". LRU-evicted
   * once MAX_SUBTREE_CACHE_ENTRIES is reached. Map insertion order is
   * preserved by spec, so the oldest entry is always at the head. */
  private subtreeCache = new Map<string, string>();

  private cacheSet(key: string, val: string): void {
    // Refresh insertion order if key already present.
    if (this.subtreeCache.has(key)) this.subtreeCache.delete(key);
    this.subtreeCache.set(key, val);
    if (this.subtreeCache.size > MAX_SUBTREE_CACHE_ENTRIES) {
      const oldest = this.subtreeCache.keys().next().value;
      if (oldest !== undefined) this.subtreeCache.delete(oldest);
    }
  }

  constructor(private sql: SqlStorage) {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS merkle_nodes (
        level INTEGER NOT NULL,
        idx INTEGER NOT NULL,
        hash TEXT NOT NULL,
        PRIMARY KEY (level, idx)
      )
    `);
    // `value` is declared NUMERIC to accept both INTEGER (tree_size) and TEXT
    // (root_hash) without a schema migration. SQLite has dynamic types per
    // row, so an INSERT supplies its own type and we cast on read.
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS merkle_meta (
        key TEXT PRIMARY KEY,
        value NUMERIC NOT NULL
      )
    `);

    // Load current tree size
    const rows = this.sql.exec("SELECT value FROM merkle_meta WHERE key = 'tree_size'").toArray();
    this.treeSize = rows.length > 0 ? (rows[0]!.value as number) : 0;

    // Load cached root hash. Persisting the root means cold-start /checkpoint
    // reads do not have to walk the entire tree to recompute it (O(N) work
    // every restart). The root is refreshed on every appendLeaf and is the
    // authoritative value emitted by getState().
    const rootRows = this.sql.exec("SELECT value FROM merkle_meta WHERE key = 'root_hash'").toArray();
    this.cachedRootHash = rootRows.length > 0 ? (rootRows[0]!.value as string) : null;
  }

  /** Last persisted root hash. Refreshed in-memory after each appendLeaf and
   * lazily filled by getState() if a legacy DO has tree_size but no root.
   * `null` only on a brand-new DO with treeSize === 0. */
  private cachedRootHash: string | null = null;

  /**
   * Append a leaf hash and update the tree. Returns the new state.
   * O(log n) node updates.
   */
  appendLeaf(leafHash: string): { leafIndex: number; treeSize: number; rootHash: string } {
    const leafIndex = this.treeSize;

    // Store leaf at level 0
    this.setNode(0, leafIndex, leafHash);
    this.treeSize++;

    // Save tree size
    this.sql.exec(
      "INSERT OR REPLACE INTO merkle_meta (key, value) VALUES ('tree_size', ?)",
      this.treeSize,
    );

    const rootHash = this.computeRoot(this.treeSize);
    this.cachedRootHash = rootHash;
    this.sql.exec(
      "INSERT OR REPLACE INTO merkle_meta (key, value) VALUES ('root_hash', ?)",
      rootHash,
    );
    return { leafIndex, treeSize: this.treeSize, rootHash };
  }

  /** Get current tree size and root hash. Reads the persisted root if one is
   * available so cold-start /checkpoint requests do not trigger an O(N) tree
   * walk. Falls back to computeRoot() for legacy DOs that pre-date the
   * persisted-root upgrade. */
  getState(): { treeSize: number; rootHash: string } {
    if (this.treeSize === 0) return { treeSize: 0, rootHash: EMPTY_HASH };
    if (this.cachedRootHash) return { treeSize: this.treeSize, rootHash: this.cachedRootHash };
    const rootHash = this.computeRoot(this.treeSize);
    this.cachedRootHash = rootHash;
    this.sql.exec(
      "INSERT OR REPLACE INTO merkle_meta (key, value) VALUES ('root_hash', ?)",
      rootHash,
    );
    return { treeSize: this.treeSize, rootHash };
  }

  /**
   * Snapshot the in-memory tree state. Use this before opening a SQLite
   * transaction that may mutate the tree (via appendLeaf), so a rolled-back
   * transaction can restoreState() to keep the in-memory tracker in sync
   * with the persisted SQL state. Without this, a failed append would leave
   * `treeSize` incremented in memory while merkle_nodes/meta were rolled
   * back, causing the next accepted submit to skip an index or compute
   * proofs against missing leaves.
   */
  snapshotState(): { treeSize: number; subtreeCache: Map<string, string>; cachedRootHash: string | null } {
    return {
      treeSize: this.treeSize,
      subtreeCache: new Map(this.subtreeCache),
      cachedRootHash: this.cachedRootHash,
    };
  }

  /** Restore tree state from a prior snapshot. See snapshotState(). */
  restoreState(snapshot: { treeSize: number; subtreeCache: Map<string, string>; cachedRootHash: string | null }): void {
    this.treeSize = snapshot.treeSize;
    this.subtreeCache = snapshot.subtreeCache;
    this.cachedRootHash = snapshot.cachedRootHash;
  }

  /**
   * Get leaf hashes for a range of indices. Public endpoint for tree auditability.
   * Returns only the hash and index — no event content.
   * Capped at 1000 per request.
   */
  getLeafHashes(start: number, count: number): { index: number; hash: string }[] {
    if (start < 0 || start >= this.treeSize || count <= 0) return [];

    const maxCount = Math.min(count, 1000);
    const end = Math.min(start + maxCount - 1, this.treeSize - 1);

    const rows = this.sql.exec(
      "SELECT idx, hash FROM merkle_nodes WHERE level = ? AND idx BETWEEN ? AND ? ORDER BY idx ASC",
      0,
      start,
      end,
    ).toArray();

    return rows.map((row) => ({
      index: row.idx as number,
      hash: row.hash as string,
    }));
  }

  /**
   * Generate an inclusion proof for a leaf at the given index in a tree of the given size.
   * Returns an array of sibling hashes, or null if the index is out of bounds.
   */
  getInclusionProof(leafIndex: number, treeSize: number): string[] | null {
    // Reject non-integer / non-finite inputs up-front. Without this, callers
    // passing NaN, fractional, or Infinity values can drive buildProof into
    // pathological recursion (RangeError / DoS).
    if (!Number.isInteger(leafIndex) || !Number.isInteger(treeSize)) return null;
    if (leafIndex < 0 || leafIndex >= treeSize || treeSize > this.treeSize) return null;
    return this.buildProof(leafIndex, 0, treeSize);
  }

  /**
   * Generate an RFC 6962 Section 2.1.2 consistency proof that the tree of
   * `first` leaves is a prefix of the tree of `second` leaves: the sibling
   * subtree hashes a verifier needs to reconstruct both roots. Returns null for
   * non-integer or out-of-range sizes. The proof is the empty array (and valid)
   * when `first` is 0 or equals `second`, since there is nothing to prove.
   */
  getConsistencyProof(first: number, second: number): string[] | null {
    if (!Number.isInteger(first) || !Number.isInteger(second)) return null;
    if (first < 0 || second < 0 || first > second || second > this.treeSize) return null;
    if (first === 0 || first === second) return [];
    return this.buildConsistencyProof(first, 0, second, true);
  }

  /**
   * Verify an inclusion proof. Pure/static — no tree state needed.
   *
   * Rejects non-canonical proofs: extra or missing elements are not allowed.
   * This prevents proof-padding attacks where an attacker appends garbage
   * elements that are silently ignored by the recursive recomputation.
   */
  static async verifyInclusionProof(
    leafHash: string,
    proof: string[],
    leafIndex: number,
    treeSize: number,
    expectedRootHash: string,
  ): Promise<boolean> {
    // Validate scalar inputs up front. Without these checks, a malformed
    // single-leaf receipt (treeSize=1, proof=[], leafHash == rootHash)
    // verifies for ANY leafIndex including negative or out-of-range values,
    // breaking the position binding that inclusion receipts rely on.
    if (!Number.isInteger(treeSize) || treeSize <= 0) return false;
    if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= treeSize) return false;
    if (typeof leafHash !== "string" || !/^[0-9a-f]{64}$/.test(leafHash)) return false;
    if (typeof expectedRootHash !== "string" || !/^[0-9a-f]{64}$/.test(expectedRootHash)) return false;
    // proof may arrive from untrusted JSON — non-array shapes (null, plain
    // objects with a `length` property) would throw on iteration.
    if (!Array.isArray(proof)) return false;

    // Validate proof length against the expected depth for this tree position.
    // A proof with too few or too many elements is non-canonical and must be rejected.
    const expectedLen = MerkleTree.expectedProofLength(leafIndex, treeSize);
    if (proof.length !== expectedLen) return false;

    // Validate all proof elements are 64-char lowercase hex (SHA-256 output)
    for (const element of proof) {
      if (!/^[0-9a-f]{64}$/.test(element)) return false;
    }

    const computedRoot = await MerkleTree.recomputeRoot(leafHash, proof, leafIndex, treeSize);
    return computedRoot === expectedRootHash;
  }

  /**
   * Compute the expected proof length for a leaf at the given index
   * in a tree of the given size, using the RFC 6962 recursive split algorithm.
   */
  static expectedProofLength(leafIndex: number, treeSize: number): number {
    if (treeSize <= 1) return 0;
    return countProofElements(leafIndex, 0, treeSize);
  }

  // ── Private helpers ──

  private setNode(level: number, idx: number, hash: string): void {
    this.sql.exec(
      "INSERT OR REPLACE INTO merkle_nodes (level, idx, hash) VALUES (?, ?, ?)",
      level,
      idx,
      hash,
    );
  }

  private getNode(level: number, idx: number): string | null {
    const rows = this.sql.exec(
      "SELECT hash FROM merkle_nodes WHERE level = ? AND idx = ?",
      level,
      idx,
    ).toArray();
    return rows.length > 0 ? (rows[0]!.hash as string) : null;
  }

  /**
   * Compute the root hash for a tree of the given size using the RFC 6962 algorithm.
   * For n leaves, split at the largest power of 2 < n, compute left and right subtrees.
   */
  private computeRoot(size: number): string {
    if (size === 0) return EMPTY_HASH;
    if (size === 1) return this.getNode(0, 0) ?? EMPTY_HASH;
    return this.computeSubtreeHash(0, size);
  }

  private computeSubtreeHash(start: number, size: number): string {
    if (size === 1) return this.getNode(0, start) ?? EMPTY_HASH;

    const cacheKey = `${start}:${size}`;
    const cached = this.subtreeCache.get(cacheKey);
    if (cached) return cached;

    const split = largestPowerOf2LessThan(size);
    const leftHash = this.computeSubtreeHash(start, split);
    const rightHash = this.computeSubtreeHash(start + split, size - split);
    const hash = hashPairSync(leftHash, rightHash);

    // Cache complete power-of-2 subtrees — they are stable in an append-only tree
    if ((size & (size - 1)) === 0 && start + size <= this.treeSize) {
      this.cacheSet(cacheKey, hash);
    }

    return hash;
  }

  /**
   * Build inclusion proof by decomposing the tree at the split point.
   */
  private buildProof(leafIndex: number, start: number, size: number): string[] {
    if (size === 1) return [];

    const split = largestPowerOf2LessThan(size);
    if (leafIndex - start < split) {
      // Leaf is in the left subtree — sibling is right subtree hash
      const rightHash = this.computeSubtreeHash(start + split, size - split);
      return [rightHash, ...this.buildProof(leafIndex, start, split)];
    } else {
      // Leaf is in the right subtree — sibling is left subtree hash
      const leftHash = this.computeSubtreeHash(start, split);
      return [leftHash, ...this.buildProof(leafIndex, start + split, size - split)];
    }
  }

  /**
   * RFC 6962 SUBPROOF recursion over the subtree covering [start, start+size).
   * `b` marks whether this subtree is still the rightmost complete subtree of
   * the first tree, in which case its hash is omitted (the verifier already
   * derives it); once the recursion descends into a strictly smaller prefix the
   * flag clears and the subtree hash is emitted.
   */
  private buildConsistencyProof(m: number, start: number, size: number, b: boolean): string[] {
    if (m === size) return b ? [] : [this.computeSubtreeHash(start, size)];
    const split = largestPowerOf2LessThan(size);
    if (m <= split) {
      return [
        ...this.buildConsistencyProof(m, start, split, b),
        this.computeSubtreeHash(start + split, size - split),
      ];
    }
    return [
      ...this.buildConsistencyProof(m - split, start + split, size - split, false),
      this.computeSubtreeHash(start, split),
    ];
  }

  /**
   * Recompute root from a leaf hash and inclusion proof (static verification).
   */
  private static async recomputeRoot(
    leafHash: string,
    proof: string[],
    leafIndex: number,
    treeSize: number,
  ): Promise<string> {
    return recomputeRootFromProof(leafHash, proof, 0, leafIndex, 0, treeSize);
  }
}

// ── Utility functions ──

/** Largest power of 2 strictly less than n. */
function largestPowerOf2LessThan(n: number): number {
  if (n <= 1) return 0;
  let p = 1;
  while (p * 2 < n) p *= 2;
  return p;
}

/**
 * RFC 6962 §2.1 internal node hash: SHA-256(0x01 || left || right).
 * Uses synchronous SHA-256 since DO SQLite operations are synchronous.
 */
function hashPairSync(left: string, right: string): string {
  const leftBytes = hexToBytes(left);
  const rightBytes = hexToBytes(right);
  const prefixed = new Uint8Array(1 + leftBytes.length + rightBytes.length);
  prefixed[0] = 0x01;
  prefixed.set(leftBytes, 1);
  prefixed.set(rightBytes, 1 + leftBytes.length);
  return sha256sync(prefixed);
}

/** Convert a hex string to Uint8Array. Throws on invalid or odd-length input.
 * Length-capped before the charset regex as defense-in-depth. Current callers
 * pass trusted 64-char SHA-256 hashes; the cap protects future callers from
 * an unbounded O(n) regex scan on adversarial input. */
const MAX_HEX_INPUT_LEN = 4096;
function hexToBytes(hex: string): Uint8Array {
  if (hex.length > MAX_HEX_INPUT_LEN) {
    throw new Error(`hex input exceeds maximum length of ${MAX_HEX_INPUT_LEN}`);
  }
  if (hex.length % 2 !== 0) throw new Error(`Invalid hex string length: ${hex.length}`);
  if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error("Invalid hex character in string");
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

// ── Synchronous SHA-256 (pure JS, K constants + compression) ──

const K: number[] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

function rotr(x: number, n: number): number { return ((x >>> n) | (x << (32 - n))) >>> 0; }
function ch(x: number, y: number, z: number): number { return ((x & y) ^ (~x & z)) >>> 0; }
function maj(x: number, y: number, z: number): number { return ((x & y) ^ (x & z) ^ (y & z)) >>> 0; }
function sigma0(x: number): number { return (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)) >>> 0; }
function sigma1(x: number): number { return (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)) >>> 0; }
function gamma0(x: number): number { return (rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3)) >>> 0; }
function gamma1(x: number): number { return (rotr(x, 17) ^ rotr(x, 19) ^ (x >>> 10)) >>> 0; }

function sha256sync(data: Uint8Array): string {
  // Length field is encoded as 32-bit big-endian below; only the low 32 bits
  // of the SHA-256 bit-length field are written. This is correct for any
  // input under 512 MB (2^32 / 8 bits). Refuse larger inputs explicitly so
  // the function can never silently produce a wrong digest. All callers
  // hash short fixed-size inputs (<= 65 bytes), so this is a defensive
  // guard against future reuse.
  if (data.length > 0x1FFFFFFF) {
    throw new Error("sha256sync: input too large (max 512 MB)");
  }

  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

  const bitLen = data.length * 8;
  // Pad: append 1 bit, zeros, then 64-bit big-endian length
  const padLen = 64 - ((data.length + 9) % 64);
  const totalLen = data.length + 1 + (padLen === 64 ? 0 : padLen) + 8;
  const padded = new Uint8Array(totalLen);
  padded.set(data);
  padded[data.length] = 0x80;
  // Write length as 64-bit big-endian. The 32-bit input cap above keeps
  // the upper 32 bits zero so setUint32 on the low word is sufficient.
  const view = new DataView(padded.buffer);
  view.setUint32(totalLen - 4, bitLen, false);

  const W = new Int32Array(64);

  for (let offset = 0; offset < totalLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      W[i] = view.getInt32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      W[i] = (gamma1(W[i - 2]!) + W[i - 7]! + gamma0(W[i - 15]!) + W[i - 16]!) | 0;
    }

    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;

    for (let i = 0; i < 64; i++) {
      const t1 = (h + sigma1(e) + ch(e, f, g) + K[i]! + W[i]!) | 0;
      const t2 = (sigma0(a) + maj(a, b, c)) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0;
      d = c; c = b; b = a; a = (t1 + t2) | 0;
    }

    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
  }

  return [h0, h1, h2, h3, h4, h5, h6, h7]
    .map((v) => (v >>> 0).toString(16).padStart(8, "0"))
    .join("");
}

/**
 * Count the number of proof elements needed for a leaf at leafIndex
 * in a subtree spanning [start, start+size). Mirrors buildProof recursion.
 */
function countProofElements(leafIndex: number, start: number, size: number): number {
  if (size <= 1) return 0;
  const split = largestPowerOf2LessThan(size);
  if (leafIndex - start < split) {
    return 1 + countProofElements(leafIndex, start, split);
  } else {
    return 1 + countProofElements(leafIndex, start + split, size - split);
  }
}

/** Recompute root from proof using RFC 6962 decomposition. */
function recomputeRootFromProof(
  currentHash: string,
  proof: string[],
  proofIdx: number,
  leafIndex: number,
  start: number,
  size: number,
): string {
  if (size === 1) return currentHash;
  if (proofIdx >= proof.length) return currentHash;

  const split = largestPowerOf2LessThan(size);

  if (leafIndex - start < split) {
    // Leaf is in left subtree, proof[proofIdx] is the right subtree hash
    const leftResult = recomputeRootFromProof(currentHash, proof, proofIdx + 1, leafIndex, start, split);
    return hashPairSync(leftResult, proof[proofIdx]!);
  } else {
    // Leaf is in right subtree, proof[proofIdx] is the left subtree hash
    const rightResult = recomputeRootFromProof(currentHash, proof, proofIdx + 1, leafIndex, start + split, size - split);
    return hashPairSync(proof[proofIdx]!, rightResult);
  }
}
