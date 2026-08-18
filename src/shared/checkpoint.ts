export interface CheckpointData {
  origin: string;
  treeSize: number;
  rootHash: string;
}

export function formatCheckpoint(data: CheckpointData): string {
  return `${data.origin}\n${data.treeSize}\n${data.rootHash}\n`;
}

/** A real checkpoint is origin (<=256) + treeSize (<=16) + rootHash (64) plus
 *  three newlines, so ~340 characters at most. 1024 leaves headroom while
 *  bounding the work a caller pays to discover an attacker-supplied blob is
 *  malformed; the per-line cap is defense in depth behind it. */
const MAX_CHECKPOINT_BODY = 1024;
const MAX_CHECKPOINT_LINE = 256;

/** A checkpoint origin appears twice in a signed checkpoint: as the first body
 *  line, and inside the `-- <origin> <signature>` line. A verifier splits that
 *  signature line at its first space, so an origin containing whitespace
 *  produces a checkpoint that cannot be verified by anyone. Control characters
 *  would break the line structure outright. */
const CHECKPOINT_ORIGIN_REGEX = /^[\x21-\x7e]+$/;

/** Whether an origin is usable in a signed checkpoint. Operators should
 *  validate `WITNESS_ORIGIN` with this at startup rather than discovering a
 *  bad value when a verifier rejects the log. */
export function isValidCheckpointOrigin(origin: unknown): origin is string {
  return (
    typeof origin === "string" &&
    origin.length > 0 &&
    origin.length <= MAX_CHECKPOINT_LINE &&
    CHECKPOINT_ORIGIN_REGEX.test(origin)
  );
}

export function parseCheckpoint(body: string): CheckpointData | null {
  // Reject oversized input before String.split allocates a partition array.
  if (typeof body !== "string" || body.length === 0 || body.length > MAX_CHECKPOINT_BODY) {
    return null;
  }
  const lines = body.split("\n");
  // Expect exactly: origin, treeSize, rootHash, trailing newline (produces 4 parts).
  // Strict equality eliminates parser differential with C2SP tlog-checkpoint
  // reference implementations that reject trailing junk.
  if (lines.length !== 4) return null;
  if (lines[3] !== "") return null;

  const origin = lines[0]!;
  const treeSizeLine = lines[1]!;
  const rootHash = lines[2]!;

  // Per-line caps before any regex or parseInt scan.
  if (origin.length > MAX_CHECKPOINT_LINE) return null;
  if (treeSizeLine.length > MAX_CHECKPOINT_LINE) return null;
  if (rootHash.length > MAX_CHECKPOINT_LINE) return null;

  // Origin must be non-empty, and must survive the round trip through a signed
  // checkpoint's `-- <origin> <signature>` line.
  if (!isValidCheckpointOrigin(origin)) return null;

  // Tree size must be a non-negative integer with no trailing junk
  if (!/^\d+$/.test(treeSizeLine)) return null;
  const treeSize = parseInt(treeSizeLine, 10);
  if (isNaN(treeSize) || treeSize < 0 || treeSize > Number.MAX_SAFE_INTEGER) return null;

  // Root hash must be exactly 64 lowercase hex chars (SHA-256 output)
  if (!/^[0-9a-f]{64}$/.test(rootHash)) return null;

  return { origin, treeSize, rootHash };
}
