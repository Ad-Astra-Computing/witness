export interface CheckpointData {
  origin: string;
  treeSize: number;
  rootHash: string;
}

export function formatCheckpoint(data: CheckpointData): string {
  return `${data.origin}\n${data.treeSize}\n${data.rootHash}\n`;
}

export function parseCheckpoint(body: string): CheckpointData | null {
  const lines = body.split("\n");
  // Expect exactly: origin, treeSize, rootHash, trailing newline (produces 4 parts).
  // Strict equality eliminates parser differential with C2SP tlog-checkpoint
  // reference implementations that reject trailing junk.
  if (lines.length !== 4) return null;
  if (lines[3] !== "") return null;

  const origin = lines[0]!;
  const treeSizeLine = lines[1]!;
  const rootHash = lines[2]!;

  // Origin must be non-empty
  if (!origin) return null;

  // Tree size must be a non-negative integer with no trailing junk
  if (!/^\d+$/.test(treeSizeLine)) return null;
  const treeSize = parseInt(treeSizeLine, 10);
  if (isNaN(treeSize) || treeSize < 0 || treeSize > Number.MAX_SAFE_INTEGER) return null;

  // Root hash must be exactly 64 lowercase hex chars (SHA-256 output)
  if (!/^[0-9a-f]{64}$/.test(rootHash)) return null;

  return { origin, treeSize, rootHash };
}
