/**
 * Vendor a frozen slice of the INK conformance corpus into `conformance/`.
 *
 * The witness re-implements the INK byte-level rules rather than importing
 * them, which is what makes it an independent decider and also what lets it
 * drift. Its own tests cannot notice: a self-referential round trip agrees
 * with whatever the witness currently does. The corpus is the outside
 * reference, so it is checked in rather than resolved at test time, and
 * refreshing it is a deliberate act recorded in `PROVENANCE.json`.
 *
 * Vectors come from the published tarball, not from a working copy, so what
 * the witness is tested against is what an adopter downloads.
 *
 *   node scripts/vendor-conformance.mjs 0.19.0
 *   node scripts/vendor-conformance.mjs --from-path ../ink   # local corpus
 */

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync, rmSync, mkdirSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(REPO, "conformance");
const PKG = "@adastracomputing/ink";

/** The categories the witness decides, and for the rest, why it does not.
 *  Every category in the corpus manifest must appear in one list or the
 *  other, so a category added upstream is a test failure rather than a
 *  silent gap. */
const COVERED = [
  "jcs-number",
  "jcs-string-safety",
  "merkle-checkpoint",
  "merkle-inclusion",
  "merkle-leaf",
  "signed-body-member-name",
  "signed-body-utf8",
  "timestamp-validity",
];

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function corpusRoot(argv) {
  const fromPath = argv.indexOf("--from-path");
  if (fromPath !== -1) {
    const dir = argv[fromPath + 1];
    if (!dir) throw new Error("--from-path needs a directory");
    return { root: join(dir, "conformance", "v1"), source: `path:${dir}`, cleanup: () => {} };
  }
  const version = argv[0];
  if (!version || version.startsWith("-")) throw new Error("usage: vendor-conformance.mjs <version>");
  const tmp = mkdtempSync(join(tmpdir(), "ink-corpus-"));
  const tarball = execFileSync("npm", ["pack", `${PKG}@${version}`, "--pack-destination", tmp], {
    encoding: "utf8",
  }).trim().split("\n").pop();
  execFileSync("tar", ["-xzf", join(tmp, tarball), "-C", tmp]);
  return {
    root: join(tmp, "package", "conformance", "v1"),
    source: `${PKG}@${version}`,
    cleanup: () => rmSync(tmp, { recursive: true, force: true }),
  };
}

const { root, source, cleanup } = corpusRoot(process.argv.slice(2));
try {
  const manifestBytes = readFileSync(join(root, "manifest.json"));
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  const byId = new Map(manifest.categories.map((c) => [c.id, c]));

  const missing = COVERED.filter((id) => !byId.has(id));
  if (missing.length > 0) throw new Error(`corpus has no category: ${missing.join(", ")}`);

  mkdirSync(join(OUT, "vectors"), { recursive: true });
  for (const stale of readdirSync(join(OUT, "vectors"))) {
    if (!COVERED.includes(stale.replace(/\.json$/, ""))) rmSync(join(OUT, "vectors", stale));
  }

  const vendored = [];
  for (const id of COVERED) {
    const entry = byId.get(id);
    const bytes = readFileSync(join(root, entry.vector));
    // The manifest digest is the corpus's own integrity claim. Checking it
    // here means a tampered or truncated tarball fails at vendor time, not as
    // a puzzling vector failure later.
    const digest = sha256(bytes);
    if (digest !== entry.sha256) {
      throw new Error(`${id}: tarball digest ${digest} does not match manifest ${entry.sha256}`);
    }
    writeFileSync(join(OUT, "vectors", `${id}.json`), bytes);
    vendored.push({ id, caseCount: entry.caseCount, sha256: entry.sha256 });
  }

  writeFileSync(join(OUT, "manifest.json"), manifestBytes);
  writeFileSync(
    join(OUT, "PROVENANCE.json"),
    JSON.stringify(
      {
        source,
        corpus: manifest.corpus,
        vendoredAt: new Date().toISOString().slice(0, 10),
        manifestSha256: sha256(manifestBytes),
        vectors: vendored,
      },
      null,
      2,
    ) + "\n",
  );
  console.log(`vendored ${vendored.length} categories from ${source}`);
} finally {
  cleanup();
}
