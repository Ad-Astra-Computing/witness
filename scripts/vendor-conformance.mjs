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
import { mkdtempSync, readFileSync, writeFileSync, rmSync, mkdirSync, readdirSync, renameSync, existsSync } from "node:fs";
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

/** Reject an archive that could write outside where it is unpacked. The
 *  tarball is a downloaded artifact whose publisher also writes the digests
 *  inside it, so the digest check below proves consistency and not
 *  authenticity; the entry names are the part that can reach the filesystem. */
function assertSafeArchive(tarball) {
  const listing = execFileSync("tar", ["-tvzf", tarball], { encoding: "utf8" });
  for (const line of listing.split("\n")) {
    if (line.trim() === "") continue;
    if (!line.startsWith("-") && !line.startsWith("d")) {
      throw new Error(`tarball carries a link or special file: ${line}`);
    }
    const name = line.slice(line.indexOf(" package/") + 1);
    if (name.startsWith("/") || name.split("/").includes("..")) {
      throw new Error(`tarball carries an unsafe path: ${name}`);
    }
  }
}

/** Run a tidy-up step that is happening because something else already went
 *  wrong. Its own failure is worth saying out loud but must not replace the
 *  error the caller is about to raise. */
function quietly(step, what) {
  try {
    step();
  } catch (err) {
    console.warn(`${what}: ${err.message}`);
  }
}

function corpusRoot(argv) {
  const fromPath = argv.indexOf("--from-path");
  if (fromPath !== -1) {
    const dir = argv[fromPath + 1];
    if (!dir) throw new Error("--from-path needs a directory");
    return { root: join(dir, "conformance", "v1"), source: `path:${dir}`, integrity: null, cleanup: () => {} };
  }
  const version = argv[0];
  // An exact version only. A tag or a range makes what was vendored depend on
  // when it was vendored, and PROVENANCE.json would record a name rather than
  // a thing.
  if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version ?? "")) {
    throw new Error("usage: vendor-conformance.mjs <exact version>");
  }
  const tmp = mkdtempSync(join(tmpdir(), "ink-corpus-"));
  const cleanup = () => rmSync(tmp, { recursive: true, force: true });
  try {
    const packed = JSON.parse(
      execFileSync("npm", ["pack", `${PKG}@${version}`, "--pack-destination", tmp, "--json"], {
        encoding: "utf8",
      }),
    )[0];
    const tarball = join(tmp, packed.filename);
    assertSafeArchive(tarball);
    execFileSync("tar", ["-xzf", tarball, "-C", tmp, "--no-same-owner", "--no-same-permissions"]);
    return {
      root: join(tmp, "package", "conformance", "v1"),
      source: `${PKG}@${version}`,
      integrity: packed.integrity ?? null,
      cleanup,
    };
  } catch (err) {
    // Tidying up must not replace the reason the download failed.
    quietly(cleanup, "could not remove the download directory");
    throw err;
  }
}

const { root, source, integrity, cleanup } = corpusRoot(process.argv.slice(2));
let staged = null;
try {
  const manifestBytes = readFileSync(join(root, "manifest.json"));
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  const byId = new Map(manifest.categories.map((c) => [c.id, c]));

  const missing = COVERED.filter((id) => !byId.has(id));
  if (missing.length > 0) throw new Error(`corpus has no category: ${missing.join(", ")}`);

  // Everything is read and checked into a staging directory first, and the
  // checked-in corpus is replaced only once all of it passed. A failure
  // halfway through would otherwise leave a tree that is part one version and
  // part another, which is the one state the digests cannot detect.
  // The scratch names carry the pid so two refreshes running at once cannot
  // delete or rename each other's half-built tree.
  const staging = `${OUT}.staging.${process.pid}`;
  rmSync(staging, { recursive: true, force: true });
  mkdirSync(join(staging, "vectors"), { recursive: true });
  staged = staging;

  const vendored = [];
  for (const id of COVERED) {
    const entry = byId.get(id);
    // The manifest names the file. A name that climbs out of the corpus root
    // decides which file gets read, so it is checked before it is used.
    if (typeof entry.vector !== "string" || entry.vector.startsWith("/") || entry.vector.split("/").includes("..")) {
      throw new Error(`${id}: manifest names an unsafe vector path ${entry.vector}`);
    }
    const bytes = readFileSync(join(root, entry.vector));
    // The manifest digest is the corpus's own integrity claim. Checking it
    // here means a truncated or inconsistent tarball fails at vendor time, not
    // as a puzzling vector failure later. It is a consistency check and not an
    // authenticity one: whoever published the tarball wrote both halves.
    const digest = sha256(bytes);
    if (digest !== entry.sha256) {
      throw new Error(`${id}: tarball digest ${digest} does not match manifest ${entry.sha256}`);
    }
    writeFileSync(join(staging, "vectors", `${id}.json`), bytes);
    vendored.push({ id, caseCount: entry.caseCount, sha256: entry.sha256 });
  }

  writeFileSync(join(staging, "manifest.json"), manifestBytes);
  writeFileSync(
    join(staging, "PROVENANCE.json"),
    JSON.stringify(
      {
        source,
        integrity,
        corpus: manifest.corpus,
        vendoredAt: new Date().toISOString().slice(0, 10),
        manifestSha256: sha256(manifestBytes),
        vectors: vendored,
      },
      null,
      2,
    ) + "\n",
  );

  // Once the live corpus has been moved aside there is a window with no
  // corpus at all. If installing the new one fails, put the old one back
  // rather than leaving the repository with nothing to check against.
  const previous = `${OUT}.previous.${process.pid}`;
  rmSync(previous, { recursive: true, force: true });
  const moved = existsSync(OUT);
  if (moved) renameSync(OUT, previous);
  try {
    renameSync(staging, OUT);
  } catch (err) {
    if (moved && !existsSync(OUT)) renameSync(previous, OUT);
    throw err;
  }
  rmSync(previous, { recursive: true, force: true });
  console.log(`vendored ${vendored.length} categories from ${source}`);
  staged = null;
} catch (err) {
  // Both steps run, and neither is allowed to replace the reason the refresh
  // failed.
  if (staged) quietly(() => rmSync(staged, { recursive: true, force: true }), "could not remove the half-built corpus");
  quietly(cleanup, "could not remove the download directory");
  throw err;
}

// Nothing else went wrong, so a tidy-up failure is the only news there is and
// it leaves scratch directories behind. Let it set the exit code.
cleanup();
