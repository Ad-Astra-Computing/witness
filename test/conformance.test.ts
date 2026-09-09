/**
 * The vendored INK conformance corpus, run against the witness.
 *
 * Every other test here builds a value, feeds it to the witness, and checks
 * the witness agrees with itself, which is why the number profile once drifted
 * a whole protocol revision behind INK without a single failure. These cases
 * come from outside: the digests are the corpus's own, the verdicts were
 * written against the reference implementation, and the witness had no say in
 * any of them.
 *
 * Refresh with `node scripts/vendor-conformance.mjs <version>`.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { decideConformanceCase, COVERED_CATEGORIES, UNCOVERED_CATEGORIES } from "../src/conformance/decide.js";

const CORPUS = join(import.meta.dirname, "..", "conformance");

type Case = {
  caseId: string;
  description: string;
  input: Record<string, unknown>;
  expect: { result: "accept" | "reject" } & Record<string, unknown>;
};

const manifest = JSON.parse(readFileSync(join(CORPUS, "manifest.json"), "utf8")) as {
  format: string;
  corpus: string;
  categories: { id: string; caseCount: number; sha256: string }[];
};
const provenance = JSON.parse(readFileSync(join(CORPUS, "PROVENANCE.json"), "utf8")) as {
  corpus: string;
  manifestSha256: string;
  vectors: { id: string; caseCount: number; sha256: string }[];
};

describe("vendored corpus integrity", () => {
  it("carries the manifest the vectors were vendored from", () => {
    const digest = createHash("sha256").update(readFileSync(join(CORPUS, "manifest.json"))).digest("hex");
    expect(digest).toBe(provenance.manifestSha256);
    expect(provenance.corpus).toBe(manifest.corpus);
  });

  it("vendors exactly the categories the witness claims to decide", () => {
    const onDisk = readdirSync(join(CORPUS, "vectors")).map((f) => f.replace(/\.json$/, "")).sort();
    expect(onDisk).toEqual([...COVERED_CATEGORIES].sort());
    expect(provenance.vectors.map((v) => v.id).sort()).toEqual([...COVERED_CATEGORIES].sort());
  });

  it("accounts for every category in the corpus", () => {
    // A category added upstream lands here rather than going unnoticed: the
    // witness either decides it or says in one line why it cannot.
    const accounted = new Set([...COVERED_CATEGORIES, ...Object.keys(UNCOVERED_CATEGORIES)]);
    const unaccounted = manifest.categories.map((c) => c.id).filter((id) => !accounted.has(id));
    expect(unaccounted).toEqual([]);
  });

  it("holds the bytes the manifest names, case for case", () => {
    for (const id of COVERED_CATEGORIES) {
      const bytes = readFileSync(join(CORPUS, "vectors", `${id}.json`));
      const entry = manifest.categories.find((c) => c.id === id);
      expect(entry, `manifest has no ${id}`).toBeDefined();
      expect(createHash("sha256").update(bytes).digest("hex"), `${id} digest`).toBe(entry!.sha256);
      const vectors = JSON.parse(bytes.toString("utf8")) as { format: string; category: string; cases: Case[] };
      expect(vectors.format).toBe("ink.conformance.v1");
      expect(vectors.category).toBe(id);
      expect(vectors.cases).toHaveLength(entry!.caseCount);
    }
  });
});

for (const category of COVERED_CATEGORIES) {
  const vectors = JSON.parse(
    readFileSync(join(CORPUS, "vectors", `${category}.json`), "utf8"),
  ) as { cases: Case[] };

  describe(category, () => {
    for (const c of vectors.cases) {
      it(`${c.caseId}: ${c.description}`, async () => {
        const decision = await decideConformanceCase(category, c.input);
        expect(decision.result, c.description).toBe(c.expect.result);
        // A verdict that agrees by accident is not agreement, so every value
        // the corpus carries is compared too.
        for (const [key, value] of Object.entries(c.expect)) {
          if (key === "result" || key === "reason") continue;
          expect(decision[key as keyof typeof decision], `${c.caseId} ${key}`).toEqual(value);
        }
      });
    }
  });
}
