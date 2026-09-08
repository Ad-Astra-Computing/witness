// The witness decider, for the INK differential harness. NDJSON cases in,
// NDJSON decisions out, the protocol the TypeScript and Go deciders speak.
// `--surfaces` prints what this witness decides so the harness can ask.

import { createInterface } from "node:readline";
import { decideConformanceCase, COVERED_SURFACES } from "../src/conformance/decide.js";

if (process.argv.includes("--surfaces")) {
  process.stdout.write(COVERED_SURFACES.join("\n") + "\n");
  process.exit(0);
}

// Fault injection for the harness's own negative control. When INK_DIFF_MUTANT
// names a surface, this decider inverts its answer on that surface only, so the
// harness can prove it would actually report a disagreement between the witness
// and the reference. A decider whose divergence nobody can detect is not a
// decider. Off unless the variable is set.
const MUTANT = process.env.INK_DIFF_MUTANT ?? "";

const out: string[] = [];
const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of rl) {
  if (line.trim() === "") continue;
  const c = JSON.parse(line) as { caseId: string; surface: string; input: Record<string, unknown> };
  let decision;
  try {
    decision = await decideConformanceCase(c.surface, c.input);
  } catch (err) {
    // Reported, never silently rejected: a crash on one side is itself a
    // divergence worth seeing.
    decision = { result: "reject", reason: `__harness_error:${(err as Error).message}` };
  }
  if (MUTANT !== "" && c.surface === MUTANT) {
    decision = { ...decision, result: decision.result === "accept" ? "reject" : "accept" };
  }
  out.push(JSON.stringify({ caseId: c.caseId, ...decision }));
  if (out.length >= 512) {
    process.stdout.write(out.join("\n") + "\n");
    out.length = 0;
  }
}
if (out.length > 0) process.stdout.write(out.join("\n") + "\n");
