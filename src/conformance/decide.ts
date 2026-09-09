/**
 * The witness as a conformance decider.
 *
 * The witness re-implements INK's byte-level rules instead of importing them,
 * which is the point: a rule two codebases agree on is a rule, and a rule one
 * codebase agrees with itself about is a habit. This module is the adapter
 * that lets an outside corpus ask the witness for a verdict, and it is
 * deliberately thin. It composes the same functions the request paths call and
 * decides nothing on their behalf, so a disagreement is the witness's, not the
 * adapter's.
 *
 * `test/conformance.test.ts` runs the vendored corpus through it. The INK
 * differential fuzzer runs generated cases through it as a third decider
 * alongside the TypeScript reference and the Go implementation.
 */

import { parseSignedBodyBytes } from "../shared/parse-signed-body.js";
import { jcsCanonicalize, computeEventHash } from "../shared/crypto.js";
import { parseTimestampMs } from "../shared/timestamp.js";
import { parseCheckpoint, formatCheckpoint } from "../shared/checkpoint.js";
import { MerkleTree } from "../merkle.js";

/** Corpus categories the witness decides. */
export const COVERED_CATEGORIES = [
  "jcs-number",
  "jcs-string-safety",
  "merkle-checkpoint",
  "merkle-inclusion",
  "merkle-leaf",
  "signed-body-member-name",
  "signed-body-utf8",
  "timestamp-validity",
] as const;

export type CoveredCategory = (typeof COVERED_CATEGORIES)[number];

/** Surfaces the witness answers for the INK differential harness. The harness
 *  names the gate-plus-canonicalize decision `signed-body-canonical` and drives
 *  it with generated bodies; the corpus splits the same decision across the
 *  three categories that exercise it. Same input, same verdict, two names. */
export const COVERED_SURFACES = [...COVERED_CATEGORIES, "signed-body-canonical"] as const;

/** Every other category, and why the witness has no verdict to offer. A
 *  witness that quietly skipped a category it could decide would be claiming
 *  agreement it never tested, so each line here is a standing claim that the
 *  rule is not one this implementation applies. */
export const UNCOVERED_CATEGORIES: Record<string, string> = {
  "agent-authorization": "sign-in is a relying-party surface; the witness is not one",
  "agent-card": "the witness reads a card for keys and never validates one as a whole",
  "agent-card-evidence": "no attestation surface",
  "agent-card-fetch": "the witness fetches cards through a service binding with its own response rules",
  "agent-card-signature": "card signatures are verified by the receiver, not the log",
  "agent-card-signature-phase-c": "same as agent-card-signature",
  "attestation": "no attestation surface",
  "audit-query-response": "the witness produces these; verifying one is the reader's job",
  "authorization-chain": "delegation is a post-1.0 extension the witness does not accept",
  "authorization-grant": "the witness authenticates transport, not grants",
  "authorization-header": "parsed inside verifyInkTransportAuth, not as a separable decision",
  "connection-payload": "handshake payloads never reach a witness",
  "discovery-query-envelope": "discovery is a directory surface",
  "evidence-refusal": "no attestation surface",
  "first-contact-transcript": "receiver-side, never logged by the witness",
  "handshake-message": "handshake payloads never reach a witness",
  "inclusion-receipt": "the witness issues receipts; verifying one is the holder's job",
  "key-rotation": "rotation windows are applied inside verifyInkTransportAuth, not as a separable decision",
  "merkle-consistency": "proofs are generated from tree state; the witness has no static verifier",
  "payload-encryption": "encrypted payloads are opaque to a transparency log",
  "principal-normalization": "the witness reads principals as given and does not normalize them",
  "private-hostname": "outbound destination policy, not a wire rule the witness applies",
  "replay-freshness": "nonce replay is stored state, not a pure decision over one input",
  "signature-base": "envelope verification runs inside verifyInkTransportAuth against stored keys",
};

export type ConformanceDecision = {
  result: "accept" | "reject";
  canonicalString?: string;
  epochMs?: number;
  leafHash?: string;
};

const REJECT: ConformanceDecision = { result: "reject" };

/** Decode hex the way Go's `encoding/hex` does: even length, hex alphabet, or
 *  nothing. This is transport, never a verdict; an undecodable input fails
 *  closed so the two sides are never comparing different bytes. */
function fromHex(hex: unknown): Uint8Array | null {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function asInt(v: unknown): number | null {
  return typeof v === "number" && Number.isInteger(v) ? v : null;
}

/** The gate plus canonicalization, the pair every signed body passes through. */
function canonicalizeBody(bodyRaw: unknown): ConformanceDecision {
  if (typeof bodyRaw !== "string") return REJECT;
  try {
    return { result: "accept", canonicalString: jcsCanonicalize(parseSignedBodyBytes(new TextEncoder().encode(bodyRaw))) };
  } catch {
    return REJECT;
  }
}

export async function decideConformanceCase(
  category: string,
  input: Record<string, unknown>,
): Promise<ConformanceDecision> {
  switch (category) {
    case "jcs-number":
    case "jcs-string-safety":
    case "signed-body-member-name":
    case "signed-body-canonical":
      return canonicalizeBody(input.bodyRaw);

    case "signed-body-utf8": {
      const bytes = fromHex(input.bodyHex);
      if (bytes === null) return REJECT;
      try {
        parseSignedBodyBytes(bytes);
        return { result: "accept" };
      } catch {
        return REJECT;
      }
    }

    case "timestamp-validity": {
      if (typeof input.timestamp !== "string") return REJECT;
      const ms = parseTimestampMs(input.timestamp);
      return ms === null ? REJECT : { result: "accept", epochMs: ms };
    }

    case "merkle-checkpoint": {
      if (typeof input.body !== "string") return REJECT;
      const parsed = parseCheckpoint(input.body);
      if (!parsed) return REJECT;
      return { result: "accept", canonicalString: formatCheckpoint(parsed) };
    }

    case "merkle-inclusion": {
      const leafIndex = asInt(input.leafIndex);
      const treeSize = asInt(input.treeSize);
      if (leafIndex === null || treeSize === null) return REJECT;
      try {
        const ok = await MerkleTree.verifyInclusionProof(
          input.leafHash as string,
          input.inclusionProof as string[],
          leafIndex,
          treeSize,
          input.rootHash as string,
        );
        return ok ? { result: "accept" } : REJECT;
      } catch {
        return REJECT;
      }
    }

    case "merkle-leaf": {
      // An audit event is a JSON object. An array, a string, a number or null
      // is not one and has no leaf hash, which is the same line the submit
      // schema draws before an event is ever hashed.
      if (typeof input.eventRaw !== "string") return REJECT;
      let event: unknown;
      try {
        event = parseSignedBodyBytes(new TextEncoder().encode(input.eventRaw));
      } catch {
        return REJECT;
      }
      if (event === null || typeof event !== "object" || Array.isArray(event)) return REJECT;
      try {
        return { result: "accept", leafHash: await computeEventHash(event as Record<string, unknown>) };
      } catch {
        return REJECT;
      }
    }

    default:
      throw new Error(`witness decider: no verdict for category ${category}`);
  }
}
