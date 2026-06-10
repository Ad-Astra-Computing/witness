import * as ed from "@noble/ed25519";
import canonicalize from "canonicalize";

// ── Encoding helpers ──

export function base64urlEncode(bytes: Uint8Array): string {
  const binString = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  const base64 = btoa(binString);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64urlDecode(str: string): Uint8Array {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binString = atob(padded);
  return Uint8Array.from(binString, (c) => c.charCodeAt(0));
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// ── JCS Canonicalization ──

/** A number is safe for canonical JSON only if every conforming canonicalizer
 *  serializes it identically: reject non-finite values, negative zero, and any
 *  value whose shortest form uses exponential notation. Mirrors the INK library
 *  so the witness and the library agree on the exact signed byte string. */
function isJcsSafeNumber(n: number): boolean {
  if (!Number.isFinite(n)) return false;
  if (Object.is(n, -0)) return false;
  return !/[eE]/.test(String(n));
}

/** Reject any JCS-unsafe number anywhere in the value before canonicalizing, so
 *  the canonical bytes are unambiguous across implementations. Depth-bounded to
 *  avoid stack exhaustion on a hostile object (events are already byte-capped at
 *  the HTTP layer). */
function assertJcsSafeNumbers(value: unknown, depth = 0): void {
  if (depth > 64) throw new Error("object too deep to canonicalize safely");
  if (typeof value === "number") {
    if (!isJcsSafeNumber(value)) throw new Error("number is not JCS-safe");
    return;
  }
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) assertJcsSafeNumbers(item, depth + 1);
    return;
  }
  for (const v of Object.values(value as Record<string, unknown>)) {
    assertJcsSafeNumbers(v, depth + 1);
  }
}

function jcsCanonicalize(obj: unknown): string {
  assertJcsSafeNumbers(obj);
  const result = canonicalize(obj);
  if (result === undefined) throw new Error("Failed to canonicalize");
  return result;
}

// ── Audit event crypto ──

export async function verifyAuditEventSignature(
  event: Record<string, unknown>,
  publicKey: Uint8Array,
): Promise<boolean> {
  const signature = event.agentSignature as string;
  if (typeof signature !== "string") return false;
  // Ed25519 signatures are exactly 64 bytes = 86 unpadded base64url chars.
  if (!/^[A-Za-z0-9_-]{86}$/.test(signature)) return false;
  const { agentSignature: _, ...eventWithoutSig } = event;
  try {
    // Canonicalize inside the try: an event carrying a JCS-unsafe number is
    // rejected (returns false) rather than throwing out of the verifier.
    const canonical = jcsCanonicalize(eventWithoutSig);
    // Domain separation: must match signAuditEvent prefix
    const prefixed = `ink/audit-event\n${canonical}`;
    const bytes = new TextEncoder().encode(prefixed);
    const sig = base64urlDecode(signature);
    return await ed.verifyAsync(sig, bytes, publicKey, { zip215: false });
  } catch {
    // Malformed signature/number/encoding — treat as invalid.
    return false;
  }
}

/**
 * Compute the leaf hash for a Merkle tree entry per RFC 6962 Section 2.1.
 * Leaf hashes use domain separation: SHA-256(0x00 || data).
 *
 * Note the name: this function computes the MERKLE LEAF HASH and is
 * used to populate the `event_hash` column. For per-agent chain
 * linkage (validating `previousEventHash`), use `computeAgentChainHash`
 * instead. Mixing the two will silently reject conformant submissions
 * because @adastracomputing/ink agents compute `previousEventHash` via
 * the unprefixed form.
 *
 * BREAKING CHANGE (v0.2): Previously computed as raw SHA-256(data) without
 * the 0x00 leaf prefix. Existing Merkle trees built before this change are
 * incompatible and must be rebuilt.
 */
export async function computeEventHash(event: Record<string, unknown>): Promise<string> {
  const { agentSignature: _, ...eventWithoutSig } = event;
  const canonical = jcsCanonicalize(eventWithoutSig);
  const eventBytes = new TextEncoder().encode(canonical);
  // RFC 6962 §2.1: leaf hash = SHA-256(0x00 || data)
  const prefixed = new Uint8Array(1 + eventBytes.length);
  prefixed[0] = 0x00;
  prefixed.set(eventBytes, 1);
  const digest = await crypto.subtle.digest("SHA-256", prefixed);
  return bytesToHex(new Uint8Array(digest));
}

/**
 * Per-agent chain-linkage hash. Used to validate `event.previousEventHash`
 * against the agent's most recently committed event. UNPREFIXED SHA-256
 * over JCS-canonicalized event (excluding agentSignature), matching the
 * `@adastracomputing/ink` library's `computeEventHash` exactly.
 *
 * Distinct from the Merkle leaf hash (`computeEventHash` in this file),
 * which RFC 6962 mandates be domain-separated with a leading 0x00.
 * Conformant INK agents compute `previousEventHash` via this unprefixed
 * form; the witness MUST validate against the same.
 */
export async function computeAgentChainHash(event: Record<string, unknown>): Promise<string> {
  const { agentSignature: _, ...eventWithoutSig } = event;
  const canonical = jcsCanonicalize(eventWithoutSig);
  const eventBytes = new TextEncoder().encode(canonical);
  const digest = await crypto.subtle.digest("SHA-256", eventBytes);
  return bytesToHex(new Uint8Array(digest));
}

export async function signData(data: string, privateKey: Uint8Array): Promise<string> {
  const bytes = new TextEncoder().encode(data);
  const sig = await ed.signAsync(bytes, privateKey);
  return base64urlEncode(sig);
}

// ── Key encoding/decoding helpers ──

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const ED25519_MULTICODEC = new Uint8Array([0xed, 0x01]);

/** Encode bytes as base58btc (no multibase prefix). */
export function encodeBase58(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";

  // Count leading zeros
  let zeros = 0;
  for (const b of bytes) {
    if (b !== 0) break;
    zeros++;
  }

  // Convert to bigint
  let num = 0n;
  for (const b of bytes) {
    num = num * 256n + BigInt(b);
  }

  let result = "";
  while (num > 0n) {
    const remainder = Number(num % 58n);
    num = num / 58n;
    result = BASE58_ALPHABET[remainder]! + result;
  }

  return "1".repeat(zeros) + result;
}

/**
 * Encode a raw Ed25519 public key as a multibase base58btc string.
 * Format: 'z' prefix + base58btc(0xed01 + public_key)
 */
export function encodePublicKeyMultibase(publicKey: Uint8Array): string {
  const prefixed = new Uint8Array(ED25519_MULTICODEC.length + publicKey.length);
  prefixed.set(ED25519_MULTICODEC);
  prefixed.set(publicKey, ED25519_MULTICODEC.length);
  return "z" + encodeBase58(prefixed);
}

/** Cap base58 input BEFORE the BigInt loop — see INK keys.ts for rationale.
 *  Without this, a 64 KB attacker-supplied multibase string forces O(n^2)
 *  BigInt arithmetic. 1024 is well above any legitimate multibase key. */
const MAX_BASE58_INPUT_LEN = 1024;

export function decodeBase58(str: string): Uint8Array {
  if (str.length === 0) return new Uint8Array(0);
  if (str.length > MAX_BASE58_INPUT_LEN) {
    throw new Error(`base58 input exceeds maximum length of ${MAX_BASE58_INPUT_LEN}`);
  }
  let num = 0n;
  for (const ch of str) {
    const idx = BASE58_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error(`Invalid base58 character: ${ch}`);
    num = num * 58n + BigInt(idx);
  }
  const hex = num.toString(16).padStart(2, "0");
  const padded = hex.length % 2 ? "0" + hex : hex;
  const bytes: number[] = [];
  for (let i = 0; i < padded.length; i += 2) {
    bytes.push(parseInt(padded.slice(i, i + 2), 16));
  }
  let zeros = 0;
  for (const ch of str) { if (ch !== "1") break; zeros++; }
  return new Uint8Array([...new Uint8Array(zeros), ...bytes]);
}

// ── INK Transport Auth (§3.3) ──

const MAX_TIMESTAMP_AGE_MS = 5 * 60 * 1000;  // 5 minutes
const MAX_FUTURE_TIMESTAMP_MS = 30 * 1000;    // 30 seconds

export type InkAuthResult =
  | { valid: true; senderAgentId: string }
  | { valid: false; error: string };

/**
 * Candidate key for multi-key verification (key rotation support).
 */
export interface WitnessCandidateKey {
  keyId: string;
  publicKey: Uint8Array;
  status: "active" | "retired" | "revoked";
}

const AGENT_CARD_TIMEOUT_MS = 3000;

/** Stream-read a Response body with a hard byte cap. Aborts after the cap
 * is exceeded so a chunked-transfer response without Content-Length cannot
 * force unbounded buffering. Returns null on cap-exceeded. */
async function readBodyWithCap(res: Response, capBytes: number): Promise<string | null> {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > capBytes) {
          try { await reader.cancel(); } catch { /* ignore */ }
          return null;
        }
        chunks.push(value);
      }
    }
  } finally {
    try { reader.releaseLock(); } catch { /* ignore */ }
  }
  const merged = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { merged.set(c, off); off += c.byteLength; }
  return new TextDecoder().decode(merged);
}

/**
 * Decode a multibase (base58btc, z-prefixed) public key to raw bytes.
 */
function decodePublicKeyMultibase(multibase: string): Uint8Array {
  if (!multibase.startsWith("z")) {
    throw new Error("Expected multibase base58btc prefix 'z'");
  }
  const decoded = decodeBase58(multibase.slice(1));
  if (decoded[0] !== ED25519_MULTICODEC[0] || decoded[1] !== ED25519_MULTICODEC[1]) {
    throw new Error("Invalid Ed25519 multicodec prefix");
  }
  const key = decoded.slice(2);
  if (key.length !== 32) {
    throw new Error(`Invalid Ed25519 public key length: expected 32, got ${key.length}`);
  }
  return key;
}

// ── Agent card LRU cache (max 100 entries, 5-min TTL) ──

interface CachedKeySet {
  keys: WitnessCandidateKey[];
  fetchedAt: number;
}

const CARD_CACHE_MAX = 100;
const CARD_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const cardCache = new Map<string, CachedKeySet>();

/**
 * Fetch the sender's agent card and extract signing keys as candidates.
 * Returns null if the card is unavailable or has no keys block.
 * Results are cached in-memory (LRU, max 100 entries, 5-min TTL).
 */
/** A subset of `Fetcher` (Cloudflare service binding) that resolveKeySetFromCard
 *  needs. Service bindings satisfy this directly; tests can pass any object
 *  with a compatible `.fetch()`. */
export interface AgentCardFetcher {
  fetch(input: RequestInfo, init?: RequestInit): Promise<Response>;
}

/** Thrown when the agent card could not be authoritatively resolved
 *  (network error, timeout, 5xx, redirect refusal, JSON parse failure,
 *  protocol/agentId mismatch, oversized body). Callers MUST treat this
 *  as auth failure — do NOT fall through to bootstrap, since we cannot
 *  prove the agent has not published a key set. The bootstrap path is
 *  only safe when we have a definitive "no key set published" answer
 *  (404 or a valid card with no `keys.signing` field), in which case
 *  the function returns null instead of throwing. */
export class AgentCardUnavailableError extends Error {
  constructor(reason: string) {
    super(`agent card unavailable: ${reason}`);
    this.name = "AgentCardUnavailableError";
  }
}

export async function resolveKeySetFromCard(
  agentId: string,
  fetcher: AgentCardFetcher,
  agentCardBaseUrl: string,
): Promise<WitnessCandidateKey[] | null> {
  // Check cache
  const cached = cardCache.get(agentId);
  if (cached && (Date.now() - cached.fetchedAt) < CARD_CACHE_TTL_MS) {
    // Move to end for LRU ordering
    cardCache.delete(agentId);
    cardCache.set(agentId, cached);
    return cached.keys;
  }

  const url = `${agentCardBaseUrl}/ink/v1/${encodeURIComponent(agentId)}/agent.json`;

  let card: {
    protocol?: string;
    keys?: {
      signing?: Array<{
        keyId: string;
        publicKeyMultibase: string;
        status: "active" | "retired" | "revoked";
      }>;
    };
  };
  let res: Response;
  try {
    res = await fetcher.fetch(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(AGENT_CARD_TIMEOUT_MS),
      // Refuse to follow redirects — the card endpoint is at a fixed path.
      // Service binding already bypasses DNS, but the redirect refusal is
      // defense-in-depth.
      redirect: "manual",
    });
  } catch (e) {
    // Network error, timeout, abort — we do NOT know whether a key set
    // exists, so callers MUST fail closed. Throwing is the explicit
    // "authority unavailable" signal.
    throw new AgentCardUnavailableError(`fetch failed: ${(e as Error)?.message ?? "unknown"}`);
  }

  // 404 is the canonical "no card published" answer — bootstrap is safe.
  if (res.status === 404) return null;
  // Any non-2xx other than 404 is an authority-unavailable signal.
  if (!res.ok) throw new AgentCardUnavailableError(`upstream status ${res.status}`);

  // Stream-read with a hard byte cap. Cap-after-buffer (res.text()) would
  // let a chunked oversized response allocate the whole body before any
  // check fires.
  const MAX_CARD_BYTES = 64 * 1024;
  const lenHeader = parseInt(res.headers.get("Content-Length") ?? "0", 10);
  if (!isNaN(lenHeader) && lenHeader > MAX_CARD_BYTES) {
    throw new AgentCardUnavailableError("response oversized");
  }
  const text = await readBodyWithCap(res, MAX_CARD_BYTES);
  if (text === null) throw new AgentCardUnavailableError("response oversized");
  try {
    card = JSON.parse(text);
  } catch {
    throw new AgentCardUnavailableError("invalid JSON");
  }

  // Top-level type guard.
  if (card === null || typeof card !== "object" || Array.isArray(card)) {
    throw new AgentCardUnavailableError("card is not an object");
  }
  if (card.protocol !== "ink/0.1") {
    throw new AgentCardUnavailableError("protocol mismatch");
  }
  // Identity binding: reject cards whose agentId does not match the requested
  // agentId. Without this check a compromised registry could return a
  // different agent's card, allowing key-confusion attacks.
  if ((card as { agentId?: string }).agentId !== agentId) {
    throw new AgentCardUnavailableError("agentId mismatch");
  }
  // Distinguish "no signing field at all" (null = no key set published, OK
  // to bootstrap-fall-back) from "signing array present but empty / all
  // revoked" (empty array = key set exists, authoritative reject — callers
  // MUST NOT fall back to the bootstrap key).
  const keysField = (card as { keys?: unknown }).keys;
  if (keysField === undefined || keysField === null) return null;
  if (typeof keysField !== "object" || Array.isArray(keysField)) {
    throw new AgentCardUnavailableError("keys field malformed");
  }
  const signing = (keysField as { signing?: unknown }).signing;
  if (signing === undefined) return null;
  if (!Array.isArray(signing)) {
    throw new AgentCardUnavailableError("keys.signing not an array");
  }
  if (signing.length === 0) {
    // Cache the empty result too — otherwise unauthenticated requests for
    // an agent that publishes an authoritative empty key set would force a
    // fresh card fetch on every request before authoritative rejection.
    if (cardCache.size >= CARD_CACHE_MAX) {
      const oldest = cardCache.keys().next().value;
      if (oldest !== undefined) cardCache.delete(oldest);
    }
    cardCache.delete(agentId);
    cardCache.set(agentId, { keys: [], fetchedAt: Date.now() });
    return [];
  }

  // Parse each entry individually. A malformed publicKeyMultibase on ONE
  // entry must not throw out of this function — that would surface as null
  // (card unavailable) and let callers bootstrap-fall-back to a key the
  // agent has rotated away from. Skip unparseable entries; if every entry
  // is unparseable, return [] (key set exists, no usable keys) → authoritative
  // reject.
  //
  // Cap the signing array to MAX_CANDIDATE_KEYS BEFORE the decode loop —
  // base58 decode is O(N^2) on a large input and a poisoned card with
  // thousands of entries would burn CPU before reaching the verification-
  // time cap. Also validate status against an explicit allowlist to drop
  // entries with malformed enum values.
  const candidatesToParse = (signing as unknown[]).slice(0, MAX_CANDIDATE_KEYS);
  const keys: WitnessCandidateKey[] = [];
  for (const rawEntry of candidatesToParse) {
    // Each entry must be a plain object with string keyId, string
    // publicKeyMultibase, and a status from the allowlist. Anything else
    // is skipped — never thrown out — so a single malformed entry can't
    // collapse the whole set to null (which would let bootstrap fallback
    // run after key rotation).
    if (rawEntry === null || typeof rawEntry !== "object" || Array.isArray(rawEntry)) continue;
    const entry = rawEntry as { keyId?: unknown; publicKeyMultibase?: unknown; status?: unknown };
    if (typeof entry.keyId !== "string" || typeof entry.publicKeyMultibase !== "string") continue;
    if (entry.status !== "active" && entry.status !== "retired" && entry.status !== "revoked") {
      continue;
    }
    try {
      keys.push({
        keyId: entry.keyId,
        publicKey: decodePublicKeyMultibase(entry.publicKeyMultibase),
        status: entry.status,
      });
    } catch {
      // Single unparseable entry — skip but keep parsing the rest.
    }
  }

  // Evict oldest entry if at capacity
  if (cardCache.size >= CARD_CACHE_MAX) {
    const oldest = cardCache.keys().next().value;
    if (oldest !== undefined) cardCache.delete(oldest);
  }
  // Remove stale entry if present
  cardCache.delete(agentId);
  cardCache.set(agentId, { keys, fetchedAt: Date.now() });

  return keys;
}

/** Maximum candidate keys tried per verification to prevent DoS from poisoned Agent Cards. */
export const MAX_CANDIDATE_KEYS = 20;

/**
 * Try verifying a signature against a set of candidate keys.
 * Order: active keys first, then retired. Revoked keys are skipped.
 * Returns { verified, keyId } on success, { verified: false } on failure.
 */
async function verifyWithCandidateKeys(
  sigBytes: Uint8Array,
  sigBase: Uint8Array,
  candidates: WitnessCandidateKey[],
  hintKeyId?: string,
): Promise<{ verified: true; keyId: string } | { verified: false }> {
  // Enforce key set size cap to prevent DoS via Agent Cards with many keys
  const bounded = candidates.slice(0, MAX_CANDIDATE_KEYS);

  // Try hinted key first if provided.
  // Use an allowlist of acceptable statuses. A deny-list (k.status !== "revoked")
  // would accept entries with malformed/unrecognised status strings — e.g. a
  // poisoned card with status "Revoked" (case mismatch) or empty string would
  // be skipped by the active/retired partition loop below but still match here.
  if (hintKeyId) {
    const hinted = bounded.find(
      (k) => k.keyId === hintKeyId && (k.status === "active" || k.status === "retired"),
    );
    if (hinted) {
      try {
        const valid = await ed.verifyAsync(sigBytes, sigBase, hinted.publicKey, { zip215: false });
        if (valid) return { verified: true, keyId: hinted.keyId };
      } catch {
        // Fall through to normal iteration
      }
    }
  }

  const active = bounded.filter((k) => k.status === "active");
  const retired = bounded.filter((k) => k.status === "retired");

  for (const key of [...active, ...retired]) {
    if (hintKeyId && key.keyId === hintKeyId) continue; // Already tried
    try {
      const valid = await ed.verifyAsync(sigBytes, sigBase, key.publicKey, { zip215: false });
      if (valid) return { verified: true, keyId: key.keyId };
    } catch {
      // Key failed, try next
    }
  }
  return { verified: false };
}

/**
 * Verify an INK-Ed25519 Authorization header per §3.3.
 * Signature base: ink/0.1\nMETHOD\nPATH\nrecipientDid\nJCS(body)\ntimestamp
 *
 * Key resolution order:
 * 1. resolveKeySet callback (if provided)
 * 2. Agent card fetch from main API (automatic rotation awareness)
 * 3. Bootstrap key from agentId (only when no key set exists)
 *
 * If the agent has rotated keys (key set found), the bootstrap key
 * embedded in the agentId is NOT trusted — a compromised bootstrap key
 * must not bypass rotation.
 */
export async function verifyInkTransportAuth(opts: {
  authHeader: string | undefined;
  method: string;
  path: string;
  recipientDid: string;
  body: Record<string, unknown>;
  resolveKeySet?: (agentId: string) => WitnessCandidateKey[] | null;
  /** Service binding used to fetch agent cards. When omitted, agent-card
   *  fallback is disabled and verification relies on the `resolveKeySet`
   *  callback or the bootstrap key extracted from agentId. */
  agentCardFetcher?: AgentCardFetcher;
  /** Base URL the agent-card fetch targets. Required when
   *  `agentCardFetcher` is supplied; ignored otherwise. */
  agentCardBaseUrl?: string;
}): Promise<InkAuthResult> {
  if (!opts.authHeader) {
    return { valid: false, error: "missing_authorization" };
  }

  // Enforce length bounds before regex matching to prevent CPU/memory waste.
  // Ed25519 signatures are exactly 64 bytes = 86 base64url chars (no padding).
  // keyId max 128 chars (generous but bounded).
  if (opts.authHeader.length > 512) {
    return { valid: false, error: "invalid_auth_scheme" };
  }
  // Ed25519 signatures are exactly 86 base64url chars — tighten the regex to
  // {86} so clearly-wrong lengths get rejected up front, rather than burning
  // CPU on the downstream length check + decode for a malformed value.
  const match = opts.authHeader.match(/^INK-Ed25519\s+([A-Za-z0-9_-]{86})(?:\s+keyId=([A-Za-z0-9_:.-]{1,128}))?$/);
  if (!match) {
    return { valid: false, error: "invalid_auth_scheme" };
  }
  const signature = match[1]!;
  const hintKeyId = match[2] ?? undefined;

  // Require string types — non-string values (numbers, objects, etc.) must be rejected
  // before being used in key resolution, signature-base construction, or downstream auth.
  const senderDid = opts.body.from;
  if (typeof senderDid !== "string" || !senderDid) {
    return { valid: false, error: "missing_sender" };
  }
  // Cap before any expensive resolution (card fetch, base58 decode) to
  // prevent CPU/memory waste on attacker-supplied oversized DIDs.
  if (senderDid.length > 256) {
    return { valid: false, error: "missing_sender" };
  }

  const timestamp = opts.body.timestamp;
  if (typeof timestamp !== "string" || !timestamp) {
    return { valid: false, error: "missing_timestamp" };
  }

  // Timestamp freshness check (§3.5)
  const msgTime = new Date(timestamp).getTime();
  if (isNaN(msgTime)) {
    return { valid: false, error: "invalid_timestamp" };
  }
  const now = Date.now();
  const drift = msgTime - now;
  if (drift > MAX_FUTURE_TIMESTAMP_MS) {
    return { valid: false, error: "timestamp_too_far_future" };
  }
  if (-drift > MAX_TIMESTAMP_AGE_MS) {
    return { valid: false, error: "timestamp_expired" };
  }

  // Reject newlines in scalar signature-base fields. Because the base string is
  // newline-delimited, a field containing \n or \r could shift field boundaries,
  // allowing two distinct logical inputs to produce the same signed bytes.
  const crlf = /[\r\n]/;
  if (crlf.test(opts.method)) return { valid: false, error: "invalid_auth_scheme" };
  if (crlf.test(opts.path)) return { valid: false, error: "invalid_auth_scheme" };
  if (crlf.test(opts.recipientDid)) return { valid: false, error: "invalid_auth_scheme" };
  // timestamp is already validated above as a proper ISO date string so newlines
  // would be caught by isNaN(msgTime), but guard explicitly for defence-in-depth.
  if (crlf.test(timestamp)) return { valid: false, error: "invalid_timestamp" };

  // Build signature base
  const canonical = jcsCanonicalize(opts.body);
  const sigBase = `ink/0.1\n${opts.method}\n${opts.path}\n${opts.recipientDid}\n${canonical}\n${timestamp}`;
  const sigBaseBytes = new TextEncoder().encode(sigBase);
  // Decode signature safely — malformed base64url must not throw a 500
  let sigBytes: Uint8Array;
  try {
    sigBytes = base64urlDecode(signature);
  } catch {
    return { valid: false, error: "invalid_auth_scheme" };
  }
  // Ed25519 signatures are exactly 64 bytes
  if (sigBytes.length !== 64) {
    return { valid: false, error: "invalid_auth_scheme" };
  }

  // Try multi-key verification: callback first, then agent card fetch
  let hasKeySet = false;

  // Key resolution semantics (mirrors INK middleware):
  //   null/undefined → no key set published for this agent → fall through to bootstrap
  //   []             → key set published but no usable signing keys (e.g. all
  //                     revoked) → authoritative reject; MUST NOT use bootstrap key
  //   [k1, ...]      → try each candidate; if none verify, authoritative reject
  if (opts.resolveKeySet) {
    const candidates = opts.resolveKeySet(senderDid);
    if (candidates !== null && candidates !== undefined) {
      hasKeySet = true;
      if (candidates.length > 0) {
        const result = await verifyWithCandidateKeys(sigBytes, sigBaseBytes, candidates, hintKeyId);
        if (result.verified) {
          return { valid: true, senderAgentId: senderDid };
        }
      }
    }
  }

  // If no callback key set, try fetching the agent card via the service
  // binding. If the integrator did not supply one, skip card fallback —
  // bootstrap path below remains.
  // resolveKeySetFromCard throws AgentCardUnavailableError on transient
  // failures (network, timeout, 5xx, invalid JSON, mismatch). Treat that
  // as auth failure: we cannot prove "no key set", so the bootstrap
  // fallback is unsafe.
  if (!hasKeySet && opts.agentCardFetcher && opts.agentCardBaseUrl) {
    let cardKeys: WitnessCandidateKey[] | null;
    try {
      cardKeys = await resolveKeySetFromCard(senderDid, opts.agentCardFetcher, opts.agentCardBaseUrl);
    } catch {
      return { valid: false, error: "unresolvable_sender_key" };
    }
    if (cardKeys !== null && cardKeys !== undefined) {
      hasKeySet = true;
      if (cardKeys.length > 0) {
        const result = await verifyWithCandidateKeys(sigBytes, sigBaseBytes, cardKeys, hintKeyId);
        if (result.verified) {
          return { valid: true, senderAgentId: senderDid };
        }
      }
    }
  }

  // If a key set exists but none matched (including the empty-set case),
  // do NOT fall through to bootstrap.
  if (hasKeySet) {
    return { valid: false, error: "invalid_signature" };
  }

  // No key set found (agent never rotated) — fall back to bootstrap key
  let publicKey: Uint8Array;
  try {
    publicKey = extractPublicKeyFromAgentId(senderDid);
  } catch {
    return { valid: false, error: "unresolvable_sender_key" };
  }

  try {
    const valid = await ed.verifyAsync(sigBytes, sigBaseBytes, publicKey, { zip215: false });
    if (!valid) {
      return { valid: false, error: "invalid_signature" };
    }
    return { valid: true, senderAgentId: senderDid };
  } catch {
    return { valid: false, error: "signature_verification_failed" };
  }
}

// ── Key extraction from agent ID ──

export function extractPublicKeyFromAgentId(agentId: string): Uint8Array {
  const prefix = "tulpa:";
  if (!agentId.startsWith(prefix)) {
    throw new Error(`Invalid agent ID format: ${agentId}`);
  }
  const multibase = agentId.slice(prefix.length);
  if (!multibase.startsWith("z")) {
    throw new Error("Expected multibase base58btc prefix 'z'");
  }
  const decoded = decodeBase58(multibase.slice(1));
  if (decoded[0] !== ED25519_MULTICODEC[0] || decoded[1] !== ED25519_MULTICODEC[1]) {
    throw new Error("Invalid Ed25519 multicodec prefix");
  }
  const key = decoded.slice(2);
  if (key.length !== 32) {
    throw new Error(`Invalid Ed25519 public key length: expected 32, got ${key.length}`);
  }
  return key;
}
