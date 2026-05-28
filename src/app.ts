import { Hono } from "hono";
import type { Env } from "./types.js";
import { InkAuditSubmitSchema, MAX_AUDIT_EVENT_DATA_BYTES } from "./shared/schemas.js";
import { verifyAuditEventSignature, extractPublicKeyFromAgentId, verifyInkTransportAuth, resolveKeySetFromCard, MAX_CANDIDATE_KEYS, type WitnessCandidateKey } from "./shared/crypto.js";
import { landingPageHtml } from "./landing.js";

/** Create the Hono app. Exported for testing. */
export function createApp() {
  const app = new Hono<{ Bindings: Env }>();

  /** Get the global WitnessLog DO stub. */
  function getWitnessLog(env: Env) {
    const id = env.WITNESS_LOG.idFromName("global");
    return env.WITNESS_LOG.get(id);
  }

  // Witness DID is operator-configured via env. Used both as the
  // recipientDid in inbound INK auth verification (so submissions signed
  // for a different witness do not authenticate here) and as the value
  // checked against body.to. Set WITNESS_DID in wrangler.toml [vars].
  function witnessDid(env: Env): string {
    return env.WITNESS_DID;
  }

  /** Peek at nonce state — does NOT commit. Returns true if the nonce
   * appears fresh; lets the worker early-reject obvious replays before
   * doing expensive signature work. */
  async function peekNonce(env: Env, nonce: string): Promise<boolean> {
    const stub = getWitnessLog(env);
    const res = await stub.fetch(
      new Request(`https://witness.internal/nonce-check?nonce=${encodeURIComponent(nonce)}&mode=peek`, {
        method: "POST",
      }),
    );
    const json = await res.json() as { ok: boolean };
    return json.ok;
  }

  /** Atomically check + record a nonce. Call only after all signature
   * verification has succeeded. Returns false on replay or race. */
  async function commitNonce(env: Env, nonce: string): Promise<boolean> {
    const stub = getWitnessLog(env);
    const res = await stub.fetch(
      new Request(`https://witness.internal/nonce-check?nonce=${encodeURIComponent(nonce)}&mode=commit`, {
        method: "POST",
      }),
    );
    const json = await res.json() as { ok: boolean };
    return json.ok;
  }

  // ── Rate limiting ──
  //
  // Per-bucket fixed-minute-window counters live in the WitnessLog DO so
  // they're consistent across isolates. The app layer composes the
  // buckets passed to the DO for each request type:
  //   submit: [agent, ip?, cidr?]
  //   query:  [agent, ip?, cidr?]
  // ip/cidr buckets are skipped when CF-Connecting-IP is absent (dev/test)
  // because there's no client IP to bind to.

  const RATE_LIMIT_AGENT_PER_MIN_DEFAULT = 30;
  const RATE_LIMIT_IP_PER_MIN_DEFAULT = 60;
  const RATE_LIMIT_CIDR_PER_MIN_DEFAULT = 300;

  /** Parse a positive-integer env override, falling back to `defaultValue`
   *  when the env var is unset, empty, or out of [1, 1_000_000]. The
   *  upper bound matches the DO-side cap on maxPerMinute so the demo
   *  can't accidentally configure caps the DO would reject. */
  function rateCapFromEnv(envValue: string | undefined, defaultValue: number): number {
    if (typeof envValue !== "string" || envValue.length === 0) return defaultValue;
    const n = Number(envValue);
    if (!Number.isInteger(n) || n < 1 || n > 1_000_000) return defaultValue;
    return n;
  }

  type RateBucket = { key: string; maxPerMinute: number };

  /** Normalize a value extracted from CF-Connecting-IP. Trims
   *  whitespace, takes the leftmost entry of any comma list (in case a
   *  misconfigured proxy chain forwarded XFF-style), strips IPv6 zone
   *  IDs (`fe80::1%eth0`), and collapses `::ffff:V4MAPPED` to the
   *  embedded IPv4 so an attacker can't pick which bucket their
   *  packets fall into by varying the encoding. Returns null if the
   *  result doesn't parse as either an IPv4 dotted quad or IPv6
   *  literal. */
  function normalizeIp(raw: string): string | null {
    let ip = raw.trim();
    if (ip.length === 0) return null;
    const comma = ip.indexOf(",");
    if (comma !== -1) ip = ip.slice(0, comma).trim();
    const pct = ip.indexOf("%");
    if (pct !== -1) ip = ip.slice(0, pct);
    if (/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/.test(ip)) {
      const parts = ip.split(".");
      for (const p of parts) {
        const n = Number(p);
        if (!Number.isInteger(n) || n < 0 || n > 255) return null;
      }
      return parts.map((p) => String(Number(p))).join(".");
    }
    if (!ip.includes(":")) return null;
    const mappedMatch = ip.match(/^[0:]*ffff:([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$/i);
    if (mappedMatch) {
      const v4 = normalizeIp(mappedMatch[1]!);
      return v4;
    }
    const expanded = expandIpv6(ip);
    if (!expanded) return null;
    const hextets = expanded.split(":");
    if (
      hextets.length === 8 &&
      hextets[0] === "0000" && hextets[1] === "0000" &&
      hextets[2] === "0000" && hextets[3] === "0000" &&
      hextets[4] === "0000" && hextets[5] === "ffff"
    ) {
      const high = parseInt(hextets[6]!, 16);
      const low = parseInt(hextets[7]!, 16);
      if (Number.isFinite(high) && Number.isFinite(low)) {
        return `${(high >> 8) & 0xff}.${high & 0xff}.${(low >> 8) & 0xff}.${low & 0xff}`;
      }
    }
    return expanded;
  }

  /** Extract the client IP from CF-Connecting-IP and compute /24 IPv4 or
   *  /64 IPv6 CIDR prefix. Returns null if no client IP is available
   *  or the header cannot be parsed as either form, signalling that
   *  IP/CIDR checks should be skipped. */
  function extractIpBuckets(req: Request): { ip: string; cidr: string } | null {
    const raw = req.headers.get("CF-Connecting-IP");
    if (!raw) return null;
    const ip = normalizeIp(raw);
    if (!ip) return null;
    if (/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(ip)) {
      const parts = ip.split(".");
      return { ip, cidr: `${parts[0]}.${parts[1]}.${parts[2]}.0/24` };
    }
    const hextets = ip.split(":");
    if (hextets.length === 8) {
      return { ip, cidr: `${hextets.slice(0, 4).join(":")}::/64` };
    }
    return null;
  }

  /** Expand an IPv6 address with `::` shorthand to 8 hextets. Returns
   *  null if the input is not a valid IPv6 literal. Strict on empty
   *  hextets: they are legal only as the marker introduced by `::`,
   *  never inside `head` or `tail` post-split. Without this guard,
   *  literals like `1:2:3:4:5:6:7:` or `:1:2:3:4:5:6:7` would
   *  normalize to a valid-looking /64 bucket. */
  function expandIpv6(ip: string): string | null {
    if (ip.includes(":::")) return null;
    const parts = ip.split("::");
    if (parts.length > 2) return null;
    const head = parts[0] === "" ? [] : parts[0]!.split(":");
    const tail = parts.length === 2 ? (parts[1] === "" ? [] : parts[1]!.split(":")) : [];
    if (parts.length === 1) {
      if (head.length !== 8) return null;
    } else {
      if (head.length + tail.length >= 8) return null;
    }
    const fillCount = 8 - head.length - tail.length;
    const fill = Array(fillCount).fill("0");
    const all = [...head, ...fill, ...tail];
    if (all.length !== 8) return null;
    for (const h of all) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(h)) return null;
    }
    return all.map((h) => h.toLowerCase().padStart(4, "0")).join(":");
  }

  /** Ask the DO to atomically check + increment a set of rate-limit
   *  buckets. Returns {ok:true} if all buckets were below their cap and
   *  every bucket was incremented; {ok:false, exceeded:bucketKey}
   *  otherwise (no buckets incremented). */
  async function checkRateLimit(env: Env, buckets: RateBucket[]): Promise<{ ok: boolean; exceeded?: string }> {
    if (buckets.length === 0) return { ok: true };
    const stub = getWitnessLog(env);
    const res = await stub.fetch(
      new Request("https://witness.internal/ratelimit-check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ buckets }),
      }),
    );
    if (!res.ok) {
      // Fail open on infrastructure errors so a misbehaving DO doesn't
      // take down legitimate traffic. Operator-side alerting on the DO
      // is the recovery path; over-rejection here would worsen outages.
      return { ok: true };
    }
    return await res.json() as { ok: boolean; exceeded?: string };
  }

  /** Compose the bucket list for a submit request. */
  function submitBuckets(env: Env, agentId: string, req: Request): RateBucket[] {
    const agentCap = rateCapFromEnv(env.RATE_LIMIT_AGENT_PER_MIN, RATE_LIMIT_AGENT_PER_MIN_DEFAULT);
    const ipCap = rateCapFromEnv(env.RATE_LIMIT_IP_PER_MIN, RATE_LIMIT_IP_PER_MIN_DEFAULT);
    const cidrCap = rateCapFromEnv(env.RATE_LIMIT_CIDR_PER_MIN, RATE_LIMIT_CIDR_PER_MIN_DEFAULT);
    const buckets: RateBucket[] = [
      { key: `agent:${agentId}`, maxPerMinute: agentCap },
    ];
    const ipInfo = extractIpBuckets(req);
    if (ipInfo) {
      buckets.push({ key: `ip:${ipInfo.ip}`, maxPerMinute: ipCap });
      buckets.push({ key: `cidr:${ipInfo.cidr}`, maxPerMinute: cidrCap });
    }
    return buckets;
  }

  // ── Request body size limits ──

  /** Max raw body size for audit submit (bytes). Prevents parse/JCS work on huge bodies. */
  const MAX_SUBMIT_BODY_BYTES = 64 * 1024;  // 64 KB

  /** Max raw body size for audit query (bytes). */
  const MAX_QUERY_BODY_BYTES = 4 * 1024;    // 4 KB

  /**
   * Stream-read a request body with a hard byte cap. Aborts and returns null
   * once the cap is exceeded, without buffering further chunks. Protects
   * against chunked-transfer requests that omit or lie about Content-Length
   * — c.req.text() otherwise buffers the entire body before any size check.
   */
  async function readBodyWithCap(req: Request, capBytes: number): Promise<string | null> {
    if (!req.body) return "";
    const reader = req.body.getReader();
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
    let offset = 0;
    for (const c of chunks) { merged.set(c, offset); offset += c.byteLength; }
    return new TextDecoder().decode(merged);
  }

  // ── Routes ──

  app.post("/ink/v1/audit/submit", async (c) => {
    // Enforce raw body size limit before JSON.parse and transport auth to prevent
    // CPU/memory waste on large bodies before any field caps apply.
    const contentLength = parseInt(c.req.header("Content-Length") ?? "0", 10);
    if (!isNaN(contentLength) && contentLength > MAX_SUBMIT_BODY_BYTES) {
      return c.json({ error: "Request body too large" }, 413);
    }

    // Stream-read with a hard cap so a chunked request without Content-Length
    // can't force unbounded buffering before the size check.
    const bodyText = await readBodyWithCap(c.req.raw, MAX_SUBMIT_BODY_BYTES);
    if (bodyText === null) {
      return c.json({ error: "Request body too large" }, 413);
    }

    let body: unknown;
    try {
      body = JSON.parse(bodyText);
    } catch {
      return c.json({ error: "Invalid JSON" }, 400);
    }

    // Require body to be a plain object — reject null, arrays, and other JSON root types
    if (body === null || typeof body !== "object" || Array.isArray(body)) {
      return c.json({ error: "Request body must be a JSON object" }, 400);
    }

    // Verify INK transport auth (§3.3)
    const authResult = await verifyInkTransportAuth({
      authHeader: c.req.header("Authorization"),
      method: "POST",
      path: "/ink/v1/audit/submit",
      recipientDid: witnessDid(c.env),
      body: body as Record<string, unknown>,
      agentCardFetcher: c.env.AGENT_DIRECTORY,
      agentCardBaseUrl: c.env.AGENT_CARD_BASE_URL,
    });
    if (!authResult.valid) {
      return c.json({ error: authResult.error }, 401);
    }

    // Rate limiting: per-agent + per-IP + per-CIDR. Fresh keypairs from
    // the same client are caught by ip/cidr buckets; honest agents on
    // shared NAT are caught by the higher cidr cap.
    {
      const rl = await checkRateLimit(c.env, submitBuckets(c.env, authResult.senderAgentId, c.req.raw));
      if (!rl.ok) {
        return c.json({ error: "rate_limit_exceeded", exceeded: rl.exceeded }, 429);
      }
    }

    // Schema validation
    const parsed = InkAuditSubmitSchema.safeParse(body);
    if (!parsed.success) {
      return c.json({ error: "Invalid submit body" }, 400);
    }

    // Storage-DoS guard: enforce a max serialized size on the data field.
    // zod can't size-check z.record(z.unknown()) so we do it explicitly here.
    if (parsed.data.event.data !== undefined) {
      const dataSize = new TextEncoder().encode(
        JSON.stringify(parsed.data.event.data),
      ).length;
      if (dataSize > MAX_AUDIT_EVENT_DATA_BYTES) {
        return c.json({ error: "event.data too large" }, 400);
      }
    }

    // Cheap optimistic replay check — does NOT commit. The commit happens
    // after every signature has been verified, so a malformed-but-
    // transport-authenticated submission cannot burn nonces.
    const noncePeek = await peekNonce(c.env, parsed.data.nonce);
    if (!noncePeek) {
      return c.json({ error: "nonce_replay" }, 401);
    }

    // Verify submission is addressed to this Witness — prevents confusing audit semantics
    if (parsed.data.to !== witnessDid(c.env)) {
      return c.json({ error: "Submission must be addressed to witness DID" }, 400);
    }

    // Verify sender consistency: transport auth sender must match body.from and event.agentId
    if (authResult.senderAgentId !== parsed.data.from) {
      return c.json({ error: "Transport sender does not match body.from" }, 401);
    }
    if (parsed.data.from !== parsed.data.event.agentId) {
      return c.json({ error: "Event agentId does not match submission sender" }, 400);
    }

    // Audit event timestamp freshness check.
    // The schema requires a datetime string, so invalid timestamps should be rejected.
    // Reject NaN (malformed despite passing schema) and extreme future values.
    const eventTimestamp = new Date(parsed.data.event.timestamp).getTime();
    const MAX_EVENT_FUTURE_MS = 5 * 60 * 1000; // 5 minutes tolerance
    if (isNaN(eventTimestamp)) {
      return c.json({ error: "Event timestamp is invalid" }, 400);
    }
    if (eventTimestamp > Date.now() + MAX_EVENT_FUTURE_MS) {
      return c.json({ error: "Event timestamp is too far in the future" }, 400);
    }

    // Verify agent signature on the embedded event.
    // Must be rotation-aware: try key set from agent card first, only
    // fall back to bootstrap key when no key set exists.
    const eventRecord = parsed.data.event as unknown as Record<string, unknown>;
    const eventAgentId = parsed.data.event.agentId;

    let eventSigValid = false;

    // Try rotation-aware verification via agent card.
    //   null            → no key set published; fall through to bootstrap
    //   []              → key set published but all keys revoked → authoritative
    //                     reject; a stolen bootstrap key MUST NOT authenticate here
    //   [k..]           → try each candidate up to MAX_CANDIDATE_KEYS
    //   throws          → authority unavailable; fail closed (do NOT bootstrap)
    let eventKeys: WitnessCandidateKey[] | null;
    try {
      eventKeys = await resolveKeySetFromCard(eventAgentId, c.env.AGENT_DIRECTORY, c.env.AGENT_CARD_BASE_URL);
    } catch {
      return c.json({ error: "agent card unavailable" }, 503);
    }
    if (eventKeys !== null && eventKeys !== undefined) {
      // Try each active/retired key (skip revoked). Bound the total to
      // MAX_CANDIDATE_KEYS so a poisoned Agent Card with many keys cannot
      // force unbounded Ed25519 verifications — matches the cap that
      // transport auth applies via verifyWithCandidateKeys.
      const active = eventKeys.filter((k) => k.status === "active");
      const retired = eventKeys.filter((k) => k.status === "retired");
      const bounded = [...active, ...retired].slice(0, MAX_CANDIDATE_KEYS);
      for (const key of bounded) {
        if (await verifyAuditEventSignature(eventRecord, key.publicKey)) {
          eventSigValid = true;
          break;
        }
      }
      // If we got here with no verification, authoritative reject — do not
      // fall through to bootstrap.
    } else {
      // No key set published → fall back to bootstrap key (TOFU window).
      let publicKey: Uint8Array;
      try {
        publicKey = extractPublicKeyFromAgentId(eventAgentId);
      } catch {
        return c.json({ error: "Invalid agent ID format" }, 400);
      }
      eventSigValid = await verifyAuditEventSignature(eventRecord, publicKey);
    }

    if (!eventSigValid) {
      return c.json({ error: "Invalid agent signature" }, 400);
    }

    // All signatures verified — only now commit the nonce. A concurrent
    // submission of the same nonce will lose the race here and be rejected.
    const nonceCommitted = await commitNonce(c.env, parsed.data.nonce);
    if (!nonceCommitted) {
      return c.json({ error: "nonce_replay" }, 401);
    }

    const stub = getWitnessLog(c.env);
    const doReq = new Request("https://witness.internal/submit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: bodyText,
    });
    const res = await stub.fetch(doReq);
    return new Response(res.body, {
      status: res.status,
      headers: res.headers,
    });
  });

  app.post("/ink/v1/audit/query", async (c) => {
    // Enforce raw body size limit
    const queryContentLength = parseInt(c.req.header("Content-Length") ?? "0", 10);
    if (!isNaN(queryContentLength) && queryContentLength > MAX_QUERY_BODY_BYTES) {
      return c.json({ error: "Request body too large" }, 413);
    }

    // Stream-read with a hard cap — same protection as /submit.
    const bodyText = await readBodyWithCap(c.req.raw, MAX_QUERY_BODY_BYTES);
    if (bodyText === null) {
      return c.json({ error: "Request body too large" }, 413);
    }

    let bodyUnknown: unknown;
    try {
      bodyUnknown = JSON.parse(bodyText);
    } catch {
      return c.json({ error: "Invalid JSON" }, 400);
    }

    // Require body to be a plain object
    if (bodyUnknown === null || typeof bodyUnknown !== "object" || Array.isArray(bodyUnknown)) {
      return c.json({ error: "Request body must be a JSON object" }, 400);
    }
    const body = bodyUnknown as Record<string, unknown>;

    // Verify INK transport auth
    const authResult = await verifyInkTransportAuth({
      authHeader: c.req.header("Authorization"),
      method: "POST",
      path: "/ink/v1/audit/query",
      recipientDid: witnessDid(c.env),
      body,
      agentCardFetcher: c.env.AGENT_DIRECTORY,
      agentCardBaseUrl: c.env.AGENT_CARD_BASE_URL,
    });
    if (!authResult.valid) {
      return c.json({ error: authResult.error }, 401);
    }

    // Rate limiting: per-agent + per-IP + per-CIDR. Without these, an
    // authenticated agent can flood unique signed nonces and grow
    // nonce_cache until TTL pruning catches up, and fresh-keypair
    // attackers can bypass the per-agent cap entirely.
    {
      const rl = await checkRateLimit(c.env, submitBuckets(c.env, authResult.senderAgentId, c.req.raw));
      if (!rl.ok) {
        return c.json({ error: "rate_limit_exceeded", exceeded: rl.exceeded }, 429);
      }
    }

    // Nonce replay protection — peek only; commit after all validation.
    // Require a string type explicitly: non-string truthy values (e.g. numbers)
    // have .length === undefined, which passes numeric comparison checks silently.
    const queryNonce = body.nonce;
    // Match the InkAuditSubmitSchema nonce check: length AND charset.
    // Without the regex, CRLF or other special chars could be stored in
    // the nonce table and contaminate log output downstream.
    if (typeof queryNonce !== "string" || queryNonce.length < 16 || queryNonce.length > 256 ||
        !/^[A-Za-z0-9_-]+$/.test(queryNonce)) {
      return c.json({ error: "nonce is required" }, 400);
    }
    const queryNoncePeek = await peekNonce(c.env, queryNonce);
    if (!queryNoncePeek) {
      return c.json({ error: "nonce_replay" }, 401);
    }

    // Require messageId to be a non-empty string with a reasonable length cap to
    // prevent storage-DoS via unbounded messageId strings forwarded to the DO.
    const messageId = body.messageId;
    if (typeof messageId !== "string" || !messageId || messageId.length > 256) {
      return c.json({ error: "messageId is required" }, 400);
    }

    // All validation passed — commit the nonce now.
    const queryNonceCommitted = await commitNonce(c.env, queryNonce);
    if (!queryNonceCommitted) {
      return c.json({ error: "nonce_replay" }, 401);
    }

    // Forward to DO with verified requester identity
    const stub = getWitnessLog(c.env);
    const doReq = new Request("https://witness.internal/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ messageId, requester: authResult.senderAgentId }),
    });
    const res = await stub.fetch(doReq);
    return new Response(res.body, {
      status: res.status,
      headers: res.headers,
    });
  });

  app.get("/ink/v1/checkpoint", async (c) => {
    const stub = getWitnessLog(c.env);
    const res = await stub.fetch(new Request("https://witness.internal/checkpoint"));
    return new Response(res.body, {
      status: res.status,
      headers: res.headers,
    });
  });

  app.get("/ink/v1/leaves", async (c) => {
    // Validate and clamp query parameters before forwarding
    const startRaw = parseInt(c.req.query("start") ?? "0", 10);
    const countRaw = parseInt(c.req.query("count") ?? "100", 10);
    if (isNaN(startRaw) || isNaN(countRaw) || startRaw < 0 || countRaw <= 0) {
      return c.json({ error: "Invalid start or count" }, 400);
    }
    const start = Math.min(startRaw, Number.MAX_SAFE_INTEGER);
    const count = Math.min(countRaw, 1000);

    const stub = getWitnessLog(c.env);
    const res = await stub.fetch(
      new Request(`https://witness.internal/leaves?start=${start}&count=${count}`),
    );
    return new Response(res.body, {
      status: res.status,
      headers: res.headers,
    });
  });

  app.get("/.well-known/did.json", async (c) => {
    const stub = getWitnessLog(c.env);
    const res = await stub.fetch(new Request("https://witness.internal/identity"));
    const identity = await res.json() as { did: string; publicKeyMultibase: string };

    return c.json({
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1",
      ],
      id: identity.did,
      verificationMethod: [
        {
          id: `${identity.did}#witness-key`,
          type: "Ed25519VerificationKey2020",
          controller: identity.did,
          publicKeyMultibase: identity.publicKeyMultibase,
        },
      ],
      authentication: [`${identity.did}#witness-key`],
      assertionMethod: [`${identity.did}#witness-key`],
    });
  });

  app.get("/", (c) => {
    return new Response(landingPageHtml(c.env.WITNESS_ORIGIN), {
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  });

  app.get("/health", async (c) => {
    // Pull current tree state from the DO so /health doubles as a
    // quick liveness probe AND a Merkle-head pointer (Rekor-style).
    // Bounded at 2s so a saturated DO can't make /health hang past
    // automated-failover thresholds; absence of `log` then degrades
    // gracefully.
    let log: { treeSize: number; rootHash: string } | null = null;
    try {
      const stub = getWitnessLog(c.env);
      const res = await stub.fetch(
        new Request("https://witness.internal/tree-state", { signal: AbortSignal.timeout(2000) }),
      );
      if (res.ok) log = await res.json() as { treeSize: number; rootHash: string };
    } catch {
      // Keep /health responsive even if the DO is slow.
    }
    const cf = (c.req.raw as Request & { cf?: { colo?: string } }).cf;
    return c.json({
      status: log ? "ok" : "degraded",
      service: c.env.WITNESS_DID,
      time: new Date().toISOString(),
      ...(log ? { log } : {}),
      ...(cf?.colo ? { region: cf.colo } : {}),
    });
  });

  // Avoid noisy 404s in browser DevTools when visiting the landing page.
  app.get("/favicon.ico", () => new Response(null, { status: 204 }));

  return app;
}
