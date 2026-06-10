import { DurableObject } from "cloudflare:workers";
import * as ed from "@noble/ed25519";
import canonicalize from "canonicalize";
import type { Env } from "./types.js";
import { initWitnessSchema } from "./schema.js";
import { MerkleTree } from "./merkle.js";
import {
  computeEventHash,
  computeAgentChainHash,
  signData,
  encodePublicKeyMultibase,
  bytesToHex,
} from "./shared/crypto.js";
import { z } from "zod";
import { InkAuditSubmitSchema, InkAuditEventSchema } from "./shared/schemas.js";

// DO-internal query payload schema. app.ts constructs this from pre-validated
// values, but the DO must validate independently so a future caller that
// passes raw client data cannot trigger SQL DoS via a malformed messageId.
const InternalQuerySchema = z.object({
  messageId: z.string().min(1).max(256).regex(/^[A-Za-z0-9_:.\-]+$/),
  requester: z.string().min(1).max(256).regex(/^[A-Za-z0-9_:.\-]+$/),
});
import { formatCheckpoint } from "./shared/checkpoint.js";
import { encryptPrivateKey, decryptPrivateKeyWithFallback, isEncryptedKey, validateWitnessKeySecret } from "./key-encryption.js";

/** Hard upper bound on nonce_cache rows to prevent storage growth between
 * TTL pruning cycles. At ~100 bytes/row this caps storage around ~10 MB. */
const MAX_NONCE_CACHE_ENTRIES = 100_000;

/** Hard caps on /audit/query response shape. A requester can submit
 *  many events to the same messageId; without these caps a query
 *  could force the witness to canonicalize + sign an unbounded body. */
const MAX_QUERY_EVENTS = 1_000;
const MAX_QUERY_RESPONSE_BYTES = 1 * 1024 * 1024;

export class WitnessLog extends DurableObject {
  private tree!: MerkleTree;
  private privateKey!: Uint8Array;
  private publicKey!: Uint8Array;
  private did!: string;
  private nonceCheckCount = 0;
  private readonly keySecret: string;
  private readonly witnessDid: string;
  private readonly witnessOrigin: string;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    // Fail loudly at startup if the deployment is missing or has a
    // low-entropy WITNESS_KEY_SECRET. Catching this at first request
    // would leave the door open to encrypting/storing the witness signing
    // key under a guessable key for the lifetime of the DO.
    validateWitnessKeySecret(env.WITNESS_KEY_SECRET);
    this.keySecret = env.WITNESS_KEY_SECRET;
    if (typeof env.WITNESS_DID !== "string" || env.WITNESS_DID.length === 0) {
      throw new Error("WITNESS_DID must be set in wrangler [vars]");
    }
    if (typeof env.WITNESS_ORIGIN !== "string" || env.WITNESS_ORIGIN.length === 0) {
      throw new Error("WITNESS_ORIGIN must be set in wrangler [vars]");
    }
    this.witnessDid = env.WITNESS_DID;
    this.witnessOrigin = env.WITNESS_ORIGIN;

    ctx.blockConcurrencyWhile(async () => {
      initWitnessSchema(ctx.storage.sql);
      this.tree = new MerkleTree(ctx.storage.sql);
      await this.ensureIdentity(ctx.storage.sql);
    });
  }

  private async ensureIdentity(sql: SqlStorage): Promise<void> {
    const rows = sql.exec("SELECT private_key, public_key, did FROM identity WHERE id = 'witness'").toArray();

    if (rows.length > 0) {
      const row = rows[0]!;
      const storedKey = row.private_key as string;

      if (isEncryptedKey(storedKey)) {
        // Encrypted key: decrypt with fallback to a legacy SHA-256 derivation
        // path. If the value was written under the legacy derivation, we
        // re-encrypt under HKDF and rewrite storage so subsequent reads use
        // the current scheme.
        //
        // Re-encryption is wrapped in try/catch because encryptPrivateKey
        // refuses weak secrets (defense against offline brute-force of a
        // freshly-rewritten ciphertext). On a weak-secret deployment we
        // keep the legacy ciphertext in storage, it is no worse than what
        // was there before, and log the failure for operator visibility.
        const { plaintext, usedLegacyDerivation } = await decryptPrivateKeyWithFallback(storedKey, this.keySecret);
        this.privateKey = plaintext;
        if (usedLegacyDerivation) {
          try {
            const reEncrypted = await encryptPrivateKey(this.privateKey, this.keySecret);
            sql.exec(
              "UPDATE identity SET private_key = ? WHERE id = 'witness'",
              reEncrypted,
            );
            console.warn("Re-encrypted witness private key using HKDF-derived AES key (was legacy SHA-256)");
          } catch (e) {
            console.warn(
              "Could not re-encrypt witness private key to HKDF — leaving legacy ciphertext in place. " +
              "Rotate WITNESS_KEY_SECRET to a strong CSPRNG value and restart to migrate.",
              e,
            );
          }
        }
      } else {
        // Legacy plaintext hex key — load it and re-encrypt in place.
        // If the secret is too weak to encrypt under, keep it as plaintext
        // (matches the pre-encryption behaviour) rather than crashing.
        this.privateKey = hexToBytes(storedKey);
        try {
          const encrypted = await encryptPrivateKey(this.privateKey, this.keySecret);
          sql.exec(
            "UPDATE identity SET private_key = ? WHERE id = 'witness'",
            encrypted,
          );
        } catch (e) {
          console.warn(
            "Could not encrypt legacy plaintext witness key — leaving as-is. " +
            "Rotate WITNESS_KEY_SECRET to a strong CSPRNG value and restart to migrate.",
            e,
          );
        }
      }

      this.publicKey = hexToBytes(row.public_key as string);
      this.did = row.did as string;
      // Refuse to silently serve a stored identity that diverges from the
      // currently-configured WITNESS_DID. Operators who legitimately rotate
      // the witness DID must explicitly clear the DO's identity row first;
      // continuing here would let the app verify submissions to one DID
      // while checkpoints and DID-doc proofs reference another.
      if (this.did !== this.witnessDid) {
        throw new Error(
          `Stored witness identity DID (${this.did}) does not match WITNESS_DID env (${this.witnessDid}). ` +
            "Refusing to start. Either set WITNESS_DID back to the stored value, " +
            "or wipe the identity row to regenerate.",
        );
      }
      return;
    }

    // Generate new Ed25519 keypair
    const { secretKey, publicKey } = await ed.keygenAsync();
    this.privateKey = secretKey;
    this.publicKey = publicKey;
    this.did = this.witnessDid;

    const encryptedKey = await encryptPrivateKey(this.privateKey, this.keySecret);
    sql.exec(
      "INSERT INTO identity (id, private_key, public_key, did) VALUES ('witness', ?, ?, ?)",
      encryptedKey,
      bytesToHex(this.publicKey),
      this.did,
    );
  }

  /** Check if a nonce has been seen — read-only, does NOT record. */
  hasSeenNonce(nonce: string): boolean {
    const existing = this.ctx.storage.sql.exec(
      "SELECT 1 FROM nonce_cache WHERE nonce = ?",
      nonce,
    ).toArray();
    return existing.length > 0;
  }

  /** Atomically check + record a nonce. Returns false if already seen
   * (replay) or already recorded by a concurrent submission. */
  checkAndStoreNonce(nonce: string): boolean {
    if (this.hasSeenNonce(nonce)) return false;

    // Hard upper bound on the nonce cache to prevent storage growth from
    // a flood of valid signed nonces between TTL pruning cycles. Prune
    // expired entries first; if still over the cap, drop the oldest by
    // expires_at to bound table size.
    const count = this.ctx.storage.sql.exec("SELECT COUNT(*) AS n FROM nonce_cache").toArray()[0] as { n: number };
    if (count && Number(count.n) >= MAX_NONCE_CACHE_ENTRIES) {
      this.pruneExpiredNonces();
      const afterPrune = this.ctx.storage.sql.exec("SELECT COUNT(*) AS n FROM nonce_cache").toArray()[0] as { n: number };
      if (afterPrune && Number(afterPrune.n) >= MAX_NONCE_CACHE_ENTRIES) {
        // Evict 10% oldest entries to make headroom.
        const evictTarget = Math.floor(MAX_NONCE_CACHE_ENTRIES / 10);
        this.ctx.storage.sql.exec(
          "DELETE FROM nonce_cache WHERE rowid IN (SELECT rowid FROM nonce_cache ORDER BY expires_at ASC LIMIT ?)",
          evictTarget,
        );
      }
    }

    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    this.ctx.storage.sql.exec(
      "INSERT INTO nonce_cache (nonce, expires_at) VALUES (?, ?)",
      nonce,
      expiresAt,
    );

    this.nonceCheckCount++;
    if (this.nonceCheckCount % 100 === 0) {
      this.pruneExpiredNonces();
    }

    return true;
  }

  /** Delete expired nonce entries. */
  pruneExpiredNonces(): void {
    this.ctx.storage.sql.exec(
      "DELETE FROM nonce_cache WHERE expires_at < ?",
      new Date().toISOString(),
    );
  }

  /** Handle nonce check forwarded from the Hono layer.
   * mode=peek: read-only `hasSeen` check (no commit). Lets the worker
   * early-reject obvious replays before doing expensive signature work.
   * mode=commit (default): atomic check-and-store. Call only after all
   * authentication has succeeded, so a malformed-but-authenticated request
   * cannot burn nonces. */
  handleNonceCheck(request: Request): Response {
    const url = new URL(request.url);
    const nonce = url.searchParams.get("nonce");
    if (!nonce) {
      return Response.json({ error: "missing_nonce" }, { status: 400 });
    }
    // Defense-in-depth on the DO boundary. app.ts already validates these
    // before calling, but the DO is independently reachable via internal
    // service bindings and must not trust its caller for shape.
    if (nonce.length < 16 || nonce.length > 256 || !/^[A-Za-z0-9_-]+$/.test(nonce)) {
      return Response.json({ error: "invalid_nonce" }, { status: 400 });
    }
    const mode = url.searchParams.get("mode") ?? "commit";
    if (mode === "peek") {
      return Response.json({ ok: !this.hasSeenNonce(nonce) });
    }
    const ok = this.checkAndStoreNonce(nonce);
    return Response.json({ ok });
  }

  /** Handle submit — verify signature, append to Merkle tree, store event, return inclusion receipt. */
  async handleSubmit(request: Request): Promise<Response> {
    const body = await request.json();
    const parsed = InkAuditSubmitSchema.safeParse(body);
    if (!parsed.success) {
      return Response.json({ error: "Invalid submit body" }, { status: 400 });
    }

    const { event } = parsed.data;

    // Signature already verified by the Hono layer before reaching the DO.

    // Compute the event hash up-front. computeEventHash is the only async op
    // between the initial dup/chain checks and the Merkle append. Doing it
    // here keeps the rest of the handler synchronous, which closes a TOCTOU
    // window: in a DO, an `await` releases the input gate and lets a second
    // concurrent submit start. With the hash already in hand, the chain
    // check, dup check, appendLeaf, and INSERT all run in one uninterrupted
    // synchronous block — no phantom Merkle leaves from races.
    const eventHash = await computeEventHash(event as unknown as Record<string, unknown>);

    // Enforce per-agent hash-chain continuity before granting Merkle inclusion.
    //
    // `event_hash` is the RFC 6962 Merkle leaf hash (0x00-prefixed) used
    // for tree lookups. INK chain-linkage uses the UNPREFIXED form, so
    // we fetch the previous event's canonical JSON and compute the
    // unprefixed hash on demand.
    const latestForAgent = this.ctx.storage.sql.exec(
      `SELECT sequence, event_json FROM audit_events
       WHERE agent_id = ? AND sequence IS NOT NULL
       ORDER BY sequence DESC LIMIT 1`,
      event.agentId,
    ).toArray()[0] as { sequence?: number; event_json?: string } | undefined;

    if (!latestForAgent) {
      if (event.sequence !== 1 || event.previousEventHash !== null) {
        return Response.json(
          { error: "First event for agent must have sequence=1 and null previousEventHash" },
          { status: 400 },
        );
      }
    } else {
      const expectedSequence = Number(latestForAgent.sequence) + 1;
      if (event.sequence !== expectedSequence) {
        return Response.json(
          { error: "Non-contiguous audit sequence" },
          { status: 409 },
        );
      }
      let previousEvent: { agentId?: unknown; sequence?: unknown };
      try {
        previousEvent = JSON.parse(latestForAgent.event_json as string);
      } catch {
        return Response.json({ error: "Integrity error" }, { status: 500 });
      }
      // Cross-check the parsed previous event against the SQL row we
      // selected by `agent_id`. If a storage bug let column-vs-JSON
      // drift accumulate, we MUST NOT chain-link onto a row whose
      // embedded payload belongs to a different agent.
      if (previousEvent.agentId !== event.agentId) {
        return Response.json({ error: "Integrity error" }, { status: 500 });
      }
      if (previousEvent.sequence !== Number(latestForAgent.sequence)) {
        return Response.json({ error: "Integrity error" }, { status: 500 });
      }
      const expectedChainHash = await computeAgentChainHash(previousEvent as Record<string, unknown>);
      if (event.previousEventHash !== expectedChainHash) {
        return Response.json(
          { error: "previousEventHash does not match agent chain head" },
          { status: 409 },
        );
      }
    }

    // Defense in depth for legacy rows where no chain head is available.
    if (event.sequence > 1 && !event.previousEventHash) {
      return Response.json(
        { error: "previousEventHash required for sequence > 1" },
        { status: 400 },
      );
    }

    // Reject duplicate event IDs — prevents phantom Merkle leaves
    const existing = this.ctx.storage.sql.exec(
      "SELECT 1 FROM audit_events WHERE event_id = ?",
      event.id,
    ).toArray();
    if (existing.length > 0) {
      return Response.json({ error: "Duplicate event ID" }, { status: 409 });
    }

    // Atomically commit the Merkle write and the event INSERT so a failure
    // in either rolls back both. Without the transaction, a quota or
    // constraint failure on INSERT after appendLeaf has already written to
    // merkle_nodes would leave a phantom Merkle leaf with no durable event.
    //
    // The transaction also needs a snapshot/restore of the MerkleTree
    // in-memory state — appendLeaf bumps `treeSize` and writes to the
    // subtree cache *in memory* before the SQL commit. If the transaction
    // rolls back, the SQL state reverts but the in-memory counters do not;
    // the next accepted submit would skip an index or compute proofs against
    // missing leaves.
    const treeSnapshot = this.tree.snapshotState();
    let leafIndex: number;
    let treeSize: number;
    let rootHash: string;
    try {
      const committed = this.ctx.storage.transactionSync(() => {
        const r = this.tree.appendLeaf(eventHash);
        this.ctx.storage.sql.exec(
          `INSERT INTO audit_events (event_id, message_id, agent_id, sequence, event_hash, counterparty_id, event_json, event_type)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          event.id,
          event.messageId ?? null,
          event.agentId,
          event.sequence,
          eventHash,
          event.counterpartyId ?? null,
          JSON.stringify(event),
          event.eventType,
        );
        return r;
      });
      leafIndex = committed.leafIndex;
      treeSize = committed.treeSize;
      rootHash = committed.rootHash;
    } catch (e) {
      // Transaction rolled back — restore in-memory tree state so the next
      // accepted submit lands at the correct index. Surface a generic 500.
      this.tree.restoreState(treeSnapshot);
      console.error("witness submit transaction failed", e);
      return Response.json({ error: "submit_failed" }, { status: 500 });
    }

    // Generate Merkle inclusion proof (read after the transaction commits)
    const inclusionProof = this.tree.getInclusionProof(leafIndex, treeSize) ?? [];

    // Sign the inclusion receipt with domain-separated, JCS-canonical format.
    // Use RFC 8785 JCS (via the `canonicalize` library) so that verifiers
    // using any conformant JCS implementation can reconstruct the same bytes.
    // The custom sort-then-stringify approach was fragile for non-primitive
    // nested values and not portable across implementations.
    const timestamp = new Date().toISOString();
    const inclusionPayload = {
      eventId: event.id,
      leafIndex,
      treeSize,
      rootHash,
      timestamp,
    };
    const canonicalized = canonicalize(inclusionPayload);
    if (canonicalized === undefined) throw new Error("Failed to canonicalize inclusion payload");
    // INK protocol-canonical inclusion-receipt signature: domain prefix
    // ink/audit-inclusion/v1 + JCS(receipt-fields-without-serviceSignature).
    // Spec: INK Auditability Section 7. Implementation-neutral so any
    // conformant verifier reconstructs the same bytes regardless of who
    // produced the receipt.
    const sigBase = `ink/audit-inclusion/v1\n${canonicalized}`;
    const serviceSignature = await signData(sigBase, this.privateKey);

    return Response.json({
      protocol: "ink/0.1",
      type: "network.tulpa.audit_inclusion",
      eventId: event.id,
      treeSize,
      leafIndex,
      rootHash,
      inclusionProof,
      timestamp,
      serviceSignature,
    });
  }

  /** Handle query — access-controlled event lookup by messageId.
   *
   *  Validates the DO-internal payload with a zod schema. app.ts already
   *  constructs this object from pre-validated user input, but defending in
   *  depth here means a future caller that passes raw or partially-validated
   *  data cannot bypass the field caps and charset checks. */
  async handleQuery(request: Request): Promise<Response> {
    let parsed: z.infer<typeof InternalQuerySchema>;
    try {
      const raw = await request.json();
      const out = InternalQuerySchema.safeParse(raw);
      if (!out.success) {
        return Response.json({ error: "messageId and requester are required" }, { status: 400 });
      }
      parsed = out.data;
    } catch {
      return Response.json({ error: "Invalid JSON" }, { status: 400 });
    }
    const { messageId, requester } = parsed;

    // Push access control into SQL so the LIMIT applies AFTER the
    // requester visibility filter. ORDER BY event_id gives a
    // deterministic result set so signed responses are reproducible.
    // Pull MAX_QUERY_EVENTS + 1 to detect overflow: if the requester
    // has more than MAX_QUERY_EVENTS visible rows the witness MUST
    // fail closed rather than sign a partial response that looks
    // complete (§7.3).
    const rows = this.ctx.storage.sql.exec(
      "SELECT event_json, event_hash, agent_id, counterparty_id, message_id FROM audit_events WHERE message_id = ? AND (agent_id = ? OR counterparty_id = ?) ORDER BY event_id ASC LIMIT ?",
      messageId,
      requester,
      requester,
      MAX_QUERY_EVENTS + 1,
    ).toArray();
    if (rows.length > MAX_QUERY_EVENTS) {
      // Fail closed: never sign a response that omits visible events
      // without the verifier being able to detect it.
      return Response.json(
        { error: "Query result exceeds maximum allowed events; refine messageId scope" },
        { status: 413 },
      );
    }

    // Snapshot the witness's tree state once so every proof refers to the
    // same (treeSize, rootHash). Re-reading per-event could race against a
    // concurrent submit and produce proofs that walk to inconsistent roots.
    const { treeSize, rootHash } = this.tree.getState();

    // For each visible row, recompute the leaf hash from the canonical
    // event JSON and build a proof. Any integrity failure (parse,
    // missing hash, hash mismatch, missing Merkle node, unprovable
    // leaf) is fatal: the witness MUST NOT silently sign omissions.
    const events: unknown[] = [];
    const proofs: { eventId: string; leafIndex: number; inclusionProof: string[] }[] = [];
    for (const row of rows) {
      // Defense in depth: SQL filter is authoritative, but if a future
      // refactor weakens the WHERE clause we still refuse to leak rows
      // the requester is not a party to.
      if (row.agent_id !== requester && row.counterparty_id !== requester) {
        return Response.json({ error: "Integrity error" }, { status: 500 });
      }
      const storedLeafHash = row.event_hash as string | null;
      if (typeof storedLeafHash !== "string" || storedLeafHash.length === 0) {
        return Response.json({ error: "Integrity error" }, { status: 500 });
      }
      let rawEvent: unknown;
      try {
        rawEvent = JSON.parse(row.event_json as string);
      } catch {
        return Response.json({ error: "Integrity error" }, { status: 500 });
      }
      // Re-validate the stored event against the live InkAuditEvent
      // schema before signing it back out. Without this, a corrupted
      // row (e.g. missing agentSignature after a migration bug) could
      // pass the leaf-hash check, get included in a signed response,
      // and only fail at the downstream verifier.
      const parsedEvent = InkAuditEventSchema.safeParse(rawEvent);
      if (!parsedEvent.success) {
        return Response.json({ error: "Integrity error" }, { status: 500 });
      }
      const event = parsedEvent.data;
      // Cross-check event_json fields against SQL columns. If the
      // index columns and the canonical event payload disagree, the
      // store is corrupted: refuse to sign. Without this, a storage
      // bug could let the witness return an event from a different
      // messageId/agent pair than the SQL filter scoped to.
      if (event.messageId !== row.message_id) {
        return Response.json({ error: "Integrity error" }, { status: 500 });
      }
      if (event.agentId !== row.agent_id) {
        return Response.json({ error: "Integrity error" }, { status: 500 });
      }
      const rowCounterparty = row.counterparty_id ?? null;
      const eventCounterparty = event.counterpartyId ?? null;
      if (eventCounterparty !== rowCounterparty) {
        return Response.json({ error: "Integrity error" }, { status: 500 });
      }
      // Defense in depth against parsed-event tampering: the requester
      // must still be a party to the canonical event itself, not just
      // the SQL columns.
      if (event.agentId !== requester && event.counterpartyId !== requester) {
        return Response.json({ error: "Integrity error" }, { status: 500 });
      }
      const recomputedLeafHash = await computeEventHash(event as unknown as Record<string, unknown>);
      if (recomputedLeafHash !== storedLeafHash) {
        return Response.json({ error: "Integrity error" }, { status: 500 });
      }
      const idxRow = this.ctx.storage.sql.exec(
        "SELECT idx FROM merkle_nodes WHERE level = 0 AND hash = ? LIMIT 1",
        recomputedLeafHash,
      ).toArray()[0];
      if (!idxRow) {
        return Response.json({ error: "Integrity error" }, { status: 500 });
      }
      const leafIndex = Number(idxRow.idx);
      const inclusionProof = this.tree.getInclusionProof(leafIndex, treeSize);
      if (!inclusionProof) {
        return Response.json({ error: "Integrity error" }, { status: 500 });
      }
      events.push(event);
      proofs.push({ eventId: event.id, leafIndex, inclusionProof });
    }

    // Build the response payload and sign canonical bytes per INK
    // Auditability §7.3:
    //   "ink/audit-query-response/v1\n" + JCS(payload)
    //
    // The signed envelope binds `requester` so a witness response cannot
    // be replayed cross-requester: an attacker who steals Alice's signed
    // response cannot present it to Bob as Bob's authoritative view.
    const payload = {
      protocol: "ink/0.1" as const,
      type: "network.tulpa.audit_query_response" as const,
      serviceDid: this.did,
      messageId,
      requester,
      events,
      proofs,
      treeSize,
      rootHash,
      timestamp: new Date().toISOString(),
    };
    const canonicalized = canonicalize(payload);
    if (canonicalized === undefined) {
      return Response.json({ error: "Failed to canonicalize response" }, { status: 500 });
    }
    const sigBase = `ink/audit-query-response/v1\n${canonicalized}`;
    const sigBaseBytes = new TextEncoder().encode(sigBase);
    if (sigBaseBytes.length > MAX_QUERY_RESPONSE_BYTES) {
      return Response.json({ error: "Response too large" }, { status: 413 });
    }
    const serviceSignature = await signData(sigBase, this.privateKey);

    return Response.json({ ...payload, serviceSignature });
  }

  /** Return current checkpoint in signed tlog-checkpoint format.
   *
   *  Per C2SP tlog-checkpoint, the signature covers the body bytes directly.
   *  The `origin` field (first line, the configured WITNESS_ORIGIN) is the
   *  spec-mandated domain separator, it uniquely identifies the log and
   *  ensures the signed bytes cannot collide with any other signed format
   *  produced by this key. We deliberately do NOT prepend an extra prefix
   *  here because it would diverge from the C2SP wire format and break
   *  third-party verifiers (e.g. transparency-dev tooling).
   *
   *  Cross-format substitution is structurally prevented because every other
   *  bytes-signed-by-this-key format starts with a different first line
   *  (e.g. inclusion receipts begin "ink/audit-inclusion/v1\\n"). */
  /**
   * Public aggregated reputation summary for an agent. Returns coarse
   * counts only — no event content, no relationship details, no
   * Merkle proofs. The witness is a transparency log so the
   * aggregated counts are intentionally public: any holder of the
   * agentId can ask "how many events involving this agent have been
   * witnessed, how many were rejections / signature failures, and
   * when was the agent first seen". Per-event detail still requires
   * INK-authed /query and the requester being a party to the event.
   */
  async handleAgentSummary(request: Request): Promise<Response> {
    let parsed: { agentId?: unknown };
    try {
      parsed = await request.json();
    } catch {
      return Response.json({ error: "invalid_json" }, { status: 400 });
    }
    const agentId = parsed?.agentId;
    // Mirrors the SAFE_ID_REGEX cap on submitted events: keep the
    // ALLOWED character set in lockstep so an agent id that could be
    // stored can also be queried back.
    if (typeof agentId !== "string" || agentId.length < 1 || agentId.length > 256 ||
        !/^[A-Za-z0-9_:.\-]+$/.test(agentId)) {
      return Response.json({ error: "invalid_agent_id" }, { status: 400 });
    }
    // Event types we treat as "high-risk" for reputation purposes:
    // rejections, signature failures, replay attempts, and the
    // INK Containment Phase 1 misuse events.
    const HIGH_RISK_TYPES = [
      "message.rejected",
      "signature.failed",
      "signature.revoked_rejected",
      "replay.detected",
      "transport_scope_violation",
      "handshake_rate_limited",
      "handshake_budget_exhausted",
    ];
    // Event types that indicate the message was successfully processed.
    const ACCEPTED_TYPES = [
      "message.delivered",
      "message.acted",
      "message.received",
    ];
    const highRiskPlaceholders = HIGH_RISK_TYPES.map(() => "?").join(", ");
    const acceptedPlaceholders = ACCEPTED_TYPES.map(() => "?").join(", ");
    // Single aggregated query. Both agent_id and counterparty_id paths
    // are aggregated so the counts cover every event the agent was
    // party to. CASE WHEN preserves a single table scan over
    // SUM(FILTER) which SQLite does not support universally.
    // Use created_at (real indexed column) rather than json_extract
    // over event_json so this hot endpoint doesn't parse JSON per
    // matched row. The few-second difference between event timestamp
    // and witness ingest time is acceptable for reputation purposes.
    const sql = `
      SELECT
        SUM(CASE WHEN event_type IN (${highRiskPlaceholders}) THEN 1 ELSE 0 END) AS high_risk_count,
        SUM(CASE WHEN event_type IN (${acceptedPlaceholders}) THEN 1 ELSE 0 END) AS accepted_count,
        COUNT(*) AS total_events,
        MIN(created_at) AS known_since
      FROM audit_events
      WHERE agent_id = ? OR counterparty_id = ?
    `;
    const rows = this.ctx.storage.sql
      .exec(sql, ...HIGH_RISK_TYPES, ...ACCEPTED_TYPES, agentId, agentId)
      .toArray();
    const r = rows[0] ?? {};
    const highRiskCount = Number(r.high_risk_count ?? 0);
    const acceptedCount = Number(r.accepted_count ?? 0);
    const totalEvents = Number(r.total_events ?? 0);
    const knownSinceRaw = r.known_since;
    const knownSince = typeof knownSinceRaw === "string" && knownSinceRaw.length > 0
      ? knownSinceRaw
      : null;
    return Response.json({
      schemaVersion: "ink.witness.agent-summary.v1",
      agentId,
      highRiskCount,
      acceptedCount,
      totalEvents,
      knownSince,
    });
  }

  async handleCheckpoint(): Promise<Response> {
    const { treeSize, rootHash } = this.tree.getState();
    const checkpointBody = formatCheckpoint({
      origin: this.witnessOrigin,
      treeSize,
      rootHash,
    }).replace(/\n$/, ""); // strip trailing newline, signature follows after blank line
    const signature = await signData(checkpointBody, this.privateKey);
    const signed = `${checkpointBody}\n\n-- ${this.witnessOrigin} ${signature}\n`;
    return new Response(signed, {
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        // C2SP checkpoints are intentionally body-stable across requests at
        // a given tree size, so verifiers compare treeSize/rootHash for
        // monotonicity. The signed body itself has no timestamp by design
        // (interop with sigsum/transparency.dev tooling). Disable upstream
        // caching so an intermediary cannot pin a verifier to a stale but
        // correctly-signed checkpoint after the log has advanced.
        "Cache-Control": "no-store",
      },
    });
  }

  /** Return leaf hashes for public tree auditability. No event content exposed. */
  handleLeaves(request: Request): Response {
    const url = new URL(request.url);
    const start = parseInt(url.searchParams.get("start") ?? "0", 10);
    const count = parseInt(url.searchParams.get("count") ?? "100", 10);

    if (isNaN(start) || isNaN(count) || start < 0 || count <= 0) {
      return Response.json({ error: "Invalid start or count" }, { status: 400 });
    }

    const { treeSize } = this.tree.getState();
    const leaves = this.tree.getLeafHashes(start, Math.min(count, 1000));

    return Response.json({
      treeSize,
      start,
      count: leaves.length,
      leaves,
    });
  }

  /** Return an RFC 6962 consistency proof between two tree sizes. */
  handleConsistency(request: Request): Response {
    const url = new URL(request.url);
    const firstRaw = url.searchParams.get("first");
    const secondRaw = url.searchParams.get("second");
    if (firstRaw === null || secondRaw === null || !/^\d+$/.test(firstRaw) || !/^\d+$/.test(secondRaw)) {
      return Response.json({ error: "first and second must be non-negative integers" }, { status: 400 });
    }
    const first = Number(firstRaw);
    const second = Number(secondRaw);
    if (!Number.isSafeInteger(first) || !Number.isSafeInteger(second)) {
      return Response.json({ error: "first or second out of range" }, { status: 400 });
    }
    const proof = this.tree.getConsistencyProof(first, second);
    if (proof === null) {
      return Response.json({ error: "require 0 <= first <= second <= treeSize" }, { status: 400 });
    }
    return Response.json({ first, second, proof });
  }

  /** Return DID document and public key. */
  async handleIdentity(): Promise<Response> {
    return Response.json({
      did: this.did,
      publicKeyMultibase: encodePublicKeyMultibase(this.publicKey),
    });
  }

  /** Route internal requests from the Hono app. */
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/nonce-check" && request.method === "POST") {
      return this.handleNonceCheck(request);
    }
    if (url.pathname === "/submit" && request.method === "POST") {
      return this.handleSubmit(request);
    }
    if (url.pathname === "/query" && request.method === "POST") {
      return this.handleQuery(request);
    }
    if (url.pathname === "/checkpoint" && request.method === "GET") {
      return this.handleCheckpoint();
    }
    if (url.pathname === "/agent-summary" && request.method === "POST") {
      return this.handleAgentSummary(request);
    }
    if (url.pathname === "/identity" && request.method === "GET") {
      return this.handleIdentity();
    }
    if (url.pathname === "/leaves" && request.method === "GET") {
      return this.handleLeaves(request);
    }
    if (url.pathname === "/consistency" && request.method === "GET") {
      return this.handleConsistency(request);
    }
    if (url.pathname === "/ratelimit-check" && request.method === "POST") {
      return this.handleRateLimitCheck(request);
    }
    if (url.pathname === "/tree-state" && request.method === "GET") {
      const { treeSize, rootHash } = this.tree.getState();
      return Response.json({ treeSize, rootHash });
    }

    return new Response("Not Found", { status: 404 });
  }

  // ── Rate limit storage ─────────────────────────────────────────────
  //
  // Fixed-minute-window counters keyed by an opaque bucket string. The
  // app layer is the only producer of bucket keys (per-agent, per-IP,
  // per-CIDR); the DO doesn't know what each bucket represents and
  // just enforces the supplied cap.
  //
  // Two-phase atomic check-and-increment: phase 1 reads every bucket
  // and short-circuits if any one is already at cap; phase 2 then
  // increments all of them. Both phases run inside a single
  // synchronous block (sql.exec is sync) so DO input gating prevents
  // interleaved requests from observing partial state.

  /** RateLimitRequest body: { now?: number, buckets: [{ key, maxPerMinute }, ...] } */
  async handleRateLimitCheck(request: Request): Promise<Response> {
    let parsed: { now?: number; buckets: Array<{ key: string; maxPerMinute: number }> };
    try {
      parsed = await request.json();
    } catch {
      return Response.json({ error: "invalid_json" }, { status: 400 });
    }
    if (!parsed || !Array.isArray(parsed.buckets)) {
      return Response.json({ error: "invalid_buckets" }, { status: 400 });
    }
    if (parsed.buckets.length > 8) {
      return Response.json({ error: "too_many_buckets" }, { status: 400 });
    }
    for (const b of parsed.buckets) {
      if (!b || typeof b.key !== "string" || b.key.length === 0 || b.key.length > 256) {
        return Response.json({ error: "invalid_bucket_key" }, { status: 400 });
      }
      if (!Number.isInteger(b.maxPerMinute) || b.maxPerMinute < 1 || b.maxPerMinute > 1_000_000) {
        return Response.json({ error: "invalid_bucket_limit" }, { status: 400 });
      }
    }

    const nowMs = typeof parsed.now === "number" && parsed.now > 0 && parsed.now < 4_000_000_000_000
      ? parsed.now
      : Date.now();
    const windowStart = Math.floor(nowMs / 60_000) * 60_000;

    this.ctx.storage.sql.exec(
      "DELETE FROM rate_limit_buckets WHERE window_start < ?",
      windowStart - 60_000,
    );

    for (const bucket of parsed.buckets) {
      const row = this.ctx.storage.sql.exec(
        "SELECT count FROM rate_limit_buckets WHERE bucket_key = ? AND window_start = ?",
        bucket.key,
        windowStart,
      ).toArray()[0] as { count?: number } | undefined;
      const count = Number(row?.count ?? 0);
      if (count >= bucket.maxPerMinute) {
        return Response.json({
          ok: false,
          exceeded: bucket.key,
          limit: bucket.maxPerMinute,
          count,
          windowStart,
        });
      }
    }

    for (const bucket of parsed.buckets) {
      this.ctx.storage.sql.exec(
        "INSERT INTO rate_limit_buckets (bucket_key, window_start, count) VALUES (?, ?, 1) " +
        "ON CONFLICT(bucket_key, window_start) DO UPDATE SET count = count + 1",
        bucket.key,
        windowStart,
      );
    }

    return Response.json({ ok: true, windowStart });
  }
}

/** Length cap before the charset regex. Without this, a corrupted or
 * adversarial private_key DB column would trigger an unbounded O(n)
 * regex scan before the length check fires. Identity material here is
 * 32-byte Ed25519 keys (64 hex chars); 4096 is generous headroom. */
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
