# Changelog

All notable changes to the INK witness reference implementation are
recorded here. Pre-1.0 releases follow `0.Y.Z` semantics.

## Unreleased

Tracks compatibility with `@adastracomputing/ink@0.1.0-alpha.3`.

### Endpoints

- `POST /ink/v1/audit/query` now returns the alpha.3 signed `network.tulpa.audit_query_response` envelope: `{protocol, type, serviceDid, messageId, requester, events, proofs[{eventId, leafIndex, inclusionProof}], treeSize, rootHash, timestamp, serviceSignature}`. Per-event inclusion proofs are bound to `(treeSize, rootHash)` at query time, so a single query produces a complete, self-verifying audit slice without needing the submit-time receipt.
- `GET /health` now returns `{status, service: did, time, log: {treeSize, rootHash}, region}` with a 2s timeout against the DO's new internal `/tree-state` endpoint. The unsigned tree head doubles as a Rekor-style head pointer; `/checkpoint` remains the canonical signed-head endpoint. `status: degraded` when the DO is unreachable.

### Security

- Per-event scope enforcement (Auditability §7.3/§7.4): every returned event's `messageId` must equal the envelope `messageId`, and the envelope `requester` must equal `event.agentId` or `event.counterpartyId`. Witness refuses to sign otherwise.
- Cross-check between SQL index columns and the canonical `event_json` (messageId, agentId, counterpartyId): any mismatch fails closed with HTTP 500.
- `LIMIT MAX_QUERY_EVENTS + 1` with `ORDER BY event_id ASC` so the response set is deterministic; if the requester has more visible events than the cap, the witness returns unsigned 413 rather than silently signing a partial response.
- Integrity failures (missing `event_hash`, hash mismatch, missing Merkle node, unprovable leaf, malformed `event_json`) now fail closed with HTTP 500.
- Response-size cap measured in UTF-8 bytes, not JS string length.
- Rate limits are now multi-bucket and DO-backed instead of per-isolate. Each `/audit/submit` and `/audit/query` checks `agent:<agentId>`, `ip:<normalized>` and `cidr:<prefix>` buckets atomically against a fixed-minute window in a new `rate_limit_buckets` table. Defaults 30/60/300 per minute respectively; overridable via `RATE_LIMIT_AGENT_PER_MIN` / `RATE_LIMIT_IP_PER_MIN` / `RATE_LIMIT_CIDR_PER_MIN` env vars. `normalizeIp` trims whitespace, takes the first entry of any comma-separated list, strips IPv6 zone IDs, collapses `::ffff:V4MAPPED` to the embedded IPv4, and falls back to skipping ip/cidr buckets on malformed input rather than minting a bypass bucket. `expandIpv6` strictly rejects empty hextets outside a `::` compression so `1:2:3:4:5:6:7:` and `:1:2:3:4:5:6:7` do not slip through.

### Configuration

- `WITNESS_DID` is now read from the operator's env (was previously hardcoded in the Tulpa fork) so the same binary can run as production or a demo lane without code changes. The DO refuses to start if the stored identity DID does not match `env.WITNESS_DID`, catching storage drift or running the wrong binary against a tree bootstrapped by a different deployment. The C2SP checkpoint origin is derived from the configured DID (strip `did:web:` prefix).

### Demo lane

- Ad Astra Computing now operates a second public deployment at `witness-demo.tulpa.network` (`did:web:witness-demo.tulpa.network`) running the same protocol implementation as this repository, on an isolated Merkle tree. It is intended for the INK quickstart and for adopters verifying integrations against a live reference; receipts from it should be treated as integration-test artifacts only. The demo's rate-limit caps are tuned for tutorial debugging slack rather than production-traffic profile. See `README.md`.

## 0.1.0, first public release

Reference implementation of the INK Auditability §7 third-party audit
service. Compatible with INK protocol `0.1`.

### Endpoints

- `POST /ink/v1/audit/submit`, append signed audit events, return an inclusion receipt bound to the leaf, current `treeSize`, and `rootHash`
- `POST /ink/v1/audit/query`, fetch matching events by `messageId` (access-controlled to parties of the message; inclusion proofs are returned at submit time, not on query)
- `GET /ink/v1/checkpoint`, signed log root in C2SP tlog-checkpoint format
- `GET /ink/v1/leaves`, public leaf hashes for tree auditability
- `GET /identity`, witness DID + public key
- `GET /health`, liveness probe

### Runtime

- Cloudflare Workers + Durable Objects, SQLite-backed Merkle tree
- AES-256-GCM encryption of the witness signing key at rest, with HKDF derivation from `WITNESS_KEY_SECRET`
- Sliding-window per-agent rate limit (30 events/min) with bounded key map
- Body-size caps (64 KB submit, 4 KB query) with stream-read enforcement
- Verify-then-commit nonce ordering: nonce peeked pre-verify, committed only after every signature passes
- Agent-card resolution via Cloudflare service binding (`AGENT_DIRECTORY` + `AGENT_CARD_BASE_URL` URL template); DNS is never reached at fetch time
- Fail-closed agent-card resolver: transient failures throw, only definitive "no key set published" returns null
