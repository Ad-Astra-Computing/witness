# Witness threat model

This document describes what an INK witness deployed from this code
aims to protect against and what it does not. Treat every "not
protected" statement as a real limit.

## In-scope protections

### 1. Event authenticity

Every audit event submission carries TWO Ed25519 signatures:

- A **transport signature** (`Authorization: INK-Ed25519`) covering
  method, path, recipient DID, body, and timestamp. Proves the
  submitter holds the signing key for the agent identified in
  `body.from`.
- An **event signature** (`agentSignature` inside `event`) covering
  the JCS-canonicalized event with `agentSignature` excluded. Proves
  the event itself was authored by `event.agentId`.

The witness verifies both and rejects on either failure. A submitter
cannot inject events on behalf of another agent because they cannot
forge the event signature.

### 2. Append-only log

Events go into a SHA-256 Merkle tree maintained inside a Durable Object.
Once an event is appended, the prior tree state is frozen: any later
checkpoint must be a strict superset (sequence + previousEventHash +
inclusion-proof verifiable). The witness cannot silently drop or
reorder events without breaking checkpoint signatures over time.

### 3. Inclusion-proof verifiability

Every `/audit/submit` response includes a Merkle inclusion proof bound
to a specific `treeSize` and `rootHash`. A verifier can re-derive the
root from the leaf and proof and compare against any signed checkpoint
they hold. Any divergence proves the witness misbehaved; no trust in
the witness operator is required for this check.

Compatible with `@adastracomputing/ink@0.1.0-alpha.3`, the `/audit/query`
endpoint also returns the signed `network.tulpa.audit_query_response`
envelope: every visible event paired with a per-event inclusion proof
against the same `(treeSize, rootHash)`, plus `requester` and `serviceDid`
bindings inside the witness signature. Verifiers re-derive each leaf via
`computeAuditMerkleLeafHash` and walk the proof up to the response's
`rootHash`. No submit-time receipt is required to verify a query result.

### 4. Replay protection

Each submission carries a `nonce` and `timestamp`. The witness rejects
timestamps more than 5 minutes old or 30 seconds in the future, and
keeps a per-DO nonce cache to reject duplicate nonces within that
window. The check is verify-then-commit ordered: the nonce is peeked
before signature work, then committed only after every signature has
verified. A holder of valid transport credentials cannot burn chosen
nonces by submitting garbage event payloads.

### 5. Multi-bucket rate limiting

Each `/audit/submit` and `/audit/query` is checked against three
fixed-minute-window buckets atomically inside the Durable Object:

- `agent:<agentId>`: bounds a single agent's submit + query volume.
- `ip:<normalized>`: bounds traffic from a single client. Catches the
  fresh-keypair bypass where one client rotates Ed25519 identities to
  evade the per-agent cap.
- `cidr:<prefix>`: aggregates per /24 (IPv4) or /64 (IPv6) so a flat
  shared NAT can't sidestep ip caps with adjacent addresses.

Defaults are 30/60/300 per minute respectively, each overridable via
`RATE_LIMIT_AGENT_PER_MIN`, `RATE_LIMIT_IP_PER_MIN`,
`RATE_LIMIT_CIDR_PER_MIN` env vars. Operators tune to their
legitimate-traffic profile; production deployments may tighten
per-agent because real audit events are low-volume, verify-against
or demo deployments may loosen it for tutorial debugging.

The check is two-phase inside one synchronous DO handler invocation:
read every bucket's current count, short-circuit if any one is at
cap (returning the exceeded bucket key without incrementing any),
otherwise increment all. DO input gating prevents concurrent
requests from observing partial state. Counters live in a
`rate_limit_buckets` SQLite table with opportunistic GC of windows
older than the current minus one full window, bounding storage to
the active two windows per bucket.

`CF-Connecting-IP` is normalized before bucketing: whitespace
trimmed, comma-list left-truncated (defense against misconfigured
upstreams), IPv6 zone IDs stripped, `::ffff:V4MAPPED` collapsed to
the embedded IPv4, and garbage falls back to skipping ip/cidr
buckets entirely rather than minting a bypass bucket. `expandIpv6`
strictly rejects empty hextets outside a `::` compression so
`1:2:3:4:5:6:7:` or `:1:2:3:4:5:6:7` cannot slip into a unique
`/64` bucket.

Infrastructure errors fail open: if the DO is unreachable, the app
allows the request rather than 429-ing legitimate traffic during a
backend outage. Auth and signatures still gate every request, so
fail-open only benefits valid-key clients during a partial outage.

### 6. Body-size caps

Submit bodies are capped at 64 KB and query bodies at 4 KB. The
high-traffic canonicalize call sites (transport-auth verification and
the `audit_query_response` envelope build) apply explicit complexity
caps before canonicalizing; the smaller direct hash/signature paths
(`computeEventHash`, `computeAgentChainHash`, `verifyAuditEventSignature`)
rely on the outer body caps to bound input size. Chunked-transfer
requests without Content-Length are stream-read with the same cap.
Aimed at preventing CPU/memory exhaustion before signature work.

### 7. Encrypted signing key at rest

The witness identity private key is stored in the Durable Object's
SQLite store under AES-256-GCM with HKDF-derived material from
`WITNESS_KEY_SECRET`. The constructor refuses low-entropy secrets
(rejects all-zero, all-same-character, and short values) to make
offline brute-force impractical.

### 8. DNS-rebinding closed for agent-card fetches

Agent cards are fetched through a Cloudflare service binding
(`AGENT_DIRECTORY`). Service-binding calls bypass DNS resolution
entirely, closing the DNS-rebinding window and keeping the call inside
the same CF account. The `AGENT_CARD_BASE_URL` env var supplies the
URL template the fetcher uses; both bindings are required.

## Out-of-scope

### 1. Witness operator integrity

The witness cannot prevent its operator from:

- Refusing to accept submissions (DoS, not silent tampering)
- Refusing to return query results
- Pre-loading the log with fake events before going live
- Running multiple instances under the same DID

Mitigation: verifiers MUST pin specific witness identities and
checkpoints they choose to trust. The protocol does not designate any
specific witness as authoritative. Running this code does not make a
witness trusted.

### 2. Cross-witness consistency

A single witness commits only to its own log being append-only.
Verifiers that want stronger guarantees should observe multiple
independent witnesses and require agreement.

### 3. Long-term key compromise

If `WITNESS_KEY_SECRET` is exposed, all events ever submitted to that
witness become forgeable in retrospect. Operators must protect this
secret with the same diligence as any TLS private key. The witness
does not currently support identity-key rotation; rotation requires
spinning up a new witness DID and reissuing checkpoints.

### 4. Submitter trust

The witness verifies that the submitter holds the signing key for
`event.agentId`, but it does not verify the truthfulness of event
contents. `message.delivered` is a claim by the agent, not a proof
of delivery. Dispute resolution between counterparties is the INK
auditability layer's job, not the witness's.

### 5. Confidentiality

Events stored at the witness are visible to anyone who can query for
the matching `messageId` and is party to that message. The witness
does not encrypt event contents at rest. Submitters who need
confidentiality should encrypt event content before submission and
treat the witness as a witness to existence/order, not content.

## Operational notes

- Cloudflare service bindings keep the agent-card fetch inside the CF
  account; the witness should NEVER be deployed without a service
  binding or a tightly-controlled `AGENT_CARD_BASE_URL`.
- `WITNESS_KEY_SECRET` rotation requires re-encrypting the stored key.
  A legacy SHA-256 derivation path is supported transparently and
  rewrites to HKDF on first read.
- Rate limits and body-size caps are deliberately conservative; tune
  per deployment but do not remove without reviewing the threat
  model implications.
