# INK transparency witness

> Reference implementation. The production witness at `witness.tulpa.network` is a separate fork and may diverge — protocol-correctness fixes flow back here, but deployment-specific endpoints (e.g. Tulpa-internal reputation reads) stay in the production fork. Open PRs welcome for protocol-correctness work.

A reference implementation of the third-party audit-service role from the [INK protocol](https://ink.tulpa.network) (Auditability §7). Runs on Cloudflare Workers + Durable Objects. Appends hash-chained, Ed25519-signed audit events to a Merkle log and returns inclusion proofs.

Status: v0.x, reference implementation. Compatible with INK `0.1`. This repository is a protocol reference and operator starting point, not a hosted service product with a guaranteed release cadence. Operating a witness using this code does not make the witness trusted; verifiers choose which witness identities and checkpoints to rely on.

## Public deployments

Ad Astra Computing operates two instances of this code so adopters have somewhere to test integrations and Tulpa-network agents have somewhere to submit:

- [`witness.tulpa.network`](https://witness.tulpa.network) (`did:web:witness.tulpa.network`): production. Real Tulpa-network audit traffic. Not a sandbox; do not point quickstart loops or test scripts here.
- [`witness-demo.tulpa.network`](https://witness-demo.tulpa.network) (`did:web:witness-demo.tulpa.network`): public verify-against lane for adopters and the INK quickstart. Separate Durable Object, separate Merkle tree, rate-limit caps tuned for tutorial debugging slack rather than production-traffic profile. May be reset periodically; treat receipts from this instance as integration-test artifacts only.

Both deployments are operated from a production fork that stays in sync with this repository for protocol-correctness work but may carry deployment-specific endpoints not present here. Other operators are free to deploy their own instance from this code and ask counterparties to pin a different identity; nothing in INK privileges any particular witness.

| | |
|---|---|
| Spec | [INK Auditability §7](https://ink.tulpa.network/extensions/witness/) |
| Protocol | INK `0.1` |
| Runtime | Cloudflare Workers + Durable Objects |
| Production instance | [`witness.tulpa.network`](https://witness.tulpa.network) |
| Public verify-against lane | [`witness-demo.tulpa.network`](https://witness-demo.tulpa.network) |
| Contributing | [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| Security | [`SECURITY.md`](SECURITY.md) |
| Code of Conduct | [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) |

## What it does

Three primary endpoints:

- `POST /ink/v1/audit/submit` accepts an [`InkAuditEvent`](https://ink.tulpa.network/extensions/witness/) wrapped in an INK-signed envelope. Verifies transport and event signatures, appends the event to a Merkle tree, returns an inclusion receipt signed by the witness (bound to the leaf, current `treeSize`, and `rootHash`).
- `POST /ink/v1/audit/query` returns a signed `network.tulpa.audit_query_response` envelope: every visible event for the queried `messageId` plus a per-event Merkle inclusion proof against the witness's `(treeSize, rootHash)` at response time, plus `requester` and `serviceDid` bindings inside the signature. Access-controlled: only `event.agentId` or `event.counterpartyId` can query. The witness fails closed with HTTP 413 when the requester's visible event set for a `messageId` exceeds the response cap, or with HTTP 500 on any storage-integrity mismatch. It never silently signs partial or contradictory responses.
- `GET /ink/v1/checkpoint` returns the current signed log root in [C2SP tlog-checkpoint](https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md) format.
- `GET /ink/v1/leaves?start=N&count=M` returns leaf hashes for public auditability without exposing event content.

## Trust model

The witness is a **non-trusted accumulator**. It commits to never tampering with history, but a verifier never has to take that promise on faith:

- Every audit event carries the submitting agent's Ed25519 signature; the witness cannot forge events.
- The Merkle tree is append-only, and every checkpoint is signed by the witness's identity key.
- Verifiers can re-fetch any checkpoint over time and compare; an inconsistency proves the witness misbehaved.
- The inclusion receipt returned at submit time binds the leaf to a specific `treeSize` and `rootHash`; the requester can independently recompute the root from the leaf and any later signed checkpoint.

What this means in practice: **running this code does not make a witness trusted.** Verifiers establish trust out-of-band by pinning specific witness DIDs and checkpoint signing keys, exactly the same model as Certificate Transparency.

See [`docs/threat-model.md`](docs/threat-model.md) for the full threat model.

## Layout

```
src/
  app.ts               Hono routes, request validation, transport auth
  witness-log.ts       Durable Object: identity, Merkle tree, nonce cache
  merkle.ts            RFC 6962-style binary Merkle tree (SQLite-backed)
  key-encryption.ts    AES-256-GCM at-rest encryption for the signing key
  schema.ts            SQLite DDL
  landing.ts           Minimal HTML index page (replaceable)
  shared/
    crypto.ts          Transport auth (verifyInkTransportAuth) + multi-key
    schemas.ts         Zod request/response shapes
    checkpoint.ts      C2SP tlog-checkpoint format
test/                  vitest unit and integration suites
docs/                  threat model + trust model
```

## Deploy

You need a Cloudflare account, the `wrangler` CLI, and a sibling Worker (or HTTP service) that serves agent cards.

1. Copy the example config and edit it:

```bash
cp wrangler.example.toml wrangler.toml
```

Set:

- `WITNESS_DID` to your witness's DID (e.g. `did:web:witness.example.com`). This is the `to` value submitters sign for.
- `WITNESS_ORIGIN` to the host the witness is reachable at. This is the first line of every checkpoint.
- `AGENT_CARD_BASE_URL` to the HTTPS root of your agent-card service. Used as the URL template for fetch.
- `[[services]] AGENT_DIRECTORY` to the name of the sibling Worker that serves agent cards. Required. Service-binding calls bypass DNS resolution entirely (closes the DNS-rebinding window) and keep the call inside the same CF account.
- `[[routes]]` to the custom domain that matches `WITNESS_ORIGIN`.

2. Set a strong `WITNESS_KEY_SECRET` as a Wrangler secret. This is the 32-byte hex AES-256-GCM key that encrypts the witness's signing key at rest:

```bash
wrangler secret put WITNESS_KEY_SECRET
# paste 64 hex chars of CSPRNG output
```

3. Deploy:

```bash
wrangler deploy
```

The witness publishes its identity public key at `/identity` for verifier convenience; the authoritative copy is whatever your DID document resolves to.

## Local development

```bash
npm test            # vitest, no Cloudflare runtime needed
npm run typecheck   # tsc --noEmit
npm run dev         # wrangler dev (requires wrangler login)
```

For Nix users: `nix develop` gives a pinned Node 24 + git + gitleaks + wrangler shell.

## Compatibility

This repository tracks INK `0.1`. The wire format is stable within `0.x` but the implementation may change without backward-compatible migration before `1.0`. If your downstream pins this repo, pin the tag.

## License

Dual-licensed under either of:

- MIT ([`LICENSE-MIT`](LICENSE-MIT))
- Apache 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))

at your option. Contributions are accepted under both licenses.
