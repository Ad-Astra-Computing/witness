# Security Policy

The witness is part of the INK auditability surface. Security reports are taken seriously.

## Reporting a vulnerability

**Do not open a public GitHub issue for security problems.**

Report privately to: **security@adastracomputing.com**

Include:

- A description of the issue and why it is a security problem
- Reproduction steps or a proof-of-concept
- The affected commit SHA or release tag
- Whether you want public credit in the fix notes

Acknowledgement within 3 business days; triage decision within 7. We coordinate disclosure with the reporter, public disclosure after a fix ships and known integrators have had time to update.

## Supported versions

Only the `main` branch receives security fixes. Pinned pre-1.0 releases are not separately maintained.

| Version | Supported |
|---------|-----------|
| `main`  | Yes |
| v0.x tags | Best-effort only |

## Scope

In scope:

- Signature forgery on transport auth or audit events (replay, nonce collision, key confusion)
- Merkle log tampering: leaves dropped/reordered/forked, inclusion proofs that verify against a different root than the one in a signed checkpoint
- Bypass of the key-rotation authority rule defined in the [INK key-rotation spec](https://ink.tulpa.network/extensions/key-rotation/)
- Witness-identity confusion (e.g. the DO accepting submissions under one DID while signing checkpoints under another)
- SSRF or DNS-rebinding bypass on the agent-card fetch path
- Cryptographic misuse: wrong signing base, non-canonical JSON, weak `WITNESS_KEY_SECRET` accepted, etc.

Out of scope:

- DoS via high-entropy inputs (rate limits + body caps are best-effort, not contractual)
- Attacks that require a compromised identity system (e.g. a malicious PDS returning a fabricated DID document)
- Timing side-channels inside `@noble/ed25519`
- Misconfiguration by the operator (e.g. running with a weak `WITNESS_KEY_SECRET` despite the startup check, exposing `wrangler.toml` in a public repo)

## Threat model

See [`docs/threat-model.md`](docs/threat-model.md).

## Audit status

The witness has not undergone an independent security audit. Do not describe or adopt this code as "audited" or "hardened" on that basis. Operators are responsible for evaluating fitness for purpose.

## Credits

Reporters who help us will be credited in release notes unless they prefer to remain anonymous.
