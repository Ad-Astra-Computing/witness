# Contributing to the INK transparency witness

The witness is a reference implementation of the INK Auditability third-party witness role. Bug reports, security findings and deployment-experience reports are welcome. Code contributions that change the on-the-wire behaviour require a discussion first since they affect protocol interop.

## License of contributions

Contributions are accepted under the project's dual license: MIT OR Apache-2.0 (see [`LICENSE-MIT`](LICENSE-MIT) and [`LICENSE-APACHE`](LICENSE-APACHE)). By submitting a pull request you agree that your contribution may be distributed under either license.

## Before you open an issue or PR

- **Security issues**: do not open a public issue. Report privately per [`SECURITY.md`](SECURITY.md).
- **Protocol changes**: the INK protocol spec lives at [github.com/Ad-Astra-Computing/ink](https://github.com/Ad-Astra-Computing/ink). Wire-format proposals belong there, not here.
- **Bug fixes, test improvements, deployment ergonomics**: open a PR directly.

## Development setup

```bash
npm install
npm test          # vitest run
npm run typecheck # tsc --noEmit
```

Requires Node 22+ and npm 10+. Nix users can run `nix develop` for a pinned shell with Node 22, git, and gitleaks.

## Test policy

All changes must include tests. For bug fixes, add a regression test that fails before the fix and passes after. For new behaviour, add unit or integration tests that exercise the new path end to end.

## Code style

- TypeScript strict mode
- Minimal runtime dependencies; treat every new dep as a tradeoff against surface area to audit
- Prefer explicit error returns over thrown exceptions in public functions

## Submitting a PR

1. Fork and branch from `main`.
2. Run the CI checks locally; both must pass before requesting review:
   - `npm test`
   - `npm run typecheck`
3. Keep commits small and focused. Commit messages: imperative mood, under 72 characters in the subject.
4. Reference any related issue, spec section, or witness operator report in the PR description.

## Spec and implementation alignment

The authoritative INK spec lives in the [INK repository](https://github.com/Ad-Astra-Computing/ink). If your change would alter the witness's on-wire behaviour, signing base, trust model or audit semantics, link the relevant INK spec section in your PR. This codebase implements the spec; it does not get to redefine it.
