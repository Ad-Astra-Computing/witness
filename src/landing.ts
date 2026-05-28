/**
 * Minimal landing page for a deployed INK witness. Operators can replace
 * with whatever HTML they want; the witness API is what matters.
 */

/** Bump alongside `package.json` `version` on every release. Surfaced in
 *  the footer so verifiers can audit deployed code against the matching
 *  GitHub release tag. */
export const WITNESS_VERSION = "0.1.0";

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function landingPageHtml(witnessOrigin: string): string {
  const safeOrigin = escapeHtml(witnessOrigin);
  const tagHref = `https://github.com/Ad-Astra-Computing/witness/releases/tag/v${WITNESS_VERSION}`;
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>INK transparency witness</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, sans-serif; max-width: 640px; margin: 4rem auto; padding: 0 1rem; line-height: 1.5; color: #1a1a1a; }
    code { background: #f3f3f3; padding: 0.1em 0.3em; border-radius: 3px; }
    a { color: #4338ca; }
    h1 { margin-bottom: 0.25rem; }
    .sub { color: #555; margin-top: 0; }
    footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #e5e5e5; font-size: 0.85rem; color: #777; }
  </style>
</head>
<body>
  <h1>INK transparency witness</h1>
  <p class="sub">Reference implementation, INK Auditability Section 7.</p>

  <p>This service appends hash-chained, Ed25519-signed audit events to a Merkle log
  and returns inclusion proofs. The log root is published at <code>/ink/v1/checkpoint</code>
  in the <a href="https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md">C2SP tlog-checkpoint</a> format.</p>

  <h2>Endpoints</h2>
  <ul>
    <li><code>POST /ink/v1/audit/submit</code></li>
    <li><code>POST /ink/v1/audit/query</code></li>
    <li><code>GET /ink/v1/checkpoint</code></li>
    <li><code>GET /ink/v1/leaves?start=N&amp;count=M</code></li>
  </ul>

  <h2>Trust model</h2>
  <p>Running this code does not make this witness trusted. Verifiers
  choose which witness identities and checkpoints to rely on; this
  instance is <code>${safeOrigin}</code>.</p>

  <p><a href="https://ink.tulpa.network/extensions/witness/">Protocol documentation</a> &middot;
  <a href="https://github.com/Ad-Astra-Computing/witness">Source</a></p>

  <footer>
    INK Witness Reference &middot; <code>${safeOrigin}</code> &middot;
    <a href="${tagHref}">v${WITNESS_VERSION}</a>
  </footer>
</body>
</html>`;
}
