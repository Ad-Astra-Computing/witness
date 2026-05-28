export interface Env {
  WITNESS_LOG: DurableObjectNamespace;
  /** 32-byte hex secret for AES-256-GCM encryption of the witness private key. */
  WITNESS_KEY_SECRET: string;
  /** DID this witness publishes as. Bound into checkpoint signatures and
   *  the `serviceSignature` field. Must match a DID document the verifier
   *  can resolve to the witness's signing key. */
  WITNESS_DID: string;
  /** Host the witness is reachable at. First line of every checkpoint body. */
  WITNESS_ORIGIN: string;
  /** Base URL (scheme + host, no path) used to build agent-card request URLs.
   *  Paired with `AGENT_DIRECTORY`: the fetcher carries the request, this
   *  string supplies the URL template. Both are required. */
  AGENT_CARD_BASE_URL: string;
  /** Service binding to a sibling Worker that serves agent cards. Required.
   *  Service-binding calls bypass DNS resolution entirely (closes the
   *  DNS-rebinding window) and keep the call inside the same CF account.
   *  See wrangler.example.toml. */
  AGENT_DIRECTORY: Fetcher;
  /** Per-deployment rate-limit overrides. Operators choose caps that
   *  match their legitimate-traffic profile. The shipped defaults are
   *  middle-of-the-road (30 agent / 60 ip / 300 cidr per minute);
   *  production deployments may tighten per-agent and verify-against
   *  / demo lanes may loosen it. Numeric strings; falls back to the
   *  default constant when undefined. */
  RATE_LIMIT_AGENT_PER_MIN?: string;
  RATE_LIMIT_IP_PER_MIN?: string;
  RATE_LIMIT_CIDR_PER_MIN?: string;
}
