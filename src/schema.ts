/** Initialize the witness SQLite schema. */
export function initWitnessSchema(sql: SqlStorage): void {
  sql.exec(`
    CREATE TABLE IF NOT EXISTS audit_events (
      event_id TEXT PRIMARY KEY,
      message_id TEXT,
      agent_id TEXT NOT NULL,
      sequence INTEGER,
      event_hash TEXT,
      counterparty_id TEXT,
      event_json TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  try {
    sql.exec("ALTER TABLE audit_events ADD COLUMN sequence INTEGER");
  } catch { /* column already exists */ }
  try {
    sql.exec("ALTER TABLE audit_events ADD COLUMN event_hash TEXT");
  } catch { /* column already exists */ }

  sql.exec(`
    CREATE INDEX IF NOT EXISTS idx_audit_events_message ON audit_events(message_id)
  `);
  sql.exec(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_events_agent_sequence
    ON audit_events(agent_id, sequence)
    WHERE sequence IS NOT NULL
  `);

  sql.exec(`
    CREATE TABLE IF NOT EXISTS identity (
      id TEXT PRIMARY KEY DEFAULT 'witness',
      private_key TEXT NOT NULL,
      public_key TEXT NOT NULL,
      did TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  sql.exec(`
    CREATE TABLE IF NOT EXISTS nonce_cache (
      nonce TEXT PRIMARY KEY,
      expires_at TEXT NOT NULL
    )
  `);

  sql.exec(`
    CREATE INDEX IF NOT EXISTS idx_witness_nonce_expires ON nonce_cache(expires_at)
  `);

  // Rate-limit buckets. Fixed minute windows keyed by (bucket, window_start).
  // One row per (bucket, window) per minute, dropped after the window slides
  // out via opportunistic GC inside handleRateLimitCheck. Authoritative across
  // isolates because it lives in DO storage; the previous in-memory Map reset
  // per isolate and let fresh-keypair attackers bypass per-agent caps.
  sql.exec(`
    CREATE TABLE IF NOT EXISTS rate_limit_buckets (
      bucket_key TEXT NOT NULL,
      window_start INTEGER NOT NULL,
      count INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (bucket_key, window_start)
    )
  `);
  sql.exec(`
    CREATE INDEX IF NOT EXISTS idx_rate_limit_window ON rate_limit_buckets(window_start)
  `);

  // merkle_nodes and merkle_meta are created by MerkleTree constructor
}
