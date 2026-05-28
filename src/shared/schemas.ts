import { z } from "zod";

// Mirrors @adastracomputing/ink InkAuditEventTypeSchema in src/models/ink-audit.ts.
// Keep both lists in lockstep; any new event type in the INK lib MUST land here
// before deploy, or the witness will reject conformant submissions.
export const InkAuditEventTypeSchema = z.enum([
  // Message lifecycle
  "message.sent",
  "message.received",
  "message.queued",
  "message.delivered",
  "message.acted",
  "message.rejected",
  "message.expired",
  "message.retracted",
  // Receipt lifecycle
  "receipt.sent",
  "receipt.received",
  // Delegation
  "delegation.granted",
  "delegation.used",
  "delegation.revoked",
  "delegation.expired",
  // Connection
  "connection.requested",
  "connection.accepted",
  "connection.declined",
  // Verification
  "signature.verified",
  "signature.verified_retired",
  "signature.failed",
  "signature.revoked_rejected",
  "replay.detected",
  // Key lifecycle
  "key.rotated",
  "key.revoked",
  // Introduction lifecycle
  "introduction.requested",
  "introduction.approved",
  "introduction.declined",
  "introduction.forwarded",
  "introduction.completed",
  "introduction.expired",
  "introduction.receipt_sent",
  "introduction.receipt_received",
  // Enclave lifecycle
  "enclave.requested",
  "enclave.authorized",
  "enclave.opened",
  "enclave.operation_submitted",
  "enclave.resolved",
  "enclave.expired",
  "enclave.aborted",
  "enclave.receipt_sent",
  "enclave.receipt_received",
  // Containment (Phase 1)
  "transport_scope_violation",
  "handshake_rate_limited",
  "handshake_budget_exhausted",
  "discovery_query_received",
  "discovery_query_granted",
  "discovery_query_denied",
]);

// Max length caps prevent storage-DoS via massive fields. Lower bounds are
// intentionally loose — INK doesn't mandate a particular ID format, only an
// upper bound to prevent abuse. Agent IDs follow tulpa:z<base58 ed25519
// pubkey> in this implementation but other producers may use different
// schemes within the cap.
// ID fields are restricted to a safe charset (alphanumerics + a handful
// of separators). Newlines and other control characters would otherwise
// reach log aggregators via console.error and let an attacker forge log
// lines — see witness-log.ts error path.
const SAFE_ID_REGEX = /^[A-Za-z0-9_:.\-]+$/;
const safeId = (max: number) => z.string().min(1).max(max).regex(SAFE_ID_REGEX);

export const InkAuditEventSchema = z.object({
  id: safeId(128),
  version: z.literal("ink-audit/1"),
  agentId: safeId(128),
  agentSignature: z.string().min(1).max(256),
  sequence: z.number().int().positive(),
  // Exactly 64 lowercase hex (SHA-256 hex) or null (genesis). Empty string
  // is intentionally rejected so the schema cannot serve as a non-null
  // sentinel that bypasses chain-integrity checks downstream.
  previousEventHash: z.string().regex(/^[0-9a-f]{64}$/).nullable(),
  eventType: InkAuditEventTypeSchema,
  timestamp: z.string().datetime(),
  messageId: safeId(128).optional(),
  correlationId: safeId(128).optional(),
  counterpartyId: safeId(128).optional(),
  data: z.record(z.string(), z.unknown()).optional(),
});

/** Max serialized size of `data` field on an audit event (bytes).
 * Enforced in handleSubmit since zod cannot size-check z.record(z.unknown()). */
export const MAX_AUDIT_EVENT_DATA_BYTES = 4096;

export type InkAuditEvent = z.infer<typeof InkAuditEventSchema>;

export const InkAuditSubmitSchema = z.object({
  protocol: z.literal("ink/0.1"),
  type: z.literal("network.tulpa.audit_submit"),
  from: z.string().max(256),
  to: z.string().max(256),
  event: InkAuditEventSchema,
  // Match the charset that checkReplay (ink.ts) enforces. Without this,
  // a CRLF-bearing nonce can slip past the schema and into structured
  // log lines or stored values that other layers don't sanitize.
  nonce: z.string().min(16).max(256).regex(/^[A-Za-z0-9_-]+$/),
  timestamp: z.string().datetime(),
});

export type InkAuditSubmit = z.infer<typeof InkAuditSubmitSchema>;

export const InkAuditInclusionSchema = z.object({
  protocol: z.literal("ink/0.1"),
  type: z.literal("network.tulpa.audit_inclusion"),
  eventId: z.string(),
  treeSize: z.number().int().positive(),
  leafIndex: z.number().int().min(0),
  rootHash: z.string(),
  timestamp: z.string().datetime(),
  serviceSignature: z.string(),
});

export type InkAuditInclusion = z.infer<typeof InkAuditInclusionSchema>;
