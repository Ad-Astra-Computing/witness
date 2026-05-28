/**
 * Regression test for the May 2026 production outage:
 *
 *   Commit bcc26b5 changed AES key derivation from raw SHA-256 to
 *   HKDF-SHA256. Existing witness private keys were stored under the
 *   SHA-256-derived key. After the migration, decryptPrivateKey failed
 *   with "OperationError: Decryption failed" and the DO could not
 *   initialize. /ink/v1/checkpoint and /.well-known/did.json returned
 *   500 in production.
 *
 *   Fix: decryptPrivateKeyWithFallback tries HKDF first, then SHA-256.
 *   On legacy-key success, the value is re-encrypted with HKDF and
 *   storage is rewritten so subsequent reads use the current scheme.
 *
 * These tests reproduce the failure and confirm the migration path.
 */
import { describe, it, expect } from "vitest";
import {
  encryptPrivateKey,
  decryptPrivateKey,
  decryptPrivateKeyWithFallback,
} from "../src/key-encryption.js";
import { bytesToHex } from "../src/shared/crypto.js";

const SECRET = "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1";

// Reproduces the pre-migration encrypt path: AES key derived from
// SHA-256(secret) instead of HKDF-SHA256(secret). Used to seed test
// state that mimics what production storage contained after bcc26b5
// but before the fix.
async function encryptWithLegacyDerivation(key: Uint8Array, secret: string): Promise<string> {
  const keyBytes = new TextEncoder().encode(secret);
  const hash = await crypto.subtle.digest("SHA-256", keyBytes);
  const aesKey = await crypto.subtle.importKey("raw", hash, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, key);
  return `${bytesToHex(iv)}:${bytesToHex(new Uint8Array(ciphertext))}`;
}

describe("legacy SHA-256 derivation fallback (production-outage regression)", () => {
  it("decrypts a value encrypted with legacy SHA-256 derivation and flags it", async () => {
    const original = new Uint8Array(32);
    for (let i = 0; i < 32; i++) original[i] = i + 1;

    // Seed test state that mimics production: stored encrypted value was
    // sealed with SHA-256(secret) before the HKDF migration.
    const legacyEncrypted = await encryptWithLegacyDerivation(original, SECRET);

    const result = await decryptPrivateKeyWithFallback(legacyEncrypted, SECRET);
    expect(result.plaintext).toEqual(original);
    expect(result.usedLegacyDerivation).toBe(true);
  });

  it("decrypts a current HKDF-encrypted value without falling back", async () => {
    const original = new Uint8Array(32);
    for (let i = 0; i < 32; i++) original[i] = i + 1;

    const encrypted = await encryptPrivateKey(original, SECRET);
    const result = await decryptPrivateKeyWithFallback(encrypted, SECRET);
    expect(result.plaintext).toEqual(original);
    expect(result.usedLegacyDerivation).toBe(false);
  });

  it("decryptPrivateKey (back-compat wrapper) still returns plaintext for legacy values", async () => {
    const original = new Uint8Array(32);
    for (let i = 0; i < 32; i++) original[i] = i + 1;

    const legacyEncrypted = await encryptWithLegacyDerivation(original, SECRET);
    const plaintext = await decryptPrivateKey(legacyEncrypted, SECRET);
    expect(plaintext).toEqual(original);
  });

  it("re-encrypting under HKDF after a legacy decrypt produces a HKDF-decryptable value", async () => {
    const original = new Uint8Array(32);
    for (let i = 0; i < 32; i++) original[i] = i + 1;

    // 1. Legacy stored value (SHA-256-derived AES key)
    const legacyEncrypted = await encryptWithLegacyDerivation(original, SECRET);

    // 2. Decrypt with fallback — succeeds, flags as legacy
    const { plaintext, usedLegacyDerivation } = await decryptPrivateKeyWithFallback(legacyEncrypted, SECRET);
    expect(usedLegacyDerivation).toBe(true);

    // 3. Re-encrypt under HKDF
    const reEncrypted = await encryptPrivateKey(plaintext, SECRET);

    // 4. New decrypt succeeds against HKDF directly (no fallback needed)
    const verifyResult = await decryptPrivateKeyWithFallback(reEncrypted, SECRET);
    expect(verifyResult.plaintext).toEqual(original);
    expect(verifyResult.usedLegacyDerivation).toBe(false);
  });

  it("still throws when both HKDF and legacy decryption fail (wrong secret)", async () => {
    const original = new Uint8Array(32).fill(1);
    const encrypted = await encryptPrivateKey(original, SECRET);
    await expect(
      decryptPrivateKeyWithFallback(encrypted, "f".repeat(64)),
    ).rejects.toThrow();
  });

  // Defense against the Codex-flagged HIGH-sev issues: a deployment with a
  // weak or passphrase-style WITNESS_KEY_SECRET could keep re-encrypting the
  // private key under a brute-forceable AES key. We allow legacy DECRYPT
  // under any secret (so weak-secret deployments still boot) but refuse to
  // encrypt new ciphertext under anything that isn't a CSPRNG-encoded
  // 32-byte value (64 hex / 43 base64url / 44 base64).
  it("refuses to encrypt fresh ciphertext under short / pattern secrets", async () => {
    const original = new Uint8Array(32).fill(1);
    await expect(encryptPrivateKey(original, "password")).rejects.toThrow();
    await expect(encryptPrivateKey(original, "a".repeat(64))).rejects.toThrow();
  });

  it("refuses to encrypt under passphrase-style secrets that pass length+diversity", async () => {
    const original = new Uint8Array(32).fill(1);
    // Passphrase with 33+ chars, plenty of unique chars, no short repeat —
    // would pass the old isAcceptableSecret check but is dictionary-guessable.
    await expect(
      encryptPrivateKey(original, "correct-horse-battery-staple-12345"),
    ).rejects.toThrow();
    await expect(
      encryptPrivateKey(original, "my-witness-secret-very-secure-2026"),
    ).rejects.toThrow();
  });

  it("accepts encrypt under valid CSPRNG-shaped secrets (hex/base64url/base64)", async () => {
    const original = new Uint8Array(32).fill(1);
    // 64 hex (TEST_SECRET above is exactly this shape)
    await expect(encryptPrivateKey(original, SECRET)).resolves.toBeTypeOf("string");
    // 43 base64url (real `crypto.randomBytes(32).toString('base64url')` shape)
    await expect(
      encryptPrivateKey(original, "rkHMCR1ZTmlQlJ0eISqK1EeAnILJHPKWgN4kneEJPzY"),
    ).resolves.toBeTypeOf("string");
    // 44 base64 with padding (same bytes, base64 form)
    await expect(
      encryptPrivateKey(original, "rkHMCR1ZTmlQlJ0eISqK1EeAnILJHPKWgN4kneEJPzY="),
    ).resolves.toBeTypeOf("string");
  });

  it("legacy decrypt still works under a weak secret (read-only recovery path)", async () => {
    const original = new Uint8Array(32).fill(7);
    // Seed with legacy SHA-256-derived ciphertext using a weak secret.
    const weakSecret = "weak-secret-12345678901234567890123";
    const legacyEncrypted = await encryptWithLegacyDerivation(original, weakSecret);
    // Decrypt path tolerates the weak secret so the DO can still boot.
    const result = await decryptPrivateKeyWithFallback(legacyEncrypted, weakSecret);
    expect(result.plaintext).toEqual(original);
    expect(result.usedLegacyDerivation).toBe(true);
  });
});

describe("favicon endpoint avoids noisy 404s", () => {
  it("returns 204 on GET /favicon.ico", async () => {
    const { createApp } = await import("../src/app.js");
    const app = createApp();
    const res = await app.fetch(
      new Request("https://w.example/favicon.ico"),
      {
        WITNESS_LOG: { idFromName: () => ({}), get: () => ({ fetch: async () => new Response("{}") }) } as unknown,
        WITNESS_KEY_SECRET: SECRET,
      } as unknown as { WITNESS_LOG: unknown; WITNESS_KEY_SECRET: string },
    );
    expect(res.status).toBe(204);
  });
});
