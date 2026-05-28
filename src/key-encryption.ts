/**
 * AES-256-GCM encryption for the witness Ed25519 private key.
 *
 * Stored format: `<iv_hex>:<ciphertext_hex>` where IV is 12 bytes.
 * Legacy format (pre-encryption): plain 64-char hex string with no colon.
 */

import { bytesToHex } from "./shared/crypto.js";

/** Local hex decode with length cap (defense-in-depth — callers already
 * validate IV ≤ 24 chars and ciphertext ≤ MAX_CIPHERTEXT_HEX, so this is
 * a belt-and-braces guard against any future caller that forgets). */
const MAX_HEX_INPUT_LEN = 4096;
function hexToBytes(hex: string): Uint8Array {
  if (hex.length > MAX_HEX_INPUT_LEN) {
    throw new Error(`hex input exceeds maximum length of ${MAX_HEX_INPUT_LEN}`);
  }
  if (hex.length % 2 !== 0) throw new Error(`Invalid hex string length: ${hex.length}`);
  if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error("Invalid hex character in string");
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

/** Derive an AES-256-GCM CryptoKey from a secret string using HKDF-SHA256.
 *
 * Uses HKDF with a fixed context string so the derived key is bound to this
 * specific use case ("witness-key-encryption"). This is stronger than raw
 * SHA-256(secret) which has no salt and no KDF cost.
 *
 * The secret should be a high-entropy value from the platform secret store
 * (e.g. Cloudflare Workers secrets — at least 32 bytes of randomness).
 */
/** Minimum entropy floor for WITNESS_KEY_SECRET. Accepts either 32 raw
 * bytes encoded as 64 hex chars (recommended) or 43-44 base64url chars.
 * Anything shorter or non-conforming is treated as a misconfigured
 * deployment and rejected: encrypting the witness signing key under a
 * predictable/low-entropy secret would let anyone with DO storage access
 * decrypt or brute-force the key offline.
 *
 * Pure length + alphabet checks can be fooled by trivial patterns like
 * "a"*64, so we also require a minimum unique-character count. Truly
 * random hex (64 chars over 16 symbols) hits ~15 unique chars in practice;
 * random base64url (43 chars over 64 symbols) hits ~30+ unique chars.
 * Setting the floor at 10 catches "a"*64 and "abcdefgh"*8 while still
 * accepting any CSPRNG-generated value. */
/** Minimum entropy floor: a CSPRNG-generated 32-byte secret is ~43 chars
 * in base64url, ~44 chars in base64, ~52 chars in base32, or 64 chars in
 * hex. We require 32 chars as a conservative floor that accepts all common
 * encodings (including base64 with `+/=`, hex, base32, base64url) without
 * rejecting legitimately-configured deployments. */
const MIN_SECRET_CHARS = 32;
const MIN_UNIQUE_CHARS = 10;

/** Detect strings made of a short repeating substring (e.g. "abcd"*16,
 * "0123456789".repeat(7), "0123456789".repeat(6)+"0123"). True random
 * output won't match any short period. Handles truncated repeats (length
 * not a clean multiple of the period) via index-modulo comparison. */
function hasShortRepeatingPeriod(s: string): boolean {
  const maxPeriod = Math.floor(s.length / 2);
  for (let p = 1; p <= maxPeriod; p++) {
    let allMatch = true;
    for (let i = p; i < s.length; i++) {
      if (s[i] !== s[i % p]) { allMatch = false; break; }
    }
    if (allMatch) return true;
  }
  return false;
}

function isAcceptableSecret(s: string): boolean {
  // Encoding-agnostic checks. Operators may set the secret via any standard
  // encoding (hex, base64, base64url, base32, raw bytes), and we don't want
  // to reject legitimate values just because they include `+`, `/`, `=` or
  // other characters outside a specific alphabet.
  if (typeof s !== "string") return false;
  if (s.length < MIN_SECRET_CHARS) return false;
  // Reject low-diversity inputs (e.g. "a"*64 has 1 unique char).
  if (new Set(s).size < MIN_UNIQUE_CHARS) return false;
  // Reject inputs that are a short period repeated (e.g. "0123456789"*7).
  if (hasShortRepeatingPeriod(s)) return false;
  return true;
}

/** Soft check: missing/empty secret throws (DO can't function), low entropy
 * warns but doesn't throw. Used at DO init to surface configuration
 * problems without breaking decrypt paths for legacy ciphertexts. */
export function validateWitnessKeySecret(secret: string | undefined): void {
  if (!secret || typeof secret !== "string" || secret.length === 0) {
    throw new Error("WITNESS_KEY_SECRET is required");
  }
  if (!isAcceptableSecret(secret)) {
    console.warn(
      "WITNESS_KEY_SECRET appears low-entropy. Rotate to a 32-byte " +
      "CSPRNG-generated value as soon as practical.",
    );
  }
}

/** Strict check used at every encrypt path. Requires the secret to be a
 * CSPRNG-encoded 32-byte value in one of three exact formats:
 *
 *   - 64 hex chars (e.g. `openssl rand -hex 32`)
 *   - 43 base64url chars without padding (e.g. node:crypto randomBytes(32) → base64url)
 *   - 44 base64 chars with padding (e.g. `openssl rand -base64 32`)
 *
 * Passphrases like `correct-horse-battery-staple-…` pass the soft length +
 * unique-char check but are dictionary-brute-forceable; we reject them
 * outright at the encrypt boundary so the witness private key cannot be
 * written to storage under a weak AES key. Decrypt of a legacy ciphertext
 * under any secret is still allowed (read-only) so the DO can boot. */
const ENCRYPT_SECRET_FORMATS = [
  /^[0-9a-fA-F]{64}$/,        // 32 bytes hex
  /^[A-Za-z0-9_-]{43}$/,      // 32 bytes base64url, no padding
  /^[A-Za-z0-9+/]{43}=$/,     // 32 bytes base64, 1 padding char
];

export function assertStrongSecretForEncrypt(secret: string | undefined): void {
  if (!secret || typeof secret !== "string" || secret.length === 0) {
    throw new Error("WITNESS_KEY_SECRET is required");
  }
  const matchesFormat = ENCRYPT_SECRET_FORMATS.some((re) => re.test(secret));
  if (!matchesFormat) {
    throw new Error(
      "WITNESS_KEY_SECRET must be exactly 32 random bytes encoded as 64 hex chars, " +
      "43 base64url chars, or 44 base64 chars. Generate with `openssl rand -hex 32`. " +
      "Passphrase-style or dictionary secrets are rejected because the resulting " +
      "ciphertext would be brute-forceable offline if storage is exposed.",
    );
  }
  // Also apply the diversity / no-repeat checks as defense in depth against
  // pathological CSPRNG-shaped values like "a".repeat(64).
  if (!isAcceptableSecret(secret)) {
    throw new Error(
      "WITNESS_KEY_SECRET passed format check but appears low-entropy " +
      "(repeated characters or short period). Use a real CSPRNG output.",
    );
  }
}

async function deriveAesKey(secret: string): Promise<CryptoKey> {
  validateWitnessKeySecret(secret);
  const keyBytes = new TextEncoder().encode(secret);
  const baseKey = await crypto.subtle.importKey("raw", keyBytes, "HKDF", false, ["deriveBits"]);
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      // No external salt available here, but the info string provides context binding.
      // The platform secret is expected to be high-entropy, so a zero salt is acceptable.
      salt: new Uint8Array(32),
      info: new TextEncoder().encode("witness/key-encryption/v1"),
    },
    baseKey,
    256,
  );
  return crypto.subtle.importKey("raw", derivedBits, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

/** Legacy AES key derivation (raw SHA-256 of the secret). Used as a fallback
 * during decrypt to read private keys that were encrypted before the
 * HKDF-SHA256 migration (commit bcc26b5, May 2026). On a successful
 * decrypt, callers should re-encrypt the value with the HKDF derivation
 * and rewrite storage so subsequent reads use the new scheme. */
async function deriveAesKeyLegacy(secret: string): Promise<CryptoKey> {
  const keyBytes = new TextEncoder().encode(secret);
  const hash = await crypto.subtle.digest("SHA-256", keyBytes);
  return crypto.subtle.importKey("raw", hash, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

/** Encrypt a private key with AES-256-GCM. Returns `iv_hex:ciphertext_hex`.
 * Refuses to encrypt under a weak secret (assertStrongSecretForEncrypt) so
 * that fresh identity material and migrated-forward ciphertexts cannot be
 * sealed under a brute-forceable key. Use a CSPRNG-generated 32-byte secret. */
export async function encryptPrivateKey(
  key: Uint8Array,
  secret: string,
): Promise<string> {
  assertStrongSecretForEncrypt(secret);
  const aesKey = await deriveAesKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    key,
  );
  return `${bytesToHex(iv)}:${bytesToHex(new Uint8Array(ciphertext))}`;
}

/** Result of decryption — includes whether the stored value used the legacy
 * SHA-256-derived AES key. Callers should re-encrypt and persist the new
 * `iv:ciphertext` when `usedLegacyDerivation` is true, so subsequent reads
 * use the current HKDF-derived key. */
export interface DecryptResult {
  plaintext: Uint8Array;
  usedLegacyDerivation: boolean;
}

/** Decrypt a private key from `iv_hex:ciphertext_hex` format.
 * Tries the current HKDF-derived key first, then falls back to the legacy
 * SHA-256-derived key for values that were encrypted before the HKDF
 * migration. Returning false from both attempts throws the AES-GCM error. */
export async function decryptPrivateKeyWithFallback(
  encrypted: string,
  secret: string,
): Promise<DecryptResult> {
  const colonIdx = encrypted.indexOf(":");
  if (colonIdx === -1) {
    throw new Error("Invalid encrypted key format: missing IV separator");
  }
  const ivHex = encrypted.slice(0, colonIdx);
  const ciphertextHex = encrypted.slice(colonIdx + 1);

  // Validate hex format strictly to catch storage corruption early
  if (ivHex.length !== 24 || !/^[0-9a-fA-F]+$/.test(ivHex)) {
    throw new Error("Invalid encrypted key format: IV must be 24 hex chars (12 bytes)");
  }
  // Length cap before the regex. The plaintext is a 32-byte Ed25519
  // private key → 32 plaintext + 16 GCM tag = 48 bytes → 96 hex chars.
  // 512 is generous headroom and bounds the regex scan + decode cost
  // for adversarial storage values.
  const MAX_CIPHERTEXT_HEX = 512;
  if (ciphertextHex.length === 0 || ciphertextHex.length > MAX_CIPHERTEXT_HEX ||
      ciphertextHex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(ciphertextHex)) {
    throw new Error("Invalid encrypted key format: ciphertext must be non-empty bounded even-length hex");
  }

  const iv = hexToBytes(ivHex);
  const ciphertext = hexToBytes(ciphertextHex);

  // Try current HKDF-derived key first.
  try {
    const aesKey = await deriveAesKey(secret);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      aesKey,
      ciphertext,
    );
    return { plaintext: new Uint8Array(plaintext), usedLegacyDerivation: false };
  } catch {
    // Fall through to legacy derivation.
  }

  // Legacy fallback for values encrypted before the HKDF migration.
  // If this also fails, the AES-GCM error propagates — caller treats as
  // "wrong secret or corrupt ciphertext" and should not silently continue.
  const legacyKey = await deriveAesKeyLegacy(secret);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    legacyKey,
    ciphertext,
  );
  return { plaintext: new Uint8Array(plaintext), usedLegacyDerivation: true };
}

/** Backward-compatible decrypt. Returns only the plaintext; callers that
 * need to detect legacy derivation should use decryptPrivateKeyWithFallback. */
export async function decryptPrivateKey(
  encrypted: string,
  secret: string,
): Promise<Uint8Array> {
  const { plaintext } = await decryptPrivateKeyWithFallback(encrypted, secret);
  return plaintext;
}

/** Check whether a stored key value is encrypted (contains colon) or legacy plaintext. */
export function isEncryptedKey(stored: string): boolean {
  return stored.includes(":");
}
