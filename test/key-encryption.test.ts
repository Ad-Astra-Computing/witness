import { describe, it, expect, vi } from "vitest";
import {
  encryptPrivateKey,
  decryptPrivateKey,
  isEncryptedKey,
  validateWitnessKeySecret,
} from "../src/key-encryption.js";

// 32-byte hex secret for testing
const TEST_SECRET = "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1";
const WRONG_SECRET = "ff".repeat(32);

describe("key encryption", () => {
  it("round-trips encrypt then decrypt", async () => {
    const key = new Uint8Array(32);
    for (let i = 0; i < 32; i++) key[i] = i;

    const encrypted = await encryptPrivateKey(key, TEST_SECRET);
    const decrypted = await decryptPrivateKey(encrypted, TEST_SECRET);

    expect(decrypted).toEqual(key);
  });

  it("produces different ciphertexts each time (random IV)", async () => {
    const key = new Uint8Array(32).fill(0x42);

    const enc1 = await encryptPrivateKey(key, TEST_SECRET);
    const enc2 = await encryptPrivateKey(key, TEST_SECRET);

    expect(enc1).not.toBe(enc2);
  });

  it("encrypted format contains colon separator (iv:ciphertext)", async () => {
    const key = new Uint8Array(32).fill(0x01);
    const encrypted = await encryptPrivateKey(key, TEST_SECRET);

    expect(encrypted).toContain(":");
    const parts = encrypted.split(":");
    expect(parts.length).toBe(2);
    // IV should be 12 bytes = 24 hex chars
    expect(parts[0]!.length).toBe(24);
  });

  it("wrong secret fails to decrypt", async () => {
    const key = new Uint8Array(32).fill(0xab);
    const encrypted = await encryptPrivateKey(key, TEST_SECRET);

    await expect(
      decryptPrivateKey(encrypted, WRONG_SECRET),
    ).rejects.toThrow();
  });

  it("isEncryptedKey detects encrypted vs legacy plaintext", () => {
    // Legacy plaintext: 64 hex chars, no colon
    const legacy = "ab".repeat(32);
    expect(isEncryptedKey(legacy)).toBe(false);

    // Encrypted: iv:ciphertext with colon
    const encrypted = "aa".repeat(12) + ":" + "bb".repeat(48);
    expect(isEncryptedKey(encrypted)).toBe(true);
  });

  it("handles legacy plaintext key migration path", async () => {
    // Simulate a legacy key: plain hex, 64 chars
    const legacyHex = "0123456789abcdef".repeat(4);
    expect(isEncryptedKey(legacyHex)).toBe(false);

    // Encrypt it
    const encrypted = await encryptPrivateKey(
      hexToBytes(legacyHex),
      TEST_SECRET,
    );
    expect(isEncryptedKey(encrypted)).toBe(true);

    // Decrypt and verify
    const decrypted = await decryptPrivateKey(encrypted, TEST_SECRET);
    expect(decrypted).toEqual(hexToBytes(legacyHex));
  });
});

describe("validateWitnessKeySecret", () => {
  // Only missing/empty is fatal — low-entropy is logged as a warning so a
  // deployment with an older secret format doesn't 500 at DO init time.

  it("throws on undefined or empty secret", () => {
    expect(() => validateWitnessKeySecret(undefined)).toThrow();
    expect(() => validateWitnessKeySecret("")).toThrow();
  });

  it("warns (but does not throw) on short low-entropy secrets", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      expect(() => validateWitnessKeySecret("password")).not.toThrow();
      expect(() => validateWitnessKeySecret("test-secret-for-witness-key-enc")).not.toThrow();
      expect(warn).toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });

  it("accepts secrets in any encoding (hex, base64, base64url, base32, etc.)", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      expect(() => validateWitnessKeySecret("aB3+fG/iJ9kL2mN5oP6qR4sT7uV0wX1yZ8aB3+fG=")).not.toThrow();
      expect(() => validateWitnessKeySecret("a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5")).not.toThrow();
      // No warning expected for these reasonable secrets.
      expect(warn).not.toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });

  it("warns on low-diversity inputs (defends against \"a\"*64)", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      expect(() => validateWitnessKeySecret("a".repeat(64))).not.toThrow();
      expect(warn).toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });

  it("warns on short-period repeating secrets", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      expect(() => validateWitnessKeySecret("0123456789".repeat(7))).not.toThrow();
      expect(() => validateWitnessKeySecret("abcdef0123456789".repeat(4))).not.toThrow();
      expect(warn).toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });

  it("warns on truncated repeats whose length is not a multiple of the period", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      expect(() => validateWitnessKeySecret("0123456789".repeat(6) + "0123")).not.toThrow();
      expect(warn).toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });

  it("warns on repeats with period > len/3 (e.g. 15-char period in 43-char string)", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
    const period = "0123456789abcde";
    // 2 full periods (30 chars) + 13-char truncated tail = 43 chars
    const candidate = period.repeat(2) + period.slice(0, 13);
    expect(candidate.length).toBe(43);
    expect(() => validateWitnessKeySecret(candidate)).not.toThrow();
    expect(warn).toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });

  it("accepts a real CSPRNG-style 64-hex-char secret", () => {
    expect(() => validateWitnessKeySecret(TEST_SECRET)).not.toThrow();
  });

  it("accepts a real CSPRNG-style 43+ base64url-char secret", () => {
    // Realistic base64url-encoded 32 random bytes
    expect(() => validateWitnessKeySecret("dGhpcy1pcy1hLXJlYWxpc3RpYy1lbnRyb3B5LXNlY3JldA")).not.toThrow();
    expect(() => validateWitnessKeySecret("aB3-fG_iJ9kL2mN5oP6qR4sT7uV0wX1yZ8aB3-fG_iJ9k")).not.toThrow();
  });
});

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}
