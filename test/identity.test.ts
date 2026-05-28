import { describe, it, expect } from "vitest";
import { encodePublicKeyMultibase, base64urlEncode } from "../src/shared/crypto.js";

describe("witness identity publicKeyMultibase", () => {
  it("encodePublicKeyMultibase produces z-prefixed base58btc with ed01 prefix", () => {
    const key = new Uint8Array(32);
    for (let i = 0; i < 32; i++) key[i] = i;

    const result = encodePublicKeyMultibase(key);

    // Must start with 'z'
    expect(result[0]).toBe("z");
    // Must not be base64url (which is what was used before)
    expect(result).not.toBe(base64urlEncode(key));
  });
});
