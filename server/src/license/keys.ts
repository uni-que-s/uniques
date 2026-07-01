/**
 * ML-DSA-65 (FIPS 204) public key for verifying on-prem license tokens *offline*
 * — POST-QUANTUM. No RSA/ECC anywhere in the license path, so the product itself
 * contains no quantum-vulnerable cryptography, and it verifies with no network
 * call (works air-gapped). ML-DSA is a NIST-standardized lattice signature; the
 * implementation is @noble/post-quantum (pure JS — no native/WASM dependency, so
 * the zero-native-dependency / air-gap posture is preserved).
 *
 * The matching 32-byte signing SEED is held only by UniQueS
 * (server/.license-signing-seed, gitignored) and drives scripts/issue-license.ts.
 * Rotation: run scripts/gen-license-keypair.ts, paste the new key below, ship a
 * new build. QV_LICENSE_PUBKEY (base64) overrides for pinning/testing.
 */
const EMBEDDED_PUBLIC_KEY_B64 =
  "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";

/** An ML-DSA-65 public key is exactly 1952 bytes. */
const ML_DSA65_PUBKEY_BYTES = 1952;

/** The active ML-DSA license verification public key bytes (env override wins). */
export function licensePublicKey(): Uint8Array {
  const override = process.env.QV_LICENSE_PUBKEY?.trim();
  const b64 = override && override.length > 0 ? override : EMBEDDED_PUBLIC_KEY_B64;
  return new Uint8Array(Buffer.from(b64, "base64"));
}

// Fail loud on a mis-pasted override rather than silently rejecting every valid
// license: warn once at startup if QV_LICENSE_PUBKEY isn't a 1952-byte key.
{
  const override = process.env.QV_LICENSE_PUBKEY?.trim();
  if (override && Buffer.from(override, "base64").length !== ML_DSA65_PUBKEY_BYTES) {
    console.warn(
      `[license] QV_LICENSE_PUBKEY is not a valid ML-DSA-65 public key (expected ${ML_DSA65_PUBKEY_BYTES} bytes) — ` +
        `license verification will reject all keys until this is fixed.`,
    );
  }
}
