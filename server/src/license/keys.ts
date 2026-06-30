/**
 * Ed25519 public key used to verify on-prem license tokens *offline* — no network
 * call, so it works air-gapped. The matching PRIVATE key is held only by UniQueS
 * (server/.license-signing-key.pem, gitignored) and is used by
 * scripts/issue-license.ts to mint customer keys.
 *
 * Rotation: run scripts/gen-license-keypair.ts to regenerate the pair, paste the
 * new public key below, and ship a new build (rotating invalidates every key
 * issued under the old pair).
 *
 * Advanced / self-host override: set QV_LICENSE_PUBKEY to a PEM public key to pin
 * your own signing key (e.g. an enterprise that mints its own internal licenses,
 * or to rotate without a rebuild). This is a deployment-level setting; anyone who
 * can set it already controls the host, so it changes no real trust boundary —
 * the signed-key model deters casual key-sharing, not a determined self-hoster.
 */
const EMBEDDED_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAsAwDchfXvPFkE2q0gJkPeNXNeFZT9HOVcfZGdpsHq0o=
-----END PUBLIC KEY-----
`;

/** The active license verification public key (env override wins, else embedded). */
export function licensePublicKeyPem(): string {
  const override = process.env.QV_LICENSE_PUBKEY?.trim();
  return override && override.length > 0 ? override : EMBEDDED_PUBLIC_KEY_PEM;
}
