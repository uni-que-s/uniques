import { createPublicKey, verify as cryptoVerify, type KeyObject } from "node:crypto";
import { licensePublicKeyPem } from "./keys.js";

/**
 * License token wire format (compact, offline-verifiable, no dependencies):
 *
 *     UQS1.<payloadB64url>.<signatureB64url>
 *
 * - `payloadB64url` is base64url(JSON.stringify(LicensePayload)).
 * - The Ed25519 signature covers the exact ASCII bytes `UQS1.<payloadB64url>`,
 *   so the version prefix and payload are both bound — you cannot swap the prefix
 *   or mutate a single byte of the payload without invalidating the signature.
 */
export const LICENSE_TOKEN_PREFIX = "UQS1";

export interface LicensePayload {
  /** Unique license id — for support, renewals, and (future) revocation lists. */
  id: string;
  /** Licensed organization name (shown in the dashboard + audit logs). */
  org: string;
  /** Plan tier, lower-case: "team" | "business" | "enterprise" (free-form). */
  edition: string;
  /** Seat / estate allowance. Informational in v0.1 — recorded, not hard-enforced. */
  seats: number;
  /** Issue date, ISO `YYYY-MM-DD`. */
  issued: string;
  /** Expiry date, ISO `YYYY-MM-DD`, inclusive (valid through that day). */
  expires: string;
}

// Ed25519 signatures are always exactly 64 bytes — used as a cheap early reject.
const ED25519_SIG_BYTES = 64;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

// Cache the parsed KeyObject, re-deriving only if the active PEM changes (the env
// override can differ between processes / tests).
let cached: { pem: string; key: KeyObject } | null = null;
function publicKey(): KeyObject {
  const pem = licensePublicKeyPem();
  if (!cached || cached.pem !== pem) cached = { pem, key: createPublicKey(pem) };
  return cached.key;
}

/** base64url → string, for issuing (the issuer encodes the payload the same way). */
export function encodePayload(payload: LicensePayload): string {
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
}

/**
 * Verify a license token's signature against the active public key and return the
 * decoded payload — ONLY if the signature is authentic. Deliberately does NOT
 * check expiry: callers apply their own policy, which keeps a genuine-but-expired
 * key distinguishable from a forgery. Never throws; any malformed, mistyped, or
 * tampered input returns null.
 */
export function verifyLicenseToken(token: unknown): LicensePayload | null {
  if (typeof token !== "string") return null;
  const parts = token.trim().split(".");
  if (parts.length !== 3) return null;
  const [prefix, payloadB64, sigB64] = parts;
  if (prefix !== LICENSE_TOKEN_PREFIX || !payloadB64 || !sigB64) return null;

  const sig = Buffer.from(sigB64, "base64url");
  if (sig.length !== ED25519_SIG_BYTES) return null;

  const signingInput = Buffer.from(`${prefix}.${payloadB64}`, "utf8");
  let authentic = false;
  try {
    authentic = cryptoVerify(null, signingInput, publicKey(), sig);
  } catch {
    return null; // malformed key / signature bytes
  }
  if (!authentic) return null;

  let payload: unknown;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  return isLicensePayload(payload) ? payload : null;
}

function isLicensePayload(p: unknown): p is LicensePayload {
  if (typeof p !== "object" || p === null) return false;
  const o = p as Record<string, unknown>;
  return (
    typeof o.id === "string" &&
    typeof o.org === "string" &&
    typeof o.edition === "string" &&
    typeof o.seats === "number" &&
    Number.isFinite(o.seats) &&
    typeof o.issued === "string" &&
    ISO_DATE.test(o.issued) &&
    typeof o.expires === "string" &&
    ISO_DATE.test(o.expires)
  );
}
