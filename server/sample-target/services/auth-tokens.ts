// Issues and verifies customer API session tokens (JWT / JOSE).
import jwt from "jsonwebtoken";

// Access tokens are signed with an RSA private key — quantum-vulnerable.
export function issueAccessToken(claims: object, rsaPrivateKey: string): string {
  return jwt.sign(claims, rsaPrivateKey, { algorithm: "RS256" });
}

// Partner webhook callbacks are signed with an ECDSA P-256 key.
export function signWebhook(payload: object, ecPrivateKey: string): string {
  return jwt.sign(payload, ecPrivateKey, { algorithm: "ES256" });
}

// Field-level encryption of PII wraps the data key with RSA-OAEP (Web Crypto).
export async function wrapDataKey(pub: CryptoKey, rawKey: ArrayBuffer): Promise<ArrayBuffer> {
  return crypto.subtle.encrypt({ name: "RSA-OAEP" }, pub, rawKey);
}
