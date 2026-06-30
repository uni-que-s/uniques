/**
 * Mint a signed on-prem license key. UniQueS founder-only — run this after a
 * customer pays, then send them the printed key. Needs the private signing key
 * at server/.license-signing-key.pem (see gen-license-keypair.ts).
 *
 *   npx tsx scripts/issue-license.ts --org "Acme Bank" --edition business --days 365
 *   npx tsx scripts/issue-license.ts --org "Acme" --edition enterprise --expires 2027-06-30 --seats 50
 *
 * Flags:
 *   --org <name>        (required) licensed organization, shown in their dashboard
 *   --edition <tier>    team | business | enterprise   (default: business)
 *   --days <n>          validity in days from today     (default: 365)
 *   --expires <date>    explicit YYYY-MM-DD expiry (overrides --days)
 *   --seats <n>         seat/estate allowance, recorded for the record (default: 1)
 */
import { sign, createPrivateKey, randomUUID } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { LICENSE_TOKEN_PREFIX, encodePayload, type LicensePayload } from "../src/license/verify.js";

const KEY_PATH = new URL("../.license-signing-key.pem", import.meta.url);

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

function isoDatePlusDays(days: number): string {
  return new Date(Date.now() + days * 86_400_000).toISOString().slice(0, 10);
}

const org = arg("org");
if (!org) {
  console.error('error: --org "<name>" is required');
  process.exit(2);
}
if (!existsSync(KEY_PATH)) {
  console.error(`error: signing key not found at ${KEY_PATH.pathname} — run scripts/gen-license-keypair.ts first`);
  process.exit(2);
}

const edition = (arg("edition") ?? "business").toLowerCase();
const seats = Number(arg("seats") ?? 1);
const expires = arg("expires") ?? isoDatePlusDays(Number(arg("days") ?? 365));
// Structural AND calendar validity — reject e.g. 2026-13-45 or 2026-02-30 at
// issue time so a fat-fingered expiry can't mint a key that silently reads as
// expired (NaN) or rolls over to the wrong date. Guard NaN before toISOString,
// which throws on an Invalid Date.
const expiresDate = new Date(`${expires}T00:00:00Z`);
if (
  !/^\d{4}-\d{2}-\d{2}$/.test(expires) ||
  Number.isNaN(expiresDate.getTime()) ||
  expiresDate.toISOString().slice(0, 10) !== expires
) {
  console.error(`error: --expires must be a real calendar date YYYY-MM-DD (got "${expires}")`);
  process.exit(2);
}

const payload: LicensePayload = {
  id: `lic_${randomUUID().slice(0, 8)}`,
  org,
  edition,
  seats,
  issued: new Date().toISOString().slice(0, 10),
  expires,
};

const payloadB64 = encodePayload(payload);
const signingInput = Buffer.from(`${LICENSE_TOKEN_PREFIX}.${payloadB64}`, "utf8");
const signature = sign(null, signingInput, createPrivateKey(readFileSync(KEY_PATH))).toString("base64url");
const token = `${LICENSE_TOKEN_PREFIX}.${payloadB64}.${signature}`;

console.error(`Issued ${payload.id} — ${org} · ${edition} · ${seats} seat(s) · expires ${expires}\n`);
console.log(token);
