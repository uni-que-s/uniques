import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import type { LicensePayload } from "../license/verify.js";

// --- Test signing identity -------------------------------------------------
// Pin a throwaway keypair as the verification key (env override) and sign test
// tokens with its private half. This exercises the real verify path without ever
// needing the founder's private .pem — so it runs in CI where that file is absent.
const issuer = generateKeyPairSync("ed25519");
const foreign = generateKeyPairSync("ed25519"); // a different, untrusted signer
process.env.QV_LICENSE_PUBKEY = issuer.publicKey.export({ type: "spki", format: "pem" }).toString();
process.env.QV_TRIAL_DAYS = "30";
process.env.QV_DB_PATH = join(mkdtempSync(join(tmpdir(), "qv-lic-")), "lic.db");

const { verifyLicenseToken, encodePayload, LICENSE_TOKEN_PREFIX } = await import("../license/verify.js");
const { getLicenseStatus, activateLicense } = await import("../license/service.js");
const { db } = await import("../store/db.js");

const DAY = 86_400_000;
const isoIn = (days: number) => new Date(Date.now() + days * DAY).toISOString().slice(0, 10);

function mint(over: Partial<LicensePayload> = {}, signer: KeyObject = issuer.privateKey): string {
  const payload: LicensePayload = {
    id: "lic_test01",
    org: "Acme Bank",
    edition: "business",
    seats: 5,
    issued: isoIn(0),
    expires: isoIn(365),
    ...over,
  };
  const b64 = encodePayload(payload);
  const sigInput = Buffer.from(`${LICENSE_TOKEN_PREFIX}.${b64}`, "utf8");
  return `${LICENSE_TOKEN_PREFIX}.${b64}.${sign(null, sigInput, signer).toString("base64url")}`;
}

beforeEach(() => {
  db.prepare("DELETE FROM app_meta").run(); // fresh trial/license state per test
});

// --- verifyLicenseToken ----------------------------------------------------

test("verify: accepts an authentic token and returns the payload", () => {
  const p = verifyLicenseToken(mint({ org: "Globex", edition: "enterprise" }));
  assert.ok(p);
  assert.equal(p?.org, "Globex");
  assert.equal(p?.edition, "enterprise");
});

test("verify: rejects a tampered payload", () => {
  const tok = mint();
  const [prefix, payload, sig] = tok.split(".");
  // flip one base64url char in the payload — signature no longer matches
  const mutated = payload.slice(0, -1) + (payload.slice(-1) === "A" ? "B" : "A");
  assert.equal(verifyLicenseToken(`${prefix}.${mutated}.${sig}`), null);
});

test("verify: rejects a token signed by an untrusted key (key substitution)", () => {
  assert.equal(verifyLicenseToken(mint({}, foreign.privateKey)), null);
});

test("verify: rejects a swapped version prefix", () => {
  const tok = mint();
  assert.equal(verifyLicenseToken("UQS2" + tok.slice(4)), null);
});

test("verify: rejects malformed / mistyped input without throwing", () => {
  for (const bad of ["", "not-a-token", "UQS1.only-two", "UQS1..", 42, null, undefined, {}]) {
    assert.equal(verifyLicenseToken(bad as unknown as string), null);
  }
});

test("verify: rejects a signature of the wrong length", () => {
  const [prefix, payload] = mint().split(".");
  assert.equal(verifyLicenseToken(`${prefix}.${payload}.${Buffer.from("short").toString("base64url")}`), null);
});

// --- trial + license status ------------------------------------------------

test("status: a fresh instance auto-starts the trial and is active", () => {
  const s = getLicenseStatus();
  assert.equal(s.state, "trial");
  assert.equal(s.active, true);
  assert.ok(s.daysRemaining >= 29 && s.daysRemaining <= 30, `daysRemaining=${s.daysRemaining}`);
  assert.match(s.expiresAt ?? "", /^\d{4}-\d{2}-\d{2}$/);
});

test("status: just past the trial it enters grace (still full access)", () => {
  getLicenseStatus(); // start the clock now (30-day trial, default 7-day grace)
  const s = getLicenseStatus(new Date(Date.now() + 31 * DAY));
  assert.equal(s.state, "grace");
  assert.equal(s.active, true);
  assert.equal(s.readOnly, false);
  assert.equal(s.reason, "trial_grace");
});

test("status: after grace it drops to the read-only resting state", () => {
  getLicenseStatus(); // start the clock now
  const s = getLicenseStatus(new Date(Date.now() + 38 * DAY));
  assert.equal(s.state, "readonly");
  assert.equal(s.active, false);
  assert.equal(s.readOnly, true);
  assert.equal(s.reason, "trial_readonly");
});

test("status: activating an authentic key flips state to licensed", () => {
  const s = activateLicense(mint({ org: "Initech", edition: "team" }));
  assert.equal(s.state, "licensed");
  assert.equal(s.active, true);
  assert.equal(s.org, "Initech");
  assert.equal(s.edition, "team");
  // persists across reads
  assert.equal(getLicenseStatus().state, "licensed");
});

test("status: a licensed key well past expiry goes read-only (not trial)", () => {
  activateLicense(mint({ org: "Initech", expires: isoIn(10) }));
  const s = getLicenseStatus(new Date(Date.now() + 20 * DAY)); // 10 days past expiry, past 7-day grace
  assert.equal(s.state, "readonly");
  assert.equal(s.reason, "license_readonly");
  assert.equal(s.org, "Initech"); // still surfaces who it was issued to
});

test("status: a licensed key just past expiry is in grace, still active", () => {
  activateLicense(mint({ org: "Initech", expires: isoIn(2) }));
  const s = getLicenseStatus(new Date(Date.now() + 3 * DAY)); // 1 day past expiry, within grace
  assert.equal(s.state, "grace");
  assert.equal(s.active, true);
  assert.equal(s.reason, "license_grace");
});

test("activate: refuses an already-expired key", () => {
  assert.throws(() => activateLicense(mint({ expires: isoIn(-1) })), /expired/i);
});

test("activate: refuses a forged / invalid key", () => {
  assert.throws(() => activateLicense(mint({}, foreign.privateKey)), /not valid/i);
  assert.throws(() => activateLicense("garbage"), /not valid/i);
});
