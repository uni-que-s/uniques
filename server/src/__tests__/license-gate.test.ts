import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

// Force the trial to be already-expired (length 0) so the gate's locked path is
// exercised on a fresh instance, and pin a test ML-DSA signing key so we can mint
// a real key to unlock it.
const issuer = ml_dsa65.keygen(new Uint8Array(randomBytes(32)));
process.env.QV_LICENSE_PUBKEY = Buffer.from(issuer.publicKey).toString("base64");
process.env.QV_TRIAL_DAYS = "0";
process.env.QV_GRACE_DAYS = "0"; // skip grace → land straight in the read-only resting state
process.env.QV_LOG = "off";
const dbDir = mkdtempSync(join(tmpdir(), "qv-gate-db-"));
process.env.QV_DB_PATH = join(dbDir, "test.db");

const { createApp } = await import("../app.js");
const { encodePayload, LICENSE_TOKEN_PREFIX } = await import("../license/verify.js");

function mintKey(): string {
  const payload = {
    id: "lic_gate01",
    org: "Acme Bank",
    edition: "business",
    seats: 5,
    issued: new Date().toISOString().slice(0, 10),
    expires: new Date(Date.now() + 365 * 86_400_000).toISOString().slice(0, 10),
  };
  const b64 = encodePayload(payload);
  const sigInput = new Uint8Array(Buffer.from(`${LICENSE_TOKEN_PREFIX}.${b64}`, "utf8"));
  const sig = Buffer.from(ml_dsa65.sign(sigInput, issuer.secretKey)).toString("base64url");
  return `${LICENSE_TOKEN_PREFIX}.${b64}.${sig}`;
}

let server: Server;
let base: string;
const get = (p: string) => fetch(base + p);
const post = (p: string, body: unknown) =>
  fetch(base + p, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

before(async () => {
  server = createApp().listen(0);
  await once(server, "listening");
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(() => {
  server.close();
  rmSync(dbDir, { recursive: true, force: true });
});

test("health stays open when the trial has lapsed", async () => {
  assert.equal((await get("/api/health")).status, 200);
});

test("the license endpoint reports the read-only resting state", async () => {
  const r = await get("/api/license");
  assert.equal(r.status, 200);
  const s = await r.json();
  assert.equal(s.active, false);
  assert.equal(s.readOnly, true);
  assert.equal(s.reason, "trial_readonly");
});

test("read-only: viewing existing data stays open (GET 200)", async () => {
  assert.equal((await get("/api/dashboard")).status, 200);
});

test("read-only: a write (new scan) is gated with 402", async () => {
  const r = await post("/api/scans", { target: "/tmp" });
  assert.equal(r.status, 402);
  assert.equal((await r.json()).error, "license_required_for_writes");
});

test("activation rejects an invalid key", async () => {
  assert.equal((await post("/api/license/activate", { key: "garbage" })).status, 400);
});

test("activating a valid key lifts the write gate", async () => {
  const r = await post("/api/license/activate", { key: mintKey() });
  assert.equal(r.status, 200);
  assert.equal((await r.json()).state, "licensed");
  // the license gate no longer blocks the write — it now falls through to the
  // route's own auth (401), proving the 402 license gate is gone.
  assert.equal((await post("/api/scans", { target: "/tmp" })).status, 401);
});
