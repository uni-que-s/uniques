import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Isolate the database before importing the app (which transitively opens it).
const dbDir = mkdtempSync(join(tmpdir(), "qv-api-db-"));
process.env.QV_DB_PATH = join(dbDir, "test.db");
process.env.QV_LOG = "off"; // keep test output clean of access logs

const { createApp } = await import("../app.js");

let server: Server;
let base: string;
const srcDir = mkdtempSync(join(tmpdir(), "qv-api-src-"));

before(async () => {
  writeFileSync(
    join(srcDir, "app.ts"),
    ["generateKeyPairSync('rsa', { modulusLength: 2048 });", "createDiffieHellman(2048);"].join("\n"),
  );
  server = createApp().listen(0);
  await once(server, "listening");
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => {
  server.close();
  rmSync(dbDir, { recursive: true, force: true });
  rmSync(srcDir, { recursive: true, force: true });
});

const json = (path: string, init?: RequestInit) => fetch(base + path, init);
const authed = (token: string, extra: RequestInit = {}): RequestInit => ({
  ...extra,
  headers: { "content-type": "application/json", authorization: `Bearer ${token}`, ...(extra.headers ?? {}) },
});

async function signup(email: string, orgName: string): Promise<string> {
  const r = await json("/api/auth/signup", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, password: "hunter2pw12", orgName }),
  });
  assert.equal(r.status, 201);
  return (await r.json()).token as string;
}

test("health reports ok and the pattern count", async () => {
  const r = await json("/api/health");
  assert.equal(r.status, 200);
  const body = await r.json();
  assert.equal(body.status, "ok");
  assert.equal(body.patterns, 28);
});

test("auth is required for scanning and status changes", async () => {
  const noTok = await json("/api/scans", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ target: srcDir }),
  });
  assert.equal(noTok.status, 401);

  const patch = await json("/api/assets/whatever/status", {
    method: "PATCH",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ status: "migrated" }),
  });
  assert.equal(patch.status, 401);
});

test("scan → list → patch status → CSV export, all org-scoped", async () => {
  const tokenA = await signup("a@acme.test", "Acme");

  // Scan a temp source tree.
  const scan = await json("/api/scans", authed(tokenA, { method: "POST", body: JSON.stringify({ target: srcDir }) }));
  assert.equal(scan.status, 201);
  assert.ok((await scan.json()).assetCount >= 2);

  // List assets for org A.
  const assets = await (await json("/api/assets", authed(tokenA))).json();
  assert.ok(Array.isArray(assets) && assets.length >= 2);
  const assetId = assets[0].id as string;

  // Invalid status rejected.
  const bad = await json(`/api/assets/${assetId}/status`, authed(tokenA, { method: "PATCH", body: JSON.stringify({ status: "nope" }) }));
  assert.equal(bad.status, 400);

  // Valid status accepted and reflected.
  const ok = await json(`/api/assets/${assetId}/status`, authed(tokenA, { method: "PATCH", body: JSON.stringify({ status: "migrated" }) }));
  assert.equal(ok.status, 200);
  assert.equal((await ok.json()).status, "migrated");

  // Dashboard reflects one migrated asset.
  const dash = await (await json("/api/dashboard", authed(tokenA))).json();
  assert.equal(dash.byStatus.migrated, 1);
  assert.ok(dash.migrationProgressPct > 0);

  // CSV export has the right content type and a header row.
  const csv = await json("/api/assets/export.csv", authed(tokenA));
  assert.equal(csv.status, 200);
  assert.match(csv.headers.get("content-type") ?? "", /text\/csv/);
  assert.match(await csv.text(), /^file,line,family,/);

  // Org B is isolated: sees no assets and cannot mutate org A's asset.
  const tokenB = await signup("b@beta.test", "Beta");
  const bAssets = await (await json("/api/assets", authed(tokenB))).json();
  assert.equal(bAssets.length, 0);
  const cross = await json(`/api/assets/${assetId}/status`, authed(tokenB, { method: "PATCH", body: JSON.stringify({ status: "open" }) }));
  assert.equal(cross.status, 404);
});

test("unknown asset id returns 404", async () => {
  const r = await json("/api/assets/does-not-exist");
  assert.equal(r.status, 404);
});

test("responses carry baseline security headers", async () => {
  const r = await json("/api/health");
  assert.equal(r.headers.get("x-content-type-options"), "nosniff");
  assert.equal(r.headers.get("x-frame-options"), "DENY");
  assert.equal(r.headers.get("x-powered-by"), null);
});

test("CORS is enabled and reflects the default (allow-any) origin", async () => {
  const r = await json("/api/health", { headers: { origin: "http://dashboard.test" } });
  assert.equal(r.headers.get("access-control-allow-origin"), "*");
});

test("unmatched API routes return a JSON 404 envelope", async () => {
  const r = await json("/api/nope/not/a/route");
  assert.equal(r.status, 404);
  assert.match(r.headers.get("content-type") ?? "", /application\/json/);
  assert.equal((await r.json()).error, "not found");
});

test("malformed JSON bodies get a 400, not a 500", async () => {
  const r = await json("/api/auth/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{ not valid json",
  });
  assert.equal(r.status, 400);
});
