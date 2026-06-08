import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Isolate the SQLite database to a temp file BEFORE importing the store, so this
// test never touches a real/seeded database. node:test runs each test file in
// its own process, so this env var is picked up cleanly at module init.
const dbDir = mkdtempSync(join(tmpdir(), "qv-store-db-"));
process.env.QV_DB_PATH = join(dbDir, "test.db");

const { store } = await import("../store/store.js");

test("store: status updates drive migration progress and are org-scoped", () => {
  const org = "org_test";
  const src = mkdtempSync(join(tmpdir(), "qv-store-src-"));
  try {
    // A source tree with a few quantum-vulnerable assets.
    writeFileSync(
      join(src, "app.ts"),
      [
        "const k = generateKeyPairSync('rsa', { modulusLength: 2048 });",
        "// uses ECDSA on prime256v1",
        "createDiffieHellman(2048);",
      ].join("\n"),
    );

    store.runScan(src, undefined, org);
    const assets = store.getAssets(undefined, org);
    assert.ok(assets.length >= 2, `expected >=2 assets, got ${assets.length}`);
    assert.ok(assets.every((a) => a.status === "open"), "new assets must start 'open'");

    // Baseline: nothing resolved.
    let dash = store.dashboard(org);
    assert.equal(dash.migrationProgressPct, 0);
    assert.equal(dash.byStatus.open, assets.length);
    const totalEffort = dash.migrationEffortDays;
    assert.equal(dash.remainingEffortDays, totalEffort);

    // Resolve one asset -> progress and remaining effort move.
    const first = assets[0];
    const updated = store.updateAssetStatus(first.id, "migrated", org);
    assert.equal(updated?.status, "migrated");

    dash = store.dashboard(org);
    assert.equal(dash.byStatus.migrated, 1);
    assert.equal(dash.migrationProgressPct, Math.round((1 / assets.length) * 100));
    assert.ok(dash.remainingEffortDays <= totalEffort);

    // Invalid status is rejected.
    assert.throws(() => store.updateAssetStatus(first.id, "bogus" as never, org), /invalid status/);

    // Unknown id -> undefined (no throw).
    assert.equal(store.updateAssetStatus("nope", "migrated", org), undefined);

    // Org isolation: another org can't mutate this org's asset.
    assert.equal(store.updateAssetStatus(first.id, "accepted", "org_other"), undefined);
    assert.equal(store.getAsset(first.id, org)?.status, "migrated");
  } finally {
    rmSync(src, { recursive: true, force: true });
  }
});

test("store: remediation status carries forward across re-scans", () => {
  const org = "org_rescan";
  const src = mkdtempSync(join(tmpdir(), "qv-rescan-src-"));
  try {
    writeFileSync(
      join(src, "app.ts"),
      ["const k = generateKeyPairSync('rsa', { modulusLength: 2048 });", "createDiffieHellman(2048);"].join("\n"),
    );

    // First scan, then resolve one finding.
    store.runScan(src, undefined, org);
    const before = store.getAssets(undefined, org);
    const target = before.find((a) => a.patternId === "rsa-modulus-bits") ?? before[0];
    store.updateAssetStatus(target.id, "migrated", org);

    // Re-scan the same (unchanged) source — a brand new scan with new asset ids.
    store.runScan(src, undefined, org);
    const after = store.getAssets(undefined, org);

    // New scan => different asset ids, but the resolved finding stays "migrated".
    assert.ok(!after.some((a) => a.id === target.id), "re-scan should produce fresh asset ids");
    const carried = after.find((a) => a.patternId === target.patternId && a.file === target.file);
    assert.equal(carried?.status, "migrated", "status should carry across re-scan");

    // Other findings remain open, and progress reflects exactly one carried asset.
    const dash = store.dashboard(org);
    assert.equal(dash.byStatus.migrated, 1);
    assert.ok(dash.byStatus.open >= 1);
  } finally {
    rmSync(src, { recursive: true, force: true });
  }
});

test("store: scan delta reports new and removed findings vs the previous scan", () => {
  const org = "org_delta";
  const src = mkdtempSync(join(tmpdir(), "qv-delta-src-"));
  try {
    // Scan 1: one RSA finding + one DH finding.
    writeFileSync(
      join(src, "app.ts"),
      ["const k = generateKeyPairSync('rsa', { modulusLength: 2048 });", "createDiffieHellman(2048);"].join("\n"),
    );
    store.runScan(src, undefined, org);
    assert.equal(store.dashboard(org).delta.hasPrevious, false, "first scan has no previous");

    // Scan 2: remove the DH line, add a DES line -> 1 new, 1 removed.
    writeFileSync(
      join(src, "app.ts"),
      ["const k = generateKeyPairSync('rsa', { modulusLength: 2048 });", "const c = createCipheriv('des-ede3', k, iv);"].join("\n"),
    );
    store.runScan(src, undefined, org);

    const delta = store.dashboard(org).delta;
    assert.equal(delta.hasPrevious, true);
    assert.ok(delta.newFindings >= 1, `expected >=1 new, got ${delta.newFindings}`);
    assert.ok(delta.removedFindings >= 1, `expected >=1 removed, got ${delta.removedFindings}`);
  } finally {
    rmSync(src, { recursive: true, force: true });
  }
});

test.after(() => rmSync(dbDir, { recursive: true, force: true }));
