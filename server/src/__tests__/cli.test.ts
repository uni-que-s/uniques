import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Run the CLI in a child process (via the tsx loader) so we can assert on both
// stdout and the process exit code — the contract CI pipelines rely on.
function runCli(args: string[]): { status: number; stdout: string } {
  try {
    const stdout = execFileSync(process.execPath, ["--import", "tsx", "src/cli.ts", ...args], {
      encoding: "utf8",
    });
    return { status: 0, stdout };
  } catch (e: any) {
    return { status: e.status ?? 1, stdout: (e.stdout ?? "").toString() };
  }
}

function vulnDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "qv-cli-vuln-"));
  writeFileSync(join(dir, "key.pem"), "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n");
  return dir;
}

test("cli: --json emits scored findings for a vulnerable directory", () => {
  const dir = vulnDir();
  try {
    const { status, stdout } = runCli([dir, "--json"]);
    assert.equal(status, 0);
    const out = JSON.parse(stdout);
    assert.ok(out.assets.length >= 1);
    assert.equal(out.assets[0].family, "RSA");
    assert.ok(out.assets[0].risk && typeof out.assets[0].risk.score === "number");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("cli: --sarif emits a valid SARIF 2.1.0 log", () => {
  const dir = vulnDir();
  try {
    const { stdout } = runCli([dir, "--sarif"]);
    const sarif = JSON.parse(stdout);
    assert.equal(sarif.version, "2.1.0");
    assert.equal(sarif.runs[0].tool.driver.name, "UniQueS");
    assert.ok(sarif.runs[0].results.length >= 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("cli: --assessment emits a branded HTML report with the org name", () => {
  const dir = vulnDir();
  try {
    const { status, stdout } = runCli([dir, "--assessment", "--org", "Globex Bank"]);
    assert.equal(status, 0);
    assert.match(stdout, /<!doctype html>/i);
    assert.ok(stdout.includes("Quantum Readiness"));
    assert.ok(stdout.includes("Globex Bank"));
    assert.ok(stdout.includes("Cryptographic Inventory"));
    // The real RSA finding drives the inventory.
    assert.ok(stdout.includes("RSA"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("cli: --fail-on gates CI — non-zero on findings, zero on a clean tree", () => {
  const vuln = vulnDir();
  const clean = mkdtempSync(join(tmpdir(), "qv-cli-clean-"));
  writeFileSync(join(clean, "ok.ts"), "export const x = 1;\n");
  try {
    assert.equal(runCli([vuln, "--fail-on", "low"]).status, 1, "vulnerable tree should fail the gate");
    assert.equal(runCli([clean, "--fail-on", "low"]).status, 0, "clean tree should pass the gate");
  } finally {
    rmSync(vuln, { recursive: true, force: true });
    rmSync(clean, { recursive: true, force: true });
  }
});

test("cli: --write-baseline then --baseline accepts existing findings (nothing new)", () => {
  const dir = vulnDir();
  const baseline = join(dir, "qv-baseline.json");
  try {
    const w = runCli([dir, "--write-baseline", baseline]);
    assert.equal(w.status, 0);
    assert.match(w.stdout, /Wrote \d+ baselined finding/);
    // Same tree → nothing new since the baseline, so the gate passes.
    assert.equal(runCli([dir, "--baseline", baseline, "--fail-on", "low"]).status, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("cli: --baseline fails only on findings new since the baseline", () => {
  const dir = vulnDir();
  const baseline = join(dir, "qv-baseline.json");
  try {
    runCli([dir, "--write-baseline", baseline]);
    writeFileSync(join(dir, "new.ts"), "const k = generateKeyPairSync('rsa', { modulusLength: 2048 });\n");
    assert.equal(runCli([dir, "--baseline", baseline, "--fail-on", "low"]).status, 1, "a new finding must fail the gate");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("cli: baseline fingerprints are line-independent (moving code is not 'new')", () => {
  const dir = mkdtempSync(join(tmpdir(), "qv-cli-blmove-"));
  const file = join(dir, "app.ts");
  const baseline = join(dir, "qv-baseline.json");
  try {
    writeFileSync(file, "const k = generateKeyPairSync('rsa', { modulusLength: 2048 });\n");
    runCli([dir, "--write-baseline", baseline]);
    // Move the same finding down several lines — it must remain accepted.
    writeFileSync(file, "\n\n\nconst k = generateKeyPairSync('rsa', { modulusLength: 2048 });\n");
    assert.equal(runCli([dir, "--baseline", baseline, "--fail-on", "low"]).status, 0, "a moved finding is still baselined");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("cli: a committed baseline file does not trip the scanner on itself", () => {
  const dir = vulnDir();
  const baseline = join(dir, "qv-baseline.json");
  try {
    runCli([dir, "--write-baseline", baseline]);
    // The baseline now lives in the scanned tree; its opaque fingerprints must
    // contribute no findings (no readable algorithm names to match).
    const out = JSON.parse(runCli([dir, "--json"]).stdout);
    assert.ok(
      !out.assets.some((a: any) => a.file.endsWith("qv-baseline.json")),
      "the baseline file must not produce findings",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("cli: --fail-on ignores low-confidence 'possible mentions'", () => {
  const dir = mkdtempSync(join(tmpdir(), "qv-cli-mention-"));
  try {
    // A JWT-alg enum is a low-confidence mention, not exposure — must not gate.
    writeFileSync(join(dir, "cfg.ts"), 'export const SUPPORTED = ["RS256", "ES256"];\n');
    assert.equal(runCli([dir, "--fail-on", "low"]).status, 0, "a mention-only tree must not fail the gate");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("cli: --help exits 0 and no path exits 2", () => {
  assert.equal(runCli(["--help"]).status, 0);
  assert.equal(runCli([]).status, 2);
});
