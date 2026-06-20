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
    assert.equal(sarif.runs[0].tool.driver.name, "QuantumVault");
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

test("cli: --help exits 0 and no path exits 2", () => {
  assert.equal(runCli(["--help"]).status, 0);
  assert.equal(runCli([]).status, 2);
});
