import { test } from "node:test";
import assert from "node:assert/strict";

import { generateReport, FRAMEWORKS } from "../compliance/reporter.js";
import type { CryptoAsset, CryptoFamily } from "../types.js";

/** Build a minimal valid CryptoAsset for compliance-report tests. */
function asset(partial: Partial<CryptoAsset> & { family: CryptoFamily }): CryptoAsset {
  return {
    id: "a1",
    scanId: "s1",
    file: "src/app.ts",
    line: 1,
    algorithm: "X",
    keyBits: null,
    language: "typescript",
    snippet: "",
    patternId: "p",
    quantumVulnerable: true,
    confidence: "high",
    pqcReplacement: "ML-KEM (Kyber)",
    status: "open",
    ...partial,
  };
}

/** A representative mix of quantum-vulnerable findings across families. */
function sampleAssets(): CryptoAsset[] {
  return [
    asset({ id: "rsa", family: "RSA", patternId: "rsa-pem-header", file: "auth/key.pem", algorithm: "RSA" }),
    asset({
      id: "ecc",
      family: "ECC",
      patternId: "tls-ecdhe",
      file: "transport/tls.ts",
      algorithm: "ECDSA",
      risk: {
        score: 88,
        priority: "critical",
        factors: { dataSensitivity: 90, retentionExposure: 80, hndlExposure: 85, complianceImpact: 70, businessImpact: 75 },
        recommendation: "Immediately migrate",
        migrationEffortDays: 12,
      },
    }),
    asset({ id: "dh", family: "DH", patternId: "dh-params", file: "transport/vpn.ts", algorithm: "DH" }),
    asset({ id: "hash", family: "HashLegacy", patternId: "hash-md5-sha1", file: "util/hash.ts", algorithm: "MD5" }),
  ];
}

// --------------------------------------------------------------- registration
test("compliance: SOC2, PCI-DSS, CNSA-2.0, and NIST-CSF-2.0 are registered in FRAMEWORKS", () => {
  assert.ok(FRAMEWORKS.includes("SOC2"));
  assert.ok(FRAMEWORKS.includes("PCI-DSS"));
  assert.ok(FRAMEWORKS.includes("CNSA-2.0"));
  assert.ok(FRAMEWORKS.includes("NIST-CSF-2.0"));
});

// --------------------------------------------------------------- new frameworks
for (const framework of ["SOC2", "PCI-DSS", "CNSA-2.0", "NIST-CSF-2.0"] as const) {
  test(`compliance: ${framework} report is well-formed with sane, bounded values`, () => {
    const assets = sampleAssets();
    const report = generateReport(framework, assets, "scan-1");

    assert.equal(report.framework, framework);
    assert.equal(report.scanId, "scan-1");
    assert.ok(report.controls.length > 0, "expected at least one control");

    // scorePct is an integer bounded 0..100
    assert.ok(Number.isInteger(report.scorePct), `scorePct not an integer: ${report.scorePct}`);
    assert.ok(report.scorePct >= 0 && report.scorePct <= 100, `scorePct out of range: ${report.scorePct}`);

    // overallStatus is consistent with the documented thresholds
    assert.ok(["pass", "gap", "fail"].includes(report.overallStatus));
    const expected = report.scorePct >= 90 ? "pass" : report.scorePct >= 60 ? "gap" : "fail";
    assert.equal(report.overallStatus, expected);

    assert.ok(report.summary.includes(framework), "summary should mention the framework");
    assert.ok(report.generatedAt.length > 0);

    // every control is fully populated, has a valid status, and a non-negative count
    const ids = new Set<string>();
    for (const c of report.controls) {
      assert.ok(c.id.length > 0, "control missing id");
      assert.ok(!ids.has(c.id), `duplicate control id: ${c.id}`);
      ids.add(c.id);
      assert.ok(c.title.length > 0, `${c.id} missing title`);
      assert.ok(c.description.length > 0, `${c.id} missing description`);
      assert.ok(["pass", "gap", "fail"].includes(c.status), `${c.id} bad status: ${c.status}`);
      assert.ok(c.affectedAssets >= 0, `${c.id} negative affectedAssets`);
      assert.ok(c.affectedAssets <= assets.length, `${c.id} affectedAssets exceeds asset count`);
      assert.ok(c.remediation.length > 0, `${c.id} missing remediation`);
      // passing controls require no action; failing/partial controls give guidance
      if (c.status === "pass") {
        assert.equal(c.remediation, "No action required.");
      }
    }
  });
}

test("compliance: SOC2 control catalog covers the expected Trust Services Criteria", () => {
  const report = generateReport("SOC2", sampleAssets(), "scan-2");
  const ids = report.controls.map((c) => c.id);
  assert.ok(ids.includes("CC6.1"));
  assert.ok(ids.includes("CC6.7"));
});

test("compliance: PCI-DSS control catalog covers stored-data, key-mgmt, and transit reqs", () => {
  const report = generateReport("PCI-DSS", sampleAssets(), "scan-3");
  const ids = report.controls.map((c) => c.id);
  for (const req of ["3.5", "3.6", "3.7", "4.2.1"]) {
    assert.ok(ids.includes(req), `missing PCI-DSS requirement ${req}`);
  }
});

test("compliance: CNSA-2.0 catalog maps the suite's algorithm requirements and fails on quantum-vulnerable crypto", () => {
  const report = generateReport("CNSA-2.0", sampleAssets(), "scan-cnsa");
  const ids = report.controls.map((c) => c.id);
  for (const req of ["CNSA2-KEM", "CNSA2-SIG", "CNSA2-SYM", "CNSA2-HASH", "CNSA2-TIMELINE"]) {
    assert.ok(ids.includes(req), `missing CNSA 2.0 control ${req}`);
  }
  // RSA/ECC/DH in the sample must trigger the KEM control (gap or fail, never pass).
  const kem = report.controls.find((c) => c.id === "CNSA2-KEM")!;
  assert.notEqual(kem.status, "pass");
  assert.ok(kem.affectedAssets > 0, "KEM control should flag the quantum-vulnerable key-establishment assets");
});

test("compliance: NIST-CSF-2.0 catalog uses official subcategory ids and treats inventory as satisfied", () => {
  const report = generateReport("NIST-CSF-2.0", sampleAssets(), "scan-csf");
  const ids = report.controls.map((c) => c.id);
  for (const req of ["ID.AM-02", "ID.RA-01", "PR.DS-01", "PR.DS-02", "PR.PS-01"]) {
    assert.ok(ids.includes(req), `missing NIST CSF 2.0 subcategory ${req}`);
  }
  // ID.AM-02 is an inventory control: having the CBOM satisfies it.
  const inv = report.controls.find((c) => c.id === "ID.AM-02")!;
  assert.equal(inv.status, "pass");
});

test("compliance: a clean scan (zero findings) is a perfect 100% pass for EVERY framework", () => {
  // Covers the inventory-control frameworks (CISA/FedRAMP/NIST-CSF) too: a clean
  // scan is a complete (empty) inventory, so inventory controls must PASS, not gap.
  for (const framework of FRAMEWORKS) {
    const report = generateReport(framework, [], "scan-empty");
    assert.equal(report.scorePct, 100, `${framework} should be 100% on a clean scan, got ${report.scorePct}`);
    assert.equal(report.overallStatus, "pass", `${framework} overall should pass on a clean scan`);
    for (const c of report.controls) {
      assert.equal(c.status, "pass", `${framework} control ${c.id} should pass on a clean scan`);
    }
  }
});
