import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { scoreAsset, scoreAssets } from "../risk/scorer.js";
import { extractKeyBits, patternCount, PATTERNS } from "../discovery/patterns.js";
import { normalizeRepo } from "../discovery/repo.js";
import { scanDirectory } from "../discovery/scanner.js";
import { assetsToCsv } from "../discovery/csv.js";
import type { CryptoAsset, CryptoFamily } from "../types.js";

/** Build a minimal valid CryptoAsset for scoring tests. */
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
    pqcReplacement: "ML-KEM (Kyber)",
    status: "open",
    ...partial,
  };
}

// ---------------------------------------------------------------- risk scorer
test("risk: RSA PEM key on a sensitive auth path scores critical", () => {
  const r = scoreAsset(
    asset({
      family: "RSA",
      file: "services/auth/payment/secret.pem",
      patternId: "rsa-pem-header",
      algorithm: "RSA",
    }),
  );
  assert.equal(r.priority, "critical");
  assert.ok(r.score >= 80, `expected >=80, got ${r.score}`);
  assert.match(r.recommendation, /Immediately migrate/);
});

test("risk: legacy hash (MD5/SHA-1) scores well below a broken RSA key", () => {
  const hash = scoreAsset(asset({ family: "HashLegacy", patternId: "hash-md5-sha1", file: "util/hash.ts" }));
  const rsa = scoreAsset(asset({ family: "RSA", patternId: "rsa-pem-header", file: "auth/key.pem" }));
  assert.ok(hash.score < rsa.score, `hash ${hash.score} should be < rsa ${rsa.score}`);
});

test("risk: all five factors stay within 0..100 and weights yield a bounded score", () => {
  for (const family of ["RSA", "ECC", "DSA", "DH", "SymmetricLegacy", "HashLegacy"] as CryptoFamily[]) {
    const r = scoreAsset(asset({ family }));
    for (const [k, v] of Object.entries(r.factors)) {
      assert.ok(v >= 0 && v <= 100, `${family}.${k} out of range: ${v}`);
    }
    assert.ok(r.score >= 0 && r.score <= 100);
    assert.ok(r.migrationEffortDays > 0);
  }
});

test("risk: Shor-broken asymmetric crypto gets a higher HNDL factor than symmetric", () => {
  const ecc = scoreAsset(asset({ family: "ECC", file: "transport/vpn/tls.ts" }));
  const sym = scoreAsset(asset({ family: "SymmetricLegacy", file: "transport/vpn/tls.ts" }));
  assert.ok(ecc.factors.hndlExposure > sym.factors.hndlExposure);
});

test("risk: scoreAssets mutates the batch in place and attaches risk", () => {
  const batch = [asset({ family: "RSA" }), asset({ family: "DH" })];
  const out = scoreAssets(batch);
  assert.equal(out, batch);
  assert.ok(batch.every((a) => a.risk && typeof a.risk.score === "number"));
});

// ------------------------------------------------------------- pattern db
test("patterns: patternCount matches the database length and health endpoint (12)", () => {
  assert.equal(patternCount(), PATTERNS.length);
  assert.equal(patternCount(), 12);
});

test("patterns: every pattern has a non-empty PQC replacement and a unique id", () => {
  const ids = new Set<string>();
  for (const p of PATTERNS) {
    assert.ok(p.pqcReplacement.length > 0, `${p.id} missing pqcReplacement`);
    assert.ok(!ids.has(p.id), `duplicate pattern id: ${p.id}`);
    ids.add(p.id);
  }
});

test("patterns: extractKeyBits respects family-specific valid sizes", () => {
  assert.equal(extractKeyBits("modulusLength: 2048", "RSA"), 2048);
  assert.equal(extractKeyBits("rsa_bits = 1024", "RSA"), 1024);
  assert.equal(extractKeyBits("ecdsa curve P-256", "ECC"), 256);
  // digits embedded in a word (secp256r1) are NOT a bounded token -> null
  assert.equal(extractKeyBits("secp256r1", "ECC"), null);
  // 2048 is not a valid ECC curve size -> null
  assert.equal(extractKeyBits("modulusLength: 2048", "ECC"), null);
  // symmetric only accepts 128/256
  assert.equal(extractKeyBits("aes-128-gcm", "SymmetricLegacy"), 128);
  assert.equal(extractKeyBits("no digits here", "RSA"), null);
});

// ------------------------------------------------------------- CSV export
test("csv: header row + RFC-4180 escaping of commas, quotes, and newlines", () => {
  const csv = assetsToCsv([
    asset({ family: "RSA", file: "src/a,b.ts", snippet: 'say "hi"', algorithm: "RSA" }),
  ]);
  const lines = csv.split("\r\n");
  assert.match(lines[0], /^file,line,family,algorithm,/);
  // comma-containing field is quoted; embedded quotes are doubled
  assert.ok(lines[1].includes('"src/a,b.ts"'), lines[1]);
  assert.ok(lines[1].includes('"say ""hi"""'), lines[1]);
  assert.equal(csv.endsWith("\r\n"), true);
});

test("csv: empty inventory still emits a header row", () => {
  const csv = assetsToCsv([]);
  assert.match(csv, /^file,line,family,/);
  assert.equal(csv.trim().split("\r\n").length, 1);
});

// ------------------------------------------------------------- repo normalizer (SSRF guard)
test("repo: owner/repo shorthand normalizes to a GitHub https clone url", () => {
  const r = normalizeRepo("openssl/openssl");
  assert.equal(r.cloneUrl, "https://github.com/openssl/openssl.git");
  assert.equal(r.label, "github.com/openssl/openssl");
});

test("repo: full https URLs are accepted and www / .git are stripped", () => {
  assert.equal(normalizeRepo("https://www.gitlab.com/group/proj.git").cloneUrl, "https://gitlab.com/group/proj.git");
  assert.equal(normalizeRepo("https://bitbucket.org/team/repo").label, "bitbucket.org/team/repo");
});

test("repo: rejects non-https, unknown hosts, and embedded credentials", () => {
  assert.throws(() => normalizeRepo("http://github.com/a/b"), /https/);
  assert.throws(() => normalizeRepo("https://evil.example.com/a/b"), /unsupported host/);
  assert.throws(() => normalizeRepo("https://user:pass@github.com/a/b"), /credentials/);
  assert.throws(() => normalizeRepo(""), /required/);
});

// ------------------------------------------------------------- scanner (integration)
test("scanner: discovers crypto assets in a temp source tree and skips junk dirs", () => {
  const dir = mkdtempSync(join(tmpdir(), "qv-test-"));
  try {
    writeFileSync(
      join(dir, "server.ts"),
      ["const k = generateKeyPairSync('rsa', { modulusLength: 2048 });", "// secp256r1 curve in use"].join("\n"),
    );
    writeFileSync(join(dir, "key.pem"), "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n");
    // binary-ish and ignored dirs must NOT be scanned
    mkdirSync(join(dir, "node_modules"));
    writeFileSync(join(dir, "node_modules", "lib.ts"), "createDiffieHellman(2048)");
    writeFileSync(join(dir, "image.png"), "\x00\x01\x02PNGbinary");

    const { job, assets } = scanDirectory(dir, "scan-test");
    assert.equal(job.status, "completed");
    assert.ok(assets.length >= 2, `expected >=2 assets, got ${assets.length}`);
    // RSA PEM header must be detected as a critical-family asset
    assert.ok(assets.some((a) => a.patternId === "rsa-pem-header"));
    // nothing from node_modules should appear
    assert.ok(!assets.some((a) => a.file.includes("node_modules")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
