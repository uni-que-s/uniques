import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { scoreAsset, scoreAssets, getRiskWeights, DEFAULT_WEIGHTS } from "../risk/scorer.js";
import { extractKeyBits, patternCount, PATTERNS } from "../discovery/patterns.js";
import { normalizeRepo } from "../discovery/repo.js";
import { scanDirectory } from "../discovery/scanner.js";
import { assetsToCsv } from "../discovery/csv.js";
import { assetsToCbom } from "../discovery/cbom.js";
import { assetsToSarif } from "../discovery/sarif.js";
import { openApiDocument } from "../openapi.js";
import { RateLimiter, rateLimit } from "../auth/rateLimit.js";
import type { Request, Response } from "express";
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

test("risk weights: defaults apply when QV_RISK_WEIGHTS is unset", () => {
  delete process.env.QV_RISK_WEIGHTS;
  assert.deepEqual(getRiskWeights(), DEFAULT_WEIGHTS);
});

test("risk weights: custom weights are merged, normalized to 1.0, and shift scores", () => {
  const prev = process.env.QV_RISK_WEIGHTS;
  try {
    // Heavily weight HNDL exposure; a partner-path key-exchange asset should score higher.
    const a = () => asset({ family: "DH", file: "transport/partner/vpn.ts", patternId: "dh-keyexchange" });
    const baseScore = scoreAsset(a()).score;

    process.env.QV_RISK_WEIGHTS = JSON.stringify({ hndlExposure: 5 });
    const w = getRiskWeights();
    const sum = Object.values(w).reduce((x, y) => x + y, 0);
    assert.ok(Math.abs(sum - 1) < 1e-9, `weights must normalize to 1.0, got ${sum}`);
    assert.ok(w.hndlExposure > DEFAULT_WEIGHTS.hndlExposure, "hndl weight should dominate");

    const tunedScore = scoreAsset(a()).score;
    assert.ok(tunedScore > baseScore, `tuned ${tunedScore} should exceed base ${baseScore} for a high-HNDL asset`);
  } finally {
    if (prev === undefined) delete process.env.QV_RISK_WEIGHTS;
    else process.env.QV_RISK_WEIGHTS = prev;
  }
});

test("risk weights: invalid JSON falls back to defaults", () => {
  const prev = process.env.QV_RISK_WEIGHTS;
  try {
    process.env.QV_RISK_WEIGHTS = "{not valid";
    assert.deepEqual(getRiskWeights(), DEFAULT_WEIGHTS);
  } finally {
    if (prev === undefined) delete process.env.QV_RISK_WEIGHTS;
    else process.env.QV_RISK_WEIGHTS = prev;
  }
});

// ------------------------------------------------------------- pattern db
test("patterns: patternCount matches the database length and health endpoint (28)", () => {
  assert.equal(patternCount(), PATTERNS.length);
  assert.equal(patternCount(), 28);
});

test("patterns: every pattern has a non-empty PQC replacement and a unique id", () => {
  const ids = new Set<string>();
  for (const p of PATTERNS) {
    assert.ok(p.pqcReplacement.length > 0, `${p.id} missing pqcReplacement`);
    assert.ok(!ids.has(p.id), `duplicate pattern id: ${p.id}`);
    ids.add(p.id);
  }
});

test("patterns: extended detectors fire and resist common false positives", () => {
  const dir = mkdtempSync(join(tmpdir(), "qv-ext-"));
  try {
    writeFileSync(join(dir, "jwt.ts"), 'const opts = { algorithm: "RS256" };\nconst v = { alg: "ES256" };\n');
    writeFileSync(join(dir, "key.pem"), "-----BEGIN EC PRIVATE KEY-----\nabc\n-----END EC PRIVATE KEY-----\n");
    writeFileSync(join(dir, "main.go"), 'import "crypto/rsa"\n');
    writeFileSync(join(dir, "infra.tf"), 'key = "ecdsa-sha2-nistp256 AAAA"\n');
    // False-positive bait: AES-256 is quantum-OK and must NOT trigger the ES256
    // matcher; neither should arbitrary identifiers ending in 256.
    writeFileSync(join(dir, "clean.ts"), 'const c = "aes-256-gcm";\nconst k = "AES256KEY";\nconst n = WINDOWS256;\n');

    const { assets } = scanDirectory(dir, "ext-test");
    const ids = new Set(assets.map((a) => a.patternId));
    assert.ok(ids.has("jwt-rsa-alg"), "RS256 detected");
    assert.ok(ids.has("jwt-ecdsa-alg"), "ES256 detected");
    assert.ok(ids.has("ecc-pem-header"), "EC private-key PEM detected");
    assert.ok(ids.has("go-crypto-rsa"), "crypto/rsa import detected");
    assert.ok(ids.has("ssh-ecdsa-key"), "ssh ecdsa key type detected");

    const cleanHits = assets.filter((a) => a.file === "clean.ts").map((a) => a.patternId);
    assert.equal(cleanHits.length, 0, `clean.ts should yield no findings, got: ${cleanHits.join(", ")}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
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

// ------------------------------------------------------------- CBOM (CycloneDX)
test("cbom: emits a valid CycloneDX 1.6 cryptography bill of materials", () => {
  const cbom = assetsToCbom(
    [
      asset({ family: "RSA", algorithm: "RSA", keyBits: 2048, file: "a.ts", line: 3, quantumVulnerable: true }),
      asset({ family: "HashLegacy", algorithm: "MD5/SHA-1", file: "b.ts", line: 9, quantumVulnerable: true }),
    ],
    { target: "/repo" },
  ) as any;

  assert.equal(cbom.bomFormat, "CycloneDX");
  assert.equal(cbom.specVersion, "1.6");
  assert.match(cbom.serialNumber, /^urn:uuid:/);
  assert.equal(cbom.metadata.component.name, "/repo");
  assert.equal(cbom.components.length, 2);

  const rsa = cbom.components[0];
  assert.equal(rsa.type, "cryptographic-asset");
  assert.equal(rsa.cryptoProperties.assetType, "algorithm");
  assert.equal(rsa.cryptoProperties.algorithmProperties.primitive, "pke");
  assert.equal(rsa.cryptoProperties.algorithmProperties.parameterSetIdentifier, "2048");
  // quantum-vulnerable -> NIST quantum security level 0
  assert.equal(rsa.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel, 0);
  assert.equal(rsa.evidence.occurrences[0].location, "a.ts");
  assert.equal(rsa.evidence.occurrences[0].line, 3);

  // hash family maps to the "hash" primitive
  assert.equal(cbom.components[1].cryptoProperties.algorithmProperties.primitive, "hash");
});

test("cbom: empty inventory still produces a well-formed BOM with no components", () => {
  const cbom = assetsToCbom([]) as any;
  assert.equal(cbom.bomFormat, "CycloneDX");
  assert.ok(Array.isArray(cbom.components));
  assert.equal(cbom.components.length, 0);
});

// ------------------------------------------------------------- SARIF
test("sarif: emits a valid SARIF 2.1.0 log with rules, results, and levels", () => {
  const rsa = scoreAsset(asset({ family: "RSA", patternId: "rsa-pem-header", file: "auth/key.pem", algorithm: "RSA", line: 2 }));
  const a1 = asset({ family: "RSA", patternId: "rsa-pem-header", file: "auth/key.pem", algorithm: "RSA", line: 2 });
  a1.risk = rsa;
  const sarif = assetsToSarif([a1]) as any;

  assert.equal(sarif.version, "2.1.0");
  const driver = sarif.runs[0].tool.driver;
  assert.equal(driver.name, "QuantumVault");
  assert.ok(driver.rules.some((r: any) => r.id === "rsa-pem-header"));

  const result = sarif.runs[0].results[0];
  assert.equal(result.ruleId, "rsa-pem-header");
  assert.ok(["error", "warning", "note"].includes(result.level));
  assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, "auth/key.pem");
  assert.equal(result.locations[0].physicalLocation.region.startLine, 2);
  // GitHub security-severity is a 0–10 string derived from the risk score
  assert.match(result.properties["security-severity"], /^\d+(\.\d)?$/);
});

test("sarif: critical/high map to error level", () => {
  const a = asset({ family: "RSA", file: "services/auth/payment/k.pem", patternId: "rsa-pem-header", algorithm: "RSA" });
  a.risk = scoreAsset(a);
  const sarif = assetsToSarif([a]) as any;
  // a payment/auth RSA key scores critical -> error
  assert.equal(sarif.runs[0].results[0].level, "error");
});

// ------------------------------------------------------------- OpenAPI
test("openapi: emits a valid 3.1 document covering the key endpoints", () => {
  const doc = openApiDocument() as any;
  assert.equal(doc.openapi, "3.1.0");
  assert.equal(doc.info.title, "QuantumVault API");
  assert.equal(doc.servers[0].url, "/api");
  assert.ok(doc.components.securitySchemes.bearerAuth);
  // representative endpoints across the surface are described
  for (const p of ["/health", "/scans", "/scans/git", "/cbom.json", "/sarif.json", "/compliance/{framework}", "/assets/{id}/status"]) {
    assert.ok(doc.paths[p], `missing path: ${p}`);
  }
  // a mutating endpoint requires bearer auth
  assert.deepEqual(doc.paths["/scans"].post.security, [{ bearerAuth: [] }]);
});

// ------------------------------------------------------------- rate limiter
test("rateLimiter: allows up to max, blocks the overflow, recovers after the window", () => {
  let now = 1000;
  const rl = new RateLimiter(3, 1000, () => now);
  assert.equal(rl.check("ip1"), true);
  assert.equal(rl.check("ip1"), true);
  assert.equal(rl.check("ip1"), true);
  assert.equal(rl.check("ip1"), false, "4th within window is blocked");
  // a different key is tracked independently
  assert.equal(rl.check("ip2"), true);
  // advance past the window -> the old hits expire and requests are allowed again
  now += 1001;
  assert.equal(rl.check("ip1"), true);
});

test("rateLimit middleware blocks after max per key and isolates keys", () => {
  const mw = rateLimit(2, 1000, (req) => req.orgId);
  const run = (org: string) => {
    const req = { orgId: org, ip: "1.1.1.1" } as unknown as Request;
    let statusCode = 0;
    let nexted = false;
    const res = {
      status(c: number) {
        statusCode = c;
        return res;
      },
      json() {
        return res;
      },
    } as unknown as Response;
    mw(req, res, () => {
      nexted = true;
    });
    return { nexted, statusCode };
  };

  assert.equal(run("orgA").nexted, true);
  assert.equal(run("orgA").nexted, true);
  const third = run("orgA");
  assert.equal(third.nexted, false, "3rd request for orgA is blocked");
  assert.equal(third.statusCode, 429);
  // a different org is tracked independently and still allowed
  assert.equal(run("orgB").nexted, true);
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

test("scanner: new multi-language patterns fire on real constructs but not on bait text", () => {
  const dir = mkdtempSync(join(tmpdir(), "qv-test-multi-"));
  try {
    // --- Real quantum-vulnerable constructs across languages ---
    writeFileSync(
      join(dir, "signer.rb"),
      [
        "key = OpenSSL::PKey::RSA.new(2048)",
        "legacy = OpenSSL::PKey::DSA.new(1024)",
        'curve = OpenSSL::PKey::EC.new("prime256v1")',
      ].join("\n"),
    );
    writeFileSync(
      join(dir, "Token.java"),
      'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");',
    );
    writeFileSync(
      join(dir, "batch.java"),
      'KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");',
    );
    writeFileSync(
      join(dir, "onboard.php"),
      "$k = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA]);",
    );
    writeFileSync(
      join(dir, "vault.rs"),
      "let master = RsaPrivateKey::new(&mut rng, 3072).unwrap();",
    );
    writeFileSync(
      join(dir, "backup.key"),
      "-----BEGIN PGP PRIVATE KEY BLOCK-----\nzZZZ\n-----END PGP PRIVATE KEY BLOCK-----\n",
    );

    // --- Bait files: superficially crypto-ish text that must NOT match ---
    // Ruby bait: mentions classes/identifiers but never the exact constructors.
    writeFileSync(
      join(dir, "bait.rb"),
      [
        "# notes mentioning AES256 and WINDOWS256 and ordinary identifiers",
        "MyRSAHelper = Object.new # a custom helper, not the OpenSSL constructor",
        "describe_rsa_options('docs about RSA but no construction')",
        "OpenSSL::PKey::RSA.generate(2048) # generate, not .new",
        "RsaPrivateKeyDocs = 'identifier mention only, no :: accessor'",
      ].join("\n"),
    );
    // PHP/Java/Rust bait: near-miss tokens in their own languages.
    writeFileSync(
      join(dir, "bait.php"),
      [
        "<?php",
        "openssl_pkey_export_to_file($x, 'out.pem'); // different fn, no KEYTYPE_RSA",
        "$type = 'OPENSSL_KEYTYPE_RSA'; // a string constant, no openssl_pkey_new call",
      ].join("\n"),
    );
    writeFileSync(
      join(dir, "bait.java"),
      [
        "int ekgPairGenerator = 1; // not a real KeyPairGenerator",
        'String alg = "RSA"; // a literal, no getInstance call',
      ].join("\n"),
    );
    writeFileSync(
      join(dir, "bait.txt"),
      "BEGIN PGP PUBLIC KEY BLOCK is a different, non-private header\n",
    );

    const { assets } = scanDirectory(dir, "scan-multi");
    const idsByFile = (f: string) =>
      new Set(assets.filter((a) => a.file === f).map((a) => a.patternId));

    // Each new construct fires exactly its intended pattern.
    assert.ok(idsByFile("signer.rb").has("rsa-ruby-openssl"));
    assert.ok(idsByFile("signer.rb").has("dsa-ruby-openssl"));
    assert.ok(idsByFile("signer.rb").has("ecc-ruby-openssl"));
    assert.ok(idsByFile("Token.java").has("rsa-java-keypairgen"));
    assert.ok(idsByFile("batch.java").has("dsa-java-keypairgen"));
    assert.ok(idsByFile("onboard.php").has("rsa-php-openssl"));
    assert.ok(idsByFile("vault.rs").has("rsa-rust-crate"));
    assert.ok(idsByFile("backup.key").has("rsa-pgp-private-block"));

    // ZERO findings on any bait file — the zero-false-positive guarantee.
    const baitFindings = assets.filter((a) => a.file.startsWith("bait."));
    assert.equal(baitFindings.length, 0, `bait produced findings: ${JSON.stringify(baitFindings.map((a) => `${a.file}:${a.patternId}`))}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
