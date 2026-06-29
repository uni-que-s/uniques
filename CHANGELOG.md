# Changelog

All notable changes to QuantumVault are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Enum-constant references downgraded — precision worklist cleared (v0.3.10)** —
  the zero-dependency stand-in for the call-vs-reference data flow a full AST would
  give, and the final qbench worklist gap. A bare read of an algorithm enum/class
  constant (`const x = SignatureAlgorithm.DSA`, `if (algo == SignatureAlgorithm.DSA)`)
  names the primitive but does not perform the operation, so it is a possible
  mention, not exposure. Scoped narrowly so it cannot swallow a real use: the match
  text itself must be `Receiver.CONSTANT` (which excludes `dsa.generate`,
  `RSA.Create`, and bare-token matches), it must not be an invocation, and it must
  sit in assignment/comparison position — an argument-position use
  (`signWith(SignatureAlgorithm.DSA, key)`) keeps its confidence and still fires.
  With this the qbench precision worklist is **empty**: every gap surfaced since the
  benchmark was introduced is resolved and gated (77 cases at 1.0/1.0). The full
  tree-sitter AST (ENG-01b) is not needed for the known gaps; it stays in reserve
  if a future gap genuinely requires data flow.

### Fixed

- **Comment-masking no longer leaks across lines from a regex literal (v0.3.10)** —
  the comment masker tracked `'`/`"` string state without resetting at end-of-line,
  so a regex containing a quote character (e.g. `str.replace(/^["']+/g, "")`) opened
  a "string" that never closed and left every following line unmasked — exposing
  later **comments** to pattern matching and producing false positives. Since a
  `'`/`"` literal cannot span a newline in JS/TS, the masker (and the string-span
  lexer) now reset that state at the line break; template literals (backticks) still
  span lines. Found by the v0.3.10 self-scan and covered by a regression case.
- **Windows-path false positive cleared + Diffie-Hellman detected in config (v0.3.9)**
  — closes the last lexical precision-worklist gap and a recall miss. The path
  classifier now also recognizes **Windows drive paths** (`"C:\\certs\\diffie-hellman.pem"`,
  `C:/…`), so a crypto name that is a backslash-path segment is a possible mention,
  not a use (key material in a path still stays actionable). And **`dh-keyexchange`
  now runs on config languages** (YAML/JSON/Terraform/conf): a real key-exchange
  config naming `diffie-hellman` (e.g. `keyExchange: diffie-hellman`) was previously
  invisible and is now detected as a medium finding — while the per-occurrence
  classifier keeps it honest (a disabled directive `diffie-hellman: false`, a
  route/URL slug, a `#`/`//` comment, or a prose mention all downgrade to a possible
  mention). After this, the qbench precision worklist is down to a single gap —
  reading an enum member (`SignatureAlgorithm.DSA`) — which needs call-vs-reference
  data flow (ENG-01b / tree-sitter AST); the zero-dependency lexical-classifier rung
  is exhausted. Corpus now 70 gated cases at 1.0/1.0.
- **URL/route slugs and disable directives no longer over-flag (v0.3.8)** — two
  more false-positive classes the zero-dependency lexical classifier can now
  resolve, keeping the air-gapped posture intact. A crypto name that is a **URL or
  route path slug** (`"/api/v2/diffie-hellman/rotate"`,
  `"https://host/v2/diffie-hellman/rotate"`) names an endpoint, not a use, so it
  is downgraded to a possible mention — while a Go module import (`"crypto/rsa"`,
  no leading slash, no scheme) and a real call sharing the line still fire. A
  crypto key type explicitly **disabled** in config (`"ssh-rsa": false`,
  `ssh-rsa: off`, `"dsa": "disabled"`) is remediation, not exposure: an explicit
  disable is the one signal allowed to override the never-downgrade rule for key
  material, because a turned-off algorithm is not a live exposure. Allow-listed
  (`["ssh-rsa"]`) and enabled (`"ssh-rsa": true`) values still fire. Two cases
  moved from the qbench worklist into the gated corpus (now 63 cases at 1.0/1.0);
  the lone remaining gap — reading an enum member (`SignatureAlgorithm.DSA`) —
  needs call-vs-reference data flow and is the marker for ENG-01b (tree-sitter
  AST), the locked-last precision rung.
- **Dedupe double-counts + PKCS#12 + SSH key files (v0.3.7)** — one construct no
  longer counts twice: `DH_generate_key` was matched by both `dh-openssl-c` and
  `dh-keyexchange`, and a chained `getInstance("RSA").generateKeyPair()` by both
  `rsa-java-keypairgen` and `rsa-keygen-openssl`; each now reports once (the
  redundant arms were removed at the source). New: **PKCS#12 keystores**
  (`.pfx`/`.p12`, `pkcs12.Decode`), and well-known **SSH key files with no
  extension** (`authorized_keys`, `known_hosts`, `id_*.pub`) are now scanned
  (they were skipped by the extension map). Pattern count 52 → 53.
- **Recall expansion — formerly-missed real crypto now detected (v0.3.6)** —
  five qbench-confirmed false negatives are fixed: **Go ECDSA** (`crypto/ecdsa` /
  `ecdsa.GenerateKey`) and **Go DSA** (`dsa.GenerateKey`, which the case-sensitive
  matcher missed), **OpenSSL `EVP_PKEY_keygen`** (the 3.x generic keygen),
  **Web Crypto ECDSA/ECDH** (`name: "ECDSA"` — was only a low curve-name mention),
  and **X.509 certificate bodies** (`-----BEGIN CERTIFICATE-----` — real RSA/ECC
  public key + signature). Pattern count 47 → 52; the cases moved from the qbench
  worklist into the gated corpus.
- **Mention classifier — label / log / identifier false positives downgraded
  (v0.3.5)** — the per-occurrence classifier now treats a crypto name inside a
  *label or message* string (≥2 words with a natural-language word, e.g.
  `"3DES weak"`, `"Diffie-Hellman handshake failed"`, `"AES128 disabled"`,
  `"ssh-dss key rejected"`) as a **possible mention**, not exposure — generalizing
  the old prose rule (which needed ≥3 words and a function word). Structured crypto
  values keep their confidence: cipher lists, SSH key lines, and single tight
  tokens (`"RSA-OAEP"`, `"diffie-hellman"`, `"des-ede3-cbc"`) carry no
  natural-language word, and real call-sites anchor in code. Also fixed
  `sym-des-3des` to require a trailing word boundary, so an identifier like
  `TripleDESLegacyAdapter` or env var `TRIPLEDES_DISABLED` no longer matches.
  These cases moved from the qbench worklist into the gated corpus (precision/
  recall held at 1.0).
- **`qbench` precision benchmark + precision/recall fixes (v0.3.4)** — a labeled
  corpus + harness scores detection **precision and recall** over real call-sites
  and known traps, gating regressions at 1.0 on every build ("more precise on
  every build" as a tracked metric), with a worklist of known gaps. Building it,
  plus an adversarial probe of 34 CLI-verified cases, surfaced and **fixed** real
  gaps: four key-material formats that were silently missed are now detected —
  **OpenSSH private keys** (the default `ssh-keygen` output), **encrypted PKCS#8**,
  **PGP public blocks**, and **JWK** (`"kty":"RSA"`/`"EC"`); and a PQC
  certificate (`signatureAlgorithm: ML-DSA-…`, or a `dilithium.pem` path) is no
  longer mislabeled "RSA (X.509)" (the `tls-rsa-cert` matcher was greedily
  matching unrelated "RSA" on the line / asserting RSA for any cert path).
  Pattern count 43 → 47. Remaining verified gaps (string/identifier false
  positives, overlapping-pattern double-counts, and uncovered APIs like Go
  ECDSA/DSA and Web Crypto ECDSA) are tracked in the benchmark worklist.
- **GitHub Action supports the baseline ratchet + "adopt in CI" docs (v0.3.3)** —
  the published Docker action gains a `baseline` input, so `fail-on` gates only on
  findings new since a committed baseline. README now has a copy-pasteable
  workflow for adopting QuantumVault on an existing codebase (generate a baseline
  once, commit it, gate on new crypto thereafter). Verified end-to-end through the
  built action image.
- **CI baseline / ratchet (v0.3.2)** — adopt QuantumVault in CI without failing
  the build on day-one debt. `--write-baseline <file>` records the current
  findings as accepted; `--baseline <file>` then gates (with `--fail-on`) only on
  findings that are **new** since the baseline. Fingerprints are
  **line-independent** (derived from file + pattern + algorithm + normalized
  snippet), so moving or reindenting an accepted finding doesn't flag it as new.
  The baseline stores **opaque fingerprints only** — never readable algorithm
  names — so a committed baseline file never trips the scanner on itself.
  Relatedly, `--fail-on` now ignores low-confidence "possible mentions"
  (consistent with the report), so a mention can no longer fail a build.
- **CBOM conformance proven against the official CycloneDX 1.6 schema** — the
  emitted CBOM is now validated against the bundled official `bom-1.6.schema.json`
  (plus its SPDX + JSF references) in CI, turning "standards-compliant" from a
  claim into a checkable fact. The runtime keeps its fast, dependency-free
  `validateCbom()` structural guard; full JSON-Schema conformance runs as a test
  with **ajv as a dev dependency only**, so the shipped runtime stays
  zero-extra-dependency. Schemas are vendored so validation runs fully offline (no
  network in CI), consistent with the air-gapped posture.
- **Version visibility + provenance (v0.3.1)** — a self-hosted instance now shows
  which build it is running: `GET /api/health` returns `version`, and the
  dashboard sidebar displays it (the backend's version, so a stale container
  serving old code is visible at a glance). Every Quantum Readiness Assessment is
  stamped "Generated by QuantumVault v<version>" for audit provenance. Strictly
  offline — no phone-home / new-release check, in keeping with the air-gapped
  posture. The dashboard falls back to the web build version if the backend is
  unreachable or predates the field.
- **Per-occurrence context classifier (v0.3.0, ENG-01a)** — confidence is now
  refined by the *syntactic context of each match*, not just the pattern that
  fired. A crypto name embedded in a **natural-language string** (a log line,
  error, or doc — e.g. `"migrating away from diffie-hellman and 3DES"`) is
  reclassified as a **low-confidence possible mention** instead of counted
  exposure. "Prose" is gated on the presence of an English function word, so a
  *structured* crypto value with no prose — an SSH key line
  (`"ssh-rsa AAAA… user@host"`), an OpenSSL cipher list, a tight identifier
  (`"RSA-OAEP"`) — is **not** downgraded, and neither is a real call
  (`createDiffieHellman(2048)`), including one inside a template-literal
  interpolation (`` `…${createDiffieHellman(2048)}…` ``). Every occurrence on a
  line is scanned, so a prose mention can't mask a real same-line call. Value-
  bearing patterns (PEM/PGP key blocks, SSH key types, X.509 signature
  algorithms) are real wherever they appear and are never downgraded. The
  classifier is a **zero-dependency lexical pass** — no parser, no new deps,
  preserving the air-gapped single-binary posture. It can only *reclassify* a
  finding as a possible mention, never fabricate or upgrade one; the policy lives
  in one tunable function (`resolveConfidence`). Hardened against a 4-lens
  adversarial review (recall / tokenizer / offset / honesty) that caught — and
  drove fixes for — six recall regressions before release. This is the honest
  down-payment on full AST/call-site detection (ENG-01b).
- **Per-finding confidence score (v0.2.5)** — every detection now carries a
  confidence level: **high** (a library call-site or key material — e.g.
  `mbedtls_rsa_gen_key(`, `getInstance("RSA")`, a PEM block), **medium** (a
  name/config token), or **low** (a bare algorithm name/number in a string, enum,
  or doc — a likely *mention*, not a usage). **Low-confidence "possible mentions"
  are surfaced separately and excluded from the posture grade and the headline
  quantum-vulnerable count**, so a config like `["RS256","ES256"]` no longer reads
  as hard exposure. The CLI splits the count, the CBOM carries
  `quantumvault:confidence`, and the dashboard shows a "Possible Mentions" stat +
  a "mention" chip in the inventory. (This is the honest middle step toward full
  AST/semantic detection — it flags the regex engine's known weakness rather than
  hiding it.)

### Fixed

- **A clean scan is now 100% compliant for every framework (v0.2.4)** — inventory
  controls (CISA `PQC-1`, FedRAMP `CM-8`, NIST-CSF `ID.AM-02`) were marked **gap**
  when a scan found zero crypto, which dragged CISA/FedRAMP to "83% Partial" and
  NIST-CSF to 90% on a clean codebase. But a clean scan **is** a complete (empty)
  inventory — a report only exists because a scan ran — so inventory controls now
  pass. A codebase with no quantum-vulnerable crypto is a perfect 100% pass across
  all seven frameworks. Test extended to cover every framework on a clean scan.

### Changed

- **Grade reflects production code, not fixtures (v0.2.3)** — the scanner now
  skips **non-production directories** by default (`test`/`tests`/`__tests__`,
  `examples`, `samples`, `fixtures`, `mocks`, `demo`, and `sample-*`/`test-*`
  prefixes), plus tooling dirs (`.claude`, `.idea`, `.vscode`). Without this, a
  healthy repo could be graded "F" on its own test inputs — the worst first
  impression a security tool can make. A real scan target (firmware, an app) is
  unaffected. Added a regression test.
- **On-prem positioning** — the README now leads with the wedge ("find your
  quantum-vulnerable crypto and produce the CBOM regulators require — on-prem, so
  your source never leaves your network"), frames single-tenant self-host as the
  intended posture, and removes the "hosted deployment" SaaS line.
- **Detection precision + honesty (v0.2.2)** — in response to an adversarial
  red-team review:
  - **Comment masking** — the scanner now matches against a comment-stripped view
    of each file, so a crypto name in a `//`, `#`, or `/* */` comment is treated as
    a *mention*, not a *use*, and no longer fires. String literals are preserved, so
    real uses (`getInstance("RSA")`, JWT alg values, PEM blocks) still fire. Added a
    precision regression test. (Eliminating *string*-mention false positives needs
    semantic/AST detection — tracked as a follow-on.)
  - **No self-asserted "pass"** — compliance output is reframed as **control-gap /
    audit evidence**: reports are titled "Control-Gap Report," the passing state
    renders as "No gaps found," and a disclaimer states it is evidence for review,
    not a certification of compliance.
  - **Honest risk-model framing** — the README now labels the 0–100 score as a
    heuristic prioritizer from transparent, **tunable default** weights (not a
    calibrated benchmark), with sensitivity inferred from path/deployment context.
  - **README accuracy** — corrected the stale "34-pattern" claim to 43.

### Added

- **Embedded C/C++ firmware crypto detection (v0.2.1)** — the scanner now natively
  detects the firmware staples of long-life embedded systems: **mbedTLS**
  (`mbedtls_rsa_*`, `mbedtls_ecdsa_*`, `mbedtls_ecdh_*`, `mbedtls_dhm_*`),
  **wolfSSL / wolfCrypt** (`wc_MakeRsaKey`, `wc_ecc_make_key`, …), and the
  **OpenSSL C API** (`EVP_PKEY_CTX_set_rsa_keygen_bits`, `EC_KEY_new_by_curve_name`,
  `DH_generate_key`, …). Adds common C++ extensions (`.cc`, `.cxx`, `.hpp`, `.hh`)
  to the scanned set. Pattern count: 35 → 43. Targets the automotive (UN R155/R156),
  medical (FDA §524B), and defense (CNSA 2.0 firmware-signing) PQC mandates.
- **Deeper CBOM & standards export (v0.2.0 milestone)** — the CycloneDX 1.6
  Cryptography Bill of Materials now carries algorithm **OIDs** (RSA/ECC/DSA/DH,
  registry-verified), `cryptoFunctions`, `classicalSecurityLevel`, elliptic
  `curve`, and a graded NIST quantum-security **category** (0–6) per finding; it
  emits a `dependencies` graph linking the scanned application to every
  discovered algorithm; and it uses **content-addressed, deterministic** bom-refs
  and serial number, so re-scanning the same code yields a diffable BOM. A new
  `validateCbom()` conformance check (sharing one set of spec enums with the
  emitter) lets the output be *proven* CycloneDX-1.6-valid, not just asserted.
  Ambiguous lumped patterns (DES/3DES, MD5/SHA-1, Ed25519/X25519) deliberately
  withhold a specific OID rather than overclaim.
- **Two new compliance frameworks** — **CNSA 2.0** (NSA Commercial National
  Security Algorithm Suite — the PQC mandate: ML-KEM-1024 / ML-DSA-87 /
  AES-256 / SHA-384+) and **NIST CSF 2.0** (cryptographic-inventory and
  data-protection subcategories) join FISMA/CISA/FedRAMP/SOC 2/PCI-DSS. Reports,
  JSON/HTML exports, and the dashboard pick them up automatically.

- **Quantum Readiness Assessment** — QuantumVault now generates its flagship
  executive report directly from a scan, instead of hand-filling a template. The
  report computes an at-a-glance quantum-posture grade (the same model the
  dashboard surfaces), a cryptographic inventory by family with quantum-impact
  classification and NIST replacements, a priority distribution, the real top
  findings (production paths first), a five-framework compliance gap matrix, and a
  phased migration roadmap quantified from the actual critical/high/medium counts.
  - CLI: `quantumvault <path> --assessment [--org "<name>"]` emits the branded,
    print-to-PDF HTML — no server required.
  - API: `GET /api/assessment/report.html` (branded HTML) and
    `GET /api/assessment/report.json` (structured model), org-scoped; `404` until
    the org has a scan. Both are listed in the OpenAPI document.
  - Dashboard: a "Quantum Readiness Assessment" action on the Compliance page
    opens the report in a new tab, ready to print or save as PDF.
  - Every figure traces to live scan data (no sample numbers), all dynamic values
    are HTML-escaped, and the report states its own methodology and limits.
- **Zero-install live demo** — a static build of the dashboard (`npm --prefix web
  run build:demo` → `docs/demo/`) that runs entirely client-side on GitHub Pages,
  serving baked fixtures from a real scan of popular OSS libraries. Gated behind a
  compile-time flag so the demo code and fixture are dead-code-eliminated from the
  normal build. Linked from the landing page ("See it live — no install").

### Fixed

- Compliance report lookups are now case-insensitive on the framework name, so
  the `FedRAMP` report and its JSON/HTML exports resolve correctly (previously a
  naive upper-casing 404'd `FedRAMP`, whose stored name is mixed-case).

## [0.1.0] - 2026-06-11

First public release. QuantumVault closes the full
**discover → prioritize → track → prove compliance** loop for the
"harvest-now, decrypt-later" threat to RSA/ECC cryptography.

### Added

- **Cryptographic asset discovery** — a 34-pattern, language-agnostic scanner
  detecting RSA, ECC (incl. Ed25519/X25519), DSA, Diffie-Hellman, legacy
  symmetric (DES/3DES/AES-128), broken hashes (MD5/SHA-1), private-key PEMs
  (incl. PGP blocks), JWT/JOSE signing algorithms, Web Crypto RSA, SSH key types
  in IaC, language-specific key APIs (Java, Ruby, PHP, Rust, Go, Python), and
  RSA X.509 certs across 25+ file types. Scans a local path or shallow-clones a
  public or private Git repo (GitHub/GitLab/Bitbucket).
- **Risk scoring & prioritization** — a transparent 5-factor weighted model
  (data sensitivity, retention exposure, harvest-now-decrypt-later exposure,
  compliance impact, business impact) producing a 0–100 score, a priority tier,
  a migration-effort estimate, and a NIST PQC replacement recommendation
  (ML-KEM / ML-DSA / SLH-DSA). Weights are tunable per deployment via
  `QV_RISK_WEIGHTS` and surfaced on the dashboard.
- **Executive quantum-posture grade** on the dashboard.
- **Migration tracking** — per-asset remediation status
  (`open → in_progress → migrated → accepted`) that **persists across re-scans**,
  matched by file + pattern + matched line.
- **Drift detection** — each scan is diffed against the previous one, flagging
  findings introduced and removed since the last run.
- **Baselining** — a `.quantumvaultignore` file at the scan root excludes
  vendored or accepted paths so `--fail-on` isn't tripped by known exceptions.
- **Compliance automation** — maps findings to FISMA, CISA, FedRAMP, SOC 2, and
  PCI-DSS controls with pass/gap/fail status and remediation guidance; exports
  auditor-ready JSON and print-to-PDF HTML reports.
- **Exports** — CSV inventory (filtered), SARIF 2.1.0 for GitHub code-scanning,
  and a CycloneDX 1.6 CBOM (Cryptography Bill of Materials).
- **CI-native CLI** — `quantumvault` scans any path with table / `--json` /
  `--sarif` / `--cbom` / `--csv` output and `--fail-on <severity>` to gate
  pipelines by exit code.
- **GitHub Action** — self-contained Docker action (`DemigodDSK/quantumvault`)
  that emits SARIF for code-scanning and optionally gates pull requests; this
  repo dogfoods it via a self-scan workflow.
- **Server API** — Express + TypeScript with auth (scrypt + session tokens),
  per-org multi-tenancy, per-IP credential rate limiting, per-org scan
  throttling, OpenAPI 3.1 description, and conservative security headers.
- **Web dashboard** — React 18 + TypeScript + Vite + Tailwind v4 + Recharts.
- **Persistence** — Node's built-in `node:sqlite`, so there are no native
  dependencies and no external database to run.
- **Packaging** — `docker compose` one-command stack and pre-built GHCR images
  (`ghcr.io/demigoddsk/quantumvault-server`, `-web`) published on every push to
  `main`.

### Security

- Private-repo access tokens are used only for the clone (via git's env-based
  config, never on the command line) and are never persisted or logged.
- The API runs as a non-root container user, drains in-flight requests on
  `SIGTERM`/`SIGINT`, and returns a JSON error envelope that never leaks 5xx
  internals.

[Unreleased]: https://github.com/DemigodDSK/quantumvault/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/DemigodDSK/quantumvault/releases/tag/v0.1.0
