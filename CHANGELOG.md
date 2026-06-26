# Changelog

All notable changes to QuantumVault are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
