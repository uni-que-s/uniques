# Changelog

All notable changes to QuantumVault are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
