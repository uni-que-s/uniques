# QuantumVault

[![CI](https://github.com/DemigodDSK/quantumvault/actions/workflows/ci.yml/badge.svg)](https://github.com/DemigodDSK/quantumvault/actions/workflows/ci.yml)

**Quantum-safe cryptography platform.** QuantumVault discovers quantum-vulnerable
cryptographic assets across a codebase, scores them for post-quantum migration
priority, tracks remediation to completion, and auto-generates FISMA, CISA,
FedRAMP, SOC 2, and PCI-DSS compliance reports.

It closes the full loop — **discover → prioritize → track → prove compliance** —
for the "harvest-now, decrypt-later" threat that puts today's RSA/ECC traffic at
risk once a cryptographically-relevant quantum computer exists.

## Features

- **Cryptographic asset discovery** — a 28-pattern, language-agnostic scanner
  detects RSA, ECC (incl. Ed25519/X25519), DSA, Diffie-Hellman, legacy symmetric
  (DES/3DES/AES-128), broken hashes (MD5/SHA-1), RSA/EC/DSA private-key PEMs (incl.
  PGP key blocks), JWT/JOSE signing algorithms (RS/ES/PS), Web Crypto RSA, SSH key
  types in IaC, language-specific key APIs (Java, Ruby, PHP, Rust, Go, Python),
  and RSA X.509 certs across 25+ file types. Scans a **local path** or
  shallow-clones a **public or private Git repo** (GitHub/GitLab/Bitbucket;
  private via an access token sent as an auth header, kept out of the URL and
  never logged).
- **Risk scoring & prioritization** — a 5-factor weighted model (data sensitivity,
  retention exposure, harvest-now-decrypt-later exposure, compliance impact,
  business impact) yields a 0–100 score, a priority tier, a migration-effort
  estimate, and a NIST PQC replacement recommendation (ML-KEM / ML-DSA / SLH-DSA).
- **Migration tracking** — mark each asset `open → in progress → migrated →
  accepted risk`. The dashboard shows live **migration progress** and the
  **remaining** engineering effort, so the inventory becomes a worklist, not just
  a report. Status **persists across re-scans**, so progress isn't lost when the
  codebase is scanned again.
- **Drift detection** — each scan is diffed against the previous one, so the
  dashboard flags **new findings introduced** and **findings removed** since last
  time — catching, e.g., a PR that adds a fresh RSA usage.
- **Compliance automation** — maps findings to FISMA, CISA, FedRAMP, SOC 2, and
  PCI-DSS controls with pass/gap/fail status and remediation guidance; exports an auditor-ready
  **JSON** (system of record) or **print-to-PDF HTML** report. The raw asset
  inventory also exports to **CSV** (filtered) for spreadsheets, SIEM, or tickets,
  and the full inventory exports as a **CycloneDX 1.6 CBOM** (Cryptography Bill of
  Materials) — the standards-based interchange format NIST/CISA reference for
  post-quantum migration inventories.
- **CI-native scanning** — a `quantumvault` CLI scans any path and emits a
  human-readable summary or machine output: **JSON**, **SARIF 2.1.0** (for GitHub
  code-scanning / PR annotations), **CSV**, or **CBOM**. `--fail-on <severity>`
  returns a non-zero exit code so a pipeline can block PRs that introduce
  quantum-vulnerable crypto. The same SARIF is served at `GET /api/sarif.json`.
- **Auth & multi-tenancy** — scrypt-hashed accounts with session tokens; every
  scan, asset, and report is scoped to an organization; credential endpoints are
  rate-limited per client IP to blunt brute-force, and the expensive scan
  endpoints are throttled per organization. An unauthenticated demo org is seeded
  so the dashboard is populated out of the box.

## Architecture

```
web/      React 18 + TypeScript + Vite + Tailwind v4 + Recharts dashboard
server/   Express + TypeScript API
            discovery/   pattern DB, directory scanner, Git clone   (core engine)
            risk/        5-factor weighted risk scorer
            compliance/  FISMA/CISA/FedRAMP/SOC2/PCI-DSS report generator + HTML export
            auth/        scrypt auth, sessions, org-scoping middleware
            store/       SQLite persistence (node:sqlite — zero native deps)
            sample-target/  bundled vulnerable fixtures, scanned on first boot
.github/  CI/CD: build, unit tests, compose integration smoke-test, GHCR publish
```

Persistence uses Node's built-in `node:sqlite`, so there are **no native
dependencies** and no external database to run. The store layer is the only
thing to swap to scale out (e.g. Postgres + Elasticsearch).

## Quick start — Docker (one command)

```bash
# from quantumvault/
docker compose up --build
# dashboard: http://localhost:8080   API: http://localhost:4000
```

The web tier (nginx) proxies `/api` to the server on the compose network. Data
persists in the `qv-data` volume. The server image bundles `git` so repo scanning
works inside the container.

### Pull pre-built images from GHCR

Every push to `main` publishes images (tagged `latest` and the commit SHA):

```
ghcr.io/demigoddsk/quantumvault-server
ghcr.io/demigoddsk/quantumvault-web
```

## Run locally (dev)

```bash
# from quantumvault/
npm run install:all

# terminal 1 — API on :4000 (runs a real seed scan over sample-target on boot)
npm run dev:server

# terminal 2 — dashboard on :5173 (proxies /api to :4000)
npm run dev:web
```

Then **sign up** in the UI and **Run Scan** against either a Git repo
(`owner/repo` or an https URL) or a local absolute path. Open any asset to see its
risk breakdown and set its remediation status.

## CLI

The same engine ships as a CLI for CI pipelines and local checks:

```bash
# from quantumvault/server  (dev: npm run cli -- <args>;  built: quantumvault <args>)
npm run cli -- ./path/to/repo                 # human-readable summary
npm run cli -- ./path/to/repo --sarif > out.sarif   # GitHub code-scanning
npm run cli -- . --fail-on high               # exit 1 if any finding is >= high
```

Output formats: default table, `--json`, `--sarif` (2.1.0), `--cbom` (CycloneDX
1.6), `--csv`. `--fail-on <critical|high|medium|low>` gates a pipeline by exit
code. In CI, run the scan with `--sarif`, upload the result to GitHub
code-scanning, and add `--fail-on` to block merges on new quantum-vulnerable
crypto.

## GitHub Action

Drop QuantumVault into any repository's CI to surface quantum-vulnerable crypto
as code-scanning alerts and (optionally) gate pull requests:

```yaml
# .github/workflows/quantumvault.yml
on: [pull_request]
permissions:
  contents: read
  security-events: write   # to upload SARIF
jobs:
  crypto-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: DemigodDSK/quantumvault@main
        with:
          path: .
          fail-on: high          # optional: fail the PR on a high+ finding
          sarif-file: quantumvault.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: quantumvault.sarif
```

Inputs: `path` (default `.`), `fail-on` (`critical|high|medium|low`, empty =
never fail), `sarif-file` (default `quantumvault.sarif`). The action is a
self-contained Docker action — no separate install. This repo dogfoods it via
the **Self-scan** workflow.

## Configuration

The server reads these environment variables (all optional):

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `4000` | API listen port |
| `QV_DB_PATH` | `./data/quantumvault.db` | SQLite database file path |
| `QV_CORS_ORIGIN` | `*` | Comma-separated CORS allowlist; set to your dashboard origin(s) if the API port is exposed directly rather than proxied |
| `QV_LOG` | on | Set to `off` to silence structured (JSON-per-line) access logs |
| `QV_SEED` | | Set to `force` to re-run the sample-target seed scan on boot |

**Hardening:** the API sends conservative security headers (`nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy`, COOP), returns a JSON error envelope
that never leaks 5xx internals, drains in-flight requests on `SIGTERM`/`SIGINT`
before closing SQLite cleanly, and runs as a **non-root** user inside its
container. Private-repo access tokens are used only for the clone (passed via
git's env-based config, never on the command line) and are never persisted or
logged.

## API

Reads are open on the demo org; mutations require `Authorization: Bearer <token>`.

| Method | Path | Auth | Description |
| --- | --- | :---: | --- |
| POST | `/api/auth/signup` | | Create an org + account, returns a token |
| POST | `/api/auth/login` | | Log in, returns a token |
| GET | `/api/auth/me` | ● | Current user/org |
| GET | `/api/health` | | Service + pattern count |
| GET | `/api/openapi.json` | | OpenAPI 3.1 description of this API |
| GET | `/api/dashboard` | | Posture + migration progress for the latest scan |
| GET | `/api/assets` | | Discovered assets (`?family=`, `?priority=`, `?q=`) |
| GET | `/api/assets/export.csv` | | Download the inventory as CSV (honors the same filters) |
| GET | `/api/cbom.json` | | CycloneDX 1.6 Cryptography Bill of Materials for the latest scan |
| GET | `/api/sarif.json` | | SARIF 2.1.0 log of the latest scan (GitHub code-scanning) |
| GET | `/api/assets/:id` | | Single asset with risk breakdown |
| PATCH | `/api/assets/:id/status` | ● | Set remediation status (`open`/`in_progress`/`migrated`/`accepted`) |
| POST | `/api/scans` | ● | Scan a local path `{ "target": "/abs/path" }` |
| POST | `/api/scans/git` | ● | Scan a repo `{ "url": "owner/repo", "token?": "…" }` |
| GET | `/api/scans` | | Scan history |
| GET | `/api/compliance` | | Reports for all frameworks |
| GET | `/api/compliance/:framework` | | One framework report |
| GET | `/api/compliance/:framework/export.json` | | Download JSON report |
| GET | `/api/compliance/:framework/export.html` | | Print-to-PDF HTML report |

## Testing & CI/CD

```bash
npm --prefix server test     # node:test: unit + store + HTTP API integration suite
npm --prefix web test        # vitest + Testing Library: component/UI tests
```

The server suite boots the real Express app on an ephemeral port (against an
isolated SQLite db) and drives it over HTTP — covering auth guards, org
isolation, scan → status → CSV export, and error paths — alongside unit tests for
scoring, patterns, repo normalization, the scanner, CSV escaping, and rate
limiting. The web suite renders UI components under jsdom.

GitHub Actions runs on every push/PR:

1. **server** — type-check, build, unit tests
2. **web** — type-check, build
3. **docker** — `docker compose build` + integration smoke-test (SPA shell,
   direct `/api/health`, and `/api/health` *through the nginx proxy*)
4. **publish** — push both images to GHCR (on `main` only)

## Notes & roadmap

- Remediation status **carries forward across re-scans**: a finding marked
  migrated/in-progress/accepted keeps that status when the codebase is re-scanned,
  matched by file + detection pattern + matched line (line numbers may shift).
- The risk model is a transparent, auditable weighted heuristic — not a black-box
  ML model — by design.
- Next up: GitHub OAuth onboarding and a hosted deployment.
