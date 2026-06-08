# QuantumVault

Quantum-safe cryptography platform. Discovers quantum-vulnerable cryptographic
assets across a codebase, scores them for migration priority, and auto-generates
FISMA / CISA / FedRAMP compliance reports.

Implements the three core capabilities from the product blueprint:

1. **Cryptographic Asset Discovery** — pattern-based scanner that detects RSA, ECC,
   DSA, Diffie-Hellman, legacy symmetric (DES/3DES/AES-128) and broken hashes
   (MD5/SHA-1) across 20+ file types and many languages.
2. **Risk Scoring & Prioritization** — a 5-factor weighted model (data sensitivity,
   retention exposure, harvest-now-decrypt-later exposure, compliance impact,
   business impact) producing a 0–100 score, priority tier, and migration effort.
3. **Compliance Automation** — maps findings to control catalogs and generates
   per-framework reports with pass/gap/fail status and remediation guidance.

## Architecture

```
web/      React 18 + TypeScript + Vite + Tailwind v4 + Recharts dashboard
server/   Express + TypeScript API
            discovery/   pattern DB + directory scanner   (the core engine)
            risk/        5-factor weighted risk scorer
            compliance/  FISMA / CISA / FedRAMP report generator
            store/       in-memory store (swap for Postgres/Elastic in prod)
            sample-target/  bundled vulnerable fixtures, scanned on startup
```

The store interface mirrors the production design (PostgreSQL + Elasticsearch +
Redis per the blueprint); only the persistence layer needs swapping to scale.

## Run with Docker (one command)

```bash
# from quantumvault/
docker compose up --build
# dashboard: http://localhost:8080   API: http://localhost:4000
```

Data persists in the `qv-data` volume. The server image bundles `git` so repo
scanning works inside the container.

## Run locally (dev)

```bash
# from quantumvault/
npm run install:all

# terminal 1 — API on :4000 (runs a real seed scan over sample-target on boot)
npm run dev:server

# terminal 2 — dashboard on :5173 (proxies /api to :4000)
npm run dev:web
```

Open the dashboard and **Run Scan** against either:

- a **Git repo** — paste `owner/repo` or an https URL (public GitHub/GitLab/Bitbucket).
  QuantumVault shallow-clones it to a temp dir, scans, and cleans up.
- a **local path** — any absolute directory on the host.

Example: scanning `rzcoder/node-rsa` reports ~29 quantum-vulnerable assets in ~25ms.

## API

| Method | Path | Description |
| --- | --- | --- |
| GET | `/api/health` | Service + pattern count |
| GET | `/api/dashboard` | Aggregated posture for the latest scan |
| GET | `/api/assets` | Discovered assets (`?family=`, `?priority=`, `?q=`) |
| GET | `/api/assets/:id` | Single asset with risk breakdown |
| POST | `/api/scans` | Scan a local path `{ "target": "/abs/path" }` |
| POST | `/api/scans/git` | Scan a public repo `{ "url": "owner/repo" }` (GitHub/GitLab/Bitbucket) |
| GET | `/api/scans` | Scan history |
| GET | `/api/compliance` | Reports for all frameworks |
| GET | `/api/compliance/:framework` | One framework report |
