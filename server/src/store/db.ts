import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DB_PATH = process.env.QV_DB_PATH ?? resolve(__dirname, "..", "..", "data", "quantumvault.db");

mkdirSync(dirname(DB_PATH), { recursive: true });

export const db = new DatabaseSync(DB_PATH);

db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS organizations (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL REFERENCES organizations(id),
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS scans (
    id            TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL,
    target        TEXT NOT NULL,
    started_at    TEXT NOT NULL,
    finished_at   TEXT NOT NULL,
    files_scanned INTEGER NOT NULL,
    duration_ms   INTEGER NOT NULL,
    asset_count   INTEGER NOT NULL,
    status        TEXT NOT NULL,
    is_latest     INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS assets (
    id                 TEXT PRIMARY KEY,
    scan_id            TEXT NOT NULL,
    org_id             TEXT NOT NULL,
    file               TEXT NOT NULL,
    line               INTEGER NOT NULL,
    family             TEXT NOT NULL,
    algorithm          TEXT NOT NULL,
    key_bits           INTEGER,
    language           TEXT NOT NULL,
    snippet            TEXT NOT NULL,
    pattern_id         TEXT NOT NULL,
    quantum_vulnerable INTEGER NOT NULL,
    pqc_replacement    TEXT NOT NULL,
    risk_score         INTEGER,
    risk_priority      TEXT,
    risk_json          TEXT,
    status             TEXT NOT NULL DEFAULT 'open'
  );

  CREATE TABLE IF NOT EXISTS reports (
    framework      TEXT NOT NULL,
    scan_id        TEXT NOT NULL,
    org_id         TEXT NOT NULL,
    generated_at   TEXT NOT NULL,
    overall_status TEXT NOT NULL,
    score_pct      INTEGER NOT NULL,
    summary        TEXT NOT NULL,
    controls_json  TEXT NOT NULL,
    PRIMARY KEY (framework, scan_id)
  );

  CREATE INDEX IF NOT EXISTS idx_assets_scan ON assets(scan_id);
  CREATE INDEX IF NOT EXISTS idx_assets_org ON assets(org_id);
  CREATE INDEX IF NOT EXISTS idx_scans_org ON scans(org_id);
`);

// Lightweight, idempotent migrations for databases created before a column
// existed. CREATE TABLE IF NOT EXISTS does not alter existing tables, so add
// new columns here; the ALTER throws (and is ignored) once the column exists.
for (const stmt of [`ALTER TABLE assets ADD COLUMN status TEXT NOT NULL DEFAULT 'open'`]) {
  try {
    db.exec(stmt);
  } catch {
    /* column already present — nothing to do */
  }
}

export const DEFAULT_ORG_ID = "org_default";

// Ensure a default organization exists for unauthenticated / seed usage.
db.prepare(
  `INSERT OR IGNORE INTO organizations (id, name, created_at) VALUES (?, ?, ?)`,
).run(DEFAULT_ORG_ID, "Default Organization", new Date().toISOString());
