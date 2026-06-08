import { randomUUID } from "node:crypto";
import type { AssetStatus, CryptoAsset, ComplianceReport, RiskScore, ScanJob } from "../types.js";
import { ASSET_STATUSES, RESOLVED_STATUSES } from "../types.js";
import { scanDirectory } from "../discovery/scanner.js";
import { scoreAssets } from "../risk/scorer.js";
import { generateReport, FRAMEWORKS } from "../compliance/reporter.js";
import { db, DEFAULT_ORG_ID } from "./db.js";

interface AssetRow {
  id: string;
  scan_id: string;
  file: string;
  line: number;
  family: string;
  algorithm: string;
  key_bits: number | null;
  language: string;
  snippet: string;
  pattern_id: string;
  quantum_vulnerable: number;
  pqc_replacement: string;
  risk_json: string | null;
  status: string;
}

interface ScanRow {
  id: string;
  target: string;
  started_at: string;
  finished_at: string;
  files_scanned: number;
  duration_ms: number;
  asset_count: number;
  status: string;
}

interface ReportRow {
  framework: string;
  scan_id: string;
  generated_at: string;
  overall_status: string;
  score_pct: number;
  summary: string;
  controls_json: string;
}

function rowToAsset(r: AssetRow): CryptoAsset {
  return {
    id: r.id,
    scanId: r.scan_id,
    file: r.file,
    line: r.line,
    family: r.family as CryptoAsset["family"],
    algorithm: r.algorithm,
    keyBits: r.key_bits,
    language: r.language,
    snippet: r.snippet,
    patternId: r.pattern_id,
    quantumVulnerable: !!r.quantum_vulnerable,
    pqcReplacement: r.pqc_replacement,
    status: (r.status as AssetStatus) ?? "open",
    risk: r.risk_json ? (JSON.parse(r.risk_json) as RiskScore) : undefined,
  };
}

function rowToScan(r: ScanRow): ScanJob {
  return {
    id: r.id,
    target: r.target,
    startedAt: r.started_at,
    finishedAt: r.finished_at,
    filesScanned: r.files_scanned,
    durationMs: r.duration_ms,
    assetCount: r.asset_count,
    status: r.status as ScanJob["status"],
  };
}

function rowToReport(r: ReportRow): ComplianceReport {
  return {
    framework: r.framework as ComplianceReport["framework"],
    scanId: r.scan_id,
    generatedAt: r.generated_at,
    overallStatus: r.overall_status as ComplianceReport["overallStatus"],
    scorePct: r.score_pct,
    summary: r.summary,
    controls: JSON.parse(r.controls_json),
  };
}

class Store {
  private insertScan = db.prepare(
    `INSERT INTO scans (id, org_id, target, started_at, finished_at, files_scanned, duration_ms, asset_count, status, is_latest)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
  );
  private clearLatest = db.prepare(`UPDATE scans SET is_latest = 0 WHERE org_id = ?`);
  private insertAsset = db.prepare(
    `INSERT INTO assets (id, scan_id, org_id, file, line, family, algorithm, key_bits, language, snippet, pattern_id, quantum_vulnerable, pqc_replacement, risk_score, risk_priority, risk_json, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  private updateStatus = db.prepare(
    `UPDATE assets SET status = ? WHERE id = ? AND org_id = ?`,
  );
  private insertReport = db.prepare(
    `INSERT OR REPLACE INTO reports (framework, scan_id, org_id, generated_at, overall_status, score_pct, summary, controls_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  );

  newScanId(): string {
    return `scan_${randomUUID().slice(0, 8)}`;
  }

  /** Run discovery → risk scoring → compliance for a target dir, persist results. */
  runScan(target: string, displayTarget?: string, orgId = DEFAULT_ORG_ID): { job: ScanJob; assetCount: number } {
    const scanId = this.newScanId();
    const { job, assets } = scanDirectory(target, scanId);
    if (displayTarget) job.target = displayTarget;
    scoreAssets(assets);

    db.exec("BEGIN");
    try {
      this.clearLatest.run(orgId);
      this.insertScan.run(
        job.id,
        orgId,
        job.target,
        job.startedAt,
        job.finishedAt,
        job.filesScanned,
        job.durationMs,
        job.assetCount,
        job.status,
      );
      for (const a of assets) {
        this.insertAsset.run(
          a.id,
          a.scanId,
          orgId,
          a.file,
          a.line,
          a.family,
          a.algorithm,
          a.keyBits,
          a.language,
          a.snippet,
          a.patternId,
          a.quantumVulnerable ? 1 : 0,
          a.pqcReplacement,
          a.risk?.score ?? null,
          a.risk?.priority ?? null,
          a.risk ? JSON.stringify(a.risk) : null,
          a.status,
        );
      }
      for (const fw of FRAMEWORKS) {
        const report = generateReport(fw, assets, scanId);
        this.insertReport.run(
          report.framework,
          report.scanId,
          orgId,
          report.generatedAt,
          report.overallStatus,
          report.scorePct,
          report.summary,
          JSON.stringify(report.controls),
        );
      }
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }

    return { job, assetCount: assets.length };
  }

  private latestScanId(orgId: string): string | null {
    const row = db
      .prepare(`SELECT id FROM scans WHERE org_id = ? AND is_latest = 1 LIMIT 1`)
      .get(orgId) as { id: string } | undefined;
    return row?.id ?? null;
  }

  getScans(orgId = DEFAULT_ORG_ID): ScanJob[] {
    const rows = db
      .prepare(`SELECT * FROM scans WHERE org_id = ? ORDER BY started_at DESC`)
      .all(orgId) as unknown as ScanRow[];
    return rows.map(rowToScan);
  }

  getAssets(filter?: { family?: string; priority?: string; q?: string }, orgId = DEFAULT_ORG_ID): CryptoAsset[] {
    const sid = this.latestScanId(orgId);
    if (!sid) return [];
    const clauses = ["scan_id = ?"];
    const params: (string | number)[] = [sid];
    if (filter?.family) {
      clauses.push("family = ?");
      params.push(filter.family);
    }
    if (filter?.priority) {
      clauses.push("risk_priority = ?");
      params.push(filter.priority);
    }
    if (filter?.q) {
      clauses.push("(lower(file) LIKE ? OR lower(algorithm) LIKE ? OR lower(snippet) LIKE ?)");
      const like = `%${filter.q.toLowerCase()}%`;
      params.push(like, like, like);
    }
    const rows = db
      .prepare(`SELECT * FROM assets WHERE ${clauses.join(" AND ")} ORDER BY risk_score DESC`)
      .all(...params) as unknown as AssetRow[];
    return rows.map(rowToAsset);
  }

  getAsset(id: string, orgId = DEFAULT_ORG_ID): CryptoAsset | undefined {
    const row = db
      .prepare(`SELECT * FROM assets WHERE id = ? AND org_id = ?`)
      .get(id, orgId) as AssetRow | undefined;
    return row ? rowToAsset(row) : undefined;
  }

  /**
   * Update an asset's remediation status. Scoped to the org so one tenant can't
   * mutate another's assets. Returns the updated asset, or undefined if no asset
   * with that id exists for the org.
   */
  updateAssetStatus(id: string, status: AssetStatus, orgId = DEFAULT_ORG_ID): CryptoAsset | undefined {
    if (!ASSET_STATUSES.includes(status)) {
      throw new Error(`invalid status: ${status}`);
    }
    const res = this.updateStatus.run(status, id, orgId);
    if (res.changes === 0) return undefined;
    return this.getAsset(id, orgId);
  }

  getReports(scanId?: string, orgId = DEFAULT_ORG_ID): ComplianceReport[] {
    const sid = scanId ?? this.latestScanId(orgId);
    if (!sid) return [];
    const rows = db
      .prepare(`SELECT * FROM reports WHERE scan_id = ? AND org_id = ?`)
      .all(sid, orgId) as unknown as ReportRow[];
    return rows.map(rowToReport);
  }

  getReport(framework: string, scanId?: string, orgId = DEFAULT_ORG_ID): ComplianceReport | undefined {
    const sid = scanId ?? this.latestScanId(orgId);
    if (!sid) return undefined;
    const row = db
      .prepare(`SELECT * FROM reports WHERE framework = ? AND scan_id = ? AND org_id = ?`)
      .get(framework, sid, orgId) as ReportRow | undefined;
    return row ? rowToReport(row) : undefined;
  }

  hasAnyScan(orgId = DEFAULT_ORG_ID): boolean {
    return this.latestScanId(orgId) !== null;
  }

  dashboard(orgId = DEFAULT_ORG_ID) {
    const assets = this.getAssets(undefined, orgId);
    const byFamily: Record<string, number> = {};
    const byPriority: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    const byStatus: Record<AssetStatus, number> = { open: 0, in_progress: 0, migrated: 0, accepted: 0 };
    let migrationEffortDays = 0;
    let remainingEffortDays = 0;

    for (const a of assets) {
      byFamily[a.family] = (byFamily[a.family] ?? 0) + 1;
      const p = a.risk?.priority ?? "low";
      byPriority[p] += 1;
      byStatus[a.status] += 1;
      const effort = a.risk?.migrationEffortDays ?? 0;
      migrationEffortDays += effort;
      if (!RESOLVED_STATUSES.includes(a.status)) remainingEffortDays += effort;
    }

    const resolved = byStatus.migrated + byStatus.accepted;
    const migrationProgressPct = assets.length ? Math.round((resolved / assets.length) * 100) : 0;

    const reports = this.getReports(undefined, orgId);
    const avgCompliance = reports.length
      ? Math.round(reports.reduce((s, r) => s + r.scorePct, 0) / reports.length)
      : 0;
    const sid = this.latestScanId(orgId);
    const latest = sid ? this.getScans(orgId).find((s) => s.id === sid) : undefined;

    return {
      totalAssets: assets.length,
      quantumVulnerable: assets.filter((a) => a.quantumVulnerable).length,
      byFamily,
      byPriority,
      byStatus,
      migrationProgressPct,
      migrationEffortDays,
      remainingEffortDays,
      avgCompliancePct: avgCompliance,
      frameworks: reports.map((r) => ({
        framework: r.framework,
        scorePct: r.scorePct,
        status: r.overallStatus,
      })),
      lastScan: latest
        ? {
            id: latest.id,
            filesScanned: latest.filesScanned,
            durationMs: latest.durationMs,
            finishedAt: latest.finishedAt,
          }
        : null,
    };
  }
}

export const store = new Store();
