/**
 * Generate the static demo dataset for the zero-install dashboard demo.
 *
 * Scans a set of recognizable open-source libraries (the "we scanned software
 * you use" story) and emits the exact JSON shapes the web app fetches, so the
 * dashboard runs fully client-side on GitHub Pages with no backend.
 *
 * Run:  QV_DB_PATH=/tmp/qv-demo.db npx tsx scripts/gen-demo-fixtures.ts <scanTarget> <outFile>
 * Default target: /tmp/qv-demo-target   Default out: ../web/src/demo/data.json
 */
import { writeFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

// Must be set before importing the store (db opens on import).
process.env.QV_DB_PATH ??= "/tmp/qv-demo-fixtures.db";
process.env.QV_SEED = "off";

const target = resolve(process.argv[2] ?? "/tmp/qv-demo-target");
const outFile = resolve(process.argv[3] ?? new URL("../../web/src/demo/data.json", import.meta.url).pathname);

if (!existsSync(target)) {
  console.error(`scan target does not exist: ${target}`);
  process.exit(1);
}

const { store } = await import("../src/store/store.js");
const { buildAssessment } = await import("../src/report/assessment.js");
const { renderAssessmentHtml } = await import("../src/report/assessmentHtml.js");
const { renderReportHtml } = await import("../src/compliance/export.js");
const { assetsToCbom } = await import("../src/discovery/cbom.js");
const { assetsToSarif } = await import("../src/discovery/sarif.js");
const { assetsToCsv } = await import("../src/discovery/csv.js");
const { getRiskWeights } = await import("../src/risk/scorer.js");

const ORG = "Demo Organization";
const SCAN_LABEL = "Popular OSS libraries — jsonwebtoken · pyjwt · golang-jwt · paramiko";

console.error(`scanning ${target} …`);
store.runScan(target, SCAN_LABEL);

const dashboard = store.dashboard();
const assets = store.getAssets();
const reports = store.getReports();
const scans = store.getScans();
const latest = scans[0];

const assessment = buildAssessment({
  orgName: ORG,
  generatedAt: latest?.finishedAt ?? new Date().toISOString(),
  scan: latest
    ? { target: SCAN_LABEL, filesScanned: latest.filesScanned, finishedAt: latest.finishedAt }
    : null,
  assets,
  reports,
});

// The active risk-scoring weights + factor descriptions (mirrors GET /risk/config).
const riskConfig = {
  weights: getRiskWeights(),
  factors: {
    dataSensitivity: "Sensitivity of the data the asset protects (auth, payments, PII).",
    retentionExposure: "How long the protected data must stay confidential.",
    hndlExposure: "Harvest-now-decrypt-later risk for key-exchange/transport crypto.",
    complianceImpact: "Whether the finding is an explicit regulatory gap.",
    businessImpact: "Operational blast radius if the asset is compromised.",
  },
};

// Two illustrative continuous monitors so the Monitoring page is populated.
// Clearly demo data; the live product derives these from scheduled re-scans.
const finishedAt = latest?.finishedAt ?? new Date().toISOString();
const monitors = [
  {
    id: "mon_demo_jwt", orgId: "org_default", name: "auth0/node-jsonwebtoken", kind: "git",
    target: "https://github.com/auth0/node-jsonwebtoken", intervalMinutes: 1440, enabled: true,
    createdAt: finishedAt, lastRunAt: finishedAt, nextRunAt: finishedAt,
    lastScanId: latest?.id ?? null, lastStatus: "ok", lastError: null, runCount: 6,
  },
  {
    id: "mon_demo_estate", orgId: "org_default", name: "Internal services (nightly)", kind: "path",
    target: "/srv/estate", intervalMinutes: 1440, enabled: true,
    createdAt: finishedAt, lastRunAt: finishedAt, nextRunAt: finishedAt,
    lastScanId: latest?.id ?? null, lastStatus: "ok", lastError: null, runCount: 12,
  },
];
const monitorDetail: Record<string, unknown> = {
  mon_demo_jwt: {
    monitor: monitors[0],
    drift: { hasPrevious: true, newFindings: 3, removedFindings: 0 },
    scans: scans.slice(0, 5),
  },
  mon_demo_estate: {
    monitor: monitors[1],
    drift: { hasPrevious: true, newFindings: 1, removedFindings: 7 },
    scans: scans.slice(0, 5),
  },
};

const data = {
  generatedAt: finishedAt,
  dashboard,
  assets,
  reports,
  scans,
  riskConfig,
  monitors,
  monitorDetail,
  assessment,
  assessmentHtml: renderAssessmentHtml(assessment),
  complianceHtml: Object.fromEntries(reports.map((r) => [r.framework, renderReportHtml(r, ORG)])),
  cbom: assetsToCbom(assets, { target: SCAN_LABEL, generatedAt: finishedAt }),
  sarif: assetsToSarif(assets),
  // CSV header + per-asset rows (each produced by the real assetsToCsv, so the
  // demo never drifts from the server format) so the demo's CSV export can honor
  // the active family/priority/search filters exactly like the server does.
  csvHeader: assetsToCsv([]).replace(/\r\n$/, ""),
  csvRows: Object.fromEntries(assets.map((a) => [a.id, assetsToCsv([a]).split("\r\n")[1]])),
};

writeFileSync(outFile, JSON.stringify(data));
console.error(
  `wrote ${outFile}\n  ${assets.length} assets · ${reports.length} frameworks · grade ${assessment.posture.grade} · ${(JSON.stringify(data).length / 1024).toFixed(0)} KB`,
);
