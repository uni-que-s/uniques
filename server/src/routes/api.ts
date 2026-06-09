import { Router } from "express";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { store } from "../store/store.js";
import { patternCount } from "../discovery/patterns.js";
import { cloneRepo } from "../discovery/repo.js";
import { requireAuth } from "../auth/middleware.js";
import { rateLimit } from "../auth/rateLimit.js";
import { renderReportHtml } from "../compliance/export.js";
import { assetsToCsv } from "../discovery/csv.js";
import { assetsToCbom } from "../discovery/cbom.js";
import { assetsToSarif } from "../discovery/sarif.js";
import { ASSET_STATUSES, type AssetStatus } from "../types.js";

export const api = Router();

// Scanning clones/walks a whole codebase, so it's far more costly than a normal
// request. Throttle per org (not per IP) so one tenant's bulk scanning can't
// starve others, while corporate NATs sharing an IP aren't lumped together.
const scanLimiter = rateLimit(30, 5 * 60_000, (req) => req.orgId);

api.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "quantumvault", patterns: patternCount() });
});

api.get("/dashboard", (req, res) => {
  res.json(store.dashboard(req.orgId));
});

api.get("/assets", (req, res) => {
  const { family, priority, q } = req.query as Record<string, string>;
  res.json(store.getAssets({ family, priority, q }, req.orgId));
});

// Raw inventory export for spreadsheets / SIEM / ticketing. Honors the same
// filters as GET /assets. Declared before "/assets/:id" so the literal path
// isn't captured as an id.
api.get("/assets/export.csv", (req, res) => {
  const { family, priority, q } = req.query as Record<string, string>;
  const assets = store.getAssets({ family, priority, q }, req.orgId);
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="quantumvault-assets.csv"`);
  res.send(assetsToCsv(assets));
});

// Cryptography Bill of Materials (CycloneDX 1.6) for the latest scan — the
// standards-based interchange format for post-quantum migration inventories.
api.get("/cbom.json", (req, res) => {
  const assets = store.getAssets(undefined, req.orgId);
  const latest = store.getScans(req.orgId)[0];
  const cbom = assetsToCbom(assets, { target: latest?.target, generatedAt: latest?.finishedAt });
  res.setHeader("Content-Type", "application/vnd.cyclonedx+json");
  res.setHeader("Content-Disposition", `attachment; filename="quantumvault-cbom.json"`);
  res.send(JSON.stringify(cbom, null, 2));
});

// SARIF 2.1.0 log for the latest scan — uploadable to GitHub code-scanning.
api.get("/sarif.json", (req, res) => {
  const assets = store.getAssets(undefined, req.orgId);
  res.setHeader("Content-Type", "application/sarif+json");
  res.setHeader("Content-Disposition", `attachment; filename="quantumvault.sarif"`);
  res.send(JSON.stringify(assetsToSarif(assets), null, 2));
});

api.get("/assets/:id", (req, res) => {
  const asset = store.getAsset(req.params.id, req.orgId);
  if (!asset) return res.status(404).json({ error: "asset not found" });
  res.json(asset);
});

// Update an asset's remediation status — an operator action, so require auth.
api.patch("/assets/:id/status", requireAuth, (req, res) => {
  const status = (req.body?.status as string | undefined)?.trim();
  if (!status || !ASSET_STATUSES.includes(status as AssetStatus)) {
    return res.status(400).json({ error: `status must be one of: ${ASSET_STATUSES.join(", ")}` });
  }
  const updated = store.updateAssetStatus(req.params.id, status as AssetStatus, req.orgId);
  if (!updated) return res.status(404).json({ error: "asset not found" });
  res.json(updated);
});

api.get("/scans", (req, res) => {
  res.json(store.getScans(req.orgId));
});

// Scanning a local path is an operator action — require an authenticated account.
api.post("/scans", requireAuth, scanLimiter, (req, res) => {
  const target = (req.body?.target as string | undefined)?.trim();
  if (!target) return res.status(400).json({ error: "target path is required" });
  const abs = resolve(target);
  if (!existsSync(abs)) return res.status(400).json({ error: `path does not exist: ${abs}` });
  const result = store.runScan(abs, undefined, req.orgId);
  res.status(201).json(result);
});

api.post("/scans/git", requireAuth, scanLimiter, async (req, res) => {
  const url = (req.body?.url as string | undefined)?.trim();
  const token = (req.body?.token as string | undefined)?.trim() || undefined;
  if (!url) return res.status(400).json({ error: "repository url is required" });

  let cloned;
  try {
    cloned = await cloneRepo(url, 60_000, token);
  } catch (err: any) {
    return res.status(400).json({ error: err?.message ?? "clone failed" });
  }

  try {
    const result = store.runScan(cloned.dir, cloned.label, req.orgId);
    res.status(201).json({ ...result, repo: cloned.label });
  } catch (err: any) {
    res.status(500).json({ error: err?.message ?? "scan failed" });
  } finally {
    cloned.cleanup();
  }
});

api.get("/compliance", (req, res) => {
  res.json(store.getReports(undefined, req.orgId));
});

api.get("/compliance/:framework", (req, res) => {
  const report = store.getReport(req.params.framework.toUpperCase(), undefined, req.orgId);
  if (!report) return res.status(404).json({ error: "report not found" });
  res.json(report);
});

// Auditor exports — JSON for systems of record, HTML (print-to-PDF) for humans.
api.get("/compliance/:framework/export.json", (req, res) => {
  const framework = req.params.framework.toUpperCase();
  const report = store.getReport(framework, undefined, req.orgId);
  if (!report) return res.status(404).json({ error: "report not found" });
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Disposition", `attachment; filename="${framework}-compliance.json"`);
  res.send(JSON.stringify(report, null, 2));
});

api.get("/compliance/:framework/export.html", (req, res) => {
  const framework = req.params.framework.toUpperCase();
  const report = store.getReport(framework, undefined, req.orgId);
  if (!report) return res.status(404).json({ error: "report not found" });
  const orgName = req.auth?.orgName ?? "Demo Organization";
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(renderReportHtml(report, orgName));
});
