import { Router } from "express";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { store } from "../store/store.js";
import { patternCount } from "../discovery/patterns.js";
import { cloneRepo } from "../discovery/repo.js";
import { requireAuth } from "../auth/middleware.js";
import { renderReportHtml } from "../compliance/export.js";
import { ASSET_STATUSES, type AssetStatus } from "../types.js";

export const api = Router();

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
api.post("/scans", requireAuth, (req, res) => {
  const target = (req.body?.target as string | undefined)?.trim();
  if (!target) return res.status(400).json({ error: "target path is required" });
  const abs = resolve(target);
  if (!existsSync(abs)) return res.status(400).json({ error: `path does not exist: ${abs}` });
  const result = store.runScan(abs, undefined, req.orgId);
  res.status(201).json(result);
});

api.post("/scans/git", requireAuth, async (req, res) => {
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
