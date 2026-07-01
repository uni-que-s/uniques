import type { ComplianceReport, ComplianceStatus } from "../types.js";

const STATUS_LABEL: Record<ComplianceStatus, string> = {
  pass: "No gaps found",
  gap: "Partial",
  fail: "Fail",
};
const STATUS_COLOR: Record<ComplianceStatus, string> = {
  pass: "#15803d",
  gap: "#b45309",
  fail: "#b91c1c",
};

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * Render a self-contained, print-ready HTML compliance report. Designed to be
 * opened in a browser and printed / saved to PDF by an auditor.
 */
export function renderReportHtml(report: ComplianceReport, orgName: string): string {
  const scoreColor = report.scorePct >= 90 ? "#15803d" : report.scorePct >= 60 ? "#b45309" : "#b91c1c";
  const generated = new Date(report.generatedAt).toLocaleString();

  const rows = report.controls
    .map(
      (c) => `
      <tr>
        <td class="mono">${esc(c.id)}</td>
        <td><strong>${esc(c.title)}</strong><div class="desc">${esc(c.description)}</div></td>
        <td><span class="badge" style="color:${STATUS_COLOR[c.status]};border-color:${STATUS_COLOR[c.status]}">${STATUS_LABEL[c.status]}</span></td>
        <td class="num">${c.affectedAssets}</td>
        <td>${c.status === "pass" ? "&mdash;" : esc(c.remediation)}</td>
      </tr>`,
    )
    .join("");

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"/>
<title>${esc(report.framework)} Control-Gap Report — ${esc(orgName)}</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #1e293b; margin: 0; padding: 40px; }
  .head { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 3px solid #6366f1; padding-bottom: 16px; }
  .brand { display:flex; align-items:center; gap:10px; }
  .logo { width:34px; height:34px; border-radius:8px; background:linear-gradient(135deg,#6366f1,#22d3ee); color:#fff; font-weight:800; display:flex; align-items:center; justify-content:center; font-size:18px; }
  h1 { font-size: 22px; margin: 18px 0 2px; }
  .muted { color: #64748b; font-size: 13px; }
  .scorebox { text-align:right; }
  .score { font-size: 40px; font-weight: 800; color: ${scoreColor}; line-height: 1; }
  .summary { background:#f1f5f9; border-radius:8px; padding:12px 16px; margin:20px 0; font-size:14px; }
  table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }
  th { text-align: left; background:#f8fafc; border-bottom:2px solid #e2e8f0; padding:8px 10px; font-size:11px; text-transform:uppercase; letter-spacing:.04em; color:#475569; }
  td { border-bottom:1px solid #e2e8f0; padding:10px; vertical-align: top; }
  .mono { font-family: ui-monospace, Menlo, monospace; white-space:nowrap; }
  .num { text-align:center; font-weight:700; }
  .desc { color:#64748b; font-size:12px; margin-top:3px; }
  .badge { display:inline-block; border:1px solid; border-radius:999px; padding:1px 9px; font-size:11px; font-weight:700; }
  footer { margin-top: 28px; color:#94a3b8; font-size:11px; border-top:1px solid #e2e8f0; padding-top:10px; }
  @media print { body { padding: 0; } @page { margin: 18mm; } }
</style></head>
<body>
  <div class="head">
    <div>
      <div class="brand"><div class="logo">U</div><strong>UniQueS</strong></div>
      <h1>${esc(report.framework)} Control-Gap Report</h1>
      <div class="muted">${esc(orgName)} &middot; Generated ${esc(generated)} &middot; Scan ${esc(report.scanId)}</div>
      <div class="muted">Control-gap evidence for review &mdash; not a certification of compliance.</div>
    </div>
    <div class="scorebox">
      <div class="score">${report.scorePct}%</div>
      <div class="muted">control coverage &middot; ${STATUS_LABEL[report.overallStatus]}</div>
    </div>
  </div>

  <div class="summary">${esc(report.summary)}</div>

  <table>
    <thead><tr><th>Control</th><th>Requirement</th><th>Status</th><th>Affected</th><th>Remediation</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>

  <footer>
    UniQueS automated post-quantum compliance assessment. This report maps discovered
    cryptographic assets to ${esc(report.framework)} control requirements. Confidential &amp; Proprietary.
  </footer>
</body></html>`;
}
