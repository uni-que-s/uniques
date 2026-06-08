import { useEffect, useState } from "react";
import {
  getCompliance,
  downloadComplianceJson,
  openCompliancePdf,
  type ComplianceReport,
} from "../lib/api";
import { Card, StatusBadge } from "../components/ui";

export default function Compliance() {
  const [reports, setReports] = useState<ComplianceReport[]>([]);
  const [active, setActive] = useState<string>("FISMA");
  const [exportMsg, setExportMsg] = useState<string | null>(null);

  useEffect(() => {
    getCompliance().then((r) => {
      setReports(r);
      if (r[0]) setActive(r[0].framework);
    });
  }, []);

  const report = reports.find((r) => r.framework === active);

  const onJson = async () => {
    setExportMsg(null);
    try {
      await downloadComplianceJson(active);
    } catch (e: any) {
      setExportMsg(e?.message ?? "Export failed.");
    }
  };
  const onPdf = async () => {
    setExportMsg(null);
    try {
      await openCompliancePdf(active);
    } catch (e: any) {
      setExportMsg(e?.message ?? "Export failed.");
    }
  };

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-bold text-white">Compliance Automation</h1>
        <p className="text-sm text-slate-400">
          Auto-generated control reports with remediation guidance
        </p>
      </header>

      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex gap-2">
          {reports.map((r) => (
            <button
              key={r.framework}
              onClick={() => setActive(r.framework)}
              className={`rounded-lg px-4 py-2 text-sm font-semibold transition ${
                active === r.framework
                  ? "bg-indigo-500 text-white"
                  : "border border-slate-700 bg-slate-900 text-slate-300 hover:bg-slate-800"
              }`}
            >
              {r.framework}
              <span className="ml-2 opacity-70">{r.scorePct}%</span>
            </button>
          ))}
        </div>
        <div className="flex gap-2">
          <button
            onClick={onJson}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm font-medium text-slate-200 transition hover:bg-slate-800"
          >
            Export JSON
          </button>
          <button
            onClick={onPdf}
            className="rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-2 text-sm font-medium text-cyan-200 transition hover:bg-cyan-500/20"
          >
            Export PDF
          </button>
        </div>
      </div>

      {exportMsg && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-2 text-sm text-rose-200">
          {exportMsg}
        </div>
      )}

      {report && (
        <>
          <Card className="p-5">
            <div className="flex items-center justify-between">
              <div>
                <div className="flex items-center gap-3">
                  <h2 className="text-lg font-bold text-white">{report.framework}</h2>
                  <StatusBadge status={report.overallStatus} />
                </div>
                <p className="mt-1 max-w-3xl text-sm text-slate-400">{report.summary}</p>
              </div>
              <div className="text-right">
                <div
                  className="text-4xl font-black"
                  style={{ color: report.scorePct >= 60 ? "#34d399" : report.scorePct >= 40 ? "#facc15" : "#f43f5e" }}
                >
                  {report.scorePct}%
                </div>
                <div className="text-xs text-slate-500">control coverage</div>
              </div>
            </div>
          </Card>

          <div className="space-y-3">
            {report.controls.map((c) => (
              <Card key={c.id} className="p-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-xs text-slate-300">
                        {c.id}
                      </span>
                      <span className="font-semibold text-slate-200">{c.title}</span>
                      <StatusBadge status={c.status} />
                    </div>
                    <p className="mt-1 text-sm text-slate-400">{c.description}</p>
                    {c.status !== "pass" && (
                      <p className="mt-2 text-sm text-cyan-300">
                        <span className="font-semibold">Remediation:</span> {c.remediation}
                      </p>
                    )}
                  </div>
                  <div className="text-right">
                    <div className="text-2xl font-bold text-slate-200">{c.affectedAssets}</div>
                    <div className="text-[11px] text-slate-500">affected assets</div>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
