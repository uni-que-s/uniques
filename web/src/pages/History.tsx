import { useEffect, useState } from "react";
import { getScans, type ScanJob } from "../lib/api";
import { Card } from "../components/ui";

function fmtTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function History() {
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getScans()
      .then(setScans)
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-2xl font-bold text-white">Scan History</h1>
        <p className="text-sm text-slate-400">
          {loading ? "Loading…" : `${scans.length} scan${scans.length === 1 ? "" : "s"} on record`}
        </p>
      </header>

      <Card>
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-slate-800 text-xs uppercase tracking-wider text-slate-500">
              <th className="px-5 py-3 font-medium">Target</th>
              <th className="px-5 py-3 font-medium">Finished</th>
              <th className="px-5 py-3 font-medium">Files</th>
              <th className="px-5 py-3 font-medium">Duration</th>
              <th className="px-5 py-3 font-medium">Assets</th>
              <th className="px-5 py-3 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((s, i) => (
              <tr key={s.id} className="border-b border-slate-800/60">
                <td className="max-w-xs truncate px-5 py-3 font-mono text-xs text-slate-300" title={s.target}>
                  {s.target}
                  {i === 0 && (
                    <span className="ml-2 rounded bg-indigo-500/20 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-indigo-300">
                      latest
                    </span>
                  )}
                </td>
                <td className="px-5 py-3 text-slate-400">{fmtTime(s.finishedAt)}</td>
                <td className="px-5 py-3 text-slate-400">{s.filesScanned}</td>
                <td className="px-5 py-3 text-slate-400">{s.durationMs}ms</td>
                <td className="px-5 py-3 font-semibold text-slate-200">{s.assetCount}</td>
                <td className="px-5 py-3">
                  <span className="inline-flex items-center gap-1.5 text-xs text-emerald-300">
                    <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                    {s.status}
                  </span>
                </td>
              </tr>
            ))}
            {!loading && scans.length === 0 && (
              <tr>
                <td colSpan={6} className="px-5 py-8 text-center text-slate-500">
                  No scans yet. Run one from the Dashboard.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
