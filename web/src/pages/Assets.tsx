import { useEffect, useMemo, useState } from "react";
import { getAssets, type CryptoAsset, type Severity } from "../lib/api";
import { Card, SeverityBadge, FAMILY_COLOR } from "../components/ui";

const FAMILIES = ["RSA", "ECC", "DSA", "DH", "SymmetricLegacy", "HashLegacy"];
const PRIORITIES: Severity[] = ["critical", "high", "medium", "low"];

export default function Assets() {
  const [assets, setAssets] = useState<CryptoAsset[]>([]);
  const [q, setQ] = useState("");
  const [family, setFamily] = useState("");
  const [priority, setPriority] = useState("");
  const [selected, setSelected] = useState<CryptoAsset | null>(null);

  useEffect(() => {
    getAssets().then(setAssets);
  }, []);

  const filtered = useMemo(() => {
    return assets.filter((a) => {
      if (family && a.family !== family) return false;
      if (priority && a.risk?.priority !== priority) return false;
      if (q) {
        const s = q.toLowerCase();
        if (
          !a.file.toLowerCase().includes(s) &&
          !a.algorithm.toLowerCase().includes(s) &&
          !a.snippet.toLowerCase().includes(s)
        )
          return false;
      }
      return true;
    });
  }, [assets, q, family, priority]);

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-2xl font-bold text-white">Asset Inventory</h1>
        <p className="text-sm text-slate-400">{filtered.length} of {assets.length} cryptographic assets</p>
      </header>

      <div className="flex flex-wrap gap-3">
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search file, algorithm, snippet…"
          className="w-80 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:border-indigo-500 focus:outline-none"
        />
        <select value={family} onChange={(e) => setFamily(e.target.value)} className={selectCls}>
          <option value="">All families</option>
          {FAMILIES.map((f) => (
            <option key={f} value={f}>{f}</option>
          ))}
        </select>
        <select value={priority} onChange={(e) => setPriority(e.target.value)} className={selectCls}>
          <option value="">All priorities</option>
          {PRIORITIES.map((p) => (
            <option key={p} value={p}>{p}</option>
          ))}
        </select>
      </div>

      <Card>
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-slate-800 text-xs uppercase tracking-wider text-slate-500">
              <th className="px-5 py-3 font-medium">Algorithm</th>
              <th className="px-5 py-3 font-medium">Location</th>
              <th className="px-5 py-3 font-medium">Key</th>
              <th className="px-5 py-3 font-medium">Risk</th>
              <th className="px-5 py-3 font-medium">Priority</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((a) => (
              <tr
                key={a.id}
                onClick={() => setSelected(a)}
                className="cursor-pointer border-b border-slate-800/60 transition hover:bg-slate-800/40"
              >
                <td className="px-5 py-3">
                  <div className="flex items-center gap-2">
                    <span className="h-2.5 w-2.5 rounded-sm" style={{ background: FAMILY_COLOR[a.family] ?? "#64748b" }} />
                    <span className="font-medium text-slate-200">{a.algorithm}</span>
                  </div>
                </td>
                <td className="px-5 py-3 font-mono text-xs text-slate-400">
                  {a.file}:{a.line}
                </td>
                <td className="px-5 py-3 text-slate-400">{a.keyBits ? `${a.keyBits}-bit` : "—"}</td>
                <td className="px-5 py-3">
                  <span className="font-semibold text-slate-200">{a.risk?.score ?? "—"}</span>
                </td>
                <td className="px-5 py-3">{a.risk && <SeverityBadge level={a.risk.priority} />}</td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={5} className="px-5 py-8 text-center text-slate-500">
                  No assets match your filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </Card>

      {selected && <AssetDrawer asset={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

function AssetDrawer({ asset, onClose }: { asset: CryptoAsset; onClose: () => void }) {
  const f = asset.risk?.factors;
  return (
    <div className="fixed inset-0 z-20 flex justify-end bg-black/50" onClick={onClose}>
      <div
        className="h-full w-[480px] overflow-y-auto border-l border-slate-800 bg-slate-950 p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between">
          <div>
            <h2 className="text-lg font-bold text-white">{asset.algorithm}</h2>
            <p className="font-mono text-xs text-slate-400">{asset.file}:{asset.line}</p>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200">✕</button>
        </div>

        <div className="mt-4 flex items-center gap-2">
          {asset.risk && <SeverityBadge level={asset.risk.priority} />}
          <span className="text-sm text-slate-400">Risk score {asset.risk?.score}/100</span>
        </div>

        <pre className="mt-4 overflow-x-auto rounded-lg border border-slate-800 bg-black/40 p-3 font-mono text-xs text-amber-200">
          {asset.snippet}
        </pre>

        {f && (
          <div className="mt-5">
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-500">
              Risk Factor Breakdown
            </h3>
            <div className="space-y-2">
              {[
                ["Data Sensitivity", f.dataSensitivity],
                ["Retention Exposure", f.retentionExposure],
                ["HNDL Exposure", f.hndlExposure],
                ["Compliance Impact", f.complianceImpact],
                ["Business Impact", f.businessImpact],
              ].map(([label, val]) => (
                <div key={label as string}>
                  <div className="mb-0.5 flex justify-between text-xs text-slate-400">
                    <span>{label}</span>
                    <span>{val}</span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-slate-800">
                    <div className="h-full rounded-full bg-indigo-400" style={{ width: `${val}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="mt-5 rounded-lg border border-cyan-500/30 bg-cyan-500/10 p-3">
          <div className="text-xs font-semibold uppercase tracking-wider text-cyan-300">Recommendation</div>
          <p className="mt-1 text-sm text-slate-200">{asset.risk?.recommendation}</p>
          <p className="mt-2 text-xs text-slate-400">
            Migration effort: ~{asset.risk?.migrationEffortDays} engineering days
          </p>
        </div>
      </div>
    </div>
  );
}

const selectCls =
  "rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 focus:border-indigo-500 focus:outline-none";
