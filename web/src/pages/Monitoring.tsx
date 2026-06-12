import { useEffect, useState, type FormEvent } from "react";
import {
  getMonitors,
  getMonitor,
  createMonitor,
  setMonitorEnabled,
  deleteMonitor,
  type MonitorTarget,
  type Drift,
} from "../lib/api";
import { Card, StatCard } from "../components/ui";

interface Row {
  monitor: MonitorTarget;
  drift: Drift;
}

function fmtTime(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function is401(err: unknown): boolean {
  return !!(err as { response?: { status?: number } })?.response && (err as { response: { status: number } }).response.status === 401;
}

export default function Monitoring({ onRequireAuth }: { onRequireAuth?: () => void }) {
  const [rows, setRows] = useState<Row[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // add-monitor form
  const [name, setName] = useState("");
  const [kind, setKind] = useState<"git" | "path">("git");
  const [target, setTarget] = useState("");
  const [interval, setIntervalMin] = useState(60);

  async function load() {
    const list = await getMonitors();
    const detail = await Promise.all(
      list.map((m) =>
        getMonitor(m.id)
          .then((d) => ({ monitor: d.monitor, drift: d.drift }))
          .catch(() => ({ monitor: m, drift: { hasPrevious: false, newFindings: 0, removedFindings: 0 } })),
      ),
    );
    setRows(detail);
  }

  useEffect(() => {
    load().finally(() => setLoading(false));
  }, []);

  function guard(err: unknown) {
    if (is401(err)) {
      onRequireAuth?.();
      setError("Sign in to manage monitors.");
    } else {
      setError((err as { response?: { data?: { error?: string } } })?.response?.data?.error ?? "Something went wrong.");
    }
  }

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await createMonitor({ name: name.trim(), kind, target: target.trim(), intervalMinutes: interval });
      setName("");
      setTarget("");
      await load();
    } catch (err) {
      guard(err);
    } finally {
      setBusy(false);
    }
  }

  async function toggle(m: MonitorTarget) {
    setError(null);
    try {
      await setMonitorEnabled(m.id, !m.enabled);
      await load();
    } catch (err) {
      guard(err);
    }
  }

  async function remove(m: MonitorTarget) {
    setError(null);
    try {
      await deleteMonitor(m.id);
      await load();
    } catch (err) {
      guard(err);
    }
  }

  const active = rows.filter((r) => r.monitor.enabled).length;
  const totalRuns = rows.reduce((s, r) => s + r.monitor.runCount, 0);
  const driftNew = rows.reduce((s, r) => s + r.drift.newFindings, 0);

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-2xl font-bold text-white">Continuous Monitoring</h1>
        <p className="text-sm text-slate-400">
          Automatically re-scan repositories on a schedule — catch new quantum-vulnerable crypto the moment it lands.
        </p>
      </header>

      <div className="grid grid-cols-3 gap-4">
        <StatCard label="Active monitors" value={active} sub={`${rows.length} configured`} />
        <StatCard label="Total scans run" value={totalRuns} accent="#22d3ee" />
        <StatCard
          label="New findings (last run)"
          value={driftNew}
          accent={driftNew > 0 ? "#fb923c" : "#34d399"}
          sub={driftNew > 0 ? "drift detected" : "no new exposure"}
        />
      </div>

      <Card className="p-5">
        <div className="mb-3 text-sm font-semibold text-slate-200">Add a monitor</div>
        <form onSubmit={handleCreate} className="grid grid-cols-12 gap-3">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Name (e.g. payments-api)"
            required
            className="col-span-3 rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:border-indigo-500 focus:outline-none"
          />
          <select
            value={kind}
            onChange={(e) => setKind(e.target.value as "git" | "path")}
            className="col-span-2 rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-sm text-slate-200 focus:border-indigo-500 focus:outline-none"
          >
            <option value="git">Git repo</option>
            <option value="path">Local path</option>
          </select>
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder={kind === "git" ? "https://github.com/org/repo" : "/srv/app"}
            required
            className="col-span-4 rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 font-mono text-xs text-slate-200 placeholder:text-slate-600 focus:border-indigo-500 focus:outline-none"
          />
          <div className="col-span-2 flex items-center rounded-lg border border-slate-700 bg-slate-950/60 px-3">
            <span className="text-xs text-slate-500">every</span>
            <input
              type="number"
              min={1}
              value={interval}
              onChange={(e) => setIntervalMin(Number(e.target.value))}
              className="w-full bg-transparent px-2 py-2 text-sm text-slate-200 focus:outline-none"
            />
            <span className="text-xs text-slate-500">min</span>
          </div>
          <button
            type="submit"
            disabled={busy}
            className="col-span-1 rounded-lg bg-indigo-500 text-sm font-semibold text-white transition hover:bg-indigo-400 disabled:opacity-50"
          >
            Add
          </button>
        </form>
        {error && <div className="mt-2 text-xs text-rose-400">{error}</div>}
      </Card>

      <Card>
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-slate-800 text-xs uppercase tracking-wider text-slate-500">
              <th className="px-5 py-3 font-medium">Target</th>
              <th className="px-5 py-3 font-medium">Schedule</th>
              <th className="px-5 py-3 font-medium">Last run</th>
              <th className="px-5 py-3 font-medium">Drift</th>
              <th className="px-5 py-3 font-medium">Runs</th>
              <th className="px-5 py-3 font-medium">State</th>
              <th className="px-5 py-3 font-medium" />
            </tr>
          </thead>
          <tbody>
            {rows.map(({ monitor: m, drift }) => (
              <tr key={m.id} className="border-b border-slate-800/60">
                <td className="px-5 py-3">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-slate-200">{m.name}</span>
                    <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-slate-400">
                      {m.kind}
                    </span>
                  </div>
                  <div className="max-w-xs truncate font-mono text-xs text-slate-500" title={m.target}>
                    {m.target}
                  </div>
                </td>
                <td className="px-5 py-3 text-slate-400">every {m.intervalMinutes}m</td>
                <td className="px-5 py-3">
                  <div className="flex items-center gap-1.5 text-xs">
                    <span
                      className="h-1.5 w-1.5 rounded-full"
                      style={{
                        backgroundColor:
                          m.lastStatus === "ok" ? "#34d399" : m.lastStatus === "failed" ? "#f43f5e" : "#64748b",
                      }}
                    />
                    <span className="text-slate-400">{fmtTime(m.lastRunAt)}</span>
                  </div>
                </td>
                <td className="px-5 py-3 text-xs">
                  {drift.hasPrevious ? (
                    <span>
                      <span className="font-semibold text-orange-400">+{drift.newFindings}</span>{" "}
                      <span className="text-slate-600">/</span>{" "}
                      <span className="font-semibold text-emerald-400">−{drift.removedFindings}</span>
                    </span>
                  ) : (
                    <span className="text-slate-600">baseline</span>
                  )}
                </td>
                <td className="px-5 py-3 font-semibold text-slate-300">{m.runCount}</td>
                <td className="px-5 py-3">
                  <button
                    onClick={() => toggle(m)}
                    className={`rounded-full px-2.5 py-0.5 text-xs font-semibold transition ${
                      m.enabled
                        ? "bg-emerald-500/15 text-emerald-300 hover:bg-emerald-500/25"
                        : "bg-slate-700/40 text-slate-400 hover:bg-slate-700/60"
                    }`}
                  >
                    {m.enabled ? "Active" : "Paused"}
                  </button>
                </td>
                <td className="px-5 py-3 text-right">
                  <button
                    onClick={() => remove(m)}
                    className="text-xs text-slate-500 transition hover:text-rose-400"
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
            {!loading && rows.length === 0 && (
              <tr>
                <td colSpan={7} className="px-5 py-10 text-center text-slate-500">
                  No monitors yet. Add one above to start continuous scanning.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
