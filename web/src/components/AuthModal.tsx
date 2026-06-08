import { useState } from "react";
import { useAuth } from "../lib/auth";

export default function AuthModal({ onClose }: { onClose: () => void }) {
  const { login, signup } = useAuth();
  const [tab, setTab] = useState<"login" | "signup">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [orgName, setOrgName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      if (tab === "login") await login(email, password);
      else await signup(email, password, orgName || undefined);
      onClose();
    } catch (e: any) {
      setError(e?.response?.data?.error ?? "Something went wrong.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-30 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div
        className="w-full max-w-sm rounded-2xl border border-slate-800 bg-slate-950 p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-4 flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-indigo-500 to-cyan-400 text-base font-black text-slate-950">
            Q
          </div>
          <h2 className="text-lg font-bold text-white">QuantumVault</h2>
        </div>

        <div className="mb-4 flex overflow-hidden rounded-lg border border-slate-800 text-sm font-semibold">
          {(["login", "signup"] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`flex-1 py-2 transition ${tab === t ? "bg-indigo-500 text-white" : "bg-slate-900 text-slate-400 hover:text-slate-200"}`}
            >
              {t === "login" ? "Sign In" : "Sign Up"}
            </button>
          ))}
        </div>

        <div className="space-y-3">
          {tab === "signup" && (
            <input
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
              placeholder="Organization name (optional)"
              className={inputCls}
            />
          )}
          <input
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            type="email"
            placeholder="Email"
            className={inputCls}
          />
          <input
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && submit()}
            type="password"
            placeholder="Password (min 8 chars)"
            className={inputCls}
          />

          {error && <div className="rounded-lg bg-rose-500/10 px-3 py-2 text-sm text-rose-300">{error}</div>}

          <button
            onClick={submit}
            disabled={busy}
            className="w-full rounded-lg bg-indigo-500 py-2.5 text-sm font-semibold text-white transition hover:bg-indigo-400 disabled:opacity-50"
          >
            {busy ? "Please wait…" : tab === "login" ? "Sign In" : "Create Account"}
          </button>
        </div>

        <p className="mt-3 text-center text-xs text-slate-500">
          Your scans and reports are isolated to your organization.
        </p>
      </div>
    </div>
  );
}

const inputCls =
  "w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:border-indigo-500 focus:outline-none";
