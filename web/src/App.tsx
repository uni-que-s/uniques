import { useState } from "react";
import { NavLink, Route, Routes } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Assets from "./pages/Assets";
import Risk from "./pages/Risk";
import Compliance from "./pages/Compliance";
import Monitoring from "./pages/Monitoring";
import History from "./pages/History";
import AuthModal from "./components/AuthModal";
import { useAuth } from "./lib/auth";

const NAV = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/assets", label: "Asset Inventory" },
  { to: "/risk", label: "Risk Analysis" },
  { to: "/compliance", label: "Compliance" },
  { to: "/monitoring", label: "Monitoring" },
  { to: "/history", label: "Scan History" },
];

function AuthPanel({ onSignIn }: { onSignIn: () => void }) {
  const { user, logout } = useAuth();
  if (user) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
        <div className="text-[11px] uppercase tracking-wider text-slate-500">Signed in</div>
        <div className="truncate text-sm font-semibold text-slate-200">{user.orgName}</div>
        <div className="truncate text-xs text-slate-400">{user.email}</div>
        <button
          onClick={logout}
          className="mt-2 w-full rounded-md border border-slate-700 py-1.5 text-xs font-medium text-slate-300 transition hover:bg-slate-800"
        >
          Sign out
        </button>
      </div>
    );
  }
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
      <div className="text-xs text-slate-400">Viewing demo data.</div>
      <button
        onClick={onSignIn}
        className="mt-2 w-full rounded-md bg-indigo-500 py-1.5 text-xs font-semibold text-white transition hover:bg-indigo-400"
      >
        Sign in to scan
      </button>
    </div>
  );
}

function Sidebar({ onSignIn }: { onSignIn: () => void }) {
  return (
    <aside className="fixed inset-y-0 left-0 flex w-60 flex-col border-r border-slate-800 bg-slate-950/80 px-4 py-6">
      <div className="flex items-center gap-2 px-2">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-indigo-500 to-cyan-400 text-lg font-black text-slate-950">
          Q
        </div>
        <div>
          <div className="text-sm font-bold tracking-tight text-white">QuantumVault</div>
          <div className="text-[10px] uppercase tracking-widest text-slate-500">Quantum-Safe</div>
        </div>
      </div>

      <nav className="mt-8 space-y-1">
        {NAV.map((n) => (
          <NavLink
            key={n.to}
            to={n.to}
            end={n.end}
            className={({ isActive }) =>
              `block rounded-lg px-3 py-2 text-sm font-medium transition ${
                isActive
                  ? "bg-indigo-500/15 text-indigo-300"
                  : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-200"
              }`
            }
          >
            {n.label}
          </NavLink>
        ))}
      </nav>

      <div className="mt-auto space-y-3">
        <AuthPanel onSignIn={onSignIn} />
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 text-[11px] text-slate-500">
          <div className="font-semibold text-slate-400">Post-Quantum Ready</div>
          NIST ML-KEM · ML-DSA · SLH-DSA migration tracking
        </div>
      </div>
    </aside>
  );
}

export default function App() {
  const [authOpen, setAuthOpen] = useState(false);
  return (
    <div className="min-h-screen">
      <Sidebar onSignIn={() => setAuthOpen(true)} />
      <main className="ml-60 px-8 py-7">
        <Routes>
          <Route path="/" element={<Dashboard onRequireAuth={() => setAuthOpen(true)} />} />
          <Route path="/assets" element={<Assets />} />
          <Route path="/risk" element={<Risk />} />
          <Route path="/compliance" element={<Compliance />} />
          <Route path="/monitoring" element={<Monitoring onRequireAuth={() => setAuthOpen(true)} />} />
          <Route path="/history" element={<History />} />
        </Routes>
      </main>
      {authOpen && <AuthModal onClose={() => setAuthOpen(false)} />}
    </div>
  );
}
