import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { createApp } from "./app.js";
import { store } from "./store/store.js";
import { db } from "./store/db.js";
import { startScheduler, stopScheduler } from "./monitor/scheduler.js";
import { activateLicense, getLicenseStatus } from "./license/service.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT ?? 4000);

const app = createApp();

// Headless license activation: if QV_LICENSE is set (e.g. by install.sh / compose
// env), apply it on boot so a self-hosted deploy can be licensed without touching
// the UI. Idempotent; a bad key warns but never blocks startup (the operator can
// still activate via the dashboard). The trial runs automatically when unset.
if (process.env.QV_LICENSE?.trim()) {
  try {
    const s = activateLicense(process.env.QV_LICENSE.trim());
    console.log(`[license] ${s.message}`);
  } catch (err) {
    console.warn(`[license] QV_LICENSE ignored — ${(err as Error).message}. Activate a valid key in the dashboard.`);
  }
}
console.log(`[license] ${getLicenseStatus().message}`);

// Seed an initial scan over the bundled sample target on first boot only, so the
// dashboard is populated out of the box. On later boots the persisted scan is
// reused. Set QV_SEED=force to always re-seed.
const sampleTarget = resolve(__dirname, "..", "sample-target");
if (process.env.QV_SEED === "force" || !store.hasAnyScan()) {
  // Seed a demo continuous monitor and run it once, so the Monitoring page is
  // populated out of the box alongside the dashboard.
  const monitor = store.createMonitor({
    name: "Sample target (demo)",
    kind: "path",
    target: sampleTarget,
    intervalMinutes: 60,
  });
  const { job, assetCount } = store.runScan(sampleTarget, undefined, undefined, monitor.id);
  store.recordMonitorRun(monitor.id, { scanId: job.id, status: "ok" });
  console.log(
    `[seed] scanned ${job.filesScanned} files in ${job.durationMs}ms — ${assetCount} crypto assets discovered`,
  );
} else {
  console.log("[seed] existing scan data found — skipping seed");
}

const server = app.listen(PORT, () => {
  console.log(`UniQueS API listening on http://localhost:${PORT}`);
});

// Continuous monitoring: re-scan configured targets on a schedule. Tick interval
// is tunable (default 60s); set QV_MONITOR_DISABLED=1 to turn it off.
if (process.env.QV_MONITOR_DISABLED !== "1") {
  startScheduler(Number(process.env.QV_MONITOR_TICK_MS ?? 60_000));
}

// Graceful shutdown: stop accepting connections, let in-flight requests finish,
// then close the SQLite handle so WAL is checkpointed cleanly. Containers send
// SIGTERM on stop; a hung drain is force-exited after 10s.
let shuttingDown = false;
function shutdown(signal: string): void {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`[shutdown] ${signal} received — draining connections`);
  stopScheduler();
  server.close(() => {
    try {
      db.close();
    } catch {
      /* already closed */
    }
    console.log("[shutdown] complete");
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
for (const sig of ["SIGTERM", "SIGINT"] as const) {
  process.on(sig, () => shutdown(sig));
}
