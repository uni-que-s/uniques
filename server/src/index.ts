import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { createApp } from "./app.js";
import { store } from "./store/store.js";
import { db } from "./store/db.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT ?? 4000);

const app = createApp();

// Seed an initial scan over the bundled sample target on first boot only, so the
// dashboard is populated out of the box. On later boots the persisted scan is
// reused. Set QV_SEED=force to always re-seed.
const sampleTarget = resolve(__dirname, "..", "sample-target");
if (process.env.QV_SEED === "force" || !store.hasAnyScan()) {
  const { job, assetCount } = store.runScan(sampleTarget);
  console.log(
    `[seed] scanned ${job.filesScanned} files in ${job.durationMs}ms — ${assetCount} crypto assets discovered`,
  );
} else {
  console.log("[seed] existing scan data found — skipping seed");
}

const server = app.listen(PORT, () => {
  console.log(`QuantumVault API listening on http://localhost:${PORT}`);
});

// Graceful shutdown: stop accepting connections, let in-flight requests finish,
// then close the SQLite handle so WAL is checkpointed cleanly. Containers send
// SIGTERM on stop; a hung drain is force-exited after 10s.
let shuttingDown = false;
function shutdown(signal: string): void {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`[shutdown] ${signal} received — draining connections`);
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
