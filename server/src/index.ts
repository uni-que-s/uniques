import express from "express";
import cors from "cors";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { api } from "./routes/api.js";
import { authRouter } from "./routes/auth.js";
import { withAuth } from "./auth/middleware.js";
import { store } from "./store/store.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT ?? 4000);

const app = express();
app.use(cors());
app.use(express.json());
app.use("/api", withAuth);
app.use("/api/auth", authRouter);
app.use("/api", api);

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

app.listen(PORT, () => {
  console.log(`QuantumVault API listening on http://localhost:${PORT}`);
});
