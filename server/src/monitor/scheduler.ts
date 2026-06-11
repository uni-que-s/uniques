import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { store } from "../store/store.js";
import { cloneRepo } from "../discovery/repo.js";
import type { MonitorTarget } from "../types.js";

/**
 * Continuous monitoring scheduler.
 *
 * Turns QuantumVault from a one-shot scanner into a platform that re-scans
 * configured targets on a schedule, maintaining the CBOM as a living system of
 * record and surfacing drift over time. The run-logic is separated from the
 * timer so it can be exercised deterministically in tests.
 */

/** Execute a single monitor run: clone (git) or re-scan (path), then record. */
export async function runMonitorOnce(monitor: MonitorTarget): Promise<void> {
  const ranAt = new Date();
  try {
    if (monitor.kind === "git") {
      const cloned = await cloneRepo(monitor.target, 120_000);
      try {
        const { job } = store.runScan(cloned.dir, cloned.label, monitor.orgId, monitor.id);
        store.recordMonitorRun(monitor.id, { scanId: job.id, status: "ok", ranAt });
      } finally {
        cloned.cleanup();
      }
    } else {
      const abs = resolve(monitor.target);
      if (!existsSync(abs)) throw new Error(`path does not exist: ${abs}`);
      const { job } = store.runScan(abs, monitor.target, monitor.orgId, monitor.id);
      store.recordMonitorRun(monitor.id, { scanId: job.id, status: "ok", ranAt });
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : "scan failed";
    store.recordMonitorRun(monitor.id, { scanId: null, status: "failed", error: message, ranAt });
  }
}

/** Run every monitor due at `now`, sequentially. Returns how many ran. */
export async function runDueMonitors(now = new Date()): Promise<number> {
  const due = store.dueMonitors(now);
  for (const m of due) await runMonitorOnce(m);
  return due.length;
}

let timer: ReturnType<typeof setInterval> | undefined;

/** Start the background scheduler (ticks every `tickMs`). Non-overlapping. */
export function startScheduler(tickMs = 60_000): () => void {
  if (timer) return stopScheduler;
  let running = false;
  timer = setInterval(() => {
    if (running) return; // a previous tick is still working — skip this one
    running = true;
    runDueMonitors()
      .catch((err) => console.error("[scheduler] tick failed:", err))
      .finally(() => {
        running = false;
      });
  }, tickMs);
  // Don't keep the process alive solely for the scheduler.
  (timer as { unref?: () => void }).unref?.();
  console.log(`[scheduler] continuous monitoring active (tick ${Math.round(tickMs / 1000)}s)`);
  return stopScheduler;
}

export function stopScheduler(): void {
  if (timer) {
    clearInterval(timer);
    timer = undefined;
  }
}
