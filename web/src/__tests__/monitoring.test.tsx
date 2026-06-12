import { describe, test, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";

const sampleMonitor = {
  id: "mon_1",
  orgId: "org",
  name: "payments-api",
  kind: "git" as const,
  target: "https://github.com/acme/payments",
  intervalMinutes: 60,
  enabled: true,
  createdAt: "2026-06-11T11:00:00Z",
  lastRunAt: "2026-06-11T12:00:00Z",
  nextRunAt: "2026-06-11T13:00:00Z",
  lastScanId: "scan_1",
  lastStatus: "ok" as const,
  lastError: null,
  runCount: 3,
};

vi.mock("../lib/api", () => ({
  getMonitors: vi.fn(() => Promise.resolve([sampleMonitor])),
  getMonitor: vi.fn(() =>
    Promise.resolve({
      monitor: sampleMonitor,
      drift: { hasPrevious: true, newFindings: 2, removedFindings: 1 },
      scans: [],
    }),
  ),
  createMonitor: vi.fn(),
  setMonitorEnabled: vi.fn(),
  deleteMonitor: vi.fn(),
}));

import Monitoring from "../pages/Monitoring";

describe("Monitoring page", () => {
  test("lists a monitor with its drift and active state", async () => {
    render(<Monitoring />);
    expect(await screen.findByText("payments-api")).toBeInTheDocument();
    expect(screen.getByText("git")).toBeInTheDocument();
    expect(screen.getByText("Active")).toBeInTheDocument();
    // drift cell shows newly-introduced findings
    expect(await screen.findByText(/\+2/)).toBeInTheDocument();
  });

  test("shows an empty state when there are no monitors", async () => {
    const api = await import("../lib/api");
    (api.getMonitors as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce([]);
    render(<Monitoring />);
    expect(await screen.findByText(/No monitors yet/i)).toBeInTheDocument();
  });
});
