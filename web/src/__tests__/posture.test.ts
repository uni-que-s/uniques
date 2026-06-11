import { describe, test, expect } from "vitest";
import { computePosture } from "../lib/posture";

const base = {
  totalAssets: 0,
  quantumVulnerable: 0,
  byPriority: { critical: 0, high: 0, medium: 0, low: 0 },
  avgCompliancePct: 0,
  migrationProgressPct: 0,
};

describe("computePosture", () => {
  test("no assets → grade A (no exposure)", () => {
    const p = computePosture({ ...base });
    expect(p.grade).toBe("A");
    expect(p.score).toBe(100);
  });

  test("fully remediated + compliant → A", () => {
    const p = computePosture({
      ...base,
      totalAssets: 10,
      quantumVulnerable: 10,
      avgCompliancePct: 100,
      migrationProgressPct: 100,
    });
    expect(p.grade).toBe("A");
    expect(p.score).toBe(100);
  });

  test("many unremediated high findings + low compliance → F", () => {
    const p = computePosture({
      totalAssets: 30,
      quantumVulnerable: 30,
      byPriority: { critical: 2, high: 20, medium: 8, low: 0 },
      avgCompliancePct: 15,
      migrationProgressPct: 0,
    });
    expect(p.grade).toBe("F");
    expect(p.score).toBeLessThan(60);
    expect(p.narrative).toMatch(/quantum-vulnerable/);
  });

  test("score is clamped to 0..100 and grade boundaries hold", () => {
    const p = computePosture({
      ...base,
      totalAssets: 5,
      quantumVulnerable: 1,
      avgCompliancePct: 80,
      migrationProgressPct: 70,
    });
    expect(p.score).toBeGreaterThanOrEqual(0);
    expect(p.score).toBeLessThanOrEqual(100);
    expect(["A", "B", "C", "D", "F"]).toContain(p.grade);
  });
});
