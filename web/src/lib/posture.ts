import type { Dashboard } from "./api";

export type Grade = "A" | "B" | "C" | "D" | "F";

export interface Posture {
  score: number; // 0–100 composite
  grade: Grade;
  label: string;
  narrative: string;
  color: string;
}

export const GRADE_COLOR: Record<Grade, string> = {
  A: "#34d399",
  B: "#22d3ee",
  C: "#facc15",
  D: "#fb923c",
  F: "#f43f5e",
};

const GRADE_LABEL: Record<Grade, string> = {
  A: "Quantum-ready",
  B: "Strong",
  C: "Moderate",
  D: "At risk",
  F: "Critical exposure",
};

function gradeFor(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

type PostureInput = Pick<
  Dashboard,
  "totalAssets" | "quantumVulnerable" | "possibleMentions" | "byPriority" | "avgCompliancePct" | "migrationProgressPct"
>;

/**
 * Transparent, explainable posture score (0–100) → letter grade, the way
 * security-rating products surface an at-a-glance verdict. It blends compliance
 * coverage and remediation progress, penalized by unmitigated critical/high
 * findings. No black box — every input is shown on the dashboard.
 */
export function computePosture(d: PostureInput): Posture {
  const mentions = d.possibleMentions ?? 0;
  if (!d.quantumVulnerable) {
    return {
      score: 100,
      grade: "A",
      label: "No exposure",
      narrative: d.totalAssets || mentions
        ? `No actionable quantum-vulnerable cryptography found${mentions ? ` — ${mentions} possible mention${mentions === 1 ? "" : "s"} flagged for review` : ""}.`
        : "No cryptographic assets discovered yet — run a scan to assess posture.",
      color: GRADE_COLOR.A,
    };
  }

  const critical = d.byPriority?.critical ?? 0;
  const high = d.byPriority?.high ?? 0;
  const severityPenalty = Math.min(100, critical * 12 + high * 4);
  const raw = 0.45 * d.avgCompliancePct + 0.3 * d.migrationProgressPct + 0.25 * (100 - severityPenalty);
  const score = Math.max(0, Math.min(100, Math.round(raw)));
  const grade = gradeFor(score);

  const priority = critical + high;
  const narrative =
    `${d.quantumVulnerable} of ${d.totalAssets} assets are quantum-vulnerable` +
    (priority ? `, ${priority} high-priority` : "") +
    (mentions ? `, ${mentions} possible mention${mentions === 1 ? "" : "s"}` : "") +
    `. ${d.migrationProgressPct}% remediated · ${d.avgCompliancePct}% avg compliance.`;

  return { score, grade, label: GRADE_LABEL[grade], narrative, color: GRADE_COLOR[grade] };
}
