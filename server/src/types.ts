export type CryptoFamily =
  | "RSA"
  | "ECC"
  | "DSA"
  | "DH"
  | "SymmetricLegacy"
  | "HashLegacy";

export type Severity = "critical" | "high" | "medium" | "low";

/** Remediation lifecycle for a discovered asset. */
export type AssetStatus = "open" | "in_progress" | "migrated" | "accepted";

export const ASSET_STATUSES: AssetStatus[] = ["open", "in_progress", "migrated", "accepted"];

/** Statuses that count as "resolved" for migration-progress reporting. */
export const RESOLVED_STATUSES: AssetStatus[] = ["migrated", "accepted"];

export interface CryptoPattern {
  id: string;
  family: CryptoFamily;
  algorithm: string;
  /** Human description of what this pattern detects. */
  description: string;
  /** Regex applied per-line against source text. */
  regex: RegExp;
  /** True if broken by a sufficiently large quantum computer (Shor/Grover). */
  quantumVulnerable: boolean;
  /** Baseline severity before risk scoring context is applied. */
  baseSeverity: Severity;
  /** Languages / file kinds this pattern is meaningful for. */
  languages: string[];
  /** NIST-recommended post-quantum replacement. */
  pqcReplacement: string;
}

export interface CryptoAsset {
  id: string;
  scanId: string;
  file: string;
  line: number;
  family: CryptoFamily;
  algorithm: string;
  keyBits: number | null;
  language: string;
  snippet: string;
  patternId: string;
  quantumVulnerable: boolean;
  pqcReplacement: string;
  /** Remediation status, defaults to "open" when an asset is first discovered. */
  status: AssetStatus;
  /** Filled in by the risk scoring service. */
  risk?: RiskScore;
}

export interface RiskFactorBreakdown {
  dataSensitivity: number;
  retentionExposure: number;
  hndlExposure: number;
  complianceImpact: number;
  businessImpact: number;
}

export interface RiskScore {
  score: number; // 0-100
  priority: Severity;
  factors: RiskFactorBreakdown;
  recommendation: string;
  migrationEffortDays: number;
}

export interface ScanJob {
  id: string;
  target: string;
  startedAt: string;
  finishedAt: string;
  filesScanned: number;
  durationMs: number;
  assetCount: number;
  status: "completed" | "running" | "failed";
}

export type ComplianceStatus = "pass" | "gap" | "fail";

export interface ComplianceControl {
  id: string;
  title: string;
  description: string;
  status: ComplianceStatus;
  affectedAssets: number;
  remediation: string;
}

export interface ComplianceReport {
  framework: "FISMA" | "CISA" | "FedRAMP";
  generatedAt: string;
  scanId: string;
  overallStatus: ComplianceStatus;
  scorePct: number;
  controls: ComplianceControl[];
  summary: string;
}
