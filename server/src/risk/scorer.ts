import type { CryptoAsset, RiskScore, RiskFactorBreakdown, Severity } from "../types.js";

/**
 * 5-factor weighted risk model.
 *
 * Each factor is scored 0-100, then combined with the weights below. The result
 * prioritizes assets for post-quantum migration. Weights sum to 1.0 and reflect
 * that "harvest-now-decrypt-later" (HNDL) exposure and data sensitivity dominate
 * the urgency of migration for long-lived secrets.
 *
 * Weights are tunable per deployment via the QV_RISK_WEIGHTS environment
 * variable (a JSON object of any subset of these keys); provided values are
 * merged over the defaults and normalized to sum to 1.0, so a sector can
 * calibrate the model to its risk appetite without code changes.
 */
export interface RiskWeights {
  dataSensitivity: number;
  retentionExposure: number;
  hndlExposure: number;
  complianceImpact: number;
  businessImpact: number;
}

export const DEFAULT_WEIGHTS: RiskWeights = {
  dataSensitivity: 0.25,
  retentionExposure: 0.2,
  hndlExposure: 0.25,
  complianceImpact: 0.2,
  businessImpact: 0.1,
};

let cacheKey: string | undefined;
let cached: RiskWeights = DEFAULT_WEIGHTS;

function parseWeights(raw: string): RiskWeights {
  try {
    const obj = JSON.parse(raw) as Partial<Record<keyof RiskWeights, unknown>>;
    const merged: RiskWeights = { ...DEFAULT_WEIGHTS };
    for (const k of Object.keys(DEFAULT_WEIGHTS) as (keyof RiskWeights)[]) {
      const v = obj[k];
      if (typeof v === "number" && Number.isFinite(v) && v >= 0) merged[k] = v;
    }
    const sum = Object.values(merged).reduce((a, b) => a + b, 0);
    if (sum <= 0) return DEFAULT_WEIGHTS;
    for (const k of Object.keys(merged) as (keyof RiskWeights)[]) merged[k] = merged[k] / sum;
    return merged;
  } catch {
    return DEFAULT_WEIGHTS;
  }
}

/**
 * Active risk weights: the defaults, optionally overridden by QV_RISK_WEIGHTS
 * (JSON) and normalized to sum to 1.0. Invalid input falls back to the defaults.
 */
export function getRiskWeights(): RiskWeights {
  const raw = process.env.QV_RISK_WEIGHTS;
  if (!raw) return DEFAULT_WEIGHTS;
  if (raw !== cacheKey) {
    cacheKey = raw;
    cached = parseWeights(raw);
  }
  return cached;
}

// Signals derived from where an asset lives. A real deployment enriches these
// from data-classification metadata; here we infer from path + algorithm.
const SENSITIVE_HINTS = ["auth", "payment", "billing", "key", "secret", "token", "settlement", "card", "ssn", "pii"];
const PARTNER_HINTS = ["partner", "gateway", "transport", "vpn", "tls", "edge", "external", "exchange"];

function pathSignal(file: string, hints: string[]): number {
  const lower = file.toLowerCase();
  let hits = 0;
  for (const h of hints) if (lower.includes(h)) hits += 1;
  return Math.min(hits, 3);
}

/** Asymmetric crypto (RSA/ECC/DSA/DH) is fully broken by Shor — max HNDL weight. */
function isShorBroken(asset: CryptoAsset): boolean {
  return ["RSA", "ECC", "DSA", "DH"].includes(asset.family);
}

function dataSensitivityScore(asset: CryptoAsset): number {
  const base = pathSignal(asset.file, SENSITIVE_HINTS) * 25;
  const pemBoost = asset.patternId.includes("pem") ? 30 : 0;
  return clamp(40 + base + pemBoost);
}

function retentionScore(asset: CryptoAsset): number {
  // Signing keys and certificates protect data with long retention windows.
  if (asset.family === "RSA" || asset.family === "DSA") return 85;
  if (asset.patternId.includes("cert") || asset.patternId.includes("pem")) return 90;
  if (asset.family === "ECC") return 70;
  return 45;
}

function hndlScore(asset: CryptoAsset): number {
  // Harvest-now-decrypt-later: key-exchange + transport crypto on partner paths
  // is the highest-urgency category — captured traffic can be decrypted later.
  if (!isShorBroken(asset)) return 35;
  const partner = pathSignal(asset.file, PARTNER_HINTS) * 20;
  const keyExchangeBoost = asset.family === "DH" || asset.family === "ECC" ? 25 : 10;
  return clamp(45 + partner + keyExchangeBoost);
}

function complianceScore(asset: CryptoAsset): number {
  // Weak hashes/ciphers and RSA certs are explicit findings under FISMA/FedRAMP.
  if (asset.family === "HashLegacy") return 75;
  if (asset.patternId.includes("cert") || asset.patternId.includes("tls")) return 80;
  if (isShorBroken(asset)) return 70;
  return 50;
}

function businessImpactScore(asset: CryptoAsset): number {
  const base = pathSignal(asset.file, SENSITIVE_HINTS) * 20;
  const keyBoost = asset.keyBits && asset.keyBits <= 1024 ? 25 : 0;
  return clamp(40 + base + keyBoost);
}

function clamp(n: number): number {
  return Math.max(0, Math.min(100, Math.round(n)));
}

function priorityFor(score: number): Severity {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  return "low";
}

function effortFor(asset: CryptoAsset, priority: Severity): number {
  const families: Record<string, number> = {
    RSA: 8,
    ECC: 6,
    DSA: 7,
    DH: 5,
    SymmetricLegacy: 3,
    HashLegacy: 2,
  };
  const base = families[asset.family] ?? 4;
  const urgencyMultiplier = priority === "critical" ? 1.5 : priority === "high" ? 1.2 : 1;
  return Math.round(base * urgencyMultiplier);
}

function recommendationFor(asset: CryptoAsset, priority: Severity): string {
  const verb = priority === "critical" ? "Immediately migrate" : priority === "high" ? "Prioritize migration of" : "Plan migration of";
  return `${verb} ${asset.algorithm} at ${asset.file}:${asset.line} to ${asset.pqcReplacement}.`;
}

export function scoreAsset(asset: CryptoAsset): RiskScore {
  const factors: RiskFactorBreakdown = {
    dataSensitivity: dataSensitivityScore(asset),
    retentionExposure: retentionScore(asset),
    hndlExposure: hndlScore(asset),
    complianceImpact: complianceScore(asset),
    businessImpact: businessImpactScore(asset),
  };

  const W = getRiskWeights();
  const score = clamp(
    factors.dataSensitivity * W.dataSensitivity +
      factors.retentionExposure * W.retentionExposure +
      factors.hndlExposure * W.hndlExposure +
      factors.complianceImpact * W.complianceImpact +
      factors.businessImpact * W.businessImpact,
  );

  const priority = priorityFor(score);
  return {
    score,
    priority,
    factors,
    recommendation: recommendationFor(asset, priority),
    migrationEffortDays: effortFor(asset, priority),
  };
}

/** Attach risk scores to a batch of assets (mutates and returns them). */
export function scoreAssets(assets: CryptoAsset[]): CryptoAsset[] {
  for (const a of assets) a.risk = scoreAsset(a);
  return assets;
}
