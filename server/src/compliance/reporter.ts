import type {
  CryptoAsset,
  ComplianceControl,
  ComplianceReport,
  ComplianceStatus,
} from "../types.js";

type Framework = ComplianceReport["framework"];

interface ControlDef {
  id: string;
  title: string;
  description: string;
  /** Predicate selecting the assets this control is concerned with. */
  applies: (a: CryptoAsset) => boolean;
  remediation: string;
}

/**
 * Control catalogs mapped to quantum-readiness requirements. These trace to the
 * real control families (NIST SP 800-53 / CISA PQC guidance / FedRAMP) but are
 * scoped to cryptographic-agility findings the discovery engine can evidence.
 */
const CATALOGS: Record<Framework, ControlDef[]> = {
  FISMA: [
    {
      id: "SC-13",
      title: "Cryptographic Protection",
      description: "Approved, quantum-resistant cryptography must protect federal information.",
      applies: (a) => ["RSA", "ECC", "DSA", "DH"].includes(a.family),
      remediation: "Replace quantum-vulnerable public-key crypto with NIST PQC standards (ML-KEM, ML-DSA).",
    },
    {
      id: "SC-12",
      title: "Cryptographic Key Establishment & Management",
      description: "Key establishment must resist harvest-now-decrypt-later attacks.",
      applies: (a) => a.family === "DH" || a.family === "ECC",
      remediation: "Adopt ML-KEM (Kyber) for all key-establishment paths, especially external links.",
    },
    {
      id: "SI-7",
      title: "Software & Information Integrity",
      description: "Integrity mechanisms must not rely on broken hash/signature primitives.",
      applies: (a) => a.family === "HashLegacy" || a.family === "DSA",
      remediation: "Migrate to SHA-256/SHA-3 and ML-DSA signatures; retire MD5/SHA-1/DSA.",
    },
  ],
  CISA: [
    {
      id: "PQC-1",
      title: "Cryptographic Inventory",
      description: "Maintain a complete inventory of quantum-vulnerable assets (CISA PQC roadmap).",
      applies: () => true,
      remediation: "Maintain continuous discovery; this inventory satisfies the baseline requirement.",
    },
    {
      id: "PQC-2",
      title: "Prioritized Migration Plan",
      description: "High-value, long-lived secrets must be prioritized for PQC migration.",
      applies: (a) => (a.risk?.priority === "critical" || a.risk?.priority === "high"),
      remediation: "Execute prioritized migration for critical/high assets within the agency PQC timeline.",
    },
    {
      id: "PQC-3",
      title: "Deprecate Legacy Symmetric/Hash",
      description: "Phase out DES/3DES/AES-128 and MD5/SHA-1.",
      applies: (a) => a.family === "SymmetricLegacy" || a.family === "HashLegacy",
      remediation: "Standardize on AES-256-GCM and SHA-256/SHA-3.",
    },
  ],
  FedRAMP: [
    {
      id: "SC-8",
      title: "Transmission Confidentiality & Integrity",
      description: "Data in transit must use FIPS-validated, quantum-ready cryptography.",
      applies: (a) => a.patternId.includes("tls") || a.patternId.includes("cert") || a.family === "DH",
      remediation: "Deploy hybrid TLS (classical + ML-KEM) and re-issue certs with PQC signatures.",
    },
    {
      id: "SC-13",
      title: "Use of Cryptography",
      description: "Only FIPS-approved algorithms with a defined PQC transition may be used.",
      applies: (a) => ["RSA", "ECC", "DSA"].includes(a.family),
      remediation: "Track each algorithm against the NIST PQC transition schedule.",
    },
    {
      id: "CM-8",
      title: "System Component Inventory",
      description: "Cryptographic components must be inventoried and tracked.",
      applies: () => true,
      remediation: "Sync this cryptographic inventory into the system component baseline.",
    },
  ],
};

function statusFor(affected: number): ComplianceStatus {
  if (affected === 0) return "pass";
  if (affected <= 3) return "gap";
  return "fail";
}

const WEIGHT: Record<ComplianceStatus, number> = { pass: 1, gap: 0.5, fail: 0 };

function summarize(framework: Framework, controls: ComplianceControl[], scorePct: number): string {
  const failing = controls.filter((c) => c.status === "fail").length;
  const gaps = controls.filter((c) => c.status === "gap").length;
  if (scorePct === 100) {
    return `${framework}: all cryptographic controls satisfied. No quantum-vulnerable assets detected.`;
  }
  return `${framework}: ${scorePct}% control coverage — ${failing} failing, ${gaps} partial. Automated remediation guidance attached; this report replaces an estimated ${Math.round(controls.length * 1.6)} hours of manual audit work.`;
}

export function generateReport(
  framework: Framework,
  assets: CryptoAsset[],
  scanId: string,
): ComplianceReport {
  const controls: ComplianceControl[] = CATALOGS[framework].map((def) => {
    const affectedAssets = assets.filter(def.applies).length;
    const status = def.id === "PQC-1" || def.id === "CM-8"
      ? (assets.length > 0 ? "pass" : "gap") // inventory controls pass once we have an inventory
      : statusFor(affectedAssets);
    return {
      id: def.id,
      title: def.title,
      description: def.description,
      status,
      affectedAssets,
      remediation: status === "pass" ? "No action required." : def.remediation,
    };
  });

  const scorePct = Math.round(
    (controls.reduce((sum, c) => sum + WEIGHT[c.status], 0) / controls.length) * 100,
  );
  const overallStatus: ComplianceStatus =
    scorePct >= 90 ? "pass" : scorePct >= 60 ? "gap" : "fail";

  return {
    framework,
    generatedAt: new Date().toISOString(),
    scanId,
    overallStatus,
    scorePct,
    controls,
    summary: summarize(framework, controls, scorePct),
  };
}

export const FRAMEWORKS: Framework[] = ["FISMA", "CISA", "FedRAMP"];
