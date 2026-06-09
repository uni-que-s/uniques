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
  SOC2: [
    {
      id: "CC6.1",
      title: "Logical Access — Encryption of Data",
      description:
        "Logical access controls protect information assets with cryptography that must remain resistant to quantum attack.",
      applies: (a) => ["RSA", "ECC", "DSA", "DH"].includes(a.family),
      remediation:
        "Replace quantum-vulnerable public-key algorithms guarding protected data with NIST PQC standards (ML-KEM, ML-DSA).",
    },
    {
      id: "CC6.7",
      title: "Transmission & Movement of Information",
      description:
        "Information in transit must be protected with strong, quantum-ready encryption channels.",
      applies: (a) => a.patternId.includes("tls") || a.patternId.includes("cert") || a.family === "DH" || a.family === "ECC",
      remediation:
        "Deploy hybrid TLS (classical + ML-KEM) for transmitted data and re-issue certificates with PQC-ready signatures.",
    },
    {
      id: "CC7.1",
      title: "Detection of Vulnerable Configurations",
      description:
        "Monitoring must detect deprecated cryptographic primitives that weaken the control environment.",
      applies: (a) => a.family === "HashLegacy" || a.family === "SymmetricLegacy" || a.family === "DSA",
      remediation:
        "Retire MD5/SHA-1, DES/3DES/AES-128, and DSA; standardize on SHA-256/SHA-3, AES-256-GCM, and ML-DSA.",
    },
  ],
  "PCI-DSS": [
    {
      id: "3.5",
      title: "Protect Stored Account Data with Strong Cryptography",
      description:
        "Stored cardholder data must be rendered unreadable using cryptography that withstands quantum-capable adversaries.",
      applies: (a) => ["RSA", "ECC"].includes(a.family) || a.family === "SymmetricLegacy",
      remediation:
        "Migrate stored-data protection to AES-256-GCM and NIST PQC public-key schemes (ML-KEM/ML-DSA); retire legacy ciphers.",
    },
    {
      id: "3.6",
      title: "Cryptographic Key Management Procedures",
      description:
        "Keys protecting account data must be generated and managed with quantum-resistant key establishment.",
      applies: (a) => a.family === "DH" || a.family === "ECC" || a.family === "RSA",
      remediation:
        "Adopt ML-KEM (Kyber) for key establishment and document a PQC key-rotation plan for all cardholder-data keys.",
    },
    {
      id: "3.7",
      title: "Key Lifecycle & Retirement of Weak Keys",
      description:
        "Cryptographic keys nearing the end of their secure life, including those broken by quantum attack, must be retired.",
      applies: (a) => a.family === "DSA" || a.family === "HashLegacy" || (a.risk?.priority === "critical" || a.risk?.priority === "high"),
      remediation:
        "Retire DSA and legacy-hash keys and prioritize critical/high-risk keys for PQC re-keying within the migration window.",
    },
    {
      id: "4.2.1",
      title: "Strong Cryptography for Transmission",
      description:
        "PAN transmitted over open networks must use strong, quantum-ready cryptography and trusted certificates.",
      applies: (a) => a.patternId.includes("tls") || a.patternId.includes("cert") || a.family === "DH",
      remediation:
        "Enforce hybrid TLS (classical + ML-KEM) on all transmission paths and re-issue certificates with PQC-ready signatures.",
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

export const FRAMEWORKS: Framework[] = ["FISMA", "CISA", "FedRAMP", "SOC2", "PCI-DSS"];
