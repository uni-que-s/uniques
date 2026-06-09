import { randomUUID } from "node:crypto";
import type { CryptoAsset, CryptoFamily } from "../types.js";

/**
 * Map our crypto families to CycloneDX cryptographic-asset algorithm
 * primitives (CycloneDX 1.6 `cryptoProperties.algorithmProperties.primitive`).
 */
const PRIMITIVE: Record<CryptoFamily, string> = {
  RSA: "pke",
  ECC: "signature",
  DSA: "signature",
  DH: "key-agree",
  SymmetricLegacy: "block-cipher",
  HashLegacy: "hash",
};

export interface CbomMeta {
  target?: string;
  generatedAt?: string;
  toolVersion?: string;
}

/**
 * Serialize discovered crypto assets to a CycloneDX 1.6 Cryptography Bill of
 * Materials (CBOM). Each finding becomes a `cryptographic-asset` component with
 * crypto properties and a source-location occurrence. Quantum-vulnerable assets
 * are reported with NIST quantum security level 0 (no security against a
 * cryptographically-relevant quantum computer). This is the interchange format
 * NIST/CISA reference for post-quantum migration inventories.
 */
export function assetsToCbom(assets: CryptoAsset[], meta: CbomMeta = {}): Record<string, unknown> {
  const components = assets.map((a) => ({
    type: "cryptographic-asset",
    "bom-ref": a.id,
    name: a.algorithm,
    cryptoProperties: {
      assetType: "algorithm",
      algorithmProperties: {
        primitive: PRIMITIVE[a.family],
        ...(a.keyBits != null ? { parameterSetIdentifier: String(a.keyBits) } : {}),
        executionEnvironment: "software-plain-ram",
        nistQuantumSecurityLevel: a.quantumVulnerable ? 0 : 1,
      },
    },
    evidence: {
      occurrences: [{ location: a.file, line: a.line }],
    },
    properties: [
      { name: "quantumvault:family", value: a.family },
      { name: "quantumvault:patternId", value: a.patternId },
      { name: "quantumvault:pqcReplacement", value: a.pqcReplacement },
      { name: "quantumvault:remediationStatus", value: a.status },
      ...(a.risk ? [{ name: "quantumvault:riskScore", value: String(a.risk.score) }] : []),
    ],
  }));

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: meta.generatedAt ?? new Date().toISOString(),
      tools: {
        components: [{ type: "application", name: "QuantumVault", version: meta.toolVersion ?? "0.1.0" }],
      },
      ...(meta.target ? { component: { type: "application", name: meta.target } } : {}),
    },
    components,
  };
}
