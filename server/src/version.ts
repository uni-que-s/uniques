/** Single source of truth for the tool version stamped into exports (CBOM tool
 *  metadata, OpenAPI, etc.) and reported by /api/health. 0.3.3 = GitHub Action
 *  gains a `baseline` input (ratchet on new findings) + "adopt in CI" docs. 0.3.2
 *  = CI baseline / ratchet CLI. 0.3.1 = version visibility + provenance. 0.3.0 =
 *  per-occurrence context classifier (ENG-01a). 0.2.5 = per-finding confidence. */
export const VERSION = "0.3.3";
