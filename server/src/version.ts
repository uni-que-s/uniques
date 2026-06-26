/** Single source of truth for the tool version stamped into exports (CBOM tool
 *  metadata, OpenAPI, etc.) and reported by /api/health. 0.3.1 = version
 *  visibility + provenance (running version in /health and the dashboard,
 *  stamped on the assessment report). 0.3.0 = per-occurrence context classifier
 *  (ENG-01a). 0.2.5 = per-finding confidence score. */
export const VERSION = "0.3.1";
