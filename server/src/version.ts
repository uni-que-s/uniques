/** Single source of truth for the tool version stamped into exports (CBOM tool
 *  metadata, OpenAPI, etc.) and reported by /api/health. 0.3.4 = qbench precision
 *  benchmark + recall/precision fixes (OpenSSH/encrypted-PKCS8/PGP-public/JWK key
 *  material now detected; PQC certs no longer mislabeled RSA). 0.3.3 = Action
 *  baseline input. 0.3.2 = CI ratchet. 0.3.1 = version visibility. 0.3.0 = ENG-01a. */
export const VERSION = "0.3.4";
