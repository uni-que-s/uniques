/** Single source of truth for the tool version stamped into exports (CBOM tool
 *  metadata, OpenAPI, etc.) and reported by /api/health. 0.3.5 = mention
 *  classifier (label/log/identifier false positives downgraded; sym-des-3des
 *  boundary fix). 0.3.4 = qbench benchmark + recall/precision fixes. 0.3.3 =
 *  Action baseline input. 0.3.2 = CI ratchet. 0.3.1 = version visibility. */
export const VERSION = "0.3.5";
