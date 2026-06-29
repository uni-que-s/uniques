/** Single source of truth for the tool version stamped into exports (CBOM tool
 *  metadata, OpenAPI, etc.) and reported by /api/health. 0.3.6 = recall expansion
 *  (Go ECDSA/DSA, OpenSSL EVP_PKEY_keygen, Web Crypto ECDSA, X.509 cert bodies;
 *  43→52 patterns over v0.3.4-6). 0.3.5 = mention classifier. 0.3.4 = qbench
 *  benchmark. 0.3.3 = Action baseline. 0.3.2 = CI ratchet. 0.3.1 = version vis. */
export const VERSION = "0.3.6";
