/** Single source of truth for the tool version stamped into exports (CBOM tool
 *  metadata, OpenAPI, etc.) and reported by /api/health. 0.4.1 = grace→read-only
 *  trial enforcement + two classifier fixes (Python-docstring FP class via
 *  triple-quote spans; Java/Kotlin JOSE-alg recall via a code-context upgrade).
 *  0.4.0 = on-prem license gate + 30-day trial (offline Ed25519 signed keys, no
 *  phone-home; the platform is gated, the free CLI is not) + one-command
 *  install.sh. 0.3.10 = enum-constant
 *  reference downgrade (qbench worklist cleared). 0.3.9 = Windows-path FP cleared +
 *  Diffie-Hellman detected on config languages. 0.3.8 = URL/route-slug +
 *  disable-directive false-positive classifiers. 0.3.7 = double-count dedupe
 *  (DH/Java) + PKCS#12 + authorized_keys filename gate. 0.3.6 = recall expansion
 *  (Go/EVP/WebCrypto/X.509). 0.3.5 = mention classifier. 0.3.4 = qbench benchmark.
 *  0.3.3 = Action baseline. 0.3.2 = CI ratchet. 0.3.1 = version vis. */
export const VERSION = "0.4.1";
