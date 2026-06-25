import type { CryptoPattern, Confidence } from "../types.js";

/**
 * Pattern database for cryptographic asset discovery.
 *
 * Each pattern targets a concrete way quantum-vulnerable cryptography shows up
 * in real source: library calls, key headers, config keys, certificate metadata.
 * Patterns are intentionally specific to keep false positives low while staying
 * language-agnostic where the API surface is shared (e.g. OpenSSL bindings).
 */
export const PATTERNS: CryptoPattern[] = [
  // ---------------------------------------------------------------- RSA
  {
    id: "rsa-keygen-openssl",
    family: "RSA",
    algorithm: "RSA",
    description: "OpenSSL/Node RSA key generation",
    regex: /\b(?:generateKeyPair(?:Sync)?|RSA\.generate|rsa_generate_key|RSA_generate_key|new RSACryptoServiceProvider)\b[\s\S]{0,40}?\b(?:rsa|RSA)?\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["javascript", "typescript", "python", "go", "java", "csharp", "c"],
    pqcReplacement: "ML-KEM (Kyber) for key exchange, ML-DSA (Dilithium) for signatures",
  },
  {
    id: "rsa-modulus-bits",
    family: "RSA",
    algorithm: "RSA",
    description: "RSA key size declaration (modulus bits)",
    regex: /\b(?:modulusLength|key_size|keySize|rsa_bits|bits)\s*[:=]\s*(512|1024|2048|3072|4096)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["javascript", "typescript", "python", "go", "java", "yaml", "json"],
    pqcReplacement: "ML-KEM (Kyber) / ML-DSA (Dilithium)",
  },
  {
    id: "rsa-pem-header",
    family: "RSA",
    algorithm: "RSA",
    description: "RSA private key PEM block (PKCS#1)",
    // PKCS#1 header is unambiguously RSA. The algorithm-agnostic PKCS#8 header
    // (`BEGIN PRIVATE KEY`, no "RSA") is handled separately so we don't label
    // EC/Ed25519/etc. keys as RSA.
    regex: /-----BEGIN RSA PRIVATE KEY-----/,
    quantumVulnerable: true,
    baseSeverity: "critical",
    languages: ["pem", "config", "any"],
    pqcReplacement: "Re-issue as ML-DSA (Dilithium) signing key",
  },
  {
    id: "pkcs8-pem-private-key",
    family: "Asymmetric",
    algorithm: "Private key (PKCS#8, algorithm unspecified)",
    description: "PKCS#8 private key PEM block — algorithm not determinable from the header",
    regex: /-----BEGIN PRIVATE KEY-----/,
    quantumVulnerable: true,
    baseSeverity: "critical",
    languages: ["pem", "config", "any"],
    pqcReplacement:
      "Identify the key's algorithm and role, then re-issue with the matching NIST PQC scheme (ML-DSA for signing, ML-KEM for key exchange)",
  },
  {
    id: "rsa-python-cryptography",
    family: "RSA",
    algorithm: "RSA",
    description: "Python cryptography/​PyCrypto RSA usage",
    regex: /\b(?:rsa\.generate_private_key|RSA\.generate|PKCS1_OAEP|rsa\.encrypt|rsa\.decrypt)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["python"],
    pqcReplacement: "ML-KEM (Kyber) / ML-DSA (Dilithium)",
  },
  {
    id: "rsa-pgp-private-block",
    family: "RSA",
    algorithm: "RSA (PGP)",
    description: "PGP/GPG private key block (commonly RSA)",
    regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/,
    quantumVulnerable: true,
    baseSeverity: "critical",
    languages: ["pem", "config", "any"],
    pqcReplacement: "Re-issue PGP identity with ML-DSA (Dilithium) once OpenPGP PQC is finalized",
  },
  {
    id: "rsa-java-keypairgen",
    family: "RSA",
    algorithm: "RSA",
    description: "Java KeyPairGenerator RSA instance",
    regex: /\bKeyPairGenerator\.getInstance\(\s*"RSA"/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["java", "kotlin", "scala"],
    pqcReplacement: "ML-KEM (Kyber) / ML-DSA (Dilithium)",
  },
  {
    id: "rsa-ruby-openssl",
    family: "RSA",
    algorithm: "RSA",
    description: "Ruby OpenSSL RSA key construction",
    regex: /\bOpenSSL::PKey::RSA\.new\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["ruby"],
    pqcReplacement: "ML-KEM (Kyber) / ML-DSA (Dilithium)",
  },
  {
    id: "rsa-php-openssl",
    family: "RSA",
    algorithm: "RSA",
    description: "PHP openssl_pkey_new RSA key generation",
    regex: /\bopenssl_pkey_new\b[\s\S]{0,80}?\bOPENSSL_KEYTYPE_RSA\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["php"],
    pqcReplacement: "ML-KEM (Kyber) / ML-DSA (Dilithium)",
  },
  {
    id: "rsa-rust-crate",
    family: "RSA",
    algorithm: "RSA (rsa crate)",
    description: "Rust rsa crate private-key usage",
    regex: /\bRsaPrivateKey::\w/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["rust"],
    pqcReplacement: "ML-KEM (Kyber) / ML-DSA (Dilithium)",
  },

  // ---------------------------------------------------------------- ECC
  {
    id: "ecc-curve-decl",
    family: "ECC",
    algorithm: "ECDSA/ECDH",
    description: "Elliptic-curve declaration (NIST/secp curves)",
    regex: /\b(?:secp256(?:k1|r1)|secp384r1|secp521r1|prime256v1|P-256|P-384|P-521|ec_genkey|ECDSA|ECDH)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["javascript", "typescript", "python", "go", "java", "csharp", "c", "yaml"],
    pqcReplacement: "ML-KEM (Kyber) for ECDH, ML-DSA / SLH-DSA for ECDSA",
  },
  {
    id: "ecc-ruby-openssl",
    family: "ECC",
    algorithm: "ECDSA/ECDH",
    description: "Ruby OpenSSL elliptic-curve key construction",
    regex: /\bOpenSSL::PKey::EC\.new\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["ruby"],
    pqcReplacement: "ML-KEM (Kyber) for ECDH, ML-DSA / SLH-DSA for ECDSA",
  },
  {
    id: "ecc-ed25519",
    family: "ECC",
    algorithm: "Ed25519/X25519",
    description: "Curve25519 family signature/key exchange",
    regex: /\b(?:ed25519|x25519|curve25519|nacl\.sign|crypto_sign)\b/i,
    quantumVulnerable: true,
    baseSeverity: "medium",
    languages: ["javascript", "typescript", "python", "go", "rust", "c"],
    pqcReplacement: "ML-DSA (Dilithium) signatures, ML-KEM (Kyber) key exchange",
  },

  // ---------------------------------------------------------------- DSA
  {
    id: "dsa-usage",
    family: "DSA",
    algorithm: "DSA",
    description: "Digital Signature Algorithm usage",
    regex: /\b(?:DSA_generate|dsa\.generate|new DSA|ssh-dss|DSAPrivateKey|SignatureAlgorithm\.DSA)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["javascript", "typescript", "python", "go", "java", "config"],
    pqcReplacement: "ML-DSA (Dilithium)",
  },
  {
    id: "dsa-java-keypairgen",
    family: "DSA",
    algorithm: "DSA",
    description: "Java KeyPairGenerator DSA instance",
    regex: /\bKeyPairGenerator\.getInstance\(\s*"DSA"/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["java", "kotlin", "scala"],
    pqcReplacement: "ML-DSA (Dilithium)",
  },
  {
    id: "dsa-ruby-openssl",
    family: "DSA",
    algorithm: "DSA",
    description: "Ruby OpenSSL DSA key construction",
    regex: /\bOpenSSL::PKey::DSA\.new\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["ruby"],
    pqcReplacement: "ML-DSA (Dilithium)",
  },

  // ---------------------------------------------------------------- DH
  {
    id: "dh-keyexchange",
    family: "DH",
    algorithm: "Diffie-Hellman",
    description: "Classical Diffie-Hellman key exchange",
    regex: /\b(?:createDiffieHellman|DH_generate_key|dh\.generate|DHParameterSpec|diffie[-_ ]?hellman)\b/i,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["javascript", "typescript", "python", "go", "java", "c"],
    pqcReplacement: "ML-KEM (Kyber)",
  },

  // ---------------------------------------------------------- Symmetric (Grover)
  {
    id: "sym-des-3des",
    family: "SymmetricLegacy",
    algorithm: "DES/3DES",
    description: "DES or Triple-DES symmetric cipher",
    regex: /\b(?:des-ede3|des3|3des|DESede|Cipher\.DES|TripleDES|createCipher(?:iv)?\(\s*['"]des)/i,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["javascript", "typescript", "python", "go", "java", "csharp"],
    pqcReplacement: "AES-256 (Grover only halves the security level)",
  },
  {
    id: "sym-aes128",
    family: "SymmetricLegacy",
    algorithm: "AES-128",
    description: "AES-128 (Grover reduces to ~64-bit security)",
    regex: /\b(?:aes-128-(?:cbc|gcm|ctr)|AES128|aes_128)\b/i,
    quantumVulnerable: true,
    baseSeverity: "medium",
    languages: ["javascript", "typescript", "python", "go", "java", "yaml"],
    pqcReplacement: "AES-256-GCM",
  },

  // -------------------------------------------------------------- Hash (Grover)
  {
    id: "hash-md5-sha1",
    family: "HashLegacy",
    algorithm: "MD5/SHA-1",
    description: "Broken/legacy hash function",
    regex: /\b(?:createHash\(\s*['"](?:md5|sha1)['"]|hashlib\.(?:md5|sha1)|MessageDigest\.getInstance\(\s*"(?:MD5|SHA-1)"|md5sum)\b/i,
    quantumVulnerable: true,
    baseSeverity: "medium",
    languages: ["javascript", "typescript", "python", "java"],
    pqcReplacement: "SHA-256 / SHA-3",
  },

  // ------------------------------------------------------------------ TLS / certs
  {
    id: "tls-rsa-cert",
    family: "RSA",
    algorithm: "RSA (X.509)",
    description: "X.509 certificate signed with RSA",
    regex: /\b(?:sha256WithRSAEncryption|sha1WithRSAEncryption|signatureAlgorithm.*RSA|ssl_certificate.*\.(?:crt|pem))\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["config", "nginx", "yaml", "pem"],
    pqcReplacement: "Hybrid X.509 (ML-DSA + classical) per NIST PQC migration",
  },

  // ---------------------------------------------- additional high-confidence
  // Asymmetric private-key PEM blocks (siblings of rsa-pem-header).
  {
    id: "ecc-pem-header",
    family: "ECC",
    algorithm: "ECDSA/ECDH (EC key)",
    description: "Elliptic-curve private key PEM block",
    regex: /-----BEGIN EC PRIVATE KEY-----/,
    quantumVulnerable: true,
    baseSeverity: "critical",
    languages: ["pem", "config", "any"],
    pqcReplacement: "Re-issue as ML-DSA (Dilithium) signing key",
  },
  {
    id: "dsa-pem-header",
    family: "DSA",
    algorithm: "DSA",
    description: "DSA private key PEM block",
    regex: /-----BEGIN DSA PRIVATE KEY-----/,
    quantumVulnerable: true,
    baseSeverity: "critical",
    languages: ["pem", "config", "any"],
    pqcReplacement: "ML-DSA (Dilithium)",
  },
  // JOSE/JWT signing algorithms imply RSA (RS*/PS*) or ECDSA (ES*) keys.
  // Case-sensitive and bounded so AES256 / arbitrary IDs don't false-match.
  {
    id: "jwt-rsa-alg",
    family: "RSA",
    algorithm: "RSA (JWT RS/PS)",
    description: "JWT/JOSE RSA signing algorithm (RS/PS 256/384/512)",
    regex: /\b(?:RS|PS)(?:256|384|512)\b/,
    quantumVulnerable: true,
    baseSeverity: "medium",
    languages: ["javascript", "typescript", "python", "go", "java", "csharp", "json", "yaml"],
    pqcReplacement: "ML-DSA (Dilithium) signatures",
  },
  {
    id: "jwt-ecdsa-alg",
    family: "ECC",
    algorithm: "ECDSA (JWT ES)",
    description: "JWT/JOSE ECDSA signing algorithm (ES 256/384/512)",
    regex: /\bES(?:256|384|512)\b/,
    quantumVulnerable: true,
    baseSeverity: "medium",
    languages: ["javascript", "typescript", "python", "go", "java", "csharp", "json", "yaml"],
    pqcReplacement: "ML-DSA (Dilithium) signatures",
  },
  // Web Crypto API asymmetric algorithm identifiers.
  {
    id: "rsa-webcrypto",
    family: "RSA",
    algorithm: "RSA (Web Crypto)",
    description: "Web Crypto RSA algorithm identifier",
    regex: /\bRSA-(?:OAEP|PSS)\b|\bRSASSA-PKCS1-v1_5\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["javascript", "typescript"],
    pqcReplacement: "ML-KEM (Kyber) for encryption, ML-DSA (Dilithium) for signatures",
  },
  // SSH public-key key types embedded in IaC / config.
  {
    id: "ssh-rsa-key",
    family: "RSA",
    algorithm: "RSA (SSH)",
    description: "SSH RSA public key type",
    regex: /\bssh-rsa\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["config", "yaml", "terraform", "json", "any"],
    pqcReplacement: "Rotate to a PQC-capable SSH key (ML-DSA) once standardized",
  },
  {
    id: "ssh-ecdsa-key",
    family: "ECC",
    algorithm: "ECDSA (SSH)",
    description: "SSH ECDSA public key type",
    regex: /\becdsa-sha2-nistp(?:256|384|521)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["config", "yaml", "terraform", "json", "any"],
    pqcReplacement: "Rotate to a PQC-capable SSH key (ML-DSA) once standardized",
  },
  // Go standard-library asymmetric crypto.
  {
    id: "go-crypto-rsa",
    family: "RSA",
    algorithm: "RSA (Go crypto)",
    description: "Go crypto/rsa import or key generation",
    regex: /\bcrypto\/rsa\b|\brsa\.GenerateKey\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["go"],
    pqcReplacement: "ML-KEM (Kyber) / ML-DSA (Dilithium)",
  },

  // ---------------------------------------- runtime crypto APIs (.NET/Py/Node/Swift)
  {
    id: "rsa-dotnet",
    family: "RSA",
    algorithm: "RSA (.NET)",
    description: ".NET RSA key construction",
    regex: /\bRSA\.Create\b|\bnew RSACng\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["csharp"],
    pqcReplacement: "ML-KEM (Kyber) / ML-DSA (Dilithium)",
  },
  {
    id: "ecc-dotnet",
    family: "ECC",
    algorithm: "ECDSA (.NET)",
    description: ".NET elliptic-curve key construction",
    regex: /\bECDsa(?:Cng)?\.Create\b|\bnew ECDsaCng\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["csharp"],
    pqcReplacement: "ML-DSA (Dilithium) / SLH-DSA",
  },
  {
    id: "dsa-dotnet",
    family: "DSA",
    algorithm: "DSA (.NET)",
    description: ".NET DSA key construction",
    regex: /\bnew DSACryptoServiceProvider\b|\bDSA\.Create\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["csharp"],
    pqcReplacement: "ML-DSA (Dilithium)",
  },
  {
    id: "ecc-python",
    family: "ECC",
    algorithm: "ECDSA/ECDH (Python)",
    description: "Python cryptography elliptic-curve key generation",
    regex: /\bec\.(?:generate_private_key|derive_private_key)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["python"],
    pqcReplacement: "ML-KEM (Kyber) for ECDH, ML-DSA / SLH-DSA for ECDSA",
  },
  {
    id: "ecc-node-ecdh",
    family: "ECC",
    algorithm: "ECDH (Node)",
    description: "Node.js elliptic-curve Diffie-Hellman",
    regex: /\bcreateECDH\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["javascript", "typescript"],
    pqcReplacement: "ML-KEM (Kyber)",
  },
  {
    id: "ecc-swift-cryptokit",
    family: "ECC",
    algorithm: "ECDSA/ECDH (Swift CryptoKit)",
    description: "Swift CryptoKit NIST-curve usage (P256/P384/P521)",
    regex: /\bP(?:256|384|521)\.(?:Signing|KeyAgreement)\b/,
    quantumVulnerable: true,
    baseSeverity: "medium",
    languages: ["swift"],
    pqcReplacement: "ML-DSA (Dilithium) signatures, ML-KEM (Kyber) key agreement",
  },

  // ----------------------------- embedded C/C++ firmware crypto (mbedTLS,
  // wolfSSL/wolfCrypt, OpenSSL C API). These are the staples of automotive,
  // medical, industrial, and aerospace firmware — long-life devices where
  // RSA/ECC signed today is the canonical harvest-now-decrypt-later target.
  // Patterns are library-prefixed, so false positives stay low.
  {
    id: "rsa-mbedtls",
    family: "RSA",
    algorithm: "RSA (mbedTLS)",
    description: "mbedTLS RSA key or signature usage",
    regex: /\bmbedtls_rsa_(?:init|setup|gen_key|import|complete|pkcs1_encrypt|pkcs1_decrypt|rsassa_pss_sign|rsassa_pkcs1_v15_sign|pkcs1_verify)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["c", "cpp"],
    pqcReplacement: "ML-KEM (Kyber) for key transport, ML-DSA (Dilithium) for signatures",
  },
  {
    id: "ecc-mbedtls",
    family: "ECC",
    algorithm: "ECDSA/ECDH (mbedTLS)",
    description: "mbedTLS elliptic-curve signature or key agreement",
    regex: /\bmbedtls_(?:ecdsa_(?:sign|verify|genkey|init)|ecdh_(?:gen_public|compute_shared|init)|ecp_gen_key(?:pair)?)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["c", "cpp"],
    pqcReplacement: "ML-KEM (Kyber) for ECDH, ML-DSA / SLH-DSA for ECDSA",
  },
  {
    id: "dh-mbedtls",
    family: "DH",
    algorithm: "Diffie-Hellman (mbedTLS)",
    description: "mbedTLS finite-field Diffie-Hellman",
    regex: /\bmbedtls_dhm_(?:init|read_params|make_params|make_public|calc_secret)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["c", "cpp"],
    pqcReplacement: "ML-KEM (Kyber)",
  },
  {
    id: "rsa-wolfssl",
    family: "RSA",
    algorithm: "RSA (wolfCrypt)",
    description: "wolfSSL/wolfCrypt RSA key or signature usage",
    regex: /\bwc_(?:InitRsaKey|MakeRsaKey|RsaPublicEncrypt|RsaPrivateDecrypt|RsaSSL_Sign|RsaSSL_Verify)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["c", "cpp"],
    pqcReplacement: "ML-KEM (Kyber) for key transport, ML-DSA (Dilithium) for signatures",
  },
  {
    id: "ecc-wolfssl",
    family: "ECC",
    algorithm: "ECDSA/ECDH (wolfCrypt)",
    description: "wolfSSL/wolfCrypt elliptic-curve usage",
    regex: /\bwc_ecc_(?:init|make_key|sign_hash|verify_hash|shared_secret)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["c", "cpp"],
    pqcReplacement: "ML-KEM (Kyber) for ECDH, ML-DSA / SLH-DSA for ECDSA",
  },
  {
    id: "rsa-openssl-c",
    family: "RSA",
    algorithm: "RSA (OpenSSL C API)",
    description: "OpenSSL C-API RSA key generation",
    regex: /\b(?:EVP_PKEY_CTX_set_rsa_keygen_bits|EVP_RSA_gen|RSA_generate_key_ex)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["c", "cpp"],
    pqcReplacement: "ML-KEM (Kyber) / ML-DSA (Dilithium)",
  },
  {
    id: "ecc-openssl-c",
    family: "ECC",
    algorithm: "ECDSA/ECDH (OpenSSL C API)",
    description: "OpenSSL C-API elliptic-curve key construction",
    regex: /\b(?:EC_KEY_new_by_curve_name|EC_KEY_generate_key|EVP_EC_gen)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["c", "cpp"],
    pqcReplacement: "ML-KEM (Kyber) for ECDH, ML-DSA / SLH-DSA for ECDSA",
  },
  {
    id: "dh-openssl-c",
    family: "DH",
    algorithm: "Diffie-Hellman (OpenSSL C API)",
    description: "OpenSSL C-API finite-field Diffie-Hellman",
    regex: /\bDH_(?:generate_key|generate_parameters_ex)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["c", "cpp"],
    pqcReplacement: "ML-KEM (Kyber)",
  },
];

const KEY_BITS_RE = /\b(512|768|1024|2048|3072|4096|256|384|521|128)\b/;

/** Best-effort key-size extraction from the matched line. */
export function extractKeyBits(line: string, family: string): number | null {
  const m = line.match(KEY_BITS_RE);
  if (!m) return null;
  const bits = Number(m[1]);
  // Curve sizes (256/384/521) only meaningful for ECC.
  if (family === "ECC") return [256, 384, 521].includes(bits) ? bits : null;
  if (family === "RSA" || family === "DSA" || family === "DH") {
    return [512, 768, 1024, 2048, 3072, 4096].includes(bits) ? bits : null;
  }
  return [128, 256].includes(bits) ? bits : null;
}

/**
 * Detection confidence per pattern: how strongly a match implies actual crypto
 * USAGE versus a mention (a name/number in a string, enum, doc, or config token).
 * Regex sees text, not call-sites, so name/enum matchers are down-ranked. Patterns
 * not listed default to "high" — they match a library call-site or key material
 * (e.g. `mbedtls_rsa_gen_key(`, `KeyPairGenerator.getInstance("RSA")`, a PEM block).
 */
const PATTERN_CONFIDENCE: Record<string, Confidence> = {
  // "low" = possible mention: fires on the bare algorithm name/number anywhere
  // (a JWT alg in an enum, a curve name in a doc, `bits = 2048` on any variable).
  // Excluded from the posture grade and the headline count; surfaced for review.
  "ecc-curve-decl": "low",
  "ecc-ed25519": "low",
  "rsa-modulus-bits": "low",
  "jwt-rsa-alg": "low",
  "jwt-ecdsa-alg": "low",
  // "medium" = a name/config token that is usually real but can be a mention.
  "ssh-rsa-key": "medium",
  "ssh-ecdsa-key": "medium",
  "dsa-usage": "medium",
  "dh-keyexchange": "medium",
  "sym-des-3des": "medium",
  "sym-aes128": "medium",
  "hash-md5-sha1": "medium",
  "tls-rsa-cert": "medium",
};

/** Detection confidence for a finding, by the pattern that matched it. */
export function confidenceFor(patternId: string): Confidence {
  return PATTERN_CONFIDENCE[patternId] ?? "high";
}

export function patternCount(): number {
  return PATTERNS.length;
}
