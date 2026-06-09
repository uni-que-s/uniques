import type { CryptoPattern } from "../types.js";

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
    description: "RSA private key PEM block",
    regex: /-----BEGIN (?:RSA )?PRIVATE KEY-----/,
    quantumVulnerable: true,
    baseSeverity: "critical",
    languages: ["pem", "config", "any"],
    pqcReplacement: "Re-issue as ML-DSA (Dilithium) signing key",
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

export function patternCount(): number {
  return PATTERNS.length;
}
