/**
 * qbench — the QuantumVault precision benchmark corpus.
 *
 * A labeled set of source snippets that pins down what "precise detection" means
 * for this product: real cryptographic USES that must fire as actionable
 * exposure (high/medium confidence), and traps — crypto names in comments,
 * prose, identifiers, quantum-safe algorithms, enums — that must NOT count as
 * exposure (clean, or surfaced only as low-confidence "possible mentions").
 *
 * The harness (qbench.test.ts) scans every case and scores precision/recall over
 * *actionable* findings (the numbers a buyer sees), gating regressions. This is
 * the "more precise on every build" contract: the engine must keep getting every
 * case right, and new precision work adds cases here.
 *
 * `expect` lists the patternIds that must fire as ACTIONABLE. An empty array
 * means the case must produce NO exposure. Cases the engine does NOT yet get
 * right live in KNOWN_GAPS (below) — the precision worklist, tracked but not
 * gated, so a clean 1.0 gate stays honest.
 */
export interface QCase {
  id: string;
  ext: string;
  code: string;
  expect: string[];
  why: string;
  /** For KNOWN_GAPS only: "fp" = should be clean but the engine over-flags;
   *  "fn" = a real use the engine misses. Lets the gaps check detect a resolved
   *  gap without coupling to a specific (future) patternId. */
  gapKind?: "fp" | "fn";
}

export const QBENCH: QCase[] = [
  // ─────────────────────────────── real uses (must fire as actionable) ──────
  { id: "node-rsa-keygen", ext: "ts", expect: ["rsa-keygen-openssl"], why: "Node RSA key generation call-site",
    code: `const key = generateKeyPairSync("rsa", { modulusLength: 2048 });\n` },
  { id: "node-ecdh", ext: "ts", expect: ["ecc-node-ecdh"], why: "Node ECDH call-site",
    code: `const ecdh = createECDH("prime256v1");\n` },
  { id: "node-dh", ext: "ts", expect: ["dh-keyexchange"], why: "classical Diffie-Hellman call-site",
    code: `const dh = createDiffieHellman(2048);\n` },
  { id: "py-rsa", ext: "py", expect: ["rsa-python-cryptography"], why: "Python cryptography RSA",
    code: `priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n` },
  { id: "py-ecc", ext: "py", expect: ["ecc-python"], why: "Python cryptography EC keygen",
    code: `k = ec.generate_private_key(ec.SECP256R1())\n` },
  { id: "java-rsa", ext: "java", expect: ["rsa-java-keypairgen"], why: "Java KeyPairGenerator RSA",
    code: `KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");\n` },
  { id: "java-dsa", ext: "java", expect: ["dsa-java-keypairgen"], why: "Java KeyPairGenerator DSA",
    code: `KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");\n` },
  { id: "dotnet-rsa", ext: "cs", expect: ["rsa-dotnet"], why: ".NET RSA.Create",
    code: `var r = RSA.Create(2048);\n` },
  { id: "go-rsa", ext: "go", expect: ["go-crypto-rsa"], why: "Go crypto/rsa import",
    code: `import "crypto/rsa"\n` },
  { id: "swift-p256", ext: "swift", expect: ["ecc-swift-cryptokit"], why: "Swift CryptoKit P256",
    code: `let key = P256.Signing.PrivateKey()\n` },
  { id: "mbedtls-rsa", ext: "c", expect: ["rsa-mbedtls"], why: "mbedTLS firmware RSA keygen",
    code: `mbedtls_rsa_gen_key(&ctx, rng, NULL, 2048, 65537);\n` },
  { id: "wolfssl-ecc", ext: "c", expect: ["ecc-wolfssl"], why: "wolfCrypt ECC keygen",
    code: `wc_ecc_make_key(&rng, 32, &eccKey);\n` },
  { id: "openssl-c-dh", ext: "c", expect: ["dh-openssl-c"], why: "OpenSSL C-API DH (param-gen form, single pattern)",
    code: `DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, NULL);\n` },
  { id: "rsa-pem", ext: "pem", expect: ["rsa-pem-header"], why: "PKCS#1 RSA private key block",
    code: `-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\n` },
  { id: "ec-pem", ext: "pem", expect: ["ecc-pem-header"], why: "EC private key block",
    code: `-----BEGIN EC PRIVATE KEY-----\nMIIabc\n-----END EC PRIVATE KEY-----\n` },
  { id: "pkcs8-pem", ext: "pem", expect: ["pkcs8-pem-private-key"], why: "PKCS#8 key (algorithm unspecified)",
    code: `-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----\n` },
  { id: "webcrypto-rsa", ext: "ts", expect: ["rsa-webcrypto"], why: "Web Crypto RSA-OAEP as a tight identifier string",
    code: `const algo = { name: "RSA-OAEP", hash: "SHA-256" };\n` },
  { id: "ssh-rsa-quoted", ext: "yaml", expect: ["ssh-rsa-key"], why: "SSH RSA key as a quoted multi-word config value (v0.3.2 fix)",
    code: `admin_key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDx root@bastion"\n` },
  { id: "ssh-ecdsa-quoted", ext: "yaml", expect: ["ssh-ecdsa-key"], why: "SSH ECDSA key as a quoted config value",
    code: `node_key: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAy deploy@host"\n` },
  { id: "cipher-list", ext: "yaml", expect: ["sym-aes128"], why: "OpenSSL cipher list (multi-token, no prose) must still count",
    code: `ciphers: "ECDHE-RSA-AES128-GCM-SHA256 DHE-RSA-AES128-GCM-SHA256 AES128-SHA"\n` },
  { id: "tls-rsa-cert", ext: "conf", expect: ["tls-rsa-cert"], why: "X.509 RSA signature algorithm",
    code: `signature_algorithm = sha256WithRSAEncryption\n` },
  { id: "dh-in-template", ext: "ts", expect: ["dh-keyexchange"], why: "real DH call inside a template interpolation (v0.3.2 fix)",
    code: "const q = `rotate ${createDiffieHellman(2048)} keys now`;\n" },
  { id: "same-line-prose-and-call", ext: "ts", expect: ["dh-keyexchange"], why: "a real call sharing a line with a prose mention (v0.3.2 fix)",
    code: `logger.info("rotating the diffie-hellman params now please"); createDiffieHellman(2048);\n` },

  // ─────────────────────────────── traps (must NOT count as exposure) ───────
  { id: "prose-migration", ext: "ts", expect: [], why: "prose naming primitives → possible mentions, not exposure",
    code: `const note = "we are migrating away from diffie-hellman and 3DES this quarter";\n` },
  { id: "comment-only", ext: "ts", expect: [], why: "crypto only in comments → masked",
    code: `// historical: used RSA, ECDSA, and mbedtls_rsa_gen_key here\nexport const X = 1;\n` },
  { id: "aes256-ok", ext: "ts", expect: [], why: "AES-256 is quantum-OK; identifiers ending in 256 must not fire",
    code: `const c = "aes-256-gcm";\nconst k = WINDOWS256;\n` },
  { id: "sha256-ok", ext: "ts", expect: [], why: "SHA-256 is not a legacy hash",
    code: `const h = createHash("sha256");\n` },
  { id: "jwt-enum-mention", ext: "ts", expect: [], why: "JWT alg enum is a low-confidence mention, not exposure",
    code: `export const SUPPORTED = ["RS256", "ES256"];\n` },
  { id: "ed25519-comment", ext: "py", expect: [], why: "ed25519 + rsa keygen only in a comment",
    code: `# migrate the ed25519 and rsa.generate_private_key path\nVALUE = 2\n` },
  { id: "doc-string-rsa", ext: "ts", expect: [], why: "prose doc string mentioning RSA/bits, no construction",
    code: `const help = "Generate an RSA key with at least 3072 bits for safety.";\n` },
  { id: "identifier-ecdsa", ext: "ts", expect: [], why: "ECDSA inside a camelCase identifier must not match (no word boundary, case-sensitive)",
    code: `let ecdsaSignature = computeSomething();\n` },
  { id: "baseline-file", ext: "json", expect: [], why: "a committed qbench/baseline-style file of opaque fingerprints must not self-trip",
    code: `{ "tool": "QuantumVault", "fingerprints": ["6ff5962fb4ff422d", "a1b2c3d4e5f60718"] }\n` },
  { id: "aes256-cipher-list", ext: "yaml", expect: [], why: "a modern cipher list (AES-256 only) is not exposure",
    code: `ciphers: "ECDHE-RSA-AES256-GCM-SHA384 ECDHE-ECDSA-AES256-GCM-SHA384"\n` },

  // ── v0.3.4: key-material recall fixes (were false negatives; now detected) ──
  { id: "openssh-private-key", ext: "pem", expect: ["openssh-pem-private-key"], why: "OpenSSH-format private key (default ssh-keygen output) — was missed",
    code: `-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAA\n-----END OPENSSH PRIVATE KEY-----\n` },
  { id: "encrypted-pkcs8", ext: "pem", expect: ["pkcs8-encrypted-pem"], why: "encrypted PKCS#8 key — was missed (ENCRYPTED keyword slipped past plain PKCS#8)",
    code: `-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG\n-----END ENCRYPTED PRIVATE KEY-----\n` },
  { id: "pgp-public", ext: "pem", expect: ["pgp-public-block"], why: "PGP public key block — was missed (only the private block was caught)",
    code: `-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQENBFexamplepublickeyblockdata\n=AbCd\n-----END PGP PUBLIC KEY BLOCK-----\n` },
  { id: "jwk-rsa", ext: "json", expect: ["jwk-asymmetric-key"], why: "JWK RSA key material — was missed (no kty pattern)",
    code: `{ "kty": "RSA", "use": "sig", "n": "0vx7agoebGcQ", "e": "AQAB", "kid": "k1" }\n` },

  // ── v0.3.4: PQC certs must NOT be flagged RSA (tls-rsa-cert greedy/path fix) ──
  { id: "pqc-cert-mldsa", ext: "yaml", expect: [], why: "a PQC ML-DSA signatureAlgorithm line must not be mislabeled RSA (greedy .*RSA fix)",
    code: `signatureAlgorithm: ML-DSA-65, fallbackName: RSA-PSS-disabled\n` },
  { id: "pqc-cert-path", ext: "conf", expect: [], why: "an ssl_certificate path carries no algorithm — must not assert RSA (path-arm dropped)",
    code: `ssl_certificate /etc/ssl/pqc/dilithium.pem;\n` },

  // ── v0.3.4: probe-confirmed correct behavior — regression guards ────────────
  { id: "guard-pqc-safe", ext: "py", expect: [], why: "PQC algorithms (SLH-DSA/Falcon/Kyber) are quantum-safe and must never be flagged",
    code: `pk = SLH_DSA_SHA2_128s.keygen()\nf = Falcon512.sign(m)\nk = Kyber768.encap()\n` },
  { id: "guard-prose-tripledes", ext: "ts", expect: [], why: "a 3-word prose string with stopwords is correctly a low mention (pairs with the gap-short-string FP)",
    code: `const err = report("TripleDES is not supported here");\n` },
  { id: "guard-forge-rsa", ext: "js", expect: ["rsa-keygen-openssl"], why: "node-forge RSA keygen is correctly caught (camelCase generateKeyPair path)",
    code: `const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });\n` },
  { id: "guard-enc-ec-pem", ext: "pem", expect: ["ecc-pem-header"], why: "encrypted EC key keeps its typed header; the AES-256-CBC DEK line is correctly not exposure",
    code: `-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,B2F8\nMIHexample\n-----END EC PRIVATE KEY-----\n` },

  // ── v0.3.5: label / message / identifier mentions no longer count as exposure
  //    (mention classifier = natural-language word in a >=2-word string;
  //     sym-des-3des gained a trailing word boundary)
  { id: "mention-label-3des", ext: "ts", expect: [], why: "a 2-word label string ('3DES weak') is a mention, not a use",
    code: `const label = "3DES weak";\n` },
  { id: "mention-toast-dh", ext: "ts", expect: [], why: "a UI/error string with no stopword ('Diffie-Hellman handshake failed') is a mention",
    code: `const toast = "Diffie-Hellman handshake failed";\n` },
  { id: "mention-banner-aes128", ext: "ts", expect: [], why: "a status string ('AES128 disabled') is a mention",
    code: `const banner = "AES128 disabled";\n` },
  { id: "mention-errmsg-dss", ext: "ts", expect: [], why: "a log/error string ('ssh-dss key rejected') is a mention",
    code: `const errmsg = "ssh-dss key rejected";\n` },
  { id: "identifier-class-3des", ext: "ts", expect: [], why: "a class name carrying a token (TripleDESLegacyAdapter) is not a cipher use (trailing-\\b fix)",
    code: `class TripleDESLegacyAdapter {}\n` },
  { id: "identifier-envvar-3des", ext: "ts", expect: [], why: "an env-var name (TRIPLEDES_FALLBACK_DISABLED) is not a cipher use (trailing-\\b fix)",
    code: `const v = process.env.TRIPLEDES_FALLBACK_DISABLED;\n` },

  // ── v0.3.6: recall expansion — real uses/formats that were silently missed ──
  { id: "go-ecdsa-keygen", ext: "go", expect: ["go-ecdsa"], why: "Go ECDSA key generation — was missed (only crypto/rsa was covered)",
    code: `k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)\n` },
  { id: "go-dsa-keygen", ext: "go", expect: ["go-dsa"], why: "Go DSA key generation (capital-G GenerateKey) — was missed (case-sensitive dsa-usage)",
    code: `dsa.GenerateKey(priv, rand.Reader)\n` },
  { id: "evp-pkey-keygen", ext: "c", expect: ["evp-pkey-keygen"], why: "OpenSSL 3.x generic EVP_PKEY_keygen entry point — was missed",
    code: `EVP_PKEY_keygen(ctx, &pkey);\n` },
  { id: "webcrypto-ecdsa", ext: "ts", expect: ["ecc-webcrypto"], why: "Web Crypto ECDSA generateKey call — was only flagged low via the bare curve name",
    code: `crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);\n` },
  { id: "x509-cert", ext: "pem", expect: ["x509-cert-body"], why: "a deployed X.509 certificate body (RSA/ECC public key + signature) — was missed",
    code: `-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBa\n-----END CERTIFICATE-----\n` },

  // ── v0.3.7: overlapping-pattern double-counts collapsed + PKCS#12 detected ──
  { id: "dh-single-count", ext: "c", expect: ["dh-openssl-c"], why: "DH_generate_key now fires only dh-openssl-c (removed from dh-keyexchange) — one finding, not two",
    code: `DH_generate_key(dh);\n` },
  { id: "java-keygen-single-count", ext: "java", expect: ["rsa-java-keypairgen"], why: "chained getInstance('RSA').generateKeyPair() now fires only rsa-java-keypairgen (java dropped from rsa-keygen-openssl)",
    code: `KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();\n` },
  { id: "pkcs12-decode", ext: "go", expect: ["pkcs12-keystore"], why: "a PKCS#12 keystore (.pfx/pkcs12.Decode) bundling a private key + cert — was missed",
    code: `pkcs12.Decode(data, "changeit")\n` },

  // ── v0.3.8: route/URL slugs and disable directives no longer count as exposure
  //    (path/URL classifier + disable-directive override of never-downgrade) ──
  { id: "route-slug-dh", ext: "ts", expect: [], why: "a REST route string ('/api/v2/diffie-hellman/rotate') names an endpoint — a path slug, not a DH use",
    code: `const route = "/api/v2/diffie-hellman/rotate";\n` },
  { id: "url-slug-dh", ext: "ts", expect: [], why: "a URL with a crypto path segment ('https://host/v2/diffie-hellman/rotate') is an endpoint, not a DH use (:// branch)",
    code: `const url = "https://api.example.com/v2/diffie-hellman/rotate";\n` },
  { id: "route-slug-single-segment", ext: "ts", expect: [], why: "a single-segment route ('/diffie-hellman') is still a route slug, not a DH use (leading-slash branch, any segment count)",
    code: `router.get("/diffie-hellman", rotateParams);\n` },
  { id: "path-keymaterial-stays", ext: "json", expect: ["ssh-rsa-key"], why: "key material named in a path ('/keys/ssh-rsa/import') is NOT downgraded — never-downgrade wins over the path rule",
    code: `{ "callback": "/keys/ssh-rsa/import/v2" }\n` },
  { id: "denylist-disabled", ext: "json", expect: [], why: "a config that DISABLES key types ('ssh-rsa': false) is remediation, not exposure (overrides never-downgrade)",
    code: `{ "ssh-rsa": false, "ecdsa-sha2-nistp256": false }\n` },
  { id: "yaml-disable-unquoted", ext: "yaml", expect: [], why: "an unquoted YAML disable directive (ssh-rsa: false) — a bare-token key, not in a string span — still downgrades",
    code: `ssh-rsa: false\n` },
  // recall guards: the disable/path rules must not over-downgrade real exposure
  { id: "guard-allowlist-enables", ext: "json", expect: ["ssh-rsa-key"], why: "allow-listing a weak key type (value position, not a disabled key) is real exposure and must still fire",
    code: `{ "allowedKeyTypes": ["ssh-rsa", "ed25519"] }\n` },
  { id: "guard-config-enabled-true", ext: "json", expect: ["ssh-rsa-key"], why: "an ENABLED weak key type ('ssh-rsa': true) is not a disable directive and must still fire",
    code: `{ "ssh-rsa": true }\n` },
];

/**
 * KNOWN_GAPS — cases the engine does NOT yet handle correctly. These are the
 * precision worklist (mostly ENG-01b / option-3 targets), tracked but NOT gated,
 * so the QBENCH gate stays an honest 1.0. `expect` is the CORRECT behavior; the
 * informational qbench-gaps check reports which are still open and flags any that
 * have been resolved (promote those into QBENCH). Add a gap here whenever the
 * benchmark or an adversarial probe surfaces a real precision miss.
 */
export const KNOWN_GAPS: QCase[] = [
  // ── false positive the lexical classifier genuinely can't resolve ──
  // (resolved in v0.3.5 and promoted into QBENCH: short label strings, no-stopword
  //  messages, and identifier-substring matches — see mention-*/identifier-* cases)
  // (resolved in v0.3.8 and promoted into QBENCH: URL/route path slugs and
  //  disable-directive config keys — see route-slug-*/denylist-*/yaml-algo-off)
  { id: "gap-enum-ref-dsa", ext: "ts", expect: [], gapKind: "fp",
    why: "reading an enum member (SignatureAlgorithm.DSA) is a reference, not a signing operation — needs call-vs-reference data flow (ENG-01b / tree-sitter AST, the locked-last rung)",
    code: `const x = SignatureAlgorithm.DSA;\n` },
  { id: "gap-windows-path-dh", ext: "py", expect: [], gapKind: "fp",
    why: "a Windows backslash path naming a primitive is a path reference, not a use — the path classifier covers POSIX '/' and '://' but not backslash paths (rarer, and '\\' is escape-ambiguous in source); deferred",
    code: `PARAMS_FILE = "C:\\\\certs\\\\diffie-hellman.pem"\n` },
  // (resolved in v0.3.7 and promoted into QBENCH / a dedicated test: the two
  //  overlapping-pattern double-counts, PKCS#12 keystores, and the
  //  authorized_keys/known_hosts no-extension filename gate)
];
