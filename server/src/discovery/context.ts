/**
 * Per-occurrence syntactic context for a regex match — the down-payment on
 * ENG-01 (call-site precision).
 *
 * The scanner matches against a comment-masked view of a file, so a match can
 * only land in CODE or inside a STRING literal. This module tells those apart
 * and flags the specific false-positive class the pattern-level confidence model
 * can't see: a crypto name embedded in a PROSE string (a log line, an error
 * message, a doc) rather than a real cryptographic use.
 *
 * Deliberately lexical, not a parser: zero dependencies, language-agnostic, and
 * microsecond-fast — preserving the air-gapped, single-binary posture that is a
 * core selling point. True AST / call-graph analysis (ENG-01b) is a later,
 * customer-pulled step; this captures the bulk of string-mention FPs now without
 * a grammar per language.
 */

/** Languages with C-style comments: line (slash-slash) and block. */
export const C_STYLE = new Set([
  "javascript", "typescript", "c", "cpp", "csharp", "java", "kotlin", "scala", "go", "rust", "swift", "php",
]);
/** Languages whose comments are `#` line. */
export const HASH_STYLE = new Set(["python", "ruby", "yaml", "config", "terraform", "php"]);
/** Languages with triple-quoted string literals that legitimately span newlines
 *  (Python docstrings `"""…"""` / `'''…'''`, Scala/Kotlin raw strings). Without
 *  this, the single-quote tokenizer resets at the first newline and a crypto name
 *  in a docstring is misread as live code instead of a prose mention. */
export const TRIPLE_QUOTE = new Set(["python", "scala", "kotlin"]);

/** Consume a triple-quoted string starting at `k` (where the opening triple is);
 *  returns the index just past the closing triple (or end-of-content). */
export function tripleQuoteEnd(content: string, k: number, q: string): number {
  let j = k + 3;
  while (j < content.length && !(content[j] === q && content[j + 1] === q && content[j + 2] === q)) j++;
  return j < content.length ? j + 3 : content.length;
}
/** Is `content` starting a triple quote (`"""` or `'''`) at index k? */
export function tripleQuoteAt(content: string, k: number): string | null {
  const ch = content[k];
  if ((ch === '"' || ch === "'") && content[k + 1] === ch && content[k + 2] === ch) return ch;
  return null;
}

/**
 * Return the [start, end) offsets of every string-literal span in `content`,
 * sorted and non-overlapping. Spans include the surrounding quotes. Comments are
 * tracked only so a quote *inside* a comment isn't mistaken for a string; comment
 * spans themselves are not returned (the scanner never matches inside a comment —
 * those are masked to spaces before matching).
 *
 * Mirrors the tokenizer in `maskComments` (escapes, block + line comments, single
 * / double / template quotes) so the two stay consistent.
 */
export function lexStringSpans(content: string, language: string): Array<[number, number]> {
  const lineMarkers: string[] = [];
  if (C_STYLE.has(language)) lineMarkers.push("//");
  if (HASH_STYLE.has(language)) lineMarkers.push("#");
  const blockComments = C_STYLE.has(language);

  const triple = TRIPLE_QUOTE.has(language);
  const spans: Array<[number, number]> = [];
  let inBlock = false;
  let quote = "";
  let quoteStart = -1;

  for (let k = 0; k < content.length; k++) {
    const ch = content[k];
    if (inBlock) {
      if (ch === "*" && content[k + 1] === "/") { k++; inBlock = false; }
      continue;
    }
    if (quote) {
      if (ch === "\\") { k++; continue; }          // skip the escaped character
      // A `'`/`"` literal can't span a newline (an unterminated one is a misparse,
      // e.g. a quote inside a regex char-class `/["']/`); reset so a bogus span
      // never swallows later lines. Backticks legitimately span lines.
      if (ch === "\n" && quote !== "`") { quote = ""; continue; }
      if (ch === quote) { spans.push([quoteStart, k + 1]); quote = ""; }
      continue;
    }
    if (blockComments && ch === "/" && content[k + 1] === "*") { k++; inBlock = true; continue; }
    // Triple-quoted (multi-line) string: a Python docstring etc. The whole block
    // is one span so a crypto name inside it is classified as a prose mention.
    if (triple && tripleQuoteAt(content, k)) {
      const end = tripleQuoteEnd(content, k, ch);
      spans.push([k, end]);
      k = end - 1;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") { quote = ch; quoteStart = k; continue; }
    if (lineMarkers.some((m) => content.startsWith(m, k))) {
      while (k < content.length && content[k] !== "\n") k++; // skip to end of line
    }
  }
  // An unterminated string (no closing quote) yields no span — it can't be
  // classified as prose, so it falls through to CODE context, which is safe.
  return spans;
}

// A natural-language word: starts with a letter, then ≥2 lowercase letters, all
// alphabetic (no digits, hyphens, or slashes). "weak", "disabled", "handshake",
// "failed", "rejected", "migrating" match; crypto tokens do NOT — "RSA"/"AES" (no
// lowercase tail), "3DES"/"AES128" (digits), "ssh-rsa"/"des-ede3-cbc"/"RSA-OAEP"
// (hyphens), "ECDHE-RSA-AES128-GCM-SHA256" (caps + hyphens + digits).
const NL_WORD = /^[A-Za-z][a-z]{2,}$/;

/**
 * Does a string literal's inner text read like a natural-language LABEL, log line,
 * error, or sentence — rather than a structured crypto value or a tight algorithm
 * identifier? A string is a mention if it has ≥2 whitespace-separated words AND at
 * least one is a natural-language word.
 *
 * This separates a mention ("3DES weak", "Diffie-Hellman handshake failed", "we
 * removed diffie-hellman and 3DES") from a structured value that must keep its
 * confidence: an SSH key line ("ssh-rsa AAAA… user@host"), an OpenSSL cipher list
 * ("ECDHE-RSA-AES128-GCM-SHA256 …"), or a single tight token ("RSA-OAEP",
 * "diffie-hellman", "des-ede3-cbc") — none of which carry a natural-language word.
 * The ≥2-word floor keeps a lone lowercase algorithm token from being downgraded.
 */
function looksLikeMention(inner: string): boolean {
  const words = inner.trim().split(/\s+/);
  if (words.length < 2) return false;
  return words.some((w) => NL_WORD.test(w));
}

/**
 * Does a string literal read like a URL or an absolute path/route, where the
 * crypto name is a path *slug* rather than a cryptographic value? A REST route
 * (`/api/v2/diffie-hellman/rotate`) or a URL (`https://host/v2/ecdsa/sign`)
 * names an endpoint; it is not a use of the primitive.
 *
 * Deliberately narrow to avoid two recall traps the worklist flagged:
 *  - A Go module import is a string too (`"crypto/rsa"`), but it has NO leading
 *    slash and NO scheme — so it is NOT downgraded and a real Go crypto import
 *    still fires.
 *  - A cipher list (`ECDHE-RSA-AES128-GCM-SHA256 …`) carries whitespace and no
 *    leading slash, so it is untouched.
 * The rule covers three path/URL shapes (all whitespace-free): a URL is any
 * string containing `://`; a POSIX path/route starts with `/` (a route slug
 * `/diffie-hellman`, a hierarchy `/api/v2/dh/rotate`, a scheme-relative host
 * `//svc/dh`); a Windows path starts with a drive letter (`C:\…`, `C:/…`). A
 * non-KEY_MATERIAL crypto name is never a *use* inside such a string — uses are
 * code call-sites — so these signals are safe for recall, and key material stays
 * protected by the never-downgrade rule this folds into.
 */
function looksLikePathOrUrl(inner: string): boolean {
  const t = inner.trim();
  if (t.length < 2 || /\s/.test(t)) return false; // routes/URLs carry no whitespace
  if (t.includes("://")) return true; // any scheme://… URL
  if (t[0] === "/") return true; // POSIX absolute path or route slug
  return /^[A-Za-z]:[\\/]/.test(t); // Windows drive path (C:\… or C:/…)
}

/**
 * Is the match at `offset` sitting inside a MENTION string literal — a label, log
 * line, error message, or sentence that merely names a primitive, rather than a
 * structured crypto value or a tight algorithm identifier? A mention is downgraded
 * to a possible-mention; a value keeps its confidence.
 *
 * A template literal containing an interpolation (`${…}`) is never a mention: it
 * embeds executable code, and a real crypto call can live inside the `${…}` — so
 * downgrading it would be a recall loss. A match outside any string literal is
 * CODE context and returns false (left to the pattern's base confidence).
 */
export function isMentionStringAt(content: string, spans: Array<[number, number]>, offset: number): boolean {
  let lo = 0;
  let hi = spans.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const [s, e] = spans[mid];
    if (offset < s) hi = mid - 1;
    else if (offset >= e) lo = mid + 1;
    else {
      const literal = content.slice(s, e);
      if (literal.charCodeAt(0) === 96 /* backtick */ && literal.includes("${")) return false;
      const inner = content.slice(s + 1, e - 1); // strip the quotes
      return looksLikeMention(inner) || looksLikePathOrUrl(inner);
    }
  }
  return false;
}

/**
 * Is the match at `offset` a bare CODE token — i.e. NOT inside any string literal?
 * Used to upgrade a JOSE-algorithm identifier (`SignatureAlgorithm RS256 = …`, a
 * real typed declaration) above its conservative base confidence, while a token
 * that only ever appears as a string value (`["RS256"]`, a config list) stays a
 * low-confidence mention.
 */
export function isCodeTokenAt(spans: Array<[number, number]>, offset: number): boolean {
  let lo = 0;
  let hi = spans.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const [s, e] = spans[mid];
    if (offset < s) hi = mid - 1;
    else if (offset >= e) lo = mid + 1;
    else return false; // inside a string span
  }
  return true;
}

/**
 * Is the match at `offset` inside a TRIPLE-QUOTED docstring (`"""…"""`/`'''…'''`)?
 * A docstring is unambiguously prose, so even key-material tokens (`ssh-rsa` named
 * as an example in a `:param` doc) are mentions there — unlike an authorized_keys
 * file or config, which is never a docstring. Lets the never-downgrade rule yield
 * for documentation without exposing real key files.
 */
export function isInTripleQuoteAt(content: string, spans: Array<[number, number]>, offset: number): boolean {
  let lo = 0;
  let hi = spans.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const [s, e] = spans[mid];
    if (offset < s) hi = mid - 1;
    else if (offset >= e) lo = mid + 1;
    else return tripleQuoteAt(content, s) !== null;
  }
  return false;
}

/** Config values that turn an algorithm OFF. Compared case-insensitively after
 *  stripping surrounding quotes. */
const DISABLE_VALUES = new Set([
  "false", "0", "null", "off", "no", "none", "disabled", "disable", "deny", "denied", "never",
]);

/**
 * Is the match at `[start, end)` a config KEY explicitly assigned a DISABLING
 * value — `"ssh-rsa": false`, `dsa: off`, `weakCiphers = none`? Such a directive
 * turns the algorithm off; counting it as live exposure is backwards (the team
 * did the right thing by disabling it).
 *
 * This is the ONE signal allowed to override the never-downgrade rule for key
 * material: an explicit disable is the strongest possible evidence the primitive
 * is not in use. It is scoped tightly to key position — only a token immediately
 * followed (across an optional closing quote and whitespace) by `:`/`=` then a
 * disabling literal qualifies. A value-position token (`cipher = "ssh-rsa"`, an
 * allow-list array element) is NOT a key, so it still fires; an enabling value
 * (`"ssh-rsa": true`) is not disabling, so it still fires.
 */
export function isDisableDirectiveAt(
  content: string,
  spans: Array<[number, number]>,
  start: number,
  end: number,
): boolean {
  // If the token sits inside a string literal (a quoted JSON/YAML key), the key
  // ends at that span's closing quote; otherwise the key is the bare token.
  let pos = end;
  let lo = 0;
  let hi = spans.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const [s, e] = spans[mid];
    if (start < s) hi = mid - 1;
    else if (start >= e) lo = mid + 1;
    else { pos = e; break; } // start is inside this span
  }
  const isSpace = (c: string) => c === " " || c === "\t";
  while (pos < content.length && isSpace(content[pos])) pos++;
  // A C# dictionary-initializer key closes with `]` before the assignment
  // (`["ssh-rsa"] = false`); skip it so the directive is still recognized.
  if (content[pos] === "]") { pos++; while (pos < content.length && isSpace(content[pos])) pos++; }
  if (content[pos] !== ":" && content[pos] !== "=") return false;
  pos++;
  // A PHP/JS arrow assignment (`'ssh-rsa' => false`) has `>` after the `=`.
  if (content[pos] === ">") pos++;
  while (pos < content.length && isSpace(content[pos])) pos++;
  // Read the value token up to the next delimiter, strip quotes, lowercase.
  let j = pos;
  const DELIM = new Set([" ", "\t", "\n", ",", ";", "}", "]", ")"]);
  while (j < content.length && !DELIM.has(content[j])) j++;
  const val = content.slice(pos, j).replace(/^["']+|["']+$/g, "").toLowerCase();
  return DISABLE_VALUES.has(val);
}

// An enum / class constant read: an identifier, a dot, an ALL-CAPS member
// (`SignatureAlgorithm.DSA`, `Cipher.DES`). Method calls (`dsa.generate`,
// `RSA.Create`) have a lower/Pascal-case member and fail this; bare tokens
// (`DES`, `new DSA`) have no dotted form. The match TEXT must be exactly this
// shape, which is why it isolates the enum-constant arms from every call-site.
const ENUM_CONST_READ = /^[A-Za-z_$][\w$]*\.[A-Z][A-Z0-9_]*$/;

/**
 * Is the match a bare READ of an algorithm enum/class constant — a reference,
 * not an operation? `const x = SignatureAlgorithm.DSA;` and
 * `if (algo == SignatureAlgorithm.DSA)` name DSA but do not sign with it; the
 * actual use would be a keygen/sign call elsewhere. So this occurrence is a
 * possible mention, not exposure.
 *
 * Deliberately narrow — the zero-dependency stand-in for the call-vs-reference
 * data flow a full AST (ENG-01b) would give, scoped so it cannot swallow a real
 * use:
 *  - the match text itself is `Receiver.CONSTANT` (see ENUM_CONST_READ) — this
 *    alone excludes `dsa.generate`, `RSA.Create`, and bare-token matches;
 *  - the next char is neither `(` nor `.` — so an invocation (`X.DSA(…)`) and a
 *    fluent member access (`X.DSA.sign(…)`, where the operation is one `.method`
 *    away) both keep their confidence; and
 *  - it is the RHS of a plain assignment (`lhs = X.DSA`). A comparison
 *    (`== X.DSA`, `!= X.DSA`) is deliberately left at base confidence — it may
 *    guard a real use, so it is too ambiguous to downgrade without data flow. An
 *    argument-position use (`signWith(SignatureAlgorithm.DSA, key)`, preceded by
 *    `(`/`,`) likewise keeps its confidence and still fires.
 *
 * Known limit (the reason a full AST/ENG-01b would do better): this is purely
 * local — it cannot trace a variable, so `const a = SignatureAlgorithm.DSA;` is
 * a possible mention even if `a` is later passed to a signer. That data-flow case
 * is the deliberate trade for staying zero-dependency.
 */
export function isEnumConstRefAt(content: string, start: number, end: number, matchText: string): boolean {
  if (!ENUM_CONST_READ.test(matchText)) return false;
  if (content[end] === "(" || content[end] === ".") return false; // invocation or fluent member access, not a bare read
  let p = start - 1;
  while (p >= 0 && (content[p] === " " || content[p] === "\t")) p--;
  if (p < 0 || content[p] !== "=") return false;
  // Only a plain assignment `=` qualifies; exclude comparison operators that end
  // in `=` (`==` `!=` `<=` `>=`) — those are references that may guard a use.
  const before = content[p - 1];
  return before !== "=" && before !== "!" && before !== "<" && before !== ">";
}

/**
 * FILE-LEVEL crypto corroboration — the file-scope companion to the per-occurrence
 * context above, and the second (file-scope) down-payment on the call-vs-object
 * data flow a full AST (ENG-01b) would give.
 *
 * Some crypto *shapes* are lexically identical whether the receiver / identifier is
 * a real cryptographic object or an ordinary application one: `dh.generate()` reads
 * the same whether `dh` is a DiffieHellman or a DateHelper; `new DSA(zone)` whether
 * DSA is the Digital Signature Algorithm or a "Delivery Service Area"; a bare
 * `des3` / `aes_128` / `md5sum` / `pkcs12` token, or a `report.p12` filename, the
 * same whether it is Triple-DES / AES-128 / a keystore or a mundane business code.
 * At the call site alone they cannot be told apart. But a file that genuinely *does*
 * cryptography carries an unambiguous co-signal — a crypto import, a PEM block, a
 * curve constant, a keygen of a named primitive, a key-size. This scans the whole
 * file once for such signals. An ambiguous shape in a file WITHOUT any is treated as
 * a possible mention (still surfaced for review, not counted as hard exposure) —
 * the honest default. Real crypto files corroborate, so recall is preserved.
 *
 * The signal set is deliberately broad (favouring corroboration) so a real crypto
 * file almost never fails to corroborate — the cost of a false *negative* here is a
 * recall loss, which this project weighs more heavily than an extra possible-mention.
 * It excludes the ambiguous tokens themselves (a bare `dsa`/`rsa`/`dh`/`des3` is NOT
 * a corroborator — that would be circular and let a coincidental variable vouch for
 * its own call).
 */
const CRYPTO_CONTEXT_RE = new RegExp(
  [
    // ── library imports / namespaces / packages ──
    "\\bcrypto\\b", "cryptography", "System\\.Security\\.Cryptography", "javax\\.crypto",
    "java\\.security", "BouncyCastle", "bouncycastle", "libsodium", "\\bsodium\\b", "tweetnacl",
    "node-forge", "forge\\.pki", "CryptoKit", "mbedtls", "wolfssl", "openssl", "OpenSSL::",
    "Crypto\\.(?:PublicKey|Cipher|Hash|Signature)", "\\bpyca\\b", "\\bjose\\b", "jsonwebtoken",
    "jwcrypto", "\\bnimbus", "\\bjjwt\\b",
    // ── unambiguous operations / structured crypto tokens ──
    "createDiffieHellman", "DiffieHellman", "KeyPairGenerator", "MessageDigest",
    "Cipher\\.getInstance", "SecureRandom", "-----BEGIN", "\\bsecp256", "prime256v1",
    "\\bP-(?:256|384|521)\\b", "ssh-rsa\\s+AAAA", "ssh-dss\\s+AAAA", "KeyFactory", "KeyFactorySpi",
    "generatePrivateKey", "\\bx509\\b", "\\bpkcs8\\b", "\\bPrivateKey\\b", "\\bPublicKey\\b",
    "\\bECDSA\\b", "\\bECDH\\b", "\\bEd25519\\b", "\\bX25519\\b", "RSACryptoServiceProvider",
    "RSACng", "DSACryptoServiceProvider", "SignatureAlgorithm", "JWSAlgorithm", "SignedJWT",
    "\\bECDHE\\b", "AES-(?:128|192|256)-(?:CBC|GCM|CTR)", "hashlib", "createHash", "createCipher",
    "\\bHKDF\\b", "\\bPBKDF2\\b", "subtle\\.(?:sign|verify|generateKey|deriveKey|importKey)",
    "modulusLength", "namedCurve", "\\bJWK\\b", "\\bJWS\\b",
  ].join("|"),
  "i",
);

export function hasCryptoContext(content: string): boolean {
  return CRYPTO_CONTEXT_RE.test(content);
}

// A local (line-adjacent) corroborator for the keygen/keyload shapes: a key size, a
// key-size parameter, or an algorithm passed as an argument. Lets an isolated
// `RSA.Create(2048)` / `generateKeyPairSync("rsa", { modulusLength: 2048 })` stay
// actionable even when the file offers no other crypto signal, while a bare
// `RSA.Create(config)` / `orderBook.generateKeyPair(shardCount)` does not.
const LOCAL_KEYISH = /\b(?:512|768|1024|2048|3072|4096|7680|8192|15360)\b|modulusLength|\bbits\b|namedCurve|["'](?:rsa|ec|dsa|secp|prime|ed25519)|\bcurve\b/i;

/**
 * Is this occurrence an inherently-AMBIGUOUS crypto shape — one that resembles a
 * cryptographic operation but is lexically indistinguishable from an ordinary
 * application identifier, and so must be corroborated by file-level crypto context
 * (see `hasCryptoContext`) before it counts as exposure?
 *
 * Scoped per pattern to the specific ambiguous ARM(s) only — the unambiguous arms of
 * the same pattern (`createDiffieHellman`, `DSA_generate`, `des-ede3`, `hashlib.md5`,
 * `pkcs12.Decode(…)`) return false here and keep their base confidence. A trailing
 * window is consulted so a key size / algorithm argument (`LOCAL_KEYISH`) rescues a
 * genuine keygen that happens to share the shape.
 */
export function isAmbiguousMatch(
  patternId: string, matchText: string, content: string, end: number,
): boolean {
  const m = matchText.trim();
  const win = content.slice(end, end + 64); // trailing args: a key size / algorithm token rescues real keygen
  switch (patternId) {
    case "dsa-usage":
      // `dsa.generate(…)` and `new DSA(…)` collide with a DataSourceAdapter / a
      // "Delivery Service Area" class. `DSA_generate`, `ssh-dss`, `DSAPrivateKey`,
      // `SignatureAlgorithm.DSA` are specific and are NOT matched here.
      return /^dsa\.generate$/i.test(m) || (/^new DSA$/.test(m) && !LOCAL_KEYISH.test(win));
    case "dh-keyexchange":
      return /^dh\.generate$/i.test(m); // a DateHelper / DispatchHandler .generate()
    case "rsa-dotnet":
      return /^RSA\.Create$/.test(m) && !LOCAL_KEYISH.test(win); // RSA = "Regional Sales Aggregator" app class
    case "dsa-dotnet":
      return /^DSA\.Create$/.test(m) && !LOCAL_KEYISH.test(win);
    case "sym-des-3des":
      return /^des3$/i.test(m); // "destination hop 3", "detail expansion stage 3" — not Triple-DES
    case "sym-aes128":
      return /^(?:AES128|aes_128)$/i.test(m); // an enum member / location code; `aes-128-cbc` etc. stay
    case "hash-md5-sha1":
      return /^md5sum$/i.test(m); // a non-security cache-key label named `md5sum`
    case "pkcs12-keystore":
      // A real parse/decode CALL (`pkcs12.Decode(data, …)`) keeps confidence; a bare
      // `pkcs12` identifier or a `.p12`/`.pfx` FILENAME string (period-12, page-12,
      // carton-standard-12) is the ambiguous business-code form.
      if (/^pkcs12$/i.test(m)) return !/^\s*\.\s*(?:Decode|decode|Parse|parse|Load|load|Read|read|From|Import|import)/.test(win);
      return true;
    case "rsa-keygen-openssl":
      // `generateKeyPair(…)` is a generic method name (sharding, id allocation).
      // `RSA.generate`, `rsa_generate_key`, `new RSACryptoServiceProvider` are not
      // matched here. A key size / `"rsa"` / `modulusLength` argument rescues it.
      return /generateKeyPair/i.test(m) && !LOCAL_KEYISH.test(win);
    case "ecc-swift-cryptokit":
      return /^P(?:256|384|521)\.(?:Signing|KeyAgreement)$/.test(m); // a "Premium 256" product SKU enum case
    case "jwk-asymmetric-key": {
      // A real JWK carries companion fields — crv/x/y (EC), n/e (RSA), or kid/use/
      // alg/d. A JSON with `"kty":"EC"` but NONE of these is a coincidental
      // descriptor (kty = "kind-type", EC = "Economy Class"), not a key. This is a
      // self-contained shape test, so the field presence — not file context —
      // decides it; a genuine key object keeps its never-downgrade protection.
      const w = content.slice(Math.max(0, end - 200), end + 200);
      return !/"(?:crv|x|y|n|e|d|kid|use|key_ops|alg)"\s*:/.test(w);
    }
    default:
      return false;
  }
}
