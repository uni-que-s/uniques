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
      if (ch === quote) { spans.push([quoteStart, k + 1]); quote = ""; }
      continue;
    }
    if (blockComments && ch === "/" && content[k + 1] === "*") { k++; inBlock = true; continue; }
    if (ch === '"' || ch === "'" || ch === "`") { quote = ch; quoteStart = k; continue; }
    if (lineMarkers.some((m) => content.startsWith(m, k))) {
      while (k < content.length && content[k] !== "\n") k++; // skip to end of line
    }
  }
  // An unterminated string (no closing quote) yields no span — it can't be
  // classified as prose, so it falls through to CODE context, which is safe.
  return spans;
}

// Common English function words. Their presence is the signal that a string is
// natural-language PROSE (a sentence / log line / doc) rather than a structured
// cryptographic value. A sentence — "we are migrating away from diffie-hellman" —
// is full of these; a structured value — an SSH key line `ssh-rsa <blob>
// user@host`, an OpenSSL cipher list, an X.509 DN — carries none. Word count
// alone can't tell them apart (a canonical SSH key is intrinsically ≥3 tokens),
// so we additionally require a function word before calling a string "prose".
const STOPWORDS = new Set([
  "a", "an", "the", "and", "or", "but", "if", "then", "else", "we", "you", "they", "he", "she", "it",
  "is", "are", "was", "were", "be", "been", "being", "to", "of", "in", "on", "at", "for", "from", "with",
  "as", "this", "that", "these", "those", "our", "your", "their", "its", "will", "would", "can", "could",
  "should", "may", "might", "must", "has", "have", "had", "do", "does", "did", "not", "no", "now", "please",
  "when", "while", "by", "via", "after", "before", "across", "all", "any", "into", "out", "up", "down", "about",
]);

/**
 * Does a string literal's inner text read like a natural-language sentence — ≥ 3
 * whitespace-separated words, at least one of which is a common function word?
 * This separates a real mention ("we removed diffie-hellman and 3DES") from a
 * structured crypto value ("ssh-rsa AAAA… user@host", "ECDHE-RSA-AES128-…") and
 * from a tight identifier ("RSA-OAEP", "RS256").
 */
function looksLikeProse(inner: string): boolean {
  const words = inner.trim().split(/\s+/);
  if (words.length < 3) return false;
  return words.some((w) => STOPWORDS.has(w.toLowerCase().replace(/[^a-z]/g, "")));
}

/**
 * Is the match at `offset` sitting inside a PROSE string literal — a string whose
 * content reads like a sentence rather than a structured crypto value or a tight
 * algorithm identifier? Prose is the signature of a *mention* (a log/error/doc
 * that names a primitive), not a use.
 *
 * A template literal containing an interpolation (`${…}`) is never prose: it
 * embeds executable code, and a real crypto call can live inside the `${…}` — so
 * downgrading it would be a recall loss. A match outside any string literal is
 * CODE context and returns false (left to the pattern's base confidence).
 */
export function isProseStringAt(content: string, spans: Array<[number, number]>, offset: number): boolean {
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
      return looksLikeProse(content.slice(s + 1, e - 1)); // strip the quotes
    }
  }
  return false;
}
