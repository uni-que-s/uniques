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
      return looksLikeMention(content.slice(s + 1, e - 1)); // strip the quotes
    }
  }
  return false;
}
