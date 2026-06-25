import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, relative, sep } from "node:path";
import type { CryptoAsset, ScanJob } from "../types.js";
import { PATTERNS, extractKeyBits, confidenceFor } from "./patterns.js";

const IGNORE_FILE = ".quantumvaultignore";

/**
 * Load path-prefix ignore patterns from a `.quantumvaultignore` at the scan
 * root. Lines are repo-relative paths (forward slashes); `#` lines and blanks
 * are skipped. Matching is deliberately prefix-based, NOT glob — a file or
 * directory is excluded only when its relative path equals a pattern or sits
 * under it. That keeps suppression explicit and unable to silently hide
 * findings via a stray wildcard. Used to baseline vendored or already-accepted
 * crypto so CI gating (`--fail-on`) isn't tripped by known exceptions.
 */
function loadIgnorePatterns(target: string): string[] {
  try {
    return readFileSync(join(target, IGNORE_FILE), "utf8")
      .split(/\r?\n/)
      .map((l) => l.trim().replace(/\/+$/, ""))
      .filter((l) => l && !l.startsWith("#"));
  } catch {
    return [];
  }
}

function makeIgnoreMatcher(patterns: string[]): (rel: string) => boolean {
  if (patterns.length === 0) return () => false;
  return (rel: string) => {
    const r = rel.split(sep).join("/");
    return patterns.some((p) => r === p || r.startsWith(p + "/"));
  };
}

const EXT_LANG: Record<string, string> = {
  ".js": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".jsx": "javascript",
  ".py": "python",
  ".go": "go",
  ".java": "java",
  ".cs": "csharp",
  ".c": "c",
  ".h": "c",
  ".cpp": "cpp",
  ".cc": "cpp",
  ".cxx": "cpp",
  ".hpp": "cpp",
  ".hh": "cpp",
  ".rs": "rust",
  ".rb": "ruby",
  ".php": "php",
  ".swift": "swift",
  ".kt": "kotlin",
  ".kts": "kotlin",
  ".scala": "scala",
  ".yaml": "yaml",
  ".yml": "yaml",
  ".json": "json",
  ".conf": "config",
  ".cfg": "config",
  ".ini": "config",
  ".pem": "pem",
  ".crt": "pem",
  ".key": "pem",
  ".env": "config",
  ".tf": "terraform",
};

const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  ".claude",
  ".idea",
  ".vscode",
  "dist",
  "build",
  "vendor",
  "__pycache__",
  ".venv",
  "target",
  "coverage",
]);

// Directories whose crypto is not part of a production cryptographic posture —
// tests, examples, samples, fixtures, mocks, demos. Skipped by default so a
// scan's grade reflects SHIPPED code, not test fixtures or sample data. Without
// this, a healthy repo gets graded "F" on its own test inputs — the worst first
// impression a security tool can make. (Applied to directories only.)
const NON_PRODUCTION_DIRS = new Set([
  "test", "tests", "__tests__", "spec", "specs", "__mocks__", "mocks", "mock",
  "e2e", "examples", "example", "samples", "sample", "fixtures", "fixture",
  "__fixtures__", "testdata", "demo", "demos",
]);
const NON_PRODUCTION_PREFIX = /^(sample|example|test|spec|mock|fixture|demo)[-_.]/;
function isNonProductionDir(name: string): boolean {
  const n = name.toLowerCase();
  return NON_PRODUCTION_DIRS.has(n) || NON_PRODUCTION_PREFIX.test(n);
}

const MAX_FILE_BYTES = 2_000_000;
const NULL_BYTE = "\x00";

function languageFor(file: string): string | null {
  const ext = extname(file).toLowerCase();
  if (ext in EXT_LANG) return EXT_LANG[ext];
  if (file.endsWith("Dockerfile") || file.endsWith(".dockerfile")) return "config";
  return null;
}

function* walk(dir: string, root: string, isIgnored: (rel: string) => boolean): Generator<string> {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const name of entries) {
    if (SKIP_DIRS.has(name)) continue;
    const full = join(dir, name);
    if (isIgnored(relative(root, full))) continue;
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      if (isNonProductionDir(name)) continue; // tests/examples/samples: not production posture
      yield* walk(full, root, isIgnored);
    } else if (st.isFile() && st.size <= MAX_FILE_BYTES) {
      yield full;
    }
  }
}

let assetSeq = 0;
function nextAssetId(): string {
  assetSeq += 1;
  return `asset_${assetSeq.toString(36)}_${Date.now().toString(36)}`;
}

const C_STYLE = new Set([
  "javascript", "typescript", "c", "cpp", "csharp", "java", "kotlin", "scala", "go", "rust", "swift", "php",
]);
const HASH_STYLE = new Set(["python", "ruby", "yaml", "config", "terraform", "php"]);

/**
 * Return `content` with comment regions blanked to spaces (newlines preserved, so
 * line/column positions are unchanged). String and template literals are kept
 * intact — a crypto name in a comment is a *mention* and must not fire, but real
 * uses live inside strings (e.g. `getInstance("RSA")`, JWT alg values, PEM blocks),
 * so those stay matchable. This is the cheap, regex-level precision win; semantic
 * (AST) call-site detection is the larger follow-on.
 */
export function maskComments(content: string, language: string): string {
  const lineMarkers: string[] = [];
  if (C_STYLE.has(language)) lineMarkers.push("//");
  if (HASH_STYLE.has(language)) lineMarkers.push("#");
  const blockComments = C_STYLE.has(language);
  if (lineMarkers.length === 0 && !blockComments) return content;

  let out = "";
  let inBlock = false;
  let quote = "";
  for (let k = 0; k < content.length; k++) {
    const ch = content[k];
    if (inBlock) {
      if (ch === "*" && content[k + 1] === "/") { out += "  "; k++; inBlock = false; }
      else out += ch === "\n" ? "\n" : " ";
      continue;
    }
    if (quote) {
      out += ch;
      if (ch === "\\") { out += content[k + 1] ?? ""; k++; }
      else if (ch === quote) quote = "";
      continue;
    }
    if (blockComments && ch === "/" && content[k + 1] === "*") { out += "  "; k++; inBlock = true; continue; }
    if (ch === '"' || ch === "'" || ch === "`") { quote = ch; out += ch; continue; }
    const isLineComment = lineMarkers.some((m) => content.startsWith(m, k));
    if (isLineComment) {
      while (k < content.length && content[k] !== "\n") { out += " "; k++; }
      if (k < content.length) out += "\n";
      continue;
    }
    out += ch;
  }
  return out;
}

export interface ScanResult {
  job: ScanJob;
  assets: CryptoAsset[];
}

/**
 * Scan a directory tree for quantum-vulnerable cryptographic assets.
 * Returns a completed ScanJob plus the assets discovered (without risk scores;
 * those are attached downstream by the risk scoring service).
 */
export function scanDirectory(target: string, scanId: string): ScanResult {
  const startedAt = new Date();
  const start = performance.now();
  const assets: CryptoAsset[] = [];
  let filesScanned = 0;

  const isIgnored = makeIgnoreMatcher(loadIgnorePatterns(target));

  for (const file of walk(target, target, isIgnored)) {
    const language = languageFor(file);
    if (!language) continue;
    filesScanned += 1;

    let content: string;
    try {
      content = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    if (content.indexOf(NULL_BYTE) !== -1) continue; // skip binary files

    const rel = relative(target, file) || file;
    const lines = content.split(/\r?\n/);
    const codeLines = maskComments(content, language).split(/\r?\n/);

    for (const pattern of PATTERNS) {
      const langOk =
        pattern.languages.includes(language) ||
        pattern.languages.includes("any") ||
        language === "pem";
      if (!langOk) continue;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const codeLine = codeLines[i] ?? line;
        if (line.length > 1000) continue;
        pattern.regex.lastIndex = 0;
        // Match against the comment-masked view: a crypto name in a comment is a
        // mention, not a use, and must not fire. String literals are preserved.
        if (!pattern.regex.test(codeLine)) continue;

        assets.push({
          id: nextAssetId(),
          scanId,
          file: rel,
          line: i + 1,
          family: pattern.family,
          algorithm: pattern.algorithm,
          keyBits: extractKeyBits(line, pattern.family),
          language,
          snippet: line.trim().slice(0, 240),
          patternId: pattern.id,
          quantumVulnerable: pattern.quantumVulnerable,
          confidence: confidenceFor(pattern.id),
          pqcReplacement: pattern.pqcReplacement,
          status: "open",
        });
      }
    }
  }

  const finishedAt = new Date();
  const durationMs = Math.round(performance.now() - start);

  const job: ScanJob = {
    id: scanId,
    target,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    filesScanned,
    durationMs,
    assetCount: assets.length,
    status: "completed",
  };

  return { job, assets };
}
