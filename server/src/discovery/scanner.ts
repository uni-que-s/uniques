import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, relative, sep } from "node:path";
import type { CryptoAsset, ScanJob } from "../types.js";
import { PATTERNS, extractKeyBits } from "./patterns.js";

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
  "dist",
  "build",
  "vendor",
  "__pycache__",
  ".venv",
  "target",
  "coverage",
]);

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

    for (const pattern of PATTERNS) {
      const langOk =
        pattern.languages.includes(language) ||
        pattern.languages.includes("any") ||
        language === "pem";
      if (!langOk) continue;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.length > 1000) continue;
        pattern.regex.lastIndex = 0;
        if (!pattern.regex.test(line)) continue;

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
