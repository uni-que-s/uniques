/**
 * Score UniQueS recall on the NIST SARD / Juliet Java 1.3 crypto test cases
 * (CWE-327 broken crypto, CWE-328 reversible hash). Run `./download.sh` first to
 * fetch and extract the corpus, and build the server (`npm --prefix ../../server
 * run build`) so the engine is compiled.
 *
 * Ground truth comes from Juliet's own filenames (`__DES_01.java`, `__MD5_07.java`,
 * …). We report per-algorithm recall = fraction of that algorithm's test files in
 * which UniQueS surfaces at least one ACTIONABLE finding. Juliet's Main.java /
 * ServletMain.java harness stubs contain no crypto and are excluded.
 *
 * SCOPE: Juliet's crypto CWEs cover the CLASSICAL threat model (weak symmetric /
 * hash). They do NOT cover RSA/ECC/DSA/DH — Juliet treats those as the "safe"
 * answer. So this measures the legacy-crypto slice of UniQueS's scope only; see
 * bench/README.md.
 */
import { scanDirectory } from "../../server/dist/discovery/scanner.js";
import { readdirSync, statSync, existsSync } from "node:fs";
import { join, basename } from "node:path";
import { fileURLToPath } from "node:url";

const here = fileURLToPath(new URL(".", import.meta.url));
const root = join(here, "juliet-java");
if (!existsSync(root)) {
  console.error("Corpus not found. Run ./download.sh first (fetches the NIST Juliet zip).");
  process.exit(1);
}

function findDir(name) {
  const stack = [root];
  while (stack.length) {
    const d = stack.pop();
    for (const e of readdirSync(d)) {
      const p = join(d, e);
      if (statSync(p).isDirectory()) {
        if (e === name) return p;
        stack.push(p);
      }
    }
  }
  return null;
}
function walk(d) {
  let out = [];
  for (const e of readdirSync(d)) {
    const p = join(d, e);
    if (statSync(p).isDirectory()) out = out.concat(walk(p));
    else if (p.endsWith(".java")) out.push(p);
  }
  return out;
}
function algoOf(f) {
  if (/^Main\.java$|^ServletMain\.java$/.test(f)) return null; // harness stubs, no crypto
  if (/__3DES/.test(f)) return "3DES/DESede";
  if (/__DES_/.test(f)) return "DES";
  if (/__MD5/.test(f)) return "MD5";
  if (/__MD2/.test(f)) return "MD2";
  if (/__SHA1/.test(f)) return "SHA1";
  return "other";
}

const scope = { DES: "in", "3DES/DESede": "in", MD5: "in", SHA1: "in", MD2: "out (obsolete)", other: "n/a" };
const tally = {};
for (const cwe of ["CWE327_Use_Broken_Crypto", "CWE328_Reversible_One_Way_Hash"]) {
  const dir = findDir(cwe);
  if (!dir) continue;
  const { assets } = scanDirectory(dir, "sard");
  const flagged = new Set(assets.filter((a) => a.confidence !== "low").map((a) => basename(a.file)));
  for (const f of walk(dir)) {
    const algo = algoOf(basename(f));
    if (algo === null) continue;
    (tally[algo] ??= { total: 0, flagged: 0 }).total++;
    if (flagged.has(basename(f))) tally[algo].flagged++;
  }
}

let inTot = 0, inHit = 0;
console.log("\nNIST SARD / Juliet Java 1.3 — CWE-327 / CWE-328\n");
console.log("algorithm       files  flagged  recall   scope");
for (const [a, t] of Object.entries(tally)) {
  if (scope[a] === "in") { inTot += t.total; inHit += t.flagged; }
  console.log(a.padEnd(15), String(t.total).padStart(5), String(t.flagged).padStart(8), " " + (100 * t.flagged / t.total).toFixed(0) + "%", "  " + scope[a]);
}
console.log("\nIN-SCOPE RECALL (DES / 3DES / MD5 / SHA-1): " + inHit + "/" + inTot + " = " + (100 * inHit / inTot).toFixed(1) + "%");
console.log("(MD2 is intentionally out of scope; RSA/ECC/DSA/DH are not in Juliet's classical corpus.)");
